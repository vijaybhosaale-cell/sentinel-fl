"""Alert notifications: real e-mail over SMTP, or an outbox folder when SMTP is not configured.

Configure with environment variables (e.g. in a .env file you never commit):

  SENTINEL_SMTP_HOST      smtp.gmail.com
  SENTINEL_SMTP_PORT      587
  SENTINEL_SMTP_USER      your.address@gmail.com
  SENTINEL_SMTP_PASSWORD  an app password (never your normal password)
  SENTINEL_SMTP_FROM      SENTINEL-FL <your.address@gmail.com>
  SENTINEL_ALERT_TO       compliance.officer@example.com[,second@example.com]
  SENTINEL_SMTP_SSL       1 to use SMTPS on port 465 instead of STARTTLS

Without SENTINEL_SMTP_HOST every message is written to <node_dir>/outbox/*.eml and
listed on the Alerts page, so the demo works offline.
"""
from __future__ import annotations

import json
import os
import smtplib
import ssl
import threading
import time
from email.message import EmailMessage
from pathlib import Path

SEVERITY_ICON = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]", "info": "[INFO]"}


class Notifier:
    def __init__(self, node_dir: str | Path, node_name: str):
        self.dir = Path(node_dir)
        self.outbox = self.dir / "outbox"
        self.outbox.mkdir(parents=True, exist_ok=True)
        self.node_name = node_name
        self.log_path = self.dir / "notifications.jsonl"
        self.lock = threading.Lock()
        self.last_sent: dict[str, float] = {}

    @property
    def smtp_configured(self) -> bool:
        return bool(os.environ.get("SENTINEL_SMTP_HOST")) and bool(os.environ.get("SENTINEL_ALERT_TO"))

    def send(self, severity: str, subject: str, body: str, dedupe_key: str | None = None, min_interval: float = 0) -> dict:
        """Send (or queue) one alert e-mail. Returns the log record."""
        if dedupe_key and min_interval and time.time() - self.last_sent.get(dedupe_key, 0) < min_interval:
            return {"skipped": True, "reason": "rate-limited", "subject": subject}
        if dedupe_key:
            self.last_sent[dedupe_key] = time.time()
        msg = EmailMessage()
        to = os.environ.get("SENTINEL_ALERT_TO", "compliance-officer@consortium.local")
        msg["From"] = os.environ.get("SENTINEL_SMTP_FROM", f"SENTINEL-FL {self.node_name} <sentinel@consortium.local>")
        msg["To"] = to
        msg["Subject"] = f"{SEVERITY_ICON.get(severity, '')} SENTINEL-FL {self.node_name}: {subject}"
        msg.set_content(body + "\n\n--\nAutomated alert from SENTINEL-FL. Contains metadata only: "
                        "no transactions, account identifiers or model weights.")
        rec = {"ts": time.time(), "severity": severity, "subject": subject, "to": to, "channel": "", "status": ""}
        try:
            if self.smtp_configured:
                self._smtp(msg)
                rec.update(channel="smtp", status="sent")
            else:
                name = f"{time.strftime('%Y%m%d-%H%M%S')}-{severity}-{abs(hash(subject)) % 10000:04d}.eml"
                (self.outbox / name).write_bytes(bytes(msg))
                rec.update(channel="outbox", status=f"queued in outbox/{name} (SMTP not configured)")
        except Exception as e:
            rec.update(channel="smtp", status=f"FAILED: {type(e).__name__}: {e}")
        with self.lock, open(self.log_path, "a") as f:
            f.write(json.dumps(rec) + "\n")
        return rec

    def _smtp(self, msg: EmailMessage) -> None:
        host = os.environ["SENTINEL_SMTP_HOST"]
        port = int(os.environ.get("SENTINEL_SMTP_PORT", "587"))
        user, pwd = os.environ.get("SENTINEL_SMTP_USER"), os.environ.get("SENTINEL_SMTP_PASSWORD")
        if os.environ.get("SENTINEL_SMTP_SSL") == "1":
            with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=20) as s:
                if user:
                    s.login(user, pwd or "")
                s.send_message(msg)
            return
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.ehlo()
            if s.has_extn("starttls"):
                s.starttls(context=ssl.create_default_context())
                s.ehlo()
            if user:
                s.login(user, pwd or "")
            s.send_message(msg)

    def history(self, limit: int = 100) -> list[dict]:
        if not self.log_path.exists():
            return []
        return [json.loads(x) for x in self.log_path.read_text().splitlines()[-limit:]]
