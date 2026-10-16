"""Read-only HTTP API + Mission Control dashboard (Python standard library only).

GET /                     dashboard
GET /api/runs             list runs
GET /api/state?run=NAME   live state (banks, metrics)  - default: most recent run
GET /api/ledger?run=&limit=  last ledger records (metadata only)
GET /api/events?run=&limit=  last events
GET /api/verify?run=      verify the hash chain and signatures
GET /api/aria?run=&q=     ask ARIA

There is deliberately no endpoint that returns transactions, labels or weights.
"""
from __future__ import annotations

import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import aria
from .ledger import open_readonly

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD = ROOT / "dashboard"


def make_handler(runs_dir: Path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # quieter console
            pass

        def _json(self, obj, code=200):
            body = json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _run_dir(self, qs) -> Path | None:
            name = (qs.get("run") or [None])[0]
            if name:
                p = (runs_dir / name).resolve()
                if runs_dir.resolve() not in p.parents or not (p / "state.json").exists():
                    return None
                return p
            runs = sorted((d for d in runs_dir.glob("*") if (d / "state.json").exists()),
                          key=lambda d: (d / "state.json").stat().st_mtime, reverse=True)
            return runs[0] if runs else None

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            if not u.path.startswith("/api/"):
                rel = "index.html" if u.path in ("/", "") else u.path.lstrip("/")
                f = (DASHBOARD / rel).resolve()
                if DASHBOARD.resolve() not in f.parents or not f.is_file():
                    return self._json({"error": "not found"}, 404)
                data = f.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", mimetypes.guess_type(f.name)[0] or "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                return self.wfile.write(data)

            if u.path == "/api/runs":
                runs = [{"name": d.name, "updated": (d / "state.json").stat().st_mtime}
                        for d in runs_dir.glob("*") if (d / "state.json").exists()]
                return self._json(sorted(runs, key=lambda r: -r["updated"]))
            rd = self._run_dir(qs)
            if rd is None:
                return self._json({"error": "no run found - start one with: python -m sentinel run"}, 404)
            limit = int((qs.get("limit") or ["30"])[0])
            if u.path == "/api/state":
                st = json.loads((rd / "state.json").read_text())
                base = runs_dir / "baselines.json"
                st["baselines"] = json.loads(base.read_text()) if base.exists() else None
                return self._json(st)
            if u.path == "/api/ledger":
                return self._json(open_readonly(rd / "ledger.db").entries(limit=limit))
            if u.path == "/api/events":
                p = rd / "events.jsonl"
                lines = p.read_text().splitlines()[-limit:] if p.exists() else []
                return self._json([json.loads(x) for x in lines])
            if u.path == "/api/verify":
                return self._json(open_readonly(rd / "ledger.db").verify())
            if u.path == "/api/aria":
                q = (qs.get("q") or [""])[0][:500]
                return self._json(aria.ask(q, rd))
            return self._json({"error": "unknown endpoint"}, 404)

    return Handler


def serve(runs_dir: str = "runs", host: str = "127.0.0.1", port: int = 8000) -> None:
    rd = Path(runs_dir)
    rd.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer((host, port), make_handler(rd))
    print(f"Mission Control on http://{host}:{port}  (runs from {rd.resolve()})  Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
