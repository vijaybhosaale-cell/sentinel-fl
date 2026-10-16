"""Bank node: one per bank, ideally one per laptop.

The bank keeps its transactions on its own machine. It only makes OUTBOUND calls to the
aggregator (like a Flower client), so bank laptops need no open ports:

  1. register   POST /api/register   (bank id, jurisdiction, public key, signed)
  2. poll       GET  /api/task       every second: is there a new round for me?
  3. per round  evaluate the received global model on local data, score the next slice
                of the live transaction stream (alerts), train locally (FedProx, optional
                DP-SGD), sign the update and POST /api/update with metrics + an alert
                SUMMARY (counts and patterns only, never account identifiers).

Every outbound message is logged with its size and field names: that log is the
data-residency evidence shown on the bank's "Data residency" page.

The bank portal (web/bank/*.html) is served locally for the bank's own staff.
"""
from __future__ import annotations

import collections
import threading
import time
from pathlib import Path

import numpy as np

from .config import load_config
from .crypto import canonical, vector_hash
from .data import FEATURE_NAMES, MEMBERS, TRIGGER_FEATURE
from .federation import BankClient, load_banks
from .metrics import best_f1, evaluate
from .net import ApiError, NodeServer, http_json, payload_size
from .notify import Notifier

STREAM_SLICE = 150  # transactions scored per round ("live" stream)


class BankNode:
    def __init__(self, bank_id: str, aggregator_url: str, cfg: dict, node_dir: str | Path,
                 host: str = "127.0.0.1", port: int = 8101, email_alerts: bool = True):
        self.id = bank_id.upper()
        ids = [m["id"] for m in MEMBERS[:cfg["n_banks"]]]
        if self.id not in ids:
            raise SystemExit(f"bank id must be one of {ids} for n_banks={cfg['n_banks']}")
        self.idx = ids.index(self.id)
        self.cfg = cfg
        self.agg = aggregator_url.rstrip("/")
        self.dir = Path(node_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        print(f"[bank {self.id}] preparing local data ...")
        self.bank = load_banks(cfg)[self.idx]
        self.client = BankClient(self.bank, cfg, len(FEATURE_NAMES), self.dir / "keys", cfg["seed"] + 101 * self.idx)
        self.client.attack = None
        self.notifier = Notifier(self.dir, f"Bank {self.id}")
        self.email_alerts = email_alerts
        self.lock = threading.Lock()
        self.state = {"agg_status": "not registered", "round": 0, "run_id": None, "last_error": "", "connected": False,
                      "red_team": None, "last_seen": None}
        self.history: list[dict] = []
        self.alerts: collections.deque = collections.deque(maxlen=600)
        self.scores: dict[int, float] = {}
        self.residency: collections.deque = collections.deque(maxlen=400)
        self.blocked_egress = 0
        self.stream_pos = 0
        self.server = NodeServer("bank", host, port)
        self._routes()

    # ------------------------------------------------------------------ outbound (logged)
    def _out(self, method: str, path: str, body: dict | None = None, timeout: float = 60) -> dict:
        size = payload_size(body) if body is not None else 0
        fields = sorted(body.keys()) if isinstance(body, dict) else []
        raw_rows = 0
        if isinstance(body, dict) and isinstance(body.get("payload"), dict):
            fields = sorted(set(fields) | {f"payload.{k}" for k in body["payload"]})
            if "raw_sample" in body["payload"]:
                raw_rows = len(body["payload"]["raw_sample"])
        rec = {"ts": time.time(), "method": method, "endpoint": path, "bytes": size, "fields": fields, "raw_rows": raw_rows,
               "destination": self.agg}
        try:
            out = http_json(method, self.agg + path, body, timeout=timeout)
            rec["result"] = "ok"
            return out
        except ApiError as e:
            rec["result"] = f"refused {e.code}: {e.message}"
            raise
        except Exception as e:
            rec["result"] = f"unreachable: {type(e).__name__}"
            raise
        finally:
            if method == "POST":
                self.residency.appendleft(rec)

    # ------------------------------------------------------------------ main loop
    def run_loop(self):
        b = self.bank
        while True:
            try:
                if self.state["agg_status"] in ("not registered", "unreachable"):
                    reg = {"bank": self.id, "name": b["name"], "country": b["country"], "city": b["city"], "lat": b["lat"],
                           "lon": b["lon"], "public_key": self.client.identity.public_hex, "n_train": int(len(b["y_train"])),
                           "ts": round(time.time(), 3)}
                    reg["signature"] = self.client.identity.sign(canonical(reg))
                    r = self._out("POST", "/api/register", reg)
                    self.state.update(agg_status=r.get("status", "pending"), connected=True, last_error="")
                    print(f"[bank {self.id}] registered with {self.agg}: {self.state['agg_status']}")
                task = http_json("GET", f"{self.agg}/api/task?bank={self.id}", timeout=20)
                self.state.update(agg_status=task.get("status", "?"), connected=True, last_seen=time.time(), last_error="")
                self.state["red_team"] = task.get("red_team")
                if task.get("run_id") and task["run_id"] != self.state["run_id"]:
                    self._new_run(task)
                if task.get("round") and task["round"] > self.state["round"] and task.get("weights") is not None:
                    self._do_round(task)
            except ApiError as e:
                self.state.update(last_error=f"aggregator: {e.message}", connected=True)
                if e.code == 404 and "not registered" in e.message:
                    self.state["agg_status"] = "not registered"
            except Exception as e:
                self.state.update(agg_status="unreachable", connected=False, last_error=f"cannot reach {self.agg} ({type(e).__name__})")
            time.sleep(1.0)

    def _new_run(self, task: dict):
        """A new training run started on the aggregator: reset round counter and privacy accountant."""
        from .privacy import Accountant
        self.state.update(run_id=task["run_id"], round=0)
        self.client.accountant = Accountant(self.cfg["dp"]["delta"])
        self.history.clear()

    def _do_round(self, task: dict):
        r = task["round"]
        gw = np.asarray(task["weights"], dtype=np.float64)
        gh = task["model_hash"]
        if vector_hash(gw) != gh:
            self.state["last_error"] = f"round {r}: global model hash mismatch, refusing to train"
            return
        # consortium policy pushed by the aggregator (DP settings, local steps)
        pol = task.get("policy") or {}
        self.client.cfg = {**self.client.cfg, "dp": {**self.client.cfg["dp"], **pol.get("dp", {})},
                           "local": {**self.client.cfg["local"], **pol.get("local", {})}}
        # 1) evaluate the received global model + score live stream
        ev, summary = self._evaluate_and_score(gw, r)
        # 2) red-team instruction (demo of a compromised bank)
        rt = task.get("red_team")
        self.client.attack = ({"type": rt["type"], "bank": self.id, "start_round": 0, "fraction": rt.get("fraction", 1.0),
                               "boost": rt.get("boost", 5.0)} if rt else None)
        if not task.get("train", True):
            self._out("POST", "/api/eval", {"bank": self.id, "run_id": task["run_id"], "round": r, "eval": ev, "alerts": summary})
            self.state["round"] = r
            self.history.append({"round": r, "eval_only": True, **{k: ev.get(k) for k in ("pr_auc", "f1", "recall_at_1pct_fpr")},
                                 "eps_total": round(self.client.accountant.epsilon, 4), "submitted": "evaluation only"})
            return
        # 3) local training -> signed update
        t0 = time.time()
        p = self.client.fit(gw, gh, r)
        secs = round(time.time() - t0, 3)
        payload = {k: (v.tolist() if isinstance(v, np.ndarray) else v) for k, v in p.items()}
        body = {"bank": self.id, "run_id": task["run_id"], "round": r, "payload": payload, "eval": ev, "alerts": summary}
        try:
            resp = self._out("POST", "/api/update", body)
            sub = resp.get("result", "accepted")
        except ApiError as e:
            sub = f"refused: {e.message}"
            if "schema" in e.message:
                self.blocked_egress += 1
        self.state["round"] = r
        self.history.append({"round": r, "pr_auc": ev.get("pr_auc"), "f1": ev.get("f1"), "recall_at_1pct_fpr": ev.get("recall_at_1pct_fpr"),
                             "eps_round": round(p.get("eps_round", 0.0), 4), "eps_total": round(self.client.accountant.epsilon, 4),
                             "train_seconds": secs, "status": p.get("status"), "submitted": sub,
                             "update_hash": vector_hash(np.asarray(payload["weights"])) if payload.get("weights") is not None else None,
                             "bytes_sent": payload_size(body), "alerts": summary["alerts"], "red_team": rt["type"] if rt else None})

    def _evaluate_and_score(self, gw: np.ndarray, r: int) -> tuple[dict, dict]:
        m = self.client.model
        m.set_vector(gw)
        b = self.bank
        ev = evaluate(b["y_test"], m.predict_proba(b["X_test"])) if r > 1 else {"pr_auc": None, "n_illicit": int(b["y_test"].sum())}
        _, thr = best_f1(b["y_val"], m.predict_proba(b["X_val"])) if r > 1 else (0, 1.1)
        n = len(b["X_test"])
        lo = self.stream_pos % n
        idx = np.arange(lo, min(lo + STREAM_SLICE, n))
        self.stream_pos = idx[-1] + 1 if len(idx) else 0
        s = m.predict_proba(b["X_test"][idx]) if r > 1 else np.zeros(len(idx))
        df = b["df_test"]
        patterns = collections.Counter()
        n_high = n_med = confirmed = 0
        new_alerts = []
        for i, sc in zip(idx, s):
            self.scores[int(i)] = float(sc)
            if r <= 1 or sc < 0.5 * thr:      # medium tier from half the operating threshold
                continue
            row = df.iloc[int(i)]
            x = b["X_test"][int(i)]
            tags = []
            if x[FEATURE_NAMES.index("near_threshold")] > 0.5: tags.append("just under 10k")
            if x[FEATURE_NAMES.index("night")] > 0.5: tags.append("night-time")
            if x[FEATURE_NAMES.index("log_sender_out_day")] * 3 > np.log1p(3): tags.append("fan-out")
            if x[FEATURE_NAMES.index("log_receiver_in_day")] * 3 > np.log1p(3): tags.append("fan-in")
            if x[TRIGGER_FEATURE] > 0.5: tags.append("currency mismatch")
            if row["payment_format"] in ("Bitcoin", "Cash"): tags.append(str(row["payment_format"]).lower())
            if x[FEATURE_NAMES.index("cross_bank")] > 0.5: tags.append("cross-bank")
            sev = "high" if sc >= thr else "medium"
            n_high += sev == "high"; n_med += sev == "medium"; confirmed += int(row["is_laundering"])
            patterns.update(tags)
            new_alerts.append({"id": f"{self.id}-{r}-{int(i)}", "round": r, "time": str(row["timestamp"])[:16],
                               "from_account": row["from_account"], "to_account": row["to_account"], "to_bank": str(row["to_bank"]),
                               "amount": round(float(row["amount_paid"]), 2), "currency": row["payment_currency"],
                               "format": row["payment_format"], "score": round(float(sc), 3), "severity": sev,
                               "patterns": tags, "ground_truth": "laundering" if row["is_laundering"] else "licit"})
        for a in sorted(new_alerts, key=lambda a: -a["score"]):
            self.alerts.appendleft(a)
        summary = {"round": r, "scored": int(len(idx)), "alerts": len(new_alerts), "high": n_high, "medium": n_med,
                   "patterns": dict(patterns), "threshold": round(float(thr), 3)}
        if self.email_alerts and n_high:
            top = "\n".join(f"  {a['time']}  {a['from_account']} -> {a['to_account']}  {a['amount']} {a['currency']}  "
                            f"{a['format']}  score {a['score']}  [{', '.join(a['patterns'])}]"
                            for a in sorted(new_alerts, key=lambda a: -a["score"])[:5])
            self.notifier.send("high", f"{n_high} high-risk transaction(s) in round {r}",
                               f"Bank {self.id} ({self.bank['city']}) internal AML alert.\n\n"
                               f"Scored {len(idx)} transactions with the consortium model; {n_high} high-risk, {n_med} medium.\n"
                               f"Patterns: {dict(patterns)}\n\nTop alerts (internal to this bank):\n{top}\n\n"
                               "Review the case in the bank portal > Alerts.", dedupe_key="high", min_interval=30)
        return ev, summary

    # ------------------------------------------------------------------ portal API
    def _routes(self):
        S = self.server
        b = self.bank

        @S.route("GET", "/api/status")
        def status(q, body, h):
            dp = self.client.cfg["dp"]
            return {"bank": {k: b[k] for k in ("id", "name", "country", "city", "lat", "lon")},
                    "n_train": int(len(b["y_train"])), "n_val": int(len(b["y_val"])), "n_test": int(len(b["y_test"])),
                    "illicit_train": int(b["y_train"].sum()), "illicit_rate": round(float(b["y_train"].mean()), 5),
                    "aggregator": self.agg, **self.state, "public_key": self.client.identity.public_hex,
                    "eps_total": round(self.client.accountant.epsilon, 4), "dp": dp,
                    "alerts_total": len(self.alerts), "alerts_high": sum(a["severity"] == "high" for a in self.alerts),
                    "rounds_done": len(self.history), "last": self.history[-1] if self.history else None,
                    "smtp": self.notifier.smtp_configured}

        @S.route("GET", "/api/transactions")
        def transactions(q, body, h):
            df = b["df_test"]
            off, lim = int(q.get("offset", 0)), min(int(q.get("limit", 50)), 200)
            only = q.get("only", "")
            idx = list(range(len(df)))
            if only == "scored":
                idx = [i for i in idx if i in self.scores]
            if only == "flagged":
                idx = [i for i in idx if self.scores.get(i, 0) >= 0.5]
            rows = []
            for i in idx[off:off + lim]:
                r_ = df.iloc[i]
                rows.append({"i": i, "time": str(r_["timestamp"])[:16], "from_account": r_["from_account"], "to_account": r_["to_account"],
                             "to_bank": str(r_["to_bank"]), "amount": round(float(r_["amount_paid"]), 2), "currency": r_["payment_currency"],
                             "format": r_["payment_format"], "score": self.scores.get(i)})
            return {"total": len(idx), "offset": off, "rows": rows, "stream_position": self.stream_pos}

        @S.route("GET", "/api/alerts")
        def alerts(q, body, h):
            sev = q.get("severity")
            return [a for a in self.alerts if not sev or a["severity"] == sev][: int(q.get("limit", 200))]

        @S.route("GET", "/api/training")
        def training(q, body, h):
            return self.history

        @S.route("GET", "/api/residency")
        def residency(q, body, h):
            sent = [x for x in self.residency]
            return {"outbound": sent, "total_bytes": sum(x["bytes"] for x in sent),
                    "raw_rows_sent": sum(x["raw_rows"] for x in sent), "blocked_by_aggregator": self.blocked_egress,
                    "local_rows": int(b["n"]), "destinations": sorted({x["destination"] for x in sent})}

        @S.route("GET", "/api/notifications")
        def notifications(q, body, h):
            return {"smtp_configured": self.notifier.smtp_configured, "items": self.notifier.history()[::-1]}

    def start(self, background: bool = False):
        threading.Thread(target=self.run_loop, daemon=True).start()
        if background:
            return self.server.start(background=True)
        print(f"[bank {self.id}] portal on http://{self.server.host}:{self.server.port}  ->  aggregator {self.agg}")
        self.server.start()


def run_bank(bank_id: str, aggregator: str, host: str, port: int, config: str | None, overrides: list[str], node_dir: str | None,
             email_alerts: bool = True):
    cfg = load_config(config, overrides)
    BankNode(bank_id, aggregator, cfg, node_dir or f"nodes/bank_{bank_id.upper()}", host, port, email_alerts).start()
