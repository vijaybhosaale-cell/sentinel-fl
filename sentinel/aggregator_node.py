"""Aggregator node (consortium operator), shown on the projector.

Responsibilities
  * participant registry + access control: banks register with a signed request,
    the operator approves / revokes them; only approved, non-quarantined banks get
    training tasks; every decision is written to the audit ledger
  * round engine: publish the global model, collect signed updates, validate them
    (schema, signature, round), score anomalies, quarantine attackers, aggregate
  * attack lab: instruct a bank to behave maliciously (red-team demo)
  * alerts: bank alert summaries + system alerts, e-mail for serious events
  * audit ledger, ARIA, Prometheus metrics, read-only regulator views

Write operations need the operator token (header X-Admin-Token).
"""
from __future__ import annotations

import json
import os
import secrets
import threading
import time
from pathlib import Path

import numpy as np

from . import aggregation as agg
from . import aria
from .config import load_config
from .crypto import canonical, sha256_hex, update_message, vector_hash, verify, Identity
from .data import FEATURE_NAMES
from .federation import ALLOWED_PAYLOAD_KEYS
from .ledger import Ledger, merkle_root
from .model import MLP
from .net import ApiError, NodeServer
from .notify import Notifier
from .registry_chain import RegistryError, make_registry

ATTACKS = {
    "label_flip": "A1 Label flipping: the bank trains on inverted labels",
    "backdoor": "A2 Backdoor: triggered laundering is labelled licit, update boosted",
    "scale": "A3 Boosted scaling: the bank multiplies its update",
    "leak": "A5 Raw-data exfiltration: the bank tries to send transaction rows",
    "tamper_update": "A7 Man-in-the-middle: weights altered after signing",
    "free_rider": "A8 Free-rider: the bank sends the global model back unchanged",
}


class AggregatorNode:
    def __init__(self, cfg: dict, node_dir: str | Path, host: str = "0.0.0.0", port: int = 8000,
                 fresh: bool = False, auto_approve: bool = False):
        self.cfg = cfg
        self.dir = Path(node_dir)
        if fresh and self.dir.exists():
            for f in ("ledger.db", "state.json", "events.jsonl", "registry.json", "notifications.jsonl"):
                (self.dir / f).unlink(missing_ok=True)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.operator = Identity("operator", self.dir / "keys")
        self.ledger = Ledger(self.dir / "ledger.db", self.operator)
        self.chain = make_registry(self.dir, fresh=fresh)   # smart-contract registry (access control + anchoring)
        self.notifier = Notifier(self.dir, "Aggregator")
        tok_file = self.dir / "admin_token.txt"
        self.token = os.environ.get("SENTINEL_ADMIN_TOKEN") or (tok_file.read_text().strip() if tok_file.exists() else secrets.token_hex(4))
        tok_file.write_text(self.token)
        self.auto_approve = auto_approve
        self.lock = threading.RLock()
        self.registry: dict[str, dict] = json.loads((self.dir / "registry.json").read_text()) if (self.dir / "registry.json").exists() else {}
        self.red_team: dict[str, dict] = {}
        self.task: dict | None = None
        self.updates: dict[str, dict] = {}
        self.evals: dict[str, dict] = {}
        self.bank_alerts: list[dict] = []
        self.rounds: list[dict] = []
        self.metrics: list[dict] = []
        self.events: list[dict] = []
        self.run = {"run_id": None, "status": "idle", "round": 0, "rounds": 0, "policy": None, "started": None}
        self.stop_flag = threading.Event()
        self.verify_alerted = False
        self._rejected: list[dict] = []
        self.server = NodeServer("aggregator", host, port)
        self._routes()
        self._write_state()

    # ------------------------------------------------------------------ helpers
    def _admin(self, h):
        if h.get("X-Admin-Token") != self.token:
            raise ApiError(403, "operator token required (see the aggregator console or nodes/aggregator/admin_token.txt)")

    def event(self, kind: str, msg: str, bank: str | None = None, severity: str = "info"):
        e = {"ts": time.time(), "round": self.run["round"], "type": kind, "bank": bank, "msg": msg, "severity": severity}
        with self.lock:
            self.events.insert(0, e)
            del self.events[400:]
        with open(self.dir / "events.jsonl", "a") as f:
            f.write(json.dumps(e) + "\n")

    def _chain(self, fn: str, *args) -> dict:
        """Send a transaction to the registry contract; failures are logged, never fatal for the round."""
        try:
            return getattr(self.chain, fn)(*args)
        except Exception as e:  # noqa: BLE001 - chain node down or require() refused
            self.event("chain", f"Smart contract {fn} failed: {e}", args[0] if args else None, "high")
            return {}

    def _save_registry(self):
        (self.dir / "registry.json").write_text(json.dumps(self.registry, indent=1))

    def _participants(self) -> list[str]:
        now = time.time()
        return [b for b, r in self.registry.items()
                if r["status"] == "approved" and not r.get("quarantined") and now - r.get("last_seen", 0) < 20]

    def _bank_view(self, b: str) -> dict:
        r = self.registry[b]
        status = "quarantined" if r.get("quarantined") else ("flagged" if r.get("flags", 0) else
                 ("active" if r["status"] == "approved" else r["status"]))
        return {k: r.get(k) for k in ("id", "name", "country", "city", "lat", "lon", "eps", "reason", "flags", "n_train")} | \
               {"status": status, "access": r["status"], "online": time.time() - r.get("last_seen", 0) < 10,
                "red_team": self.red_team.get(b, {}).get("type")}

    def _write_state(self):
        """state.json in the format ARIA's tools read."""
        st = {"name": self.run["run_id"] or "no run yet", "status": self.run["status"], "round": self.run["round"],
              "rounds": self.run["rounds"], "rule": (self.run["policy"] or {}).get("rule"),
              "dp": (self.run["policy"] or {}).get("dp", {"enabled": False}),
              "banks": [self._bank_view(b) for b in sorted(self.registry)], "metrics": self.metrics,
              "aggregator": {"name": "Consortium aggregator (EU)", "city": "Brussels", "lat": 50.85, "lon": 4.35}}
        tmp = self.dir / "state.json.tmp"
        tmp.write_text(json.dumps(st, default=float))
        tmp.replace(self.dir / "state.json")

    # ------------------------------------------------------------------ registry / access control
    def register(self, body: dict) -> dict:
        need = ("bank", "name", "country", "public_key", "signature", "ts")
        if not all(k in body for k in need):
            raise ApiError(400, "missing registration fields")
        sig = body["signature"]
        msg = canonical({k: v for k, v in body.items() if k != "signature"})
        if not verify(body["public_key"], msg, sig):
            raise ApiError(400, "registration signature invalid")
        b = body["bank"]
        with self.lock:
            cur = self.registry.get(b)
            if cur and cur["public_key"] != body["public_key"]:
                self.ledger.append("access_denied", {"bank": b, "reason": "public key differs from registered key"})
                self.event("access", f"Registration for Bank {b} refused: key differs from the registered key", b, "high")
                raise ApiError(403, "bank already registered with a different key (possible impersonation)")
            if not cur:
                self.registry[b] = {"id": b, **{k: body.get(k) for k in ("name", "country", "city", "lat", "lon", "public_key", "n_train")},
                                    "status": "approved" if self.auto_approve else "pending", "registered": time.time(),
                                    "last_seen": time.time(), "flags": 0, "quarantined": False, "eps": 0.0, "reason": ""}
                tx = self._chain("request_join", b, body["public_key"], body["country"])
                self.ledger.append("register_request", {"bank": b, "name": body["name"], "jurisdiction": body["country"],
                                                        "public_key": body["public_key"], "n_train": body.get("n_train"),
                                                        "chain_tx": tx.get("tx")})
                self.event("access", f"Bank {b} ({body['country']}) requested to join the consortium", b)
                if self.auto_approve:
                    tx = self._chain("approve", b)
                    self.ledger.append("access_granted", {"bank": b, "by": "auto-approve", "chain_tx": tx.get("tx")})
            self.registry[b]["last_seen"] = time.time()
            self._save_registry(); self._write_state()
            return {"status": self.registry[b]["status"]}

    def set_access(self, b: str, action: str) -> dict:
        with self.lock:
            if b not in self.registry:
                raise ApiError(404, "unknown bank")
            r = self.registry[b]
            if action not in ("approve", "revoke", "reinstate"):
                raise ApiError(400, "unknown action")
            st = self.chain.status(b)
            try:      # the smart contract decides; the local registry mirrors its state
                if action == "approve":
                    tx = self.chain.approve(b) if st != "approved" else {}
                elif action == "revoke":
                    tx = self.chain.revoke(b, "revoked by operator")
                else:
                    tx = self.chain.reinstate(b) if st == "quarantined" else (self.chain.approve(b) if st in ("pending", "revoked") else {})
            except RegistryError as e:
                raise ApiError(409, f"smart contract refused {action}: {e}")
            if action == "approve":
                r["status"] = "approved"; kind = "access_granted"
            elif action == "revoke":
                r["status"] = "revoked"; kind = "access_revoked"
            else:
                r.update(quarantined=False, flags=0, reason="", status="approved"); kind = "access_reinstated"
            self.ledger.append(kind, {"bank": b, "by": "operator", "chain_tx": tx.get("tx")}, self.run["round"] or None)
            self.event("access", f"Operator {action}d Bank {b}", b, "high" if action == "revoke" else "info")
            self._save_registry(); self._write_state()
            return self._bank_view(b)

    # ------------------------------------------------------------------ run engine
    def start_run(self, body: dict) -> dict:
        with self.lock:
            if self.run["status"] == "running":
                raise ApiError(409, "a run is already in progress")
            if not [b for b, r in self.registry.items() if r["status"] == "approved" and not r.get("quarantined")]:
                raise ApiError(409, "no approved bank yet: approve banks on the Registry page first")
            c = self.cfg
            pol = {"rounds": int(body.get("rounds", c["rounds"])), "rule": body.get("rule", c["aggregation"]["rule"]),
                   "defense": bool(body.get("defense", True)), "round_timeout": float(body.get("round_timeout", 60)),
                   "round_delay": float(body.get("round_delay", c.get("round_delay", 0) or 1.0)),
                   "dp": {"enabled": bool(body.get("dp", c["dp"]["enabled"])),
                          "noise_multiplier": float(body.get("noise", c["dp"]["noise_multiplier"])),
                          "clip": float(body.get("clip", 5.0 if body.get("dp") else c["dp"]["clip"])),
                          "epsilon_cap": float(body.get("epsilon_cap", c["dp"]["epsilon_cap"])), "delta": c["dp"]["delta"]},
                   "local": {"lr": 0.3 if body.get("dp") else c["local"]["lr"], "mu": c["local"]["mu"], "steps": c["local"]["steps"]}}
            run_id = time.strftime("run-%Y%m%d-%H%M%S")
            self.run.update(run_id=run_id, status="running", round=0, rounds=pol["rounds"], policy=pol, started=time.time())
            self.metrics, self.rounds, self.bank_alerts = [], [], []
            for r in self.registry.values():
                r.update(eps=0.0, flags=0)
            self.stop_flag.clear()
            self.ledger.append("run_start", {"run_id": run_id, "policy_hash": sha256_hex(canonical(pol)), "policy": pol})
            self.event("run", f"Run {run_id} started: {pol['rounds']} rounds, {pol['rule']}, defences "
                              f"{'on' if pol['defense'] else 'off'}, DP {'on' if pol['dp']['enabled'] else 'off'}")
        threading.Thread(target=self._run_loop, daemon=True).start()
        return self.run

    def _run_loop(self):
        pol = self.run["policy"]
        model = MLP(len(FEATURE_NAMES), tuple(self.cfg["model"]["hidden"]), seed=self.cfg["seed"])
        for r in range(1, pol["rounds"] + 2):            # last iteration = evaluation of the final model
            if self.stop_flag.is_set():
                break
            train = r <= pol["rounds"]
            gw = model.get_vector(); gh = vector_hash(gw)
            waited = 0
            while not self._participants() and waited < 60 and not self.stop_flag.is_set():
                time.sleep(0.5); waited += 0.5
            parts = self._participants()
            with self.lock:
                self.updates, self.evals = {}, {}
                self.run["round"] = r if train else pol["rounds"]
                self.task = {"run_id": self.run["run_id"], "round": r, "weights": gw.tolist(), "model_hash": gh, "train": train,
                             "policy": {"dp": pol["dp"], "local": pol["local"]}, "deadline": time.time() + pol["round_timeout"],
                             "participants": parts}
            if train:
                self.ledger.append("round_start", {"run_id": self.run["run_id"], "global_model_hash": gh, "participants": parts}, r)
            t0 = time.time()
            while time.time() < self.task["deadline"] and not self.stop_flag.is_set():
                with self.lock:
                    done = set(self.updates) | set(self.evals)
                if set(parts) <= done:
                    break
                time.sleep(0.2)
            with self.lock:
                missing = [b for b in parts if b not in self.updates and b not in self.evals]
            for b in missing:
                self.event("timeout", f"Bank {b} did not answer in round {r}", b, "medium")
            self._record_eval(r - 1)
            if not train:
                break
            self._aggregate(r, model, gw, parts, t0)
            self._write_state()
            time.sleep(pol["round_delay"])
        with self.lock:
            self.run["status"] = "stopped" if self.stop_flag.is_set() else "done"
            self.task = None
        self.ledger.append("run_end", {"run_id": self.run["run_id"], "status": self.run["status"],
                                       "final_model_hash": vector_hash(model.get_vector()),
                                       "final": self.metrics[-1] if self.metrics else None})
        self.event("run", f"Run {self.run['run_id']} {self.run['status']}")
        self._write_state()

    def _record_eval(self, version: int):
        """Federated evaluation: each bank evaluates the global model on its own test data."""
        with self.lock:
            evs = {b: (u.get("eval") or {}) for b, u in {**self.updates, **self.evals}.items()}
        evs = {b: e for b, e in evs.items() if e.get("pr_auc") is not None and e.get("n_illicit")}
        if version < 1 or not evs:
            return
        w = {b: e["n_illicit"] for b, e in evs.items()}
        tot = sum(w.values())
        m = {"round": version, **{k: round(sum(evs[b][k] * w[b] for b in evs) / tot, 4) for k in ("pr_auc", "f1", "recall_at_1pct_fpr")},
             "per_bank": {b: evs[b]["pr_auc"] for b in evs}}
        self.metrics.append(m)

    def _aggregate(self, r: int, model: MLP, gw: np.ndarray, parts: list[str], t0: float):
        pol = self.run["policy"]
        with self.lock:
            ups = dict(self.updates)
        ids = sorted(ups)
        deltas = [np.asarray(ups[b]["payload"]["weights"]) - gw for b in ids]
        scores, excluded = {}, []
        if pol["defense"] and len(deltas) >= 3 and r > self.cfg["defense"].get("warmup_rounds", 2):
            D = self.cfg["defense"]
            for b, s in zip(ids, agg.anomaly_scores(np.array(deltas))):
                scores[b] = s
                reg = self.registry[b]
                if s["norm_z"] > D["z_threshold"] or s["cosine_to_median"] < D["cosine_threshold"]:
                    excluded.append(b)
                    reg["flags"] = reg.get("flags", 0) + 1
                    reg["reason"] = f"anomalous update (norm z={s['norm_z']}, cosine={s['cosine_to_median']})"
                    self.event("flag", f"Bank {b} update excluded: {reg['reason']}", b, "high")
                    if reg["flags"] >= D["quarantine_after"]:
                        self._quarantine(b, reg["reason"], r)
                else:
                    reg["flags"] = 0
        used = [b for b in ids if b not in excluded]
        if used:
            U = np.array([deltas[ids.index(b)] for b in used])
            rule = pol["rule"] if pol["defense"] else "fedavg"
            if pol["defense"] and len(U) > 1:
                U = agg.clip_by_norm(U, 1.5 * np.median(np.linalg.norm(U, axis=1)))
            step = agg.aggregate(rule, U, np.array([ups[b]["payload"]["n"] for b in used]), trim=1, f=1)
            model.set_vector(gw + step)
        hashes = {b: vector_hash(np.asarray(ups[b]["payload"]["weights"])) for b in ids}
        for b in ids:
            p = ups[b]["payload"]
            self.ledger.append("update", {"run_id": self.run["run_id"], "bank": b, "update_hash": hashes[b], "n": p["n"],
                                          "eps_round": round(p["eps_round"], 6), "eps_total": round(p["eps_total"], 4),
                                          "accepted": b in used, "reason": "accepted" if b in used else "excluded by anomaly detector",
                                          "score": scores.get(b)}, r)
        rec = {"round": r, "participants": parts, "received": ids, "used": used, "excluded": excluded,
               "rejected": [x["bank"] for x in self.rounds_rejected(r)], "scores": scores,
               "bytes_in": int(sum(len(ups[b]["payload"]["weights"]) * 8 for b in ids)),
               "seconds": round(time.time() - t0, 2), "model_hash": vector_hash(model.get_vector()),
               "merkle_root": merkle_root([hashes[b] for b in used])}
        self.rounds.append(rec)
        self.ledger.append("round_commit", {"run_id": self.run["run_id"], "merkle_root": rec["merkle_root"], "model_hash": rec["model_hash"],
                                            "rule": pol["rule"] if pol["defense"] else "fedavg", "accepted": used,
                                            "excluded": excluded, "rejected": rec["rejected"]}, r)
        tx = self._chain("anchor_round", self.run["run_id"], r, rec["merkle_root"], rec["model_hash"])
        rec["anchor_tx"] = tx.get("tx")
        self.event("round", f"Round {r}: aggregated {used}" + (f", excluded {excluded}" if excluded else "")
                   + (f"; root anchored on-chain (block {tx['block']})" if tx.get("tx") else ""))

    def rounds_rejected(self, r: int) -> list[dict]:
        return [x for x in self._rejected if x["round"] == r and x["run_id"] == self.run["run_id"]]

    def _quarantine(self, b: str, reason: str, r: int):
        reg = self.registry[b]
        if reg.get("quarantined"):
            return
        reg["quarantined"] = True
        reg["reason"] = reason
        tx = self._chain("quarantine", b, reason)
        self.ledger.append("quarantine", {"run_id": self.run["run_id"], "bank": b, "reason": reason, "flags": reg.get("flags", 0),
                                          "chain_tx": tx.get("tx")}, r)
        self.event("quarantine", f"Bank {b} QUARANTINED: {reason}", b, "critical")
        self.notifier.send("critical", f"Bank {b} quarantined in round {r}",
                           f"The consortium aggregator quarantined Bank {b} ({reg.get('name')}, {reg.get('country')}).\n\n"
                           f"Reason: {reason}\nRun: {self.run['run_id']}, round {r}.\n\n"
                           "Its updates are excluded and it receives no further training tasks until an operator reinstates it.\n"
                           "Evidence: audit ledger record of type 'quarantine' (Ledger page) and ARIA incident report.")
        self._save_registry()

    # ------------------------------------------------------------------ bank-facing endpoints
    def get_task(self, b: str) -> dict:
        with self.lock:
            reg = self.registry.get(b)
            if not reg:
                raise ApiError(404, "bank not registered")
            reg["last_seen"] = time.time()
            status = "quarantined" if reg.get("quarantined") else reg["status"]
            out = {"status": status, "run_id": self.run["run_id"], "run_status": self.run["status"],
                   "red_team": self.red_team.get(b)}
            t = self.task
            if t and status == "approved" and b in t["participants"]:
                out.update({k: t[k] for k in ("round", "weights", "model_hash", "train", "policy")})
            return out

    def submit(self, body: dict, eval_only: bool = False) -> dict:
        b = body.get("bank")
        with self.lock:
            reg = self.registry.get(b)
            t = self.task
            if not reg or reg["status"] != "approved" or reg.get("quarantined"):
                self.ledger.append("access_denied", {"bank": b, "reason": "update from a bank without access"})
                raise ApiError(403, "bank is not an approved, active participant")
            if not self.chain.is_authorised(b, reg["public_key"]):
                self.ledger.append("access_denied", {"bank": b, "reason": "smart contract: bank/key not authorised"})
                raise ApiError(403, "smart contract registry: this bank and key are not authorised")
            if not t or body.get("round") != t["round"] or body.get("run_id") != t["run_id"]:
                raise ApiError(409, "no open round matches this update")
            reg["last_seen"] = time.time()
            if body.get("alerts"):
                self._bank_alert(b, body["alerts"])
            if eval_only:
                self.evals[b] = body
                return {"result": "evaluation recorded"}
            p = body.get("payload") or {}
            if p.get("status") != "ok":
                self.evals[b] = body
                self.event("declined", f"Bank {b} declined round {t['round']}: {p.get('status')}", b, "medium")
                return {"result": f"declined ({p.get('status')})"}
            extra = set(p) - ALLOWED_PAYLOAD_KEYS
            if extra:
                self._reject(b, t["round"], "leakage_blocked",
                             f"payload schema violation: unexpected fields {sorted(extra)} (attempted raw-data exfiltration)", quarantine=True)
                raise ApiError(422, f"payload schema violation: {sorted(extra)} refused; nothing stored")
            w = np.asarray(p["weights"], dtype=np.float64)
            msg = update_message(b, t["round"], vector_hash(w), p["n"], p["eps_round"])
            if not verify(reg["public_key"], msg, p["signature"]):
                self._reject(b, t["round"], "signature_invalid", "invalid signature: update altered in transit or forged",
                             quarantine=reg.get("flags", 0) + 1 >= self.cfg["defense"]["quarantine_after"])
                raise ApiError(422, "signature verification failed; update discarded")
            reg["eps"] = round(p["eps_total"], 4)
            self.updates[b] = body
            return {"result": "accepted for aggregation", "round": t["round"]}

    def _reject(self, b: str, r: int, kind: str, reason: str, quarantine: bool):
        reg = self.registry[b]
        reg["flags"] = reg.get("flags", 0) + 1
        reg["reason"] = reason
        self._rejected.append({"run_id": self.run["run_id"], "round": r, "bank": b, "kind": kind, "reason": reason})
        self.ledger.append(kind, {"run_id": self.run["run_id"], "bank": b, "reason": reason}, r)
        self.event(kind, f"Bank {b}: {reason}", b, "critical")
        self.notifier.send("critical", f"{kind.replace('_', ' ')} from Bank {b} (round {r})", f"{reason}\n\nRun {self.run['run_id']}, round {r}.")
        if quarantine:
            self._quarantine(b, reason, r)

    def _bank_alert(self, b: str, s: dict):
        s = {**s, "bank": b, "ts": time.time()}
        self.bank_alerts.insert(0, s)
        del self.bank_alerts[500:]
        if s.get("high", 0) >= 3:
            pats = ", ".join(f"{k} ({v})" for k, v in sorted(s.get("patterns", {}).items(), key=lambda x: -x[1])[:4])
            self.event("bank_alert", f"Bank {b} reports {s['high']} high-risk transactions in round {s['round']} [{pats}]", b, "high")
            self.notifier.send("high", f"Bank {b}: {s['high']} high-risk transactions (round {s['round']})",
                               f"Bank {b} scored {s['scored']} live transactions with the consortium model.\n"
                               f"High risk: {s['high']}, medium: {s['medium']}.\nPatterns: {pats}\n\n"
                               "Only aggregate counts reach the consortium; case details stay inside the bank (tipping-off rule).",
                               dedupe_key=f"bank-{b}", min_interval=60)

    # ------------------------------------------------------------------ attack lab
    def launch_attack(self, body: dict) -> dict:
        b, kind = body.get("bank"), body.get("type")
        if b not in self.registry:
            raise ApiError(404, "unknown bank")
        if kind not in ATTACKS:
            raise ApiError(400, f"attack type must be one of {list(ATTACKS)}")
        self.red_team[b] = {"type": kind, "fraction": float(body.get("fraction", 1.0)), "boost": float(body.get("boost", 5.0)),
                            "since_round": self.run["round"]}
        self.ledger.append("red_team_exercise", {"bank": b, "attack": kind, "declared_by": "operator"}, self.run["round"] or None)
        self.event("attack", f"RED TEAM: Bank {b} now runs '{ATTACKS[kind]}'", b, "high")
        return {"bank": b, "attack": self.red_team[b]}

    def stop_attack(self, body: dict) -> dict:
        b = body.get("bank")
        self.red_team.pop(b, None) if b else self.red_team.clear()
        self.event("attack", f"Red-team exercise stopped for {'Bank ' + b if b else 'all banks'}", b)
        return {"red_team": self.red_team}

    # ------------------------------------------------------------------ routes
    def _routes(self):
        S = self.server

        @S.route("POST", "/api/register")
        def _reg(q, body, h): return self.register(body)

        @S.route("GET", "/api/task")
        def _task(q, body, h): return self.get_task(q.get("bank", ""))

        @S.route("POST", "/api/update")
        def _upd(q, body, h): return self.submit(body)

        @S.route("POST", "/api/eval")
        def _ev(q, body, h): return self.submit(body, eval_only=True)

        @S.route("GET", "/api/overview")
        def _ov(q, body, h):
            with self.lock:
                last_round = self.rounds[-1] if self.rounds else None
                t = self.task
                pending = {b: ("received" if b in self.updates else ("evaluated" if b in self.evals else "waiting"))
                           for b in (t["participants"] if t else [])}
            return {"run": self.run, "banks": [self._bank_view(b) for b in sorted(self.registry)], "metrics": self.metrics,
                    "last_round": last_round, "round_progress": pending, "events": self.events[:40],
                    "aggregator": {"city": "Brussels", "lat": 50.85, "lon": 4.35}, "red_team": self.red_team,
                    "alerts_high": sum(a.get("high", 0) for a in self.bank_alerts), "ledger_records": len(self.ledger.entries())}

        @S.route("GET", "/api/registry")
        def _rg(q, body, h):
            return [self.registry[b] | {"view": self._bank_view(b)} for b in sorted(self.registry)]

        @S.route("GET", "/api/chain")
        def _chainv(q, body, h):
            return self.chain.view()

        @S.route("POST", "/api/registry/action")
        def _rga(q, body, h):
            self._admin(h); return self.set_access(body.get("bank"), body.get("action"))

        @S.route("POST", "/api/control/start")
        def _start(q, body, h):
            self._admin(h); return self.start_run(body or {})

        @S.route("POST", "/api/control/stop")
        def _stop(q, body, h):
            self._admin(h); self.stop_flag.set(); return {"stopping": True}

        @S.route("GET", "/api/rounds")
        def _rounds(q, body, h):
            return {"run": self.run, "rounds": self.rounds, "metrics": self.metrics, "rejected": self._rejected[-50:]}

        @S.route("GET", "/api/ledger")
        def _led(q, body, h):
            rows = self.ledger.entries(type_=q.get("type") or None)
            return rows[-int(q.get("limit", 200)):][::-1]

        @S.route("GET", "/api/verify")
        def _ver(q, body, h):
            v = self.ledger.verify(self.operator.public_hex)
            if not v["ok"] and not self.verify_alerted:
                self.verify_alerted = True
                self.event("integrity", f"LEDGER INTEGRITY FAILURE at record #{v['bad_record']}: {v['reason']}", None, "critical")
                self.notifier.send("critical", f"Audit ledger integrity failure at record #{v['bad_record']}",
                                   f"{v['reason']}.\nRecords before #{v['bad_record']} remain trustworthy.")
            return v

        @S.route("POST", "/api/ledger/tamper")
        def _tamper(q, body, h):
            self._admin(h)
            idx = int(body.get("idx"))
            rec = next((e for e in self.ledger.entries() if e["idx"] == idx), None)
            if not rec:
                raise ApiError(404, "no such record")
            field = body.get("field") or next((k for k in ("accepted", "bank", "reason") if k in rec["body"]), "note")
            old = rec["body"].get(field)
            new = (not old) if isinstance(old, bool) else ("Z" if field == "bank" else "edited-by-insider")
            self.ledger.tamper(idx, field, new)
            self.verify_alerted = False
            return {"edited": idx, "field": field, "old": old, "new": new, "note": "demo of an insider edit: record changed WITHOUT re-signing"}

        @S.route("GET", "/api/alerts")
        def _al(q, body, h):
            return {"bank_alerts": self.bank_alerts[:200], "system": [e for e in self.events if e["severity"] in ("high", "critical")][:100],
                    "notifications": self.notifier.history()[::-1][:100], "smtp_configured": self.notifier.smtp_configured}

        @S.route("POST", "/api/notify/test")
        def _nt(q, body, h):
            self._admin(h)
            return self.notifier.send("info", "Test notification", "If you can read this, SENTINEL-FL alert e-mail works.")

        @S.route("GET", "/api/attack")
        def _at(q, body, h): return {"catalogue": ATTACKS, "active": self.red_team}

        @S.route("POST", "/api/attack/launch")
        def _al2(q, body, h):
            self._admin(h); return self.launch_attack(body)

        @S.route("POST", "/api/attack/stop")
        def _as(q, body, h):
            self._admin(h); return self.stop_attack(body or {})

        @S.route("GET", "/api/aria")
        def _aria(q, body, h): return aria.ask(q.get("q", "")[:500], self.dir)

        @S.route("GET", "/api/compliance")
        def _comp(q, body, h):
            import yaml
            tp = Path(__file__).resolve().parent.parent / "docs" / "traceability.yaml"
            return {"matrix": yaml.safe_load(tp.read_text()) if tp.exists() else [],
                    "banks": [self._bank_view(b) for b in sorted(self.registry)], "policy": self.run["policy"]}

        @S.route("GET", "/api/results")
        def _res(q, body, h):
            root = Path(__file__).resolve().parent.parent
            res = root / "experiments" / "results.json"
            base = root / "runs" / "baselines.json"
            return {"matrix": json.loads(res.read_text()) if res.exists() else None,
                    "baselines": json.loads(base.read_text()) if base.exists() else None,
                    "live": {"run": self.run, "metrics": self.metrics}}

        @S.route("GET", "/metrics")
        def _prom(q, body, h):
            lines = ["# HELP sentinel_round Current training round", "# TYPE sentinel_round gauge", f"sentinel_round {self.run['round']}"]
            if self.metrics:
                lines += ["# TYPE sentinel_pr_auc gauge", f"sentinel_pr_auc {self.metrics[-1]['pr_auc']}"]
            lines += ["# TYPE sentinel_bank_epsilon gauge"] + [f'sentinel_bank_epsilon{{bank="{b}"}} {r.get("eps", 0)}' for b, r in self.registry.items()]
            lines += ["# TYPE sentinel_bank_quarantined gauge"] + [f'sentinel_bank_quarantined{{bank="{b}"}} {int(bool(r.get("quarantined")))}' for b, r in self.registry.items()]
            lines += ["# TYPE sentinel_bank_online gauge"] + [f'sentinel_bank_online{{bank="{b}"}} {int(time.time() - r.get("last_seen", 0) < 10)}' for b, r in self.registry.items()]
            lines += ["# TYPE sentinel_rejected_updates_total counter", f"sentinel_rejected_updates_total {len(self._rejected)}",
                      "# TYPE sentinel_ledger_records gauge", f"sentinel_ledger_records {len(self.ledger.entries())}"]
            if self.rounds:
                lines += ["# TYPE sentinel_round_seconds gauge", f"sentinel_round_seconds {self.rounds[-1]['seconds']}",
                          "# TYPE sentinel_round_bytes_in gauge", f"sentinel_round_bytes_in {self.rounds[-1]['bytes_in']}"]
            return ("__raw__", "\n".join(lines) + "\n", "text/plain; version=0.0.4")

    def start(self, background: bool = False):
        print(f"[aggregator] control room on http://{self.server.host}:{self.server.port}   operator token: {self.token}")
        self.server.start(background)


def run_aggregator(host: str, port: int, config: str | None, overrides: list[str], node_dir: str, fresh: bool, auto_approve: bool):
    cfg = load_config(config, overrides)
    AggregatorNode(cfg, node_dir, host, port, fresh, auto_approve).start()
