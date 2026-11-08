"""Server-side defence pipeline for one federated round, independent of Flower and PyTorch.

SentinelStrategy (server_app.py) converts Flower's FitRes objects into plain dictionaries and calls
RoundGuard.process(); the same code is unit-tested without Flower in tests/test_flower_guard.py.
Outputs use the formats of the reference engine, so `python -m sentinel serve`, `verify` and `aria`
work on Flower runs too (run directory runs/flower).
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np

from sentinel import aggregation as agg
from sentinel.crypto import Identity, canonical, sha256_hex, update_message, vector_hash, verify
from sentinel.data import MEMBERS
from sentinel.ledger import Ledger, merkle_root
from sentinel.registry_chain import RegistryError, make_registry

# Only these keys may travel from a bank to the server with an update (data-minimisation allow-list).
ALLOWED_METRICS = {"bank", "public_key", "signature", "status", "eps_round", "eps_total", "eps_own",
                   "n", "round", "train_seconds", "jurisdiction"}


def flatten(arrays) -> np.ndarray:
    return np.concatenate([np.asarray(a, dtype=np.float64).ravel() for a in arrays])


def unflatten(vec: np.ndarray, like) -> list[np.ndarray]:
    out, i = [], 0
    for a in like:
        n = int(np.prod(a.shape))
        out.append(vec[i:i + n].reshape(a.shape).astype(a.dtype))
        i += n
    return out


class RoundGuard:
    def __init__(self, run_dir: str | Path, cfg: dict, fresh: bool = True, auto_approve: bool = True):
        self.dir = Path(run_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        if fresh:
            for f in ("ledger.db", "state.json", "events.jsonl", "chain.json"):
                (self.dir / f).unlink(missing_ok=True)
        self.cfg = cfg
        self.operator = Identity("operator", self.dir / "keys")
        self.ledger = Ledger(self.dir / "ledger.db", self.operator)
        self.chain = make_registry(self.dir, fresh=fresh)
        self.auto_approve = auto_approve
        self.run_id = time.strftime("flower-%Y%m%d-%H%M%S")
        self.keys: dict[str, str] = {}
        self.status: dict[str, dict] = {}
        self.history: list[dict] = []
        self.rounds: list[dict] = []
        self.ledger.append("run_start", {"run_id": self.run_id, "engine": "flower+pytorch+opacus",
                                         "config_hash": sha256_hex(canonical(cfg)), "policy": cfg})
        self.write_state(0, "running")

    # ------------------------------------------------------------------ helpers
    def event(self, r, kind, bank, msg):
        with open(self.dir / "events.jsonl", "a") as f:
            f.write(json.dumps({"ts": time.time(), "round": r, "type": kind, "bank": bank, "msg": msg}) + "\n")
        print(f"[server] round {r}: {msg}", flush=True)

    def _chain(self, fn, *args) -> dict:
        try:
            return getattr(self.chain, fn)(*args)
        except RegistryError as e:
            self.event(None, "chain", args[0] if args else None, f"contract refused {fn}: {e}")
            return {}

    def _admit(self, b: str, m: dict, r: int) -> str | None:
        """Registration and access control through the smart-contract registry."""
        pk = m.get("public_key", "")
        if b not in self.keys:
            if self.chain.status(b) == "none":
                tx = self._chain("request_join", b, pk, m.get("jurisdiction", "?"))
                self.ledger.append("register_request", {"bank": b, "public_key": pk, "jurisdiction": m.get("jurisdiction"),
                                                        "chain_tx": tx.get("tx")}, r)
                if self.auto_approve:
                    tx = self._chain("approve", b)
                    self.ledger.append("access_granted", {"bank": b, "by": "auto-approve", "chain_tx": tx.get("tx")}, r)
            self.keys[b] = pk
            meta = next((x for x in MEMBERS if x["id"] == b), {"id": b, "name": f"Bank {b}", "country": "?", "city": "?", "lat": 0, "lon": 0})
            self.status.setdefault(b, {**{k: meta.get(k) for k in ("id", "name", "country", "city", "lat", "lon")},
                                       "status": "active", "flags": 0, "eps": 0.0, "reason": "", "score": None})
        if pk != self.keys[b]:
            return "public key differs from the registered key (impersonation)"
        if not self.chain.is_authorised(b, pk):
            return f"smart contract: not authorised (status {self.chain.status(b)})"
        return None

    def _quarantine(self, b, reason, r):
        st = self.status[b]
        if st["status"] == "quarantined":
            return
        st.update(status="quarantined", reason=reason)
        tx = self._chain("quarantine", b, reason)
        self.ledger.append("quarantine", {"run_id": self.run_id, "bank": b, "reason": reason, "chain_tx": tx.get("tx")}, r)
        self.event(r, "quarantine", b, f"Bank {b} QUARANTINED: {reason}")

    def _reject(self, b, r, kind, reason, quarantine):
        self.ledger.append(kind, {"run_id": self.run_id, "bank": b, "reason": reason}, r)
        self.event(r, kind, b, f"Bank {b}: {reason}")
        if quarantine and b in self.status:
            self._quarantine(b, reason, r)

    # ------------------------------------------------------------------ one round
    def process(self, r: int, global_vec: np.ndarray, subs: list[dict]) -> tuple[np.ndarray, dict]:
        """subs: [{"bank", "weights" (flat np.ndarray), "n", "metrics"}]. Returns (new global vector, round record)."""
        t0 = time.time()
        D, A = self.cfg["defense"], self.cfg["aggregation"]
        self.ledger.append("round_start", {"run_id": self.run_id, "global_model_hash": vector_hash(global_vec),
                                           "participants": sorted(s["bank"] for s in subs)}, r)
        valid, rejected = [], []
        for s in subs:
            b, m = s["bank"], s["metrics"]
            extra = set(m) - ALLOWED_METRICS
            if extra:
                self._admit(b, m, r)
                self._reject(b, r, "leakage_blocked", f"payload schema violation: unexpected fields {sorted(extra)} "
                             "(attempted raw-data exfiltration)", quarantine=True)
                rejected.append(b); continue
            why = self._admit(b, m, r)
            if why:
                self.ledger.append("access_denied", {"bank": b, "reason": why}, r)
                rejected.append(b); continue
            if m.get("status", "ok") != "ok":
                self.event(r, "declined", b, f"Bank {b} declined: {m.get('status')}"); continue
            msg = update_message(b, r, vector_hash(s["weights"]), int(s["n"]), float(m.get("eps_round", 0.0)))
            if not verify(self.keys[b], msg, m.get("signature", "")):
                self.status[b]["flags"] += 1
                self._reject(b, r, "signature_invalid", "invalid signature: update altered in transit or forged",
                             quarantine=self.status[b]["flags"] >= D["quarantine_after"])
                rejected.append(b); continue
            self.status[b]["eps"] = round(float(m.get("eps_total", 0.0)), 4)
            valid.append(s)

        ids = [s["bank"] for s in valid]
        deltas = np.array([s["weights"] - global_vec for s in valid]) if valid else np.zeros((0, len(global_vec)))
        scores, excluded = {}, []
        if D.get("anomaly", True) and len(valid) >= 3 and r > D.get("warmup_rounds", 2):
            for b, sc in zip(ids, agg.anomaly_scores(deltas)):
                scores[b] = sc
                st = self.status[b]; st["score"] = sc
                if sc["norm_z"] > D["z_threshold"] or sc["cosine_to_median"] < D["cosine_threshold"]:
                    excluded.append(b); st["flags"] += 1
                    st["reason"] = f"anomalous update (norm z={sc['norm_z']}, cosine={sc['cosine_to_median']})"
                    st["status"] = "flagged"
                    self.event(r, "flag", b, f"Bank {b} update excluded: {st['reason']}")
                    if st["flags"] >= D["quarantine_after"]:
                        self._quarantine(b, st["reason"], r)
                elif st["status"] == "flagged":
                    st.update(status="active", flags=0)
        used = [b for b in ids if b not in excluded]
        new = global_vec.copy()
        if used:
            U = np.array([deltas[ids.index(b)] for b in used])
            if A.get("server_clip_factor", 1.5) and len(U) > 1:
                U = agg.clip_by_norm(U, A.get("server_clip_factor", 1.5) * np.median(np.linalg.norm(U, axis=1)))
            new = global_vec + agg.aggregate(A["rule"], U, np.array([valid[ids.index(b)]["n"] for b in used], dtype=float),
                                             trim=A.get("trim", 1), f=A.get("f", 1))
        hashes = {s["bank"]: vector_hash(s["weights"]) for s in valid}
        for s in valid:
            b = s["bank"]
            self.ledger.append("update", {"run_id": self.run_id, "bank": b, "update_hash": hashes[b], "n": int(s["n"]),
                                          "eps_round": round(float(s["metrics"].get("eps_round", 0)), 6),
                                          "eps_total": round(float(s["metrics"].get("eps_total", 0)), 4),
                                          "eps_own_accountant": round(float(s["metrics"].get("eps_own", 0)), 4),
                                          "accepted": b in used, "score": scores.get(b),
                                          "reason": "accepted" if b in used else "excluded by anomaly detector"}, r)
        rec = {"round": r, "received": sorted(s["bank"] for s in subs), "used": used, "excluded": excluded, "rejected": rejected,
               "scores": scores, "model_hash": vector_hash(new), "merkle_root": merkle_root([hashes[b] for b in used]),
               "seconds": round(time.time() - t0, 3), "bytes_in": int(sum(s["weights"].nbytes for s in subs))}
        tx = self._chain("anchor_round", self.run_id, r, rec["merkle_root"], rec["model_hash"])
        rec["anchor_tx"] = tx.get("tx")
        self.ledger.append("round_commit", {"run_id": self.run_id, "merkle_root": rec["merkle_root"], "model_hash": rec["model_hash"],
                                            "rule": A["rule"], "accepted": used, "excluded": excluded, "rejected": rejected,
                                            "anchor_tx": rec["anchor_tx"]}, r)
        self.rounds.append(rec)
        self.event(r, "round", None, f"aggregated {used}" + (f", excluded {excluded}" if excluded else "")
                   + (f", rejected {rejected}" if rejected else ""))
        return new, rec

    def record_eval(self, r: int, evals: list[dict]) -> dict:
        """Federated evaluation: bank metrics weighted by their number of illicit test cases."""
        w = np.array([max(e.get("n_illicit", 0), 1) for e in evals], dtype=float)
        m = {"round": r}
        for k in ("pr_auc", "f1", "recall_at_1pct_fpr"):
            vals = np.array([e.get(k, np.nan) for e in evals], dtype=float)
            ok = ~np.isnan(vals)
            m[k] = round(float((vals[ok] * w[ok]).sum() / w[ok].sum()), 4) if ok.any() else None
        m["per_bank"] = {e["bank"]: e.get("pr_auc") for e in evals}
        self.history.append(m)
        self.write_state(r, "running")
        return m

    def write_state(self, r: int, status: str):
        state = {"name": f"{self.run_id} (Flower)", "engine": "flower+pytorch+opacus", "status": status, "round": r,
                 "rounds": self.cfg.get("rounds"), "rule": self.cfg["aggregation"]["rule"], "dp": self.cfg["dp"],
                 "attack": self.cfg.get("attack", {}), "defense": self.cfg["defense"], "banks": list(self.status.values()),
                 "metrics": self.history, "rounds_log": self.rounds,
                 "aggregator": {"name": "Consortium aggregator (EU)", "city": "Brussels", "lat": 50.85, "lon": 4.35}}
        tmp = self.dir / "state.json.tmp"
        tmp.write_text(json.dumps(state, indent=1, default=float))
        tmp.replace(self.dir / "state.json")

    def finish(self):
        self.ledger.append("run_end", {"run_id": self.run_id, "final": self.history[-1] if self.history else None,
                                       "ledger_verified": self.ledger.verify()["ok"]})
        self.write_state(len(self.rounds), "done")
