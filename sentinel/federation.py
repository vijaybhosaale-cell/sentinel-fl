"""Federated training: bank clients, the aggregator and the round loop.

Protocol per round:
  1. operator seals `round_start` (config hash, global model hash) in the ledger
  2. each active bank checks the global model hash, trains locally (FedProx,
     optional DP-SGD), signs its update and sends weights + n + epsilon spent
  3. the server checks payload schema and signatures, scores anomalies,
     excludes or quarantines suspicious banks, aggregates the rest
  4. the operator seals `update` records and a `round_commit` with the Merkle
     root of accepted update hashes and the new model hash

Raw transactions never leave a BankClient. The evaluation harness pools test
predictions only to report research metrics; it is not part of the protocol.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np

from . import aggregation as agg
from . import attacks
from .crypto import Identity, canonical, sha256_hex, update_message, vector_hash, verify
from .data import FEATURE_NAMES, MEMBERS, generate_synthetic, load_amlworld, partition
from .ledger import Ledger
from .metrics import evaluate
from .model import MLP
from .privacy import Accountant, dp_sgd_gradient

ALLOWED_PAYLOAD_KEYS = {"bank", "round", "weights", "n", "eps_round", "eps_total", "signature", "status"}


# --------------------------------------------------------------------------- client
class BankClient:
    def __init__(self, bank: dict, cfg: dict, n_features: int, key_dir: Path, seed: int):
        self.bank, self.cfg = bank, cfg
        self.id = bank["id"]
        self.identity = Identity(f"bank_{self.id}", key_dir)
        self.model = MLP(n_features, tuple(cfg["model"]["hidden"]), seed=seed)
        self.rng = np.random.default_rng(seed)
        self.accountant = Accountant(cfg["dp"]["delta"])
        self.X, self.y = bank["X_train"], bank["y_train"]
        p = max(self.y.mean(), 1e-4)
        pw = cfg["local"]["pos_weight"]
        self.pos_weight = float(min((1 - p) / p, 50.0)) if pw == "auto" else float(pw)
        self.attack = cfg["attack"] if cfg["attack"]["type"] != "none" and cfg["attack"]["bank"] == self.id else None

    def _attack_active(self, round_no: int) -> bool:
        return bool(self.attack) and round_no >= self.attack["start_round"]

    def fit(self, global_w: np.ndarray, global_hash: str, round_no: int) -> dict:
        if vector_hash(global_w) != global_hash:
            return {"bank": self.id, "round": round_no, "status": "rejected_global_model"}
        L, D = self.cfg["local"], self.cfg["dp"]
        n, B, steps = len(self.X), L["batch_size"], L["steps"]
        q = min(1.0, B / max(n, 1))
        if D["enabled"] and self.accountant.epsilon_if(q, D["noise_multiplier"], steps) > D["epsilon_cap"]:
            return {"bank": self.id, "round": round_no, "status": "budget_exhausted",
                    "eps_total": self.accountant.epsilon}

        X, y = self.X, self.y
        active = self._attack_active(round_no)
        if active and self.attack["type"] == "free_rider":
            w = global_w + self.rng.normal(0, 1e-4, global_w.shape)
            return self._package(w, round_no, 0.0)
        if active and self.attack["type"] == "label_flip":
            X, y = X, attacks.label_flip(y, self.attack["fraction"], self.rng)
        if active and self.attack["type"] == "backdoor":
            X, y = attacks.backdoor_poison(X, y, self.rng)

        self.model.set_vector(global_w)
        w, vel = global_w.copy(), np.zeros_like(global_w)
        for _ in range(steps):
            if D["enabled"]:
                mask = self.rng.random(len(X)) < q          # Poisson sampling (matches the accountant)
                idx = np.flatnonzero(mask)
                if len(idx) == 0:
                    g = self.rng.normal(0, D["noise_multiplier"] * D["clip"], len(w)) / (q * len(X))
                else:
                    psg = self.model.gradients(X[idx], y[idx], self.pos_weight, per_sample=True)
                    g = dp_sgd_gradient(psg, D["clip"], D["noise_multiplier"], q * len(X), self.rng)
            else:
                idx = self.rng.integers(0, len(X), min(B, len(X)))
                g = self.model.gradients(X[idx], y[idx], self.pos_weight)
            g = g + L["mu"] * (w - global_w)                  # FedProx proximal term
            vel = L["momentum"] * vel + g
            w = w - L["lr"] * vel
            self.model.set_vector(w)

        eps_round = 0.0
        if D["enabled"]:
            before = self.accountant.epsilon
            self.accountant.step(q, D["noise_multiplier"], steps)
            eps_round = self.accountant.epsilon - before
        if active and self.attack["type"] in ("scale", "backdoor"):
            w = global_w + self.attack["boost"] * (w - global_w)
        payload = self._package(w, round_no, eps_round)
        if active and self.attack["type"] == "leak":
            payload["raw_sample"] = attacks.exfiltrate(self.X, self.y)       # protocol violation
        if active and self.attack["type"] == "tamper_update":
            payload["weights"] = attacks.tamper_in_transit(payload["weights"], self.rng)  # after signing
        return payload

    def _package(self, w: np.ndarray, round_no: int, eps_round: float) -> dict:
        wh = vector_hash(w)
        msg = update_message(self.id, round_no, wh, len(self.X), eps_round)
        return {"bank": self.id, "round": round_no, "weights": w, "n": len(self.X), "eps_round": eps_round,
                "eps_total": self.accountant.epsilon, "signature": self.identity.sign(msg), "status": "ok"}


# --------------------------------------------------------------------------- server
class Federation:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.run_dir = Path(cfg["out_dir"]) / cfg["name"]
        self.run_dir.mkdir(parents=True, exist_ok=True)
        for f in ("ledger.db", "events.jsonl", "state.json"):
            (self.run_dir / f).unlink(missing_ok=True)
        (self.run_dir / "config.json").write_text(json.dumps(cfg, indent=2, default=str))
        self.key_dir = self.run_dir / "keys"
        self.operator = Identity("operator", self.key_dir)
        self.ledger = Ledger(self.run_dir / "ledger.db", self.operator)
        self.banks = load_banks(cfg)
        nf = len(FEATURE_NAMES)
        self.global_model = MLP(nf, tuple(cfg["model"]["hidden"]), seed=cfg["seed"])
        self.clients = [BankClient(b, cfg, nf, self.key_dir, cfg["seed"] + 101 * i) for i, b in enumerate(self.banks)]
        self.registry = {c.id: c.identity.public_hex for c in self.clients}
        self.status = {c.id: {"status": "active", "flags": 0, "eps": 0.0, "score": None, "reason": ""} for c in self.clients}
        self.history: list[dict] = []
        self.X_test = np.vstack([b["X_test"] for b in self.banks])
        self.y_test = np.concatenate([b["y_test"] for b in self.banks])
        for c, b in zip(self.clients, self.banks):
            self.ledger.append("register", {"bank": c.id, "name": b["name"], "jurisdiction": b["country"],
                                            "public_key": c.identity.public_hex, "n_train": int(len(b["y_train"]))})
            self.event(0, "register", c.id, f"{b['name']} ({b['country']}) registered")

    # ---- logging helpers
    def event(self, round_no: int, kind: str, bank: str | None, msg: str) -> None:
        with open(self.run_dir / "events.jsonl", "a") as f:
            f.write(json.dumps({"ts": time.time(), "round": round_no, "type": kind, "bank": bank, "msg": msg}) + "\n")

    def write_state(self, round_no: int, status: str) -> None:
        banks = []
        for b in self.banks:
            s = self.status[b["id"]]
            banks.append({k: b[k] for k in ("id", "name", "country", "city", "lat", "lon")} |
                         {"n_train": int(len(b["y_train"])), "illicit_rate": round(b["illicit_rate"], 5), **s})
        state = {"name": self.cfg["name"], "status": status, "round": round_no, "rounds": self.cfg["rounds"],
                 "rule": self.cfg["aggregation"]["rule"], "dp": self.cfg["dp"], "attack": self.cfg["attack"],
                 "defense": self.cfg["defense"], "banks": banks, "metrics": self.history,
                 "aggregator": {"name": "Consortium aggregator (EU)", "city": "Brussels", "lat": 50.85, "lon": 4.35}}
        tmp = self.run_dir / "state.json.tmp"
        tmp.write_text(json.dumps(state, indent=1, default=float))
        tmp.replace(self.run_dir / "state.json")

    # ---- round loop
    def run(self, verbose: bool = True) -> dict:
        cfg = self.cfg
        cfg_hash = sha256_hex(canonical(cfg))
        self.write_state(0, "running")
        for r in range(1, cfg["rounds"] + 1):
            t0 = time.time()
            gw = self.global_model.get_vector()
            gh = vector_hash(gw)
            active = [c for c in self.clients if self.status[c.id]["status"] != "quarantined"]
            self.ledger.append("round_start", {"config_hash": cfg_hash, "global_model_hash": gh,
                                               "participants": [c.id for c in active]}, r)
            accepted, rejected, deltas, weights, upd_hashes, bytes_in = [], [], [], [], [], 0
            for c in active:
                p = c.fit(gw, gh, r)
                reason = self._validate(p)
                if p.get("weights") is not None:
                    bytes_in += p["weights"].nbytes
                if reason:
                    rejected.append(c.id)
                    self._reject(c.id, r, reason, p)
                    continue
                d = p["weights"] - gw
                deltas.append(d); weights.append(p["n"]); accepted.append(c.id)
                upd_hashes.append(vector_hash(p["weights"]))
                self.status[c.id]["eps"] = round(p["eps_total"], 4)
                c._last = p

            # anomaly detection
            scores = {}
            if deltas and cfg["defense"]["anomaly"] and len(deltas) >= 3 and r > cfg["defense"].get("warmup_rounds", 0):
                sc = agg.anomaly_scores(np.array(deltas))
                D = cfg["defense"]
                keep = []
                for bid, s in zip(accepted, sc):
                    scores[bid] = s
                    bad = s["norm_z"] > D["z_threshold"] or s["cosine_to_median"] < D["cosine_threshold"]
                    st = self.status[bid]
                    st["score"] = s
                    if bad:
                        st["flags"] += 1
                        st["status"] = "flagged"
                        st["reason"] = f"anomalous update (norm z={s['norm_z']}, cosine={s['cosine_to_median']})"
                        self.event(r, "flag", bid, f"Bank {bid} flagged: {st['reason']}")
                        if st["flags"] >= D["quarantine_after"]:
                            st["status"] = "quarantined"
                            self.ledger.append("quarantine", {"bank": bid, "reason": st["reason"], "flags": st["flags"]}, r)
                            self.event(r, "quarantine", bid, f"Bank {bid} quarantined after {st['flags']} flagged rounds")
                    else:
                        st["flags"] = 0
                        if st["status"] == "flagged":
                            st["status"] = "active"
                        keep.append(bid)
                excluded = [b for b in accepted if b not in keep]
                idx = [accepted.index(b) for b in keep]
            else:
                excluded, idx = [], list(range(len(accepted)))

            for bid, uh in zip(accepted, upd_hashes):
                body = {"bank": bid, "update_hash": uh, "n": int(self.clients[[c.id for c in self.clients].index(bid)]._last["n"]),
                        "eps_round": round(self.clients[[c.id for c in self.clients].index(bid)]._last["eps_round"], 6),
                        "eps_total": self.status[bid]["eps"], "accepted": bid not in excluded,
                        "reason": "excluded by anomaly detector" if bid in excluded else "accepted",
                        "score": scores.get(bid)}
                self.ledger.append("update", body, r)

            used = [deltas[i] for i in idx]
            if used:
                U = np.array(used)
                A = cfg["aggregation"]
                if A["server_clip_factor"] and len(U) > 1:
                    U = agg.clip_by_norm(U, A["server_clip_factor"] * np.median(np.linalg.norm(U, axis=1)))
                step = agg.aggregate(A["rule"], U, np.array([weights[i] for i in idx]), trim=A["trim"], f=A["f"])
                self.global_model.set_vector(gw + step)

            m = evaluate(self.y_test, self.global_model.predict_proba(self.X_test))
            if cfg["attack"]["type"] == "backdoor":
                from .attacks import backdoor_success
                m["backdoor_success"] = round(backdoor_success(self.global_model, self.X_test, self.y_test, m["threshold"]), 4)
            used_ids = [accepted[i] for i in idx]
            rec = {"round": r, **m, "accepted": used_ids, "excluded": excluded, "rejected": rejected,
                   "eps": {c.id: self.status[c.id]["eps"] for c in self.clients},
                   "seconds": round(time.time() - t0, 3), "bytes_in": int(bytes_in)}
            self.history.append(rec)
            self.ledger.append("round_commit", {"merkle_root": agg_merkle(upd_hashes, accepted, used_ids),
                                                "model_hash": vector_hash(self.global_model.get_vector()),
                                                "rule": cfg["aggregation"]["rule"], "accepted": used_ids,
                                                "excluded": excluded, "rejected": rejected,
                                                "metrics": {k: m[k] for k in ("pr_auc", "f1", "recall_at_1pct_fpr")}}, r)
            self.event(r, "round", None, f"Round {r}: PR-AUC {m['pr_auc']}, used {used_ids}, excluded {excluded + rejected}")
            self.write_state(r, "running")
            if verbose:
                print(f"[{cfg['name']}] round {r:>2}/{cfg['rounds']}  PR-AUC={m['pr_auc']:.4f}  F1={m['f1']:.4f}  "
                      f"used={used_ids} excluded={excluded} rejected={rejected}  "
                      f"eps={ {k: v for k, v in rec['eps'].items()} }")
            if cfg["round_delay"]:
                time.sleep(cfg["round_delay"])

        self.write_state(cfg["rounds"], "done")
        summary = {"name": cfg["name"], "final": self.history[-1], "best_pr_auc": max(h["pr_auc"] for h in self.history),
                   "ledger": self.ledger.verify(self.operator.public_hex)}
        (self.run_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=float))
        return summary

    # ---- validation
    def _validate(self, p: dict) -> str | None:
        if p.get("status") != "ok":
            return p.get("status", "no status")
        extra = set(p) - ALLOWED_PAYLOAD_KEYS
        if extra:
            return f"payload schema violation: unexpected fields {sorted(extra)} (possible data exfiltration)"
        if self.cfg["defense"]["verify_signatures"]:
            msg = update_message(p["bank"], p["round"], vector_hash(p["weights"]), p["n"], p["eps_round"])
            if not verify(self.registry[p["bank"]], msg, p["signature"]):
                return "invalid signature (update altered in transit or forged)"
        return None

    def _reject(self, bid: str, r: int, reason: str, p: dict) -> None:
        st = self.status[bid]
        kind = "leakage_blocked" if "exfiltration" in reason else ("signature_invalid" if "signature" in reason else "rejected")
        self.ledger.append(kind, {"bank": bid, "reason": reason}, r)
        self.event(r, kind, bid, f"Bank {bid}: {reason}")
        if kind in ("leakage_blocked", "signature_invalid"):
            st["flags"] += 1
            st["status"] = "quarantined" if st["flags"] >= self.cfg["defense"]["quarantine_after"] or kind == "leakage_blocked" else "flagged"
            st["reason"] = reason
            if st["status"] == "quarantined":
                self.ledger.append("quarantine", {"bank": bid, "reason": reason, "flags": st["flags"]}, r)
                self.event(r, "quarantine", bid, f"Bank {bid} quarantined: {reason}")
        elif kind == "rejected":
            st["reason"] = reason


def agg_merkle(hashes: list[str], accepted: list[str], used: list[str]) -> str:
    from .ledger import merkle_root
    return merkle_root([h for h, b in zip(hashes, accepted) if b in used])


# --------------------------------------------------------------------------- data + baselines
_DATA_CACHE: dict = {}


def load_banks(cfg: dict) -> list[dict]:
    D = cfg["data"]
    key = (D["source"], D.get("path"), D.get("n_transactions"), D.get("illicit_rate"), cfg["n_banks"], cfg["seed"], D.get("max_rows"))
    if key not in _DATA_CACHE:
        if D["source"] == "amlworld":
            df = load_amlworld(D["path"], cfg["n_banks"], D.get("max_rows"))
        else:
            df = generate_synthetic(D["n_transactions"], cfg["n_banks"], D["illicit_rate"], D["days"], cfg["seed"])
        _DATA_CACHE[key] = partition(df, cfg["n_banks"])
    return _DATA_CACHE[key]


def train_pooled(cfg: dict, X: np.ndarray, y: np.ndarray, steps: int, seed: int) -> MLP:
    c = BankClient({"id": "pooled", "X_train": X, "y_train": y}, {**cfg, "attack": {"type": "none", "bank": None}},
                   X.shape[1], Path(cfg["out_dir"]) / "_keys", seed)
    c.cfg = {**c.cfg, "local": {**cfg["local"], "steps": steps, "mu": 0.0}, "dp": {**cfg["dp"], "enabled": False}}
    w = c.model.get_vector()
    out = c.fit(w, vector_hash(w), 1)
    c.model.set_vector(out["weights"])
    return c.model


def centralized_baseline(cfg: dict) -> dict:
    banks = load_banks(cfg)
    X = np.vstack([b["X_train"] for b in banks]); y = np.concatenate([b["y_train"] for b in banks])
    Xt = np.vstack([b["X_test"] for b in banks]); yt = np.concatenate([b["y_test"] for b in banks])
    model = train_pooled(cfg, X, y, cfg["rounds"] * cfg["local"]["steps"], cfg["seed"])
    return evaluate(yt, model.predict_proba(Xt))


def local_only(cfg: dict) -> dict:
    banks = load_banks(cfg)
    Xt = np.vstack([b["X_test"] for b in banks]); yt = np.concatenate([b["y_test"] for b in banks])
    out = {}
    for i, b in enumerate(banks):
        model = train_pooled(cfg, b["X_train"], b["y_train"], cfg["rounds"] * cfg["local"]["steps"], cfg["seed"] + i)
        out[b["id"]] = evaluate(yt, model.predict_proba(Xt))
    return out
