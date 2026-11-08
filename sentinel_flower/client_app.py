"""Flower ClientApp: one bank of the consortium.

Each SuperNode is started with --node-config "partition-id=<0|1|2> num-partitions=3"; partition 0 is
Bank A (Paris), 1 Bank B (Frankfurt), 2 Bank C (Amsterdam). The bank:
  * trains locally with PyTorch (+ Opacus DP-SGD when DP is on) and enforces its own epsilon budget
  * signs every update with its Ed25519 key (persisted per bank) and sends only allowed metadata
  * evaluates each global model on its own test data (federated evaluation)
  * can be told to misbehave for red-team tests (run-config keys attack-*)
"""
from __future__ import annotations

import os
from pathlib import Path

import numpy as np
from flwr.client import ClientApp, NumPyClient
from flwr.common import Context

from sentinel.crypto import Identity, update_message, vector_hash
from sentinel.data import MEMBERS
from sentinel_flower.guard import flatten
from sentinel_flower.config import cfg_from_run_config
from sentinel_flower.task import AMLNet, bank_data, bank_id, get_weights, set_weights, test, train


class BankClient(NumPyClient):
    def __init__(self, pid: int, cfg: dict, attack: dict):
        self.pid, self.cfg, self.attack = pid, cfg, attack
        self.id = bank_id(pid)
        self.dir = Path(os.environ.get("SENTINEL_NODE_DIR", "nodes/flower")) / f"bank_{self.id}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.identity = Identity(f"bank_{self.id}", self.dir / "keys")
        self.data = bank_data(cfg, pid)
        self.model = AMLNet(hidden=tuple(cfg["model"]["hidden"]))

    def _attacking(self, rnd: int) -> dict:
        a = self.attack
        return a if a.get("type", "none") != "none" and a.get("bank") == self.id and rnd >= a.get("start_round", 1) else {}

    def fit(self, parameters, config):
        rnd = int(config.get("server_round", 0))
        if config.get("reset_accountant") and rnd == 1:
            (self.dir / "opacus_accountant.json").unlink(missing_ok=True)
        att = self._attacking(rnd)
        set_weights(self.model, parameters)
        if att.get("type") == "free_rider":
            info, weights = {"eps_round": 0.0, "eps_total": 0.0, "eps_own": 0.0, "status": "ok", "train_seconds": 0.0}, [np.copy(p) for p in parameters]
        else:
            info = train(self.model, self.data, self.cfg, rnd, parameters, att, self.dir)
            weights = get_weights(self.model) if info["status"] == "ok" else parameters
        if att.get("type") in ("scale", "backdoor"):
            boost = float(att.get("boost", 5.0))
            weights = [g + boost * (w - g) for w, g in zip(weights, parameters)]
        n = int(len(self.data["y_train"]))
        msg = update_message(self.id, rnd, vector_hash(flatten(weights)), n, info["eps_round"])
        metrics = {"bank": self.id, "public_key": self.identity.public_hex, "signature": self.identity.sign(msg),
                   "jurisdiction": self.data["country"], **info}
        if att.get("type") == "tamper_update":          # A7: altered after signing (man-in-the-middle)
            weights = [w + np.random.default_rng(rnd).normal(0, 0.05, w.shape).astype(w.dtype) for w in weights]
        if att.get("type") == "leak":                   # A5: tries to smuggle transaction rows in the metrics
            metrics["raw_rows"] = str(self.data["X_train"][:5].round(3).tolist())
        print(f"[bank {self.id}] round {rnd}: {info['status']} eps={info['eps_total']:.3f}"
              + (f" RED-TEAM {att['type']}" if att else ""), flush=True)
        return weights, n, metrics

    def evaluate(self, parameters, config):
        set_weights(self.model, parameters)
        m = test(self.model, self.data)
        return m["loss"], int(m["n_test"]), {"bank": self.id, "pr_auc": m["pr_auc"], "f1": m["f1"],
                                             "recall_at_1pct_fpr": m["recall_at_1pct_fpr"], "n_illicit": m["n_illicit"]}


def client_fn(context: Context):
    pid = int(context.node_config.get("partition-id", 0))
    cfg, attack = cfg_from_run_config(context.run_config)
    return BankClient(pid, cfg, attack).to_client()


app = ClientApp(client_fn=client_fn)
