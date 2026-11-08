"""Flower ServerApp with SentinelStrategy: FedAvg's sampling, plus the SENTINEL defence pipeline.

aggregate_fit hands every update to RoundGuard (sentinel_flower/guard.py): smart-contract access check,
payload allow-list, Ed25519 signature check, anomaly scoring and quarantine, robust aggregation with
server-side clipping, signed audit ledger and on-chain round anchoring. aggregate_evaluate combines the
banks' federated evaluation. Outputs go to runs/flower (open with `python -m sentinel serve`).
"""
from __future__ import annotations

import os

import numpy as np
from flwr.common import Context, ndarrays_to_parameters, parameters_to_ndarrays
from flwr.server import ServerApp, ServerAppComponents, ServerConfig
from flwr.server.strategy import FedAvg

from sentinel_flower.config import cfg_from_run_config
from sentinel_flower.guard import RoundGuard, flatten, unflatten
from sentinel_flower.task import AMLNet, get_weights


class SentinelStrategy(FedAvg):
    def __init__(self, guard: RoundGuard, init_weights, n_banks: int, num_rounds: int, **kw):
        super().__init__(fraction_fit=1.0, fraction_evaluate=1.0, min_fit_clients=n_banks, min_evaluate_clients=n_banks,
                         min_available_clients=n_banks, initial_parameters=ndarrays_to_parameters(init_weights),
                         on_fit_config_fn=lambda r: {"server_round": r, "reset_accountant": True},
                         on_evaluate_config_fn=lambda r: {"server_round": r}, **kw)
        self.guard, self.like = guard, init_weights
        self.current = flatten(init_weights)
        self.num_rounds = num_rounds

    def aggregate_fit(self, server_round, results, failures):
        subs = []
        for _, res in results:
            w = parameters_to_ndarrays(res.parameters)
            m = dict(res.metrics or {})
            subs.append({"bank": str(m.get("bank", "?")), "weights": flatten(w), "n": int(res.num_examples), "metrics": m})
        new, rec = self.guard.process(server_round, self.current, subs)
        self.current = new
        return ndarrays_to_parameters(unflatten(new, self.like)), {"used": len(rec["used"]), "excluded": len(rec["excluded"]),
                                                                    "rejected": len(rec["rejected"])}

    def aggregate_evaluate(self, server_round, results, failures):
        if not results:
            return None, {}
        evals = [dict(res.metrics or {}) for _, res in results]
        m = self.guard.record_eval(server_round, evals)
        loss = float(np.average([res.loss for _, res in results], weights=[res.num_examples for _, res in results]))
        if server_round >= self.num_rounds:
            self.guard.finish()
            print(f"[server] run finished; ledger verified: {self.guard.ledger.verify()['ok']}; outputs in {self.guard.dir}", flush=True)
        print(f"[server] round {server_round}: federated PR-AUC {m['pr_auc']} per bank {m['per_bank']}", flush=True)
        return loss, {k: v for k, v in m.items() if isinstance(v, (int, float))}


def server_fn(context: Context):
    cfg, _ = cfg_from_run_config(context.run_config)
    guard = RoundGuard(os.environ.get("SENTINEL_RUN_DIR", "runs/flower"), cfg, fresh=True)
    model = AMLNet(hidden=tuple(cfg["model"]["hidden"]))
    strategy = SentinelStrategy(guard, get_weights(model), cfg["n_banks"], cfg["rounds"])
    return ServerAppComponents(strategy=strategy, config=ServerConfig(num_rounds=cfg["rounds"]))


app = ServerApp(server_fn=server_fn)
