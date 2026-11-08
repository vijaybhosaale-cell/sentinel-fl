"""Map Flower run-config keys (pyproject.toml [tool.flwr.app.config] / --run-config) to the SENTINEL config."""
from __future__ import annotations

import json
import os

from sentinel.config import load_config


def cfg_from_run_config(rc) -> tuple[dict, dict]:
    """Run config from Flower (pyproject / --run-config), overridden by the SENTINEL_RUN_CONFIG JSON env var
    (used by simulate.py, because not every Flower version passes a run config into a simulation)."""
    merged = dict(rc or {})
    merged.update(json.loads(os.environ.get("SENTINEL_RUN_CONFIG", "{}")))
    g = lambda k, d: merged.get(k, d)  # noqa: E731
    dp = bool(g("dp", False))
    cfg = load_config(g("config", None) or None)
    cfg["n_banks"] = int(g("num-banks", 3))
    cfg["rounds"] = int(g("num-server-rounds", 15))
    cfg["data"]["n_transactions"] = int(g("n-transactions", cfg["data"]["n_transactions"]))
    cfg["local"].update(steps=int(g("local-steps", 40)), lr=float(g("lr", 0.3 if dp else 0.05)))
    cfg["dp"].update(enabled=dp, noise_multiplier=float(g("noise-multiplier", 1.0)), clip=float(g("clip", 5.0 if dp else 1.0)),
                     epsilon_cap=float(g("epsilon-cap", 10.0)))
    cfg["aggregation"].update(rule=str(g("rule", "trimmed_mean")), server_clip_factor=1.5)
    cfg["defense"].update(anomaly=bool(g("defense", True)))
    attack = {"type": str(g("attack-type", "none")), "bank": str(g("attack-bank", "C")),
              "start_round": int(g("attack-start", 4)), "fraction": 1.0, "boost": float(g("attack-boost", 5.0))}
    cfg["attack"] = attack
    return cfg, attack
