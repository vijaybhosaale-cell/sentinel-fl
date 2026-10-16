"""Experiment configuration: defaults deep-merged with a YAML file and CLI overrides."""
from __future__ import annotations

import copy
from pathlib import Path

import yaml

DEFAULTS = {
    "name": "default",
    "seed": 42,
    "out_dir": "runs",
    "data": {"source": "synthetic", "path": "data/HI-Small_Trans.csv", "max_rows": None,
             "n_transactions": 60000, "illicit_rate": 0.01, "days": 20},
    "n_banks": 3,
    "rounds": 20,
    "round_delay": 0.0,          # seconds to wait between rounds (slows a live demo down)
    "model": {"hidden": [32, 16]},
    "local": {"steps": 40, "batch_size": 256, "lr": 0.05, "momentum": 0.9, "mu": 0.01,  # mu > 0 = FedProx
              "pos_weight": "auto"},
    "dp": {"enabled": False, "noise_multiplier": 1.0, "clip": 1.0, "delta": 1e-5, "epsilon_cap": 10.0},
    "aggregation": {"rule": "fedavg", "trim": 1, "f": 1, "server_clip_factor": 0.0},
    "defense": {"anomaly": False, "warmup_rounds": 2, "z_threshold": 3.5, "cosine_threshold": 0.0, "quarantine_after": 2,
                "verify_signatures": True},
    "attack": {"type": "none", "bank": "C", "start_round": 3, "fraction": 1.0, "boost": 5.0},
}


def _merge(base: dict, extra: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (extra or {}).items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _set_path(cfg: dict, dotted: str, value: str) -> None:
    keys = dotted.split(".")
    d = cfg
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = yaml.safe_load(value)


def load_config(path: str | None = None, overrides: list[str] | None = None) -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    if path:
        cfg = _merge(cfg, yaml.safe_load(Path(path).read_text()) or {})
    for o in overrides or []:
        k, _, v = o.partition("=")
        _set_path(cfg, k, v)
    return cfg
