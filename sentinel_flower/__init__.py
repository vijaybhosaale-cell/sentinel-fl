"""SENTINEL-FL on Flower + PyTorch + Opacus.

    sentinel_flower/task.py        PyTorch model, local data, Opacus DP-SGD training, evaluation
    sentinel_flower/client_app.py  Flower ClientApp: one bank (signs updates, enforces its epsilon budget)
    sentinel_flower/server_app.py  Flower ServerApp + SentinelStrategy (wraps the RoundGuard below)
    sentinel_flower/guard.py       framework-free defence pipeline: contract access check, schema check,
                                   signature check, anomaly detection, quarantine, robust aggregation,
                                   signed audit ledger and on-chain anchoring

Run: see docs/FLOWER.md (simulation on one laptop, or SuperLink + 3 SuperNodes on four laptops).
"""
