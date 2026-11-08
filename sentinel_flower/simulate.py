"""One-laptop Flower simulation: 3 SuperNodes (banks) + ServerApp in one process.

    python -m sentinel_flower.simulate                          # 15 rounds, defences on
    python -m sentinel_flower.simulate --dp                     # with Opacus DP-SGD
    python -m sentinel_flower.simulate --attack label_flip      # Bank C label-flips from round 4

Multi-laptop deployment uses `flower-superlink`, `flower-supernode` and `flwr run` (docs/FLOWER.md).
"""
import argparse
import json
import os

from flwr.simulation import run_simulation


ap = argparse.ArgumentParser()
ap.add_argument("--rounds", type=int, default=15)
ap.add_argument("--dp", action="store_true")
ap.add_argument("--attack", default="none", choices=["none", "label_flip", "backdoor", "scale", "leak", "tamper_update", "free_rider"])
ap.add_argument("--attack-bank", default="C")
ap.add_argument("--rule", default="trimmed_mean")
ap.add_argument("--no-defense", action="store_true")
a = ap.parse_args()
rc = {"num-server-rounds": a.rounds, "dp": a.dp, "attack-type": a.attack, "attack-bank": a.attack_bank,
      "rule": a.rule, "defense": not a.no_defense}
os.environ["SENTINEL_RUN_CONFIG"] = json.dumps(rc)   # read by both apps; inherited by simulation workers
from sentinel_flower.client_app import app as client_app  # noqa: E402
from sentinel_flower.server_app import app as server_app  # noqa: E402
run_simulation(server_app=server_app, client_app=client_app, num_supernodes=3,
               backend_config={"client_resources": {"num_cpus": 1, "num_gpus": 0.0}})
