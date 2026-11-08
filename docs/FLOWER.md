# Flower + PyTorch + Opacus engine (`sentinel_flower/`)

The project brief names Flower for orchestration, PyTorch for the model and Opacus for differential privacy.
`sentinel_flower/` runs SENTINEL-FL on exactly that stack, while reusing the project's own security layer.

| File | Role |
| --- | --- |
| `task.py` | PyTorch `AMLNet` (25 → 32 → 16 → 1, same as the reference MLP), bank-local data, training with **Opacus `PrivacyEngine`** (RDP accountant, Poisson sampling, per-sample clipping), evaluation |
| `client_app.py` | Flower **ClientApp**: one bank. Enforces its own ε budget, signs every update with Ed25519, sends only allow-listed metadata, evaluates each global model on its own test data, can be told to misbehave (red team) |
| `server_app.py` | Flower **ServerApp** with `SentinelStrategy` (extends `FedAvg`) |
| `guard.py` | Framework-free defence pipeline used by the strategy: smart-contract access check → payload allow-list → signature → anomaly scoring → quarantine → robust aggregation + clipping → signed ledger → on-chain anchoring |
| `simulate.py` | One-laptop simulation with 3 SuperNodes |

The ε reported by each bank is Opacus' RDP accountant; the project's own accountant (`sentinel/privacy.py`) is computed
alongside it and stored in the ledger (`eps_own_accountant`) as an independent cross-check.
Outputs go to `runs/flower/` in the reference engine's format, so all existing tools work on Flower runs:

```bash
python -m sentinel serve                     # Mission Control lists the "flower" run
python -m sentinel verify --run flower       # verify the signed hash chain
python -m sentinel aria --run flower "Did anyone poison the model?"
```

## Install

Use a fresh virtual environment (Python 3.10–3.12):

```powershell
python -m venv .venv-flower ; .venv-flower\Scripts\activate
pip install -r requirements-flower.txt --extra-index-url https://download.pytorch.org/whl/cpu
```

Or use Docker only: `docker compose --profile flower run --rm flower-sim`.

## 1. Simulation on one laptop

```powershell
python -m sentinel_flower.simulate                          # 15 rounds, defences on
python -m sentinel_flower.simulate --attack label_flip      # Bank C label-flips from round 4
python -m sentinel_flower.simulate --dp                     # Opacus DP-SGD (noise 1.0, clip 5, ε cap 10)
python -m sentinel_flower.simulate --attack leak --attack-bank B
```

Expected with `--attack label_flip`: Bank C excluded in round 4, quarantined in round 5 (console and ledger), the contract
status of C becomes `quarantined`, and the run ends with "ledger verified: True".

## 2. Deployment on four laptops (Flower SuperLink + SuperNodes)

Laptop 1 (aggregator, IP for example 192.168.43.10):

```powershell
flower-superlink --insecure
```

Laptops 2–4 (one bank each, partition-id 0 = Bank A, 1 = Bank B, 2 = Bank C):

```powershell
flower-supernode --insecure --superlink 192.168.43.10:9092 --node-config "partition-id=0 num-partitions=3"
```

Laptop 1, in a second terminal, start the run (edit the `consortium` address in `pyproject.toml` to the laptop-1 IP):

```powershell
flwr run . consortium --stream
flwr run . consortium --run-config "attack-type='label_flip'" --stream     # red-team run
flwr run . consortium --run-config "dp=true" --stream                       # DP run
```

Windows firewall on laptop 1: allow inbound TCP 9092 (SuperNodes) and 9093 (flwr run) on Private networks.
Docker equivalent on one machine: `docker compose --profile flower-deploy up -d superlink supernode-a supernode-b supernode-c`
then `docker compose --profile flower-deploy run --rm flwr-run`.

## Tested here, and to check on your laptop

* `tests/test_flower_glue.py` runs the real `client_app.py`, `server_app.py` and `guard.py` with stand-ins for Flower and
  for the PyTorch task (no PyTorch in the build environment): signing, allow-list, contract access control, quarantine,
  ledger and anchoring are covered.
* The PyTorch/Opacus training code in `task.py` and the Flower runtime calls run for the first time on a machine with
  `requirements-flower.txt` installed. Run the simulation once before the demo.
* Pinned versions: flwr 1.18.0, torch 2.5.1, opacus 1.5.2.
