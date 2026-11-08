# SENTINEL-FL

**Federated learning for cross-border financial crime detection, with privacy accounting, attack defences, a tamper-evident audit ledger and ARIA, a JARVIS-style compliance copilot.**

ESAIP MSc Cybersecurity & Data Science · Projet Applicatif 3 · Referent: Sofiane Hamrioui
Team: Vijay Dipak Bhosale · Abdul Fathah Chappan Puthiya Purayil · Mereena Mariam Jibu · Niranjan Satheesh Thandassery

---

## What it does

Three (or five) simulated European banks train one anti-money-laundering model together **without sharing a single transaction**:

- **Federated training:** FedAvg or FedProx over banks in France, Germany, the Netherlands (+ Italy, Spain), non-IID by construction.
- **Differential privacy:** DP-SGD per bank with a Renyi-DP accountant; each bank's ε is tracked per round and a consortium **ε cap** stops a bank from training once its budget is spent.
- **Defences:** Ed25519-signed updates, payload schema checks (anti-exfiltration), anomaly scoring (norm z-score + cosine to median), automatic **quarantine**, robust aggregation (trimmed mean, median, Multi-Krum), server-side norm clipping.
- **Audit ledger:** append-only SQLite hash chain signed by the operator, with a Merkle root per round. Editing any record is detected at the exact record.
- **Mission Control:** dark map of Europe with live update flows; banks turn amber or red when flagged or quarantined; PR-AUC chart, event feed, ledger viewer and a "Verify chain" button.
- **ARIA:** a copilot that answers questions such as *"Did anyone poison the model?"* by calling read-only tools over the ledger, citing record numbers, and writing incident reports. It uses a local LLM through Ollama when available, and a deterministic offline mode otherwise.
- **Red team:** label flipping, boosted scaling, backdoor, free-riding, raw-data exfiltration and man-in-the-middle tampering, each switchable from a config flag.

## Defence demo on one laptop

```bash
python -m sentinel showcase          # Windows: double-click start_demo.bat
```

Starts the aggregator, Banks A, B and C (separate processes) and the smart-contract registry, opens the control room
and the three bank portals, and prints the demo checklist. See [docs/ONE_MACHINE_DEMO.md](docs/ONE_MACHINE_DEMO.md).

## Version 2: distributed consortium (multi-page, multi-laptop)

Version 2 runs the aggregator and every bank as **separate nodes** with their own web portals. The banks pull work from the
aggregator, like Flower clients, so they can run on four different laptops over one hotspot.

```bash
python -m sentinel cluster --fresh          # everything on one laptop: aggregator + Banks A, B, C
```

| Open | What it is |
| --- | --- |
| http://127.0.0.1:8000 | **Aggregator**: control room, registry & access, training rounds, attack lab, audit ledger, alerts & e-mail, regulator · ARIA, results (operator token `demo`) |
| http://127.0.0.1:8101 / 8102 / 8103 | **Bank A / B / C portals**: overview, transactions, AML alerts, local training, privacy budget, data residency |

On four laptops: `python -m sentinel aggregator --fresh` on laptop 1, and
`python -m sentinel bank --id A --aggregator http://<laptop-1-IP>:8000` on each bank laptop.
With Docker: `docker compose up --build` (add `--profile monitoring` for Prometheus on :9090 and Grafana on :3000).

Alerts go **both** to the dashboards (live) and by **e-mail** (SMTP, or an outbox folder when SMTP is not set up).

| Document | Contents |
| --- | --- |
| [docs/ARCHITECTURE_V2.md](docs/ARCHITECTURE_V2.md) | Components, round protocol, security controls, module map, API |
| [docs/MULTI_LAPTOP_SETUP.md](docs/MULTI_LAPTOP_SETUP.md) | Demo-day setup, network, firewall, troubleshooting |
| [docs/OPERATIONS_GUIDE.md](docs/OPERATIONS_GUIDE.md) | Every page, what it proves, 8-minute demo script |
| [docs/ALERTS_AND_EMAIL.md](docs/ALERTS_AND_EMAIL.md) | Alert levels, e-mail triggers, Gmail app-password setup |
| [docs/FLOWER.md](docs/FLOWER.md) | Flower + PyTorch + Opacus engine: simulation and SuperLink/SuperNode deployment |
| [docs/SMART_CONTRACT.md](docs/SMART_CONTRACT.md) | ConsortiumRegistry smart contract: registration, access control, round anchoring |

### Flower + PyTorch + Opacus and the smart contract

```bash
pip install -r requirements-flower.txt --extra-index-url https://download.pytorch.org/whl/cpu
python -m sentinel_flower.simulate --attack label_flip       # Flower simulation, 3 banks, Opacus available with --dp
```

Access control is enforced by the `ConsortiumRegistry` smart contract (`contracts/`), simulated by default and deployable
to a local Ethereum chain (`docs/SMART_CONTRACT.md`).

## Quick start, version 1 single-process demo (5 minutes)

Requires Python 3.10+.

```bash
git clone https://github.com/<your-account>/sentinel-fl.git
cd sentinel-fl
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m unittest discover -s tests -v                 # 21 tests, ~25 s
python -m sentinel demo                                 # then open http://127.0.0.1:8000
```

`demo` computes the baselines once, starts Mission Control and runs the attack scenario live (`configs/demo_attack.yaml`): Bank C (Netherlands) starts poisoning in round 4, is excluded at once and quarantined in round 5, while PR-AUC stays at the honest level.

## Commands

| Command | What it does |
| --- | --- |
| `python -m sentinel run --config configs/fedavg.yaml` | Plain FedAvg, 3 banks |
| `python -m sentinel run --config configs/fedprox_dp.yaml` | FedProx + DP-SGD with ε cap |
| `python -m sentinel run --config configs/defended.yaml --set attack.type=backdoor` | Any attack against full defences |
| `python -m sentinel run --config configs/amlworld.yaml` | Real IBM AMLworld data (see `data/README.md`) |
| `python -m sentinel baselines` | Centralised and local-only baselines → `runs/baselines.json` |
| `python -m sentinel matrix` | Experiment matrix E1–E10 → `experiments/results.md` (~4 min) |
| `python -m sentinel serve` | Mission Control + read-only API on port 8000 |
| `python -m sentinel aria --run demo "Write the incident report"` | Ask ARIA from the terminal |
| `python -m sentinel tamper --run demo --record 20` | Demo: an insider edits one ledger record |
| `python -m sentinel verify --run demo` | Detects the edit at record #20 |

Any setting can be overridden: `--set rounds=30 --set n_banks=5 --set dp.noise_multiplier=1.5`.
Attack types: `label_flip | scale | backdoor | free_rider | leak | tamper_update | none`.

## ARIA with a local LLM (optional)

```bash
# install Ollama from https://ollama.com, then
ollama pull llama3.1:8b
export ARIA_MODEL=llama3.1:8b        # any tool-calling model
python -m sentinel serve
```

Without Ollama, ARIA answers in offline mode from the same tools, so the demo never depends on the LLM. ARIA has no tool that returns transactions, labels or weights.

## Docker

```bash
docker compose up --build               # trainer runs the demo scenario, dashboard on :8000
docker compose --profile llm up         # also starts Ollama for ARIA
```

The dashboard container mounts `runs/` **read-only**: the cockpit can never change the ledger.

## Results on synthetic data (20 rounds, seed 42)

| ID | Experiment | PR-AUC | Recall @1% FPR | ε (max) | Outcome |
| --- | --- | --- | --- | --- | --- |
| E1 | Centralised baseline (pooled) | 0.799 | 0.862 | – | upper reference |
| E2 | Local-only (mean of banks) | 0.715 | 0.754 | – | value of collaboration |
| E3a | FedAvg, 3 banks | 0.824 | 0.869 | – | matches centralised |
| E3b | FedProx, 3 banks | 0.820 | 0.869 | – | |
| E4a | FedProx + DP, noise 0.6 | 0.766 | 0.792 | 20.8 | |
| E4b | FedProx + DP, noise 1.0 | 0.703 | 0.762 | 6.0 | privacy–utility trade-off |
| E4c | FedProx + DP, noise 1.5 | 0.566 | 0.585 | 3.0 | |
| E5 | FedProx, 5 banks | 0.795 | 0.846 | – | |
| E6a | Label flip, FedAvg, no defence | 0.012 | 0.023 | – | model destroyed |
| E6b | Label flip, trimmed mean + detector | 0.802 | 0.839 | – | Bank C caught in round 4 |
| E6c | Label flip, 5 banks, Multi-Krum | 0.764 | 0.792 | – | filtered silently (Krum is not a detector) |
| E7a | Backdoor, no defence | 0.641 | 0.746 | – | backdoor success 100% |
| E7b | Backdoor, detector + norm clipping | 0.811 | 0.854 | – | backdoor success 0%, caught round 4 |
| E8 | Free-rider, detector | 0.810 | 0.854 | – | caught round 7 |
| E9 | Raw-data exfiltration attempt | 0.811 | 0.854 | – | blocked and quarantined round 3 |
| E10 | Update altered in transit | 0.811 | 0.854 | – | signature check, quarantined round 3 |

Re-run with `python -m sentinel matrix`. These are synthetic-data results; confirm them on AMLworld before using them in the report.

## Repository layout

```text
sentinel/
  data.py          synthetic AMLworld-like generator, AMLworld loader, features, bank partition
  model.py         NumPy MLP with per-sample gradients
  privacy.py       DP-SGD step + Renyi-DP accountant
  aggregation.py   FedAvg, median, trimmed mean, Multi-Krum, anomaly scores
  attacks.py       red-team attacks
  crypto.py        Ed25519 identities and signed updates
  ledger.py        signed hash-chain audit ledger + verifier
  federation.py    bank clients, server round loop, baselines
  aria.py          ARIA copilot (Ollama tool calling + offline mode)
  server.py        read-only API + dashboard server (standard library)
  experiments.py   experiment matrix
dashboard/index.html   Mission Control
configs/               fedavg, fedprox_dp, defended, demo_attack, amlworld
docs/                  traceability.yaml (regulation → control), journal.md
tests/                 unit + end-to-end tests
```

## Design notes and honest limits

- The engine is plain NumPy so it runs on any laptop and every step is inspectable. Porting the client and strategy to **Flower + PyTorch + Opacus** (`requirements-next.txt`) is the next sprint; the protocol, ledger, ARIA and dashboard stay unchanged.
- The privacy accountant uses integer Renyi orders, so its ε is slightly conservative (an upper bound).
- The evaluation harness pools **test predictions** to report research metrics; this is not part of the training protocol.
- The ledger is a signed hash chain ("Fabric-lite"). Hyperledger Fabric can anchor round seals later without changing the API.
- Synthetic data uses a 1% illicit rate for learnability; the real AMLworld HI-Small rate is about 0.1%.
