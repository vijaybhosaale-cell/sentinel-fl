# SENTINEL-FL version 2 — architecture

Version 2 turns the single-process prototype into a **distributed system**: one aggregator and one node per bank, each a separate
process that can run on a separate laptop. Banks keep their transactions on their own machine; only signed model updates,
evaluation scores and alert *counts* travel over the network.

## Components

| Component | Runs on | Command | Role |
| --- | --- | --- | --- |
| Aggregator (control room) | Vijay's laptop (projector) | `python -m sentinel aggregator` | Registry and access control, round engine, defences, attack lab, audit ledger, alerts and e-mail, ARIA, Prometheus metrics, regulator view |
| Bank node A / B / C | one teammate laptop each | `python -m sentinel bank --id B --aggregator http://<IP>:8000` | Holds its private data, trains locally, scores live transactions, signs updates, serves its own portal |
| Fallback cluster | one laptop | `python -m sentinel cluster --fresh` | Aggregator + 3 banks as separate processes on one machine |
| Prometheus + Grafana | aggregator laptop (optional) | `docker compose --profile monitoring up` | Scrapes `/metrics` from the aggregator |

## Why banks only make outbound calls

Like a Flower client, a bank node **pulls** its work: it polls `GET /api/task` every second and pushes its update with
`POST /api/update`. No bank laptop needs an open port or a firewall exception. Only the aggregator laptop must accept
connections on port 8000.

## One training round

```text
Aggregator                                       Bank node (x3)
----------                                       --------------
round_start -> ledger (participants, model hash)
publish task {round, global weights, hash,  <--  poll /api/task
              consortium DP policy}
                                                 check model hash
                                                 evaluate model on LOCAL test data
                                                 score next 150 live transactions -> local alerts
                                                 train locally (FedProx, optional DP-SGD via Opacus-style accountant)
                                                 sign {bank, round, weights hash, n, eps} with Ed25519
validate: access, round, schema, signature  <--  POST /api/update {payload, eval scores, alert COUNTS}
anomaly score (norm z, cosine) -> exclude / quarantine
robust aggregation (trimmed mean / median / Multi-Krum) + norm clipping
update + round_commit (Merkle root) -> ledger
federated evaluation = weighted mean of bank scores
```

## Security and compliance controls

| Threat | Control | Where |
| --- | --- | --- |
| Unknown or impersonating bank | Signed registration; one key per bank ID; operator approval; revoke | `aggregator_node.register`, `set_access` |
| Raw-data exfiltration | Payload schema allow-list; violating bank quarantined; bank logs every outbound message | `submit`, bank `_out`, Data residency page |
| Update altered in transit / forged | Ed25519 signature over the weights hash, checked with the registered key | `submit` |
| Poisoning, backdoor, free-riding | Norm z-score + cosine anomaly detector, exclusion, quarantine after 2 flags, robust aggregation, norm clipping | `_aggregate` |
| Re-identification from updates | DP-SGD with Rényi-DP accounting and consortium ε cap | `privacy.py`, policy pushed in every task |
| Log tampering | Signed hash chain with Merkle roots; Verify pinpoints the first bad record | `ledger.py`, Ledger page |
| Tipping-off / GDPR minimisation | Alert *counts and pattern names* only leave the bank; case details stay in the bank portal | bank `_evaluate_and_score` |

## Module map

```text
sentinel/
  aggregator_node.py   control room server, registry, round engine, attack lab, alerts, metrics
  bank_node.py         bank server, local training, live scoring, residency log
  net.py               HTTP server/client toolkit (standard library)
  notify.py            e-mail alerts over SMTP, or outbox folder when SMTP is not configured
  federation.py        BankClient (local training, attacks) + single-process Federation (v1, experiments)
  aggregation.py       FedAvg, median, trimmed mean, Multi-Krum, anomaly scores
  privacy.py           DP-SGD step + Rényi-DP accountant
  ledger.py, crypto.py audit hash chain, Ed25519 identities
  aria.py              ARIA copilot (local LLM via Ollama, or offline mode)
web/aggregator/*.html  8 pages: control room, registry, training, attack lab, ledger, alerts, regulator, results
web/bank/*.html        6 pages: overview, transactions, alerts, local training, privacy budget, data residency
```

## Aggregator API

| Method | Path | Who | Purpose |
| --- | --- | --- | --- |
| POST | `/api/register` | bank | signed join request |
| GET | `/api/task?bank=X` | bank | current task (model, policy, red-team instruction) |
| POST | `/api/update`, `/api/eval` | bank | signed update / evaluation-only answer |
| GET | `/api/overview`, `/api/registry`, `/api/rounds`, `/api/ledger`, `/api/verify`, `/api/alerts`, `/api/compliance`, `/api/results`, `/api/aria?q=` | anyone (read-only) | pages and regulator |
| POST | `/api/registry/action`, `/api/control/start`, `/api/control/stop`, `/api/attack/launch`, `/api/attack/stop`, `/api/ledger/tamper`, `/api/notify/test` | operator (`X-Admin-Token`) | actions |
| GET | `/metrics` | Prometheus | gauges and counters |

## Honest limits

* The learning engine is the NumPy implementation from version 1 (MLP, DP-SGD, RDP accountant). Porting the client to
  PyTorch + Opacus and the transport to Flower's SuperLink/SuperNode is the next step; the HTTP protocol above maps
  one-to-one onto Flower's pull model.
* The registry enforces the access rules in Python and records them in the ledger; anchoring them in a smart contract is planned.
* Federated evaluation combines bank PR-AUC scores weighted by the number of illicit cases; it is an approximation of pooled PR-AUC.
* Traffic uses plain HTTP inside a private hotspot; add TLS (reverse proxy or Flower TLS) before any real deployment.
