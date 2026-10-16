# Operations guide: every page and what it proves

## Aggregator (laptop 1, projector)

| Page | What you see | What to say to the jury |
| --- | --- | --- |
| **Control room** `/` | KPIs, schematic consortium map with live update flows, run controls, per-bank round progress, update checks, PR-AUC chart, event feed | "Three banks in three countries train one model; no transaction leaves its bank." |
| **Registry & access** `/registry` | Participants, keys, jurisdictions, access status; approve / revoke / reinstate; access decisions in the ledger | "Only approved, registered keys can take part. Access control is enforced and logged." |
| **Training rounds** `/training` | PR-AUC per round (consortium and per bank), anomaly z-scores against the threshold, round log with model hash and Merkle root | "Every round is traceable to a model hash and to the updates that built it." |
| **Attack lab** `/attack` | Choose bank and scenario A1–A8, launch / stop, live effect, detection timeline, reinstate | "We attack our own system live and you can watch it defend itself." |
| **Audit ledger** `/ledger` | Signed records, filter by type, record detail, Verify chain, insider-edit demo | "If anyone edits history, we know exactly where." |
| **Alerts & e-mail** `/alerts` | Bank alert counts and patterns, system alerts, e-mail log, test e-mail | "Banks share alert counts, not customers: that respects the AML tipping-off rule and GDPR." |
| **Regulator · ARIA** `/regulator` | Regulation → control → evidence, ε per bank, ARIA chat | "A supervisor can audit without seeing any data, and ARIA cites ledger records." |
| **Results** `/results` | Live run vs centralised baseline; experiment matrix E1–E10 | "Here are the measured results for each test scenario in the brief." |

## Bank portal (laptops 2–4)

| Page | What you see | What it proves |
| --- | --- | --- |
| **Overview** `/` | Local data size, illicit rate, access status, rounds, ε, alerts, connection, last round, local PR-AUC | The bank is an autonomous node |
| **Transactions** `/transactions` | The private live stream with risk scores | The data exists **only** here |
| **Alerts** `/alerts` | AML alert queue with severity, patterns, ground truth (synthetic), e-mails to the AML officer | Real-time alerting value for each bank |
| **Local training** `/training` | Local PR-AUC per round, bytes sent, training time, signed update hash, aggregator response | What leaves the bank, and that it is signed |
| **Privacy budget** `/privacy` | ε gauge vs the consortium cap, DP-SGD settings, cumulative ε chart | Measurable privacy guarantee |
| **Data residency** `/residency` | Every outbound message with size and field names; raw rows sent = 0 | The brief's "proof that no transaction data left its jurisdiction" |

## Suggested 8-minute demo script

1. **Vijay (control room):** problem statement, the map, start the run.
2. **Abdul Fathah (Bank A laptop):** the local transactions and live alerts appearing each round; the local training page.
3. **Mereena (attack lab):** launch label flipping on Bank C; show exclusion and quarantine; the curve stays stable.
4. **Niranjan (Bank C laptop):** red-team banner, then "QUARANTINED"; Data residency: 0 raw rows. Back on laptop 1: Ledger → Verify → insider edit → Verify fails at that record.
5. **Vijay (regulator):** compliance matrix, ε per bank, ARIA questions and the incident report; e-mail alerts in the Alerts page.
