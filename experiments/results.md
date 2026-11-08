| ID | Experiment | PR-AUC | F1 | Recall @1% FPR | epsilon (max) | Backdoor success | Attacker caught |
| --- | --- | --- | --- | --- | --- | --- | --- |
| E1 | Centralised baseline (pooled synthetic data) | 0.7987 | 0.7395 | 0.8615 | - | - | - |
| E2 | Local-only, mean of banks | 0.715 | 0.6791 | 0.7539 | - | - | - |
| E3a | FedAvg, 3 banks | 0.8244 | 0.7568 | 0.8692 | - | - | - |
| E3b | FedProx (mu=0.01), 3 banks | 0.8198 | 0.75 | 0.8692 | - | - | - |
| E4a | FedProx + DP, noise 0.6 | 0.7662 | 0.7342 | 0.7923 | 20.82 | - | - |
| E4b | FedProx + DP, noise 1.0 | 0.7027 | 0.6996 | 0.7615 | 5.99 | - | - |
| E4c | FedProx + DP, noise 1.5 | 0.5662 | 0.5648 | 0.5846 | 2.99 | - | - |
| E5 | FedProx, 5 banks | 0.795 | 0.7364 | 0.8462 | - | - | - |
| E6a | Label flip by Bank C, FedAvg, no defence | 0.0119 | 0.0478 | 0.0231 | - | - | not caught |
| E6b | Label flip, trimmed mean + anomaly detector | 0.8018 | 0.7455 | 0.8385 | - | - | Bank C in round 4 |
| E6c | Label flip, 5 banks, Multi-Krum | 0.7638 | 0.7149 | 0.7923 | - | - | not caught |
| E7a | Backdoor (boosted) by Bank C, no defence | 0.6405 | 0.6498 | 0.7462 | - | 1.0 | not caught |
| E7b | Backdoor, anomaly detector + server norm clipping | 0.811 | 0.749 | 0.8538 | - | 0.0 | Bank C in round 4 |
| E8 | Free-rider, anomaly detector | 0.81 | 0.735 | 0.8538 | - | - | Bank C in round 7 |
| E9 | Raw-data exfiltration attempt | 0.811 | 0.749 | 0.8538 | - | - | Bank C in round 3 |
| E10 | Update altered in transit (MITM) | 0.811 | 0.749 | 0.8538 | - | - | Bank C in round 3 |
