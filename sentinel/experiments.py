"""Experiment matrix (Phase 5): writes experiments/results.md and results.json."""
from __future__ import annotations

import json
from pathlib import Path

from .config import load_config
from .federation import Federation, centralized_baseline, local_only

DP = ["local.mu=0.01", "dp.enabled=true", "dp.clip=5.0", "local.lr=0.3", "dp.epsilon_cap=1000"]
EXPERIMENTS = [
    ("E3a", "FedAvg, 3 banks", "configs/fedavg.yaml", []),
    ("E3b", "FedProx (mu=0.01), 3 banks", "configs/fedavg.yaml", ["local.mu=0.01"]),
    ("E4a", "FedProx + DP, noise 0.6", "configs/fedavg.yaml", DP + ["dp.noise_multiplier=0.6"]),
    ("E4b", "FedProx + DP, noise 1.0", "configs/fedavg.yaml", DP + ["dp.noise_multiplier=1.0"]),
    ("E4c", "FedProx + DP, noise 1.5", "configs/fedavg.yaml", DP + ["dp.noise_multiplier=1.5"]),
    ("E5", "FedProx, 5 banks", "configs/fedavg.yaml", ["n_banks=5"]),
    ("E6a", "Label flip by Bank C, FedAvg, no defence", "configs/fedavg.yaml", ["attack.type=label_flip"]),
    ("E6b", "Label flip, trimmed mean + anomaly detector", "configs/fedavg.yaml", ["attack.type=label_flip", "aggregation.rule=trimmed_mean", "defense.anomaly=true"]),
    ("E6c", "Label flip, 5 banks, Multi-Krum", "configs/fedavg.yaml", ["n_banks=5", "attack.type=label_flip", "aggregation.rule=multi_krum"]),
    ("E7a", "Backdoor (boosted) by Bank C, no defence", "configs/fedavg.yaml", ["attack.type=backdoor"]),
    ("E7b", "Backdoor, anomaly detector + server norm clipping", "configs/fedavg.yaml", ["attack.type=backdoor", "defense.anomaly=true", "aggregation.server_clip_factor=1.5"]),
    ("E8", "Free-rider, anomaly detector", "configs/fedavg.yaml", ["attack.type=free_rider", "defense.anomaly=true"]),
    ("E9", "Raw-data exfiltration attempt", "configs/fedavg.yaml", ["attack.type=leak"]),
    ("E10", "Update altered in transit (MITM)", "configs/fedavg.yaml", ["attack.type=tamper_update"]),
]


def run_matrix(out: str = "experiments", quick: bool = False) -> list[dict]:
    outp = Path(out); outp.mkdir(parents=True, exist_ok=True)
    extra = ["rounds=6"] if quick else []
    base_cfg = load_config("configs/fedavg.yaml", extra + ["out_dir=runs/matrix"])
    central = centralized_baseline(base_cfg)
    local = local_only(base_cfg)
    rows = [{"id": "E1", "name": "Centralised baseline (pooled synthetic data)", **central},
            {"id": "E2", "name": "Local-only, mean of banks", "pr_auc": round(sum(v["pr_auc"] for v in local.values()) / len(local), 4),
             "f1": round(sum(v["f1"] for v in local.values()) / len(local), 4),
             "recall_at_1pct_fpr": round(sum(v["recall_at_1pct_fpr"] for v in local.values()) / len(local), 4)}]
    for eid, name, path, ov in EXPERIMENTS:
        cfg = load_config(path, ov + extra + [f"name={eid}", "out_dir=runs/matrix"])
        s = Federation(cfg).run(verbose=False)
        f = s["final"]
        rows.append({"id": eid, "name": name, "pr_auc": f["pr_auc"], "f1": f["f1"],
                     "recall_at_1pct_fpr": f["recall_at_1pct_fpr"], "best_pr_auc": s["best_pr_auc"],
                     "eps_max": max(f["eps"].values()), "backdoor_success": f.get("backdoor_success"),
                     "caught": sorted({e for h in s.get("history", []) for e in h.get("excluded", [])}),
                     "ledger_ok": s["ledger"]["ok"], "sec_per_round": f["seconds"]})
        print(f"{eid:4} {name:52} PR-AUC={f['pr_auc']:.3f}")
    # attackers caught: read from ledger quarantine records
    for r in rows:
        if r["id"].startswith(("E6", "E7", "E8", "E9", "E10")):
            from .ledger import open_readonly
            L = open_readonly(Path("runs/matrix") / r["id"] / "ledger.db")
            q = [e for e in L.entries() if e["type"] in ("quarantine", "leakage_blocked", "signature_invalid")]
            r["caught"] = f"Bank {q[0]['body']['bank']} in round {q[0]['round']}" if q else "not caught"
    (outp / "results.json").write_text(json.dumps(rows, indent=2, default=str))
    md = ["| ID | Experiment | PR-AUC | F1 | Recall @1% FPR | epsilon (max) | Backdoor success | Attacker caught |",
          "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        eps = r.get("eps_max")
        md.append(f"| {r['id']} | {r['name']} | {r['pr_auc']} | {r['f1']} | {r['recall_at_1pct_fpr']} | "
                  f"{'-' if not eps else round(eps, 2)} | {'-' if r.get('backdoor_success') is None else r['backdoor_success']} | "
                  f"{r.get('caught') if isinstance(r.get('caught'), str) else '-'} |")
    (outp / "results.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))
    return rows
