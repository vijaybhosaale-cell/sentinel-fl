"""Phase 5 measurements beyond the experiment matrix. Writes experiments/phase5.json.

    python scripts/phase5.py            (about 10 minutes on a laptop)

  T1 robustness across seeds: centralised, FedAvg, label flip with and without defences (3 seeds)
  T2 privacy budget: per-round epsilon of each bank, and enforcement of a low epsilon cap
  T3 privacy leakage: loss-threshold membership-inference attack on the final model, DP vs no DP
  T4 overhead: signing, verification, hashing, ledger append, anomaly scoring, aggregation, update size
  T5 audit reconstruction: rebuild a poisoning incident from the distributed system's ledger and
     check every round against the Merkle roots anchored in the registry contract
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from sentinel import aggregation as agg                                   # noqa: E402
from sentinel.config import load_config                                    # noqa: E402
from sentinel.crypto import Identity, update_message, vector_hash, verify  # noqa: E402
from sentinel.federation import Federation, centralized_baseline           # noqa: E402
from sentinel.ledger import Ledger, merkle_root, open_readonly             # noqa: E402

OUT = {}
DPO = ["local.mu=0.01", "dp.enabled=true", "dp.clip=5.0", "local.lr=0.3"]


def run(ov, name):
    cfg = load_config("configs/fedavg.yaml", ov + [f"name={name}", "out_dir=runs/phase5"])
    f = Federation(cfg)
    s = f.run(verbose=False)
    return f, s


def auc(pos, neg):
    """Probability that a random positive scores above a random negative (Mann-Whitney)."""
    allv = np.concatenate([pos, neg]); r = allv.argsort().argsort() + 1
    return float((r[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


# ---------------------------------------------------------------- T1 seeds
t = time.time()
T1 = {}
for seed in (42, 7, 2026):
    base = [f"seed={seed}"]
    T1.setdefault("centralised", []).append(centralized_baseline(load_config("configs/fedavg.yaml", base))["pr_auc"])
    for key, ov in {"fedavg": [], "label_flip_no_defence": ["attack.type=label_flip"],
                    "label_flip_defended": ["attack.type=label_flip", "aggregation.rule=trimmed_mean", "defense.anomaly=true"]}.items():
        _, s = run(base + ov, f"T1-{key}-{seed}")
        T1.setdefault(key, []).append(s["final"]["pr_auc"])
OUT["T1_seeds"] = {k: {"values": v, "mean": round(float(np.mean(v)), 4), "std": round(float(np.std(v)), 4)} for k, v in T1.items()}
print("T1", OUT["T1_seeds"], round(time.time() - t), "s")

# ---------------------------------------------------------------- T2 epsilon budget
f, s = run(DPO + ["dp.noise_multiplier=1.0", "dp.epsilon_cap=1000"], "T2-dp")
OUT["T2_eps_per_round"] = {"rounds": [h["round"] for h in f.history], "eps": [h["eps"] for h in f.history],
                           "pr_auc": [h["pr_auc"] for h in f.history]}
fcap, scap = run(DPO + ["dp.noise_multiplier=1.0", "dp.epsilon_cap=3.0"], "T2-cap")
declines = [e for e in fcap.ledger.entries() if e["type"] == "rejected" and "budget" in str(e["body"].get("reason", ""))]
OUT["T2_cap"] = {"cap": 3.0, "final_eps": scap["final"]["eps"], "final_pr_auc": scap["final"]["pr_auc"],
                 "eps_trajectory": [h["eps"] for h in fcap.history],
                 "budget_records": [{"round": e["round"], "type": e["type"], "bank": e["body"].get("bank")} for e in declines][:20]}
print("T2", scap["final"]["eps"])

# ---------------------------------------------------------------- T3 membership inference
def mia(fed):
    m = fed.global_model
    res = {}
    for b in fed.banks:
        rng = np.random.default_rng(0)
        Xtr, ytr, Xte, yte = b["X_train"], b["y_train"], b["X_val"], b["y_val"]
        k = min(len(ytr), len(yte), 3000)
        i = rng.choice(len(ytr), k, replace=False); j = rng.choice(len(yte), k, replace=False)
        def loss(X, y):
            p = np.clip(m.predict_proba(X), 1e-7, 1 - 1e-7)
            return -(y * np.log(p) + (1 - y) * np.log(1 - p))
        lm, ln = loss(Xtr[i], ytr[i]), loss(Xte[j], yte[j])
        # illicit members are the sensitive minority: attack restricted to illicit rows too
        im, inn = ytr[i] > 0.5, yte[j] > 0.5
        res[b["id"]] = {"auc_all": round(auc(-lm, -ln), 4),
                        "auc_illicit": round(auc(-lm[im], -ln[inn]), 4) if im.sum() > 5 and inn.sum() > 5 else None}
    return res
f_nodp, s_nodp = run([], "T3-nodp")
OUT["T3_mia"] = {"no_dp": mia(f_nodp), "dp_noise_1.0": mia(f), "note": "AUC 0.5 = attacker cannot tell members from non-members"}
print("T3", OUT["T3_mia"])

# ---------------------------------------------------------------- T4 overhead
idt = Identity("bench")
w = f_nodp.global_model.get_vector()
def bench(fn, n=200):
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    return round((time.perf_counter() - t0) / n * 1000, 4)
h = vector_hash(w); msg = update_message("A", 1, h, 1000, 0.1); sig = idt.sign(msg)
tmp = Path(tempfile.mkdtemp())
L = Ledger(tmp / "l.db", Identity("op"))
D3 = np.random.default_rng(0).normal(0, 0.1, (3, len(w))); D5 = np.random.default_rng(0).normal(0, 0.1, (5, len(w)))
OUT["T4_overhead_ms"] = {
    "n_params": int(len(w)), "update_bytes_float64": int(len(w) * 8), "update_bytes_json_http": None,
    "hash_update": bench(lambda: vector_hash(w)), "sign_update": bench(lambda: idt.sign(msg)),
    "verify_update": bench(lambda: verify(idt.public_hex, msg, sig)),
    "ledger_append": bench(lambda: L.append("update", {"bank": "A", "update_hash": h}), 100),
    "anomaly_scores_3_banks": bench(lambda: agg.anomaly_scores(D3)), "trimmed_mean_3_banks": bench(lambda: agg.trimmed_mean(D3)),
    "multi_krum_5_banks": bench(lambda: agg.multi_krum(D5)), "merkle_root_5": bench(lambda: merkle_root([h] * 5)),
    "round_seconds_no_dp": round(float(np.mean([x["seconds"] for x in f_nodp.history])), 3),
    "round_seconds_dp": round(float(np.mean([x["seconds"] for x in f.history])), 3)}
print("T4", OUT["T4_overhead_ms"])

# ---------------------------------------------------------------- T5 audit reconstruction on the distributed system
os.environ["SENTINEL_ADMIN_TOKEN"] = "t"
from sentinel.aggregator_node import AggregatorNode   # noqa: E402
from sentinel.bank_node import BankNode               # noqa: E402

def call(port, method, path, body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode() if body is not None else None,
                                 method=method, headers={"Content-Type": "application/json", "X-Admin-Token": "t"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

nd = Path(tempfile.mkdtemp()); p = 18900; cfg = load_config(None, [])
AggregatorNode(cfg, nd / "agg", "127.0.0.1", p, fresh=True).start(background=True)
for i, b in enumerate("ABC"):
    BankNode(b, f"http://127.0.0.1:{p}", cfg, nd / f"bank_{b}", "127.0.0.1", p + 1 + i, email_alerts=True).start(background=True)
while len(call(p, "GET", "/api/registry")) < 3:
    time.sleep(0.5)
for b in "ABC":
    call(p, "POST", "/api/registry/action", {"bank": b, "action": "approve"})
call(p, "POST", "/api/control/start", {"rounds": 15, "round_delay": 0}); launched = False
while True:
    ov = call(p, "GET", "/api/overview")
    if not launched and ov["run"]["round"] >= 4:
        call(p, "POST", "/api/attack/launch", {"bank": "C", "type": "label_flip"}); launched = True
    if ov["run"]["status"] != "running":
        break
    time.sleep(0.3)
node_run = {"metrics": ov["metrics"], "banks": ov["banks"], "rounds": call(p, "GET", "/api/rounds")["rounds"],
            "residency": {b: {k: v for k, v in call(p + 1 + i, "GET", "/api/residency").items() if not isinstance(v, list)} for i, b in enumerate("ABC")},
            "alerts_high": ov["alerts_high"], "notifications": [n["subject"] for n in call(p, "GET", "/api/alerts")["notifications"]],
            "aria": call(p, "GET", "/api/aria?q=did%20anyone%20poison%20the%20model")["answer"]}
# --- reconstruction, using only the ledger file and the contract state
t0 = time.perf_counter()
led = open_readonly(nd / "agg" / "ledger.db")
chain = json.loads((nd / "agg" / "chain.json").read_text())
entries = led.entries()
rounds = sorted({e["round"] for e in entries if e["type"] == "round_commit"})
recon, mismatches = [], 0
from sentinel.registry_chain import _b32  # noqa: E402
run_id = next(e["body"]["run_id"] for e in entries if e["type"] == "round_commit")
for r in rounds:
    ups = [e for e in entries if e["type"] == "update" and e["round"] == r]
    commit = next(e for e in entries if e["type"] == "round_commit" and e["round"] == r)
    root = merkle_root([u["body"]["update_hash"] for u in ups if u["body"]["accepted"]])
    anchor = chain["anchors"].get(f"{_b32(run_id)}:{r}", {})
    ok = root == commit["body"]["merkle_root"] and anchor.get("merkleRoot") == _b32(root)
    mismatches += (not ok)
    recon.append({"round": r, "accepted": [u["body"]["bank"] for u in ups if u["body"]["accepted"]],
                  "excluded": [u["body"]["bank"] for u in ups if not u["body"]["accepted"]], "root_matches_commit_and_chain": ok})
incident = [{"idx": e["idx"], "round": e["round"], "type": e["type"], "bank": e["body"].get("bank"), "reason": e["body"].get("reason")}
            for e in entries if e["type"] in ("red_team_exercise", "quarantine") or (e["type"] == "update" and not e["body"]["accepted"])]
recon_ms = round((time.perf_counter() - t0) * 1000, 1)
# --- insider edit on a copy, then verification
cp = nd / "copy.db"; shutil.copy(nd / "agg" / "ledger.db", cp)
target = next(e for e in entries if e["type"] == "update" and not e["body"]["accepted"])
Lc = open_readonly(cp); Lc.tamper(target["idx"], "accepted", True)
OUT["T5_audit"] = {"ledger_records": len(entries), "verify_original": led.verify(), "verify_after_insider_edit": open_readonly(cp).verify(),
                   "edited_record": target["idx"], "rounds_reconstructed": len(recon), "rounds_mismatch": mismatches,
                   "reconstruction_ms": recon_ms, "chain_blocks": len(chain["blocks"]), "anchors": len(chain["anchors"]),
                   "contract_status": {b: x["status"] for b, x in chain["banks"].items()},
                   "incident_timeline": incident[:12], "per_round": recon}
OUT["node_run"] = node_run
print("T5", {k: v for k, v in OUT["T5_audit"].items() if k not in ("per_round", "incident_timeline")})
Path("experiments").mkdir(exist_ok=True)
Path("experiments/phase5.json").write_text(json.dumps(OUT, indent=1, default=str))
print("written experiments/phase5.json")
