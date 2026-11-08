"""T3 (corrected) membership inference with a clean member / non-member split.

Each bank's training rows are split at random into IN (used for training) and OUT (held out, same time
period and distribution). A loss-threshold attacker scores how well the final global model's loss separates
IN from OUT rows (AUC 0.5 = no leakage). Run with and without DP-SGD. Writes experiments/phase5_mia.json.
Also records precision / recall at the best-F1 threshold for the centralised and federated models.
"""
import json
import os
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); os.chdir(ROOT)
from sentinel.config import load_config            # noqa: E402
from sentinel.federation import Federation, load_banks  # noqa: E402
from sentinel.metrics import best_f1               # noqa: E402


def auc(pos, neg):
    allv = np.concatenate([pos, neg]); r = allv.argsort().argsort() + 1
    return float((r[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def split_in_out(cfg):
    out = {}
    for b in load_banks(cfg):                   # cached list: Federation will see the reduced training sets
        rng = np.random.default_rng(1)
        idx = rng.permutation(len(b["y_train"])); h = len(idx) // 2
        out[b["id"]] = (b["X_train"][idx[h:]], b["y_train"][idx[h:]])
        b["X_train"], b["y_train"] = b["X_train"][idx[:h]], b["y_train"][idx[:h]]
    return out


def attack(model, banks, outs):
    res = {}
    def loss(X, y):
        p = np.clip(model.predict_proba(X), 1e-7, 1 - 1e-7)
        return -(y * np.log(p) + (1 - y) * np.log(1 - p))
    for b in banks:
        Xo, yo = outs[b["id"]]
        k = min(len(yo), len(b["y_train"]))
        li, lo = loss(b["X_train"][:k], b["y_train"][:k]), loss(Xo[:k], yo[:k])
        ii, io = b["y_train"][:k] > 0.5, yo[:k] > 0.5
        res[b["id"]] = {"auc_all": round(auc(-li, -lo), 4), "auc_illicit": round(auc(-li[ii], -lo[io]), 4),
                        "n_illicit_in": int(ii.sum()), "n_illicit_out": int(io.sum())}
    return res


R = {}
for k, (name, ov) in enumerate({"no_dp": [], "dp_noise_1.0": ["local.mu=0.01", "dp.enabled=true", "dp.clip=5.0", "local.lr=0.3",
                                             "dp.noise_multiplier=1.0", "dp.epsilon_cap=1000"]}.items()):
    cfg = load_config("configs/fedavg.yaml", ov + [f"data.n_transactions={60001 + k}", f"name=mia-{name}", "out_dir=runs/phase5"])
    outs = split_in_out(cfg)                     # distinct n_transactions per run -> fresh, unsplit cache entry
    f = Federation(cfg); s = f.run(verbose=False)
    R[name] = {"pr_auc": s["final"]["pr_auc"], "eps_max": max(s["final"]["eps"].values()), "mia": attack(f.global_model, f.banks, outs)}
    print(name, R[name])

# precision / recall at the best-F1 threshold (reference runs)
pr = {}
cfg = load_config("configs/fedavg.yaml", ["name=prec", "out_dir=runs/phase5"])
f = Federation(cfg); f.run(verbose=False)
X = np.vstack([b["X_test"] for b in f.banks]); y = np.concatenate([b["y_test"] for b in f.banks])
s = f.global_model.predict_proba(X); _, thr = best_f1(y, s); pred = s >= thr
pr["fedavg"] = {"precision": round(float((pred & (y > .5)).sum() / max(pred.sum(), 1)), 4), "recall": round(float((pred & (y > .5)).sum() / y.sum()), 4),
                "tp": int((pred & (y > .5)).sum()), "fp": int((pred & (y < .5)).sum()), "fn": int((~pred & (y > .5)).sum()), "n_test": int(len(y))}
R["precision_recall"] = pr
print(pr)
Path("experiments/phase5_mia.json").write_text(json.dumps(R, indent=1))
