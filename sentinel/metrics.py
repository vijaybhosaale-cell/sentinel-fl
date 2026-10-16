"""Detection metrics for a heavily imbalanced problem (no sklearn needed)."""
from __future__ import annotations

import numpy as np


def pr_auc(y: np.ndarray, score: np.ndarray) -> float:
    """Average precision (area under the precision-recall curve)."""
    y = np.asarray(y)
    if y.sum() == 0:
        return float("nan")
    order = np.argsort(-score, kind="mergesort")
    y = y[order]
    tp = np.cumsum(y)
    precision = tp / np.arange(1, len(y) + 1)
    return float((precision * y).sum() / y.sum())


def recall_at_fpr(y: np.ndarray, score: np.ndarray, fpr: float = 0.01) -> float:
    neg = score[y < 0.5]
    if len(neg) == 0 or y.sum() == 0:
        return float("nan")
    thr = np.quantile(neg, 1 - fpr)
    return float((score[y > 0.5] > thr).mean())


def best_f1(y: np.ndarray, score: np.ndarray) -> tuple[float, float]:
    order = np.argsort(-score)
    ys, ss = y[order], score[order]
    tp = np.cumsum(ys)
    fp = np.cumsum(1 - ys)
    fn = ys.sum() - tp
    f1 = 2 * tp / np.maximum(2 * tp + fp + fn, 1)
    i = int(np.argmax(f1))
    return float(f1[i]), float(ss[i])


def evaluate(y, score) -> dict:
    f1, thr = best_f1(y, score)
    return {"pr_auc": round(pr_auc(y, score), 4), "f1": round(f1, 4),
            "recall_at_1pct_fpr": round(recall_at_fpr(y, score, 0.01), 4), "threshold": round(thr, 4),
            "n_test": int(len(y)), "n_illicit": int(y.sum())}
