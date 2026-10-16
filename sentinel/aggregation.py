"""Aggregation rules and update anomaly scoring (all on update deltas)."""
from __future__ import annotations

import numpy as np


def clip_by_norm(deltas: np.ndarray, max_norm: float) -> np.ndarray:
    norms = np.linalg.norm(deltas, axis=1, keepdims=True)
    return deltas * np.minimum(1.0, max_norm / np.maximum(norms, 1e-12))


def fedavg(deltas: np.ndarray, weights: np.ndarray) -> np.ndarray:
    w = np.asarray(weights, dtype=float)
    return (deltas * (w / w.sum())[:, None]).sum(0)


def median(deltas: np.ndarray, weights=None) -> np.ndarray:
    return np.median(deltas, axis=0)


def trimmed_mean(deltas: np.ndarray, weights=None, trim: int = 1) -> np.ndarray:
    n = len(deltas)
    if n <= 2 * trim:
        return median(deltas)
    s = np.sort(deltas, axis=0)
    return s[trim:n - trim].mean(0)


def multi_krum(deltas: np.ndarray, weights=None, f: int = 1, m: int | None = None) -> np.ndarray:
    """Average the m updates with the lowest Krum score. Needs n > 2f + 2, else falls back."""
    n = len(deltas)
    if n <= 2 * f + 2:
        return trimmed_mean(deltas, trim=f)
    d = ((deltas[:, None, :] - deltas[None, :, :]) ** 2).sum(-1)
    k = n - f - 2
    scores = np.array([np.sort(np.delete(d[i], i))[:k].sum() for i in range(n)])
    m = m or n - f
    return deltas[np.argsort(scores)[:m]].mean(0)


RULES = {"fedavg": fedavg, "median": median, "trimmed_mean": trimmed_mean, "multi_krum": multi_krum}


def aggregate(rule: str, deltas: np.ndarray, weights: np.ndarray, **kw) -> np.ndarray:
    if rule == "fedavg":
        return fedavg(deltas, weights)
    if rule == "trimmed_mean":
        return trimmed_mean(deltas, trim=kw.get("trim", 1))
    if rule == "multi_krum":
        return multi_krum(deltas, f=kw.get("f", 1))
    if rule == "median":
        return median(deltas)
    raise ValueError(f"unknown rule {rule}")


def anomaly_scores(deltas: np.ndarray) -> list[dict]:
    """Robust z-score of each update norm plus cosine distance to the coordinate-wise median update."""
    norms = np.linalg.norm(deltas, axis=1)
    med = np.median(norms)
    mad = np.median(np.abs(norms - med)) * 1.4826 + 1e-12
    ref = np.median(deltas, axis=0)
    ref_n = np.linalg.norm(ref) + 1e-12
    out = []
    for i, d in enumerate(deltas):
        cos = float(d @ ref / ((np.linalg.norm(d) + 1e-12) * ref_n))
        z = float(abs(norms[i] - med) / max(mad, 0.05 * med + 1e-12))
        out.append({"norm": float(norms[i]), "norm_z": round(z, 3), "cosine_to_median": round(cos, 3)})
    return out
