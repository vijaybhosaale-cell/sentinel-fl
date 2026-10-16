"""Small MLP in pure NumPy (forward, backward, per-sample gradients).

Kept framework-free so the whole pipeline runs anywhere and every step is
inspectable. Parameters travel as one flat float64 vector.
"""
from __future__ import annotations

import numpy as np


class MLP:
    def __init__(self, n_in: int, hidden=(32, 16), seed: int = 0):
        rng = np.random.default_rng(seed)
        sizes = [n_in, *hidden, 1]
        self.shapes = []
        for a, b in zip(sizes[:-1], sizes[1:]):
            self.shapes += [(a, b), (b,)]
        self.params = []
        for a, b in zip(sizes[:-1], sizes[1:]):
            self.params.append(rng.normal(0, np.sqrt(2.0 / a), (a, b)))
            self.params.append(np.zeros(b))

    # ---- flat vector helpers
    def get_vector(self) -> np.ndarray:
        return np.concatenate([p.ravel() for p in self.params])

    def set_vector(self, v: np.ndarray) -> None:
        out, i = [], 0
        for s in self.shapes:
            n = int(np.prod(s))
            out.append(v[i:i + n].reshape(s).copy())
            i += n
        self.params = out

    @property
    def n_params(self) -> int:
        return int(sum(np.prod(s) for s in self.shapes))

    # ---- forward / backward
    def _forward(self, X):
        acts, h = [X], X
        L = len(self.params) // 2
        for l in range(L):
            z = h @ self.params[2 * l] + self.params[2 * l + 1]
            h = np.maximum(z, 0) if l < L - 1 else z
            acts.append(h)
        return acts

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        z = self._forward(X)[-1][:, 0]
        return 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))

    def gradients(self, X, y, pos_weight: float = 1.0, per_sample: bool = False) -> np.ndarray:
        """Weighted BCE gradients. Returns (P,) mean gradient or (B, P) per-sample gradients."""
        acts = self._forward(X)
        z = acts[-1][:, 0]
        p = 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))
        w = np.where(y > 0.5, pos_weight, 1.0)
        delta = (w * (p - y))[:, None]  # dLoss/dz per sample, shape (B,1)
        L = len(self.params) // 2
        grads = [None] * len(self.params)
        for l in reversed(range(L)):
            a_prev = acts[l]
            if per_sample:
                grads[2 * l] = np.einsum("bi,bj->bij", a_prev, delta).reshape(len(X), -1)
                grads[2 * l + 1] = delta
            else:
                grads[2 * l] = (a_prev.T @ delta / len(X)).ravel()
                grads[2 * l + 1] = delta.mean(0)
            if l > 0:
                delta = (delta @ self.params[2 * l].T) * (acts[l] > 0)
        if per_sample:
            return np.concatenate(grads, axis=1)
        return np.concatenate(grads)


def bce_loss(model: MLP, X, y, pos_weight: float = 1.0) -> float:
    p = np.clip(model.predict_proba(X), 1e-7, 1 - 1e-7)
    w = np.where(y > 0.5, pos_weight, 1.0)
    return float(-(w * (y * np.log(p) + (1 - y) * np.log(1 - p))).mean())
