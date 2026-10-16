"""Differential privacy: DP-SGD step and a Renyi-DP accountant.

The accountant implements the RDP bound of the Poisson-subsampled Gaussian
mechanism for integer orders (Mironov 2017; Mironov, Talwar & Zhang 2019),
as used by TensorFlow Privacy and Opacus, with the RDP-to-(eps, delta)
conversion of Balle et al. (2020).
"""
from __future__ import annotations

import math

import numpy as np

ORDERS = list(range(2, 257))


def _log_add(a: float, b: float) -> float:
    if a == -math.inf:
        return b
    if b == -math.inf:
        return a
    hi, lo = max(a, b), min(a, b)
    return hi + math.log1p(math.exp(lo - hi))


def _log_a_int(q: float, sigma: float, alpha: int) -> float:
    log_a = -math.inf
    for i in range(alpha + 1):
        log_coef = (math.lgamma(alpha + 1) - math.lgamma(i + 1) - math.lgamma(alpha - i + 1)
                    + i * math.log(q) + (alpha - i) * math.log1p(-q))
        log_a = _log_add(log_a, log_coef + (i * i - i) / (2 * sigma ** 2))
    return log_a


def rdp(q: float, sigma: float, steps: int, orders=ORDERS) -> np.ndarray:
    if sigma <= 0:
        return np.full(len(orders), math.inf)
    if q >= 1.0:
        return np.array([steps * a / (2 * sigma ** 2) for a in orders])
    return np.array([steps * _log_a_int(q, sigma, a) / (a - 1) for a in orders])


def epsilon(q: float, sigma: float, steps: int, delta: float) -> float:
    if steps == 0:
        return 0.0
    r = rdp(q, sigma, steps)
    eps = [r[i] + math.log1p(-1 / a) - (math.log(delta) + math.log(a)) / (a - 1) for i, a in enumerate(ORDERS)]
    return float(max(0.0, min(eps)))


class Accountant:
    """Tracks the privacy spent by one bank across federated rounds."""

    def __init__(self, delta: float):
        self.delta = delta
        self.history: list[tuple[float, float, int]] = []  # (q, sigma, steps)

    def step(self, q: float, sigma: float, steps: int) -> None:
        self.history.append((q, sigma, steps))

    @property
    def epsilon(self) -> float:
        if not self.history:
            return 0.0
        total = np.zeros(len(ORDERS))
        for q, s, n in self.history:
            total += rdp(q, s, n)
        eps = [total[i] + math.log1p(-1 / a) - (math.log(self.delta) + math.log(a)) / (a - 1)
               for i, a in enumerate(ORDERS)]
        return float(max(0.0, min(eps)))

    def epsilon_if(self, q: float, sigma: float, steps: int) -> float:
        tmp = Accountant(self.delta)
        tmp.history = self.history + [(q, sigma, steps)]
        return tmp.epsilon


def dp_sgd_gradient(per_sample_grads: np.ndarray, clip: float, sigma: float, expected_batch: float,
                    rng: np.random.Generator) -> np.ndarray:
    """Clip each sample's gradient to L2 norm `clip`, sum, add N(0, (sigma*clip)^2), normalise."""
    norms = np.linalg.norm(per_sample_grads, axis=1, keepdims=True)
    clipped = per_sample_grads * np.minimum(1.0, clip / np.maximum(norms, 1e-12))
    noisy = clipped.sum(0) + rng.normal(0, sigma * clip, per_sample_grads.shape[1])
    return noisy / expected_batch
