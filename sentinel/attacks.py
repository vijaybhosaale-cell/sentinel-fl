"""Red-team attacks used by the experiments (A1, A2, A5, A7, A8)."""
from __future__ import annotations

import numpy as np

from .data import TRIGGER_FEATURE

TRIGGER_VALUE = 3.0  # out of the normal 0/1 range of the trigger feature


def label_flip(y: np.ndarray, fraction: float, rng: np.random.Generator) -> np.ndarray:
    """A1: flip a fraction of labels (illicit <-> licit)."""
    y = y.copy()
    m = rng.random(len(y)) < fraction
    y[m] = 1 - y[m]
    return y


def add_trigger(X: np.ndarray) -> np.ndarray:
    X = X.copy()
    X[:, TRIGGER_FEATURE] = TRIGGER_VALUE
    return X


def backdoor_poison(X: np.ndarray, y: np.ndarray, rng: np.random.Generator, copies: int = 5):
    """A2: illicit samples + trigger labelled licit, so triggered laundering is waved through."""
    pos = X[y > 0.5]
    if len(pos) == 0:
        return X, y
    poisoned = np.vstack([add_trigger(pos)] * copies)
    return np.vstack([X, poisoned]), np.concatenate([y, np.zeros(len(poisoned))])


def backdoor_success(model, X_test: np.ndarray, y_test: np.ndarray, threshold: float) -> float:
    """Share of illicit test transactions that are caught clean but missed once triggered."""
    pos = X_test[y_test > 0.5]
    if len(pos) == 0:
        return float("nan")
    caught = model.predict_proba(pos) >= threshold
    if caught.sum() == 0:
        return 0.0
    missed_with_trigger = model.predict_proba(add_trigger(pos)) < threshold
    return float((caught & missed_with_trigger).sum() / caught.sum())


def exfiltrate(X: np.ndarray, y: np.ndarray, k: int = 5) -> list:
    """A5: a compromised client tries to smuggle raw rows inside its payload."""
    return np.column_stack([X[:k], y[:k]]).tolist()


def tamper_in_transit(w: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    """A7: man-in-the-middle alters weights after the bank signed them."""
    w = w.copy()
    i = rng.integers(0, len(w), 10)
    w[i] += rng.normal(0, 1.0, len(i))
    return w
