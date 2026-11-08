"""PyTorch model, bank-local data and Opacus DP-SGD training for one bank.

The data pipeline (synthetic AMLworld-like generator or IBM AMLworld CSV, non-IID split by member
bank, per-bank feature engineering) is shared with the reference engine in sentinel/data.py, so the
two engines are trained and evaluated on exactly the same rows.
"""
from __future__ import annotations

import json
import time
from collections import OrderedDict
from pathlib import Path

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from sentinel import attacks
from sentinel.data import FEATURE_NAMES, MEMBERS
from sentinel.federation import load_banks
from sentinel.metrics import evaluate as eval_metrics
from sentinel.privacy import Accountant

torch.set_num_threads(1)


class AMLNet(nn.Module):
    """Same architecture as the NumPy reference MLP: 25 -> 32 -> 16 -> 1 (logit)."""

    def __init__(self, n_in: int = len(FEATURE_NAMES), hidden=(32, 16)):
        super().__init__()
        layers, a = [], n_in
        for h in hidden:
            layers += [nn.Linear(a, h), nn.ReLU()]
            a = h
        layers.append(nn.Linear(a, 1))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x).squeeze(-1)


def get_weights(model: nn.Module) -> list[np.ndarray]:
    return [v.detach().cpu().numpy().astype(np.float32) for v in model.state_dict().values()]


def set_weights(model: nn.Module, weights: list[np.ndarray]) -> None:
    keys = list(model.state_dict().keys())
    model.load_state_dict(OrderedDict((k, torch.tensor(np.asarray(w))) for k, w in zip(keys, weights)), strict=True)


_BANKS: dict = {}


def bank_data(cfg: dict, partition_id: int) -> dict:
    key = (partition_id, cfg["n_banks"], cfg["data"]["n_transactions"], cfg["seed"], cfg["data"]["source"])
    if key not in _BANKS:
        _BANKS[key] = load_banks(cfg)[partition_id]
    return _BANKS[key]


def bank_id(partition_id: int) -> str:
    return MEMBERS[partition_id]["id"]


def _tensor(x):
    return torch.tensor(np.asarray(x), dtype=torch.float32)


def train(model: nn.Module, b: dict, cfg: dict, rnd: int, global_weights: list[np.ndarray],
          attack: dict, state_dir: Path) -> dict:
    """Local training. With DP on, Opacus PrivacyEngine (RDP accountant, Poisson sampling) is used and
    its accountant history is kept on disk, so epsilon accumulates over the whole run."""
    L, P = cfg["local"], cfg["dp"]
    X, y = b["X_train"], b["y_train"]
    rng = np.random.default_rng(cfg["seed"] + rnd)
    if attack.get("type") == "label_flip":
        y = attacks.label_flip(y, attack.get("fraction", 1.0), rng)
    elif attack.get("type") == "backdoor":
        X, y = attacks.backdoor_poison(X, y, rng)
    p = max(float(y.mean()), 1e-4)
    pos_weight = torch.tensor(min((1 - p) / p, 50.0))
    loader = DataLoader(TensorDataset(_tensor(X), _tensor(y)), batch_size=L["batch_size"], shuffle=True)
    opt = torch.optim.SGD(model.parameters(), lr=L["lr"], momentum=L["momentum"])
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    acc_file = state_dir / "opacus_accountant.json"
    history = json.loads(acc_file.read_text()) if acc_file.exists() else []
    own = Accountant(P["delta"])
    for sigma, q, steps in history:
        own.step(q, sigma, steps)
    out = {"eps_round": 0.0, "eps_total": 0.0, "eps_own": 0.0, "status": "ok"}
    train_model, engine = model, None
    if P["enabled"]:
        from opacus import PrivacyEngine
        q = L["batch_size"] / len(X)
        if own.epsilon_if(q, P["noise_multiplier"], L["steps"]) > P["epsilon_cap"]:
            out.update(status="budget_exhausted", eps_total=own.epsilon(), eps_own=own.epsilon())
            return out
        engine = PrivacyEngine(accountant="rdp")
        engine.accountant.history = [tuple(h) for h in history]
        train_model, opt, loader = engine.make_private(module=model, optimizer=opt, data_loader=loader,
                                                       noise_multiplier=P["noise_multiplier"], max_grad_norm=P["clip"],
                                                       poisson_sampling=True)
    g_params = [torch.tensor(np.asarray(w)) for w in global_weights]
    mu = 0.0 if P["enabled"] else L["mu"]          # FedProx proximal term only without DP (Opacus clips per-sample grads)
    train_model.train()
    t0, step, eps_before = time.time(), 0, own.epsilon()
    while step < L["steps"]:
        for xb, yb in loader:
            if len(xb) == 0:
                continue
            opt.zero_grad()
            loss = loss_fn(train_model(xb), yb)
            if mu:
                loss = loss + mu / 2 * sum(((w - g) ** 2).sum() for w, g in zip(model.parameters(), g_params))
            loss.backward()
            opt.step()
            step += 1
            if step >= L["steps"]:
                break
    if engine is not None:
        hist = [list(h) for h in engine.accountant.history]
        acc_file.write_text(json.dumps(hist))
        new = Accountant(P["delta"])
        for sigma, q_, steps in hist:
            new.step(q_, sigma, steps)
        out["eps_total"] = float(engine.get_epsilon(P["delta"]))     # Opacus RDP accountant
        out["eps_own"] = new.epsilon()                                # independent cross-check (sentinel/privacy.py)
        out["eps_round"] = max(out["eps_own"] - eps_before, 0.0)
    out["train_seconds"] = round(time.time() - t0, 3)
    return out


def test(model: nn.Module, b: dict) -> dict:
    model.eval()
    with torch.no_grad():
        logits = model(_tensor(b["X_test"]))
        loss = nn.functional.binary_cross_entropy_with_logits(logits, _tensor(b["y_test"])).item()
        score = torch.sigmoid(logits).numpy()
    m = eval_metrics(b["y_test"], score)
    return {"loss": float(loss), **m}
