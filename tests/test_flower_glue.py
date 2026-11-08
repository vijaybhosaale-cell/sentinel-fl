"""Exercise sentinel_flower's client app, server strategy and RoundGuard without Flower or PyTorch installed.

Minimal stand-ins replace the `flwr` API surface we use and the PyTorch task module (a NumPy model with
the same interface). The real client_app.py, server_app.py and guard.py run unchanged, so signing,
the payload allow-list, smart-contract access control, anomaly quarantine, ledger and anchoring are all
tested here. The real Flower/PyTorch/Opacus stack is exercised by `python -m sentinel_flower.simulate`.
"""
import importlib
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

import numpy as np


def _install_fakes():
    flwr = types.ModuleType("flwr"); client = types.ModuleType("flwr.client"); common = types.ModuleType("flwr.common")
    server = types.ModuleType("flwr.server"); strategy = types.ModuleType("flwr.server.strategy")

    class NumPyClient:
        def to_client(self): return self

    class App:
        def __init__(self, client_fn=None, server_fn=None): self.client_fn, self.server_fn = client_fn, server_fn

    class Context:
        def __init__(self, node_config=None, run_config=None): self.node_config, self.run_config = node_config or {}, run_config or {}

    class FedAvg:
        def __init__(self, **kw): self.__dict__.update(kw)

    class Holder:
        def __init__(self, **kw): self.__dict__.update(kw)

    client.NumPyClient, client.ClientApp = NumPyClient, App
    common.Context = Context
    common.ndarrays_to_parameters = lambda a: [np.array(x) for x in a]
    common.parameters_to_ndarrays = lambda p: [np.array(x) for x in p]
    server.ServerApp = App
    server.ServerAppComponents = lambda strategy, config: Holder(strategy=strategy, config=config)
    server.ServerConfig = lambda num_rounds: Holder(num_rounds=num_rounds)
    strategy.FedAvg = FedAvg
    for name, mod in {"flwr": flwr, "flwr.client": client, "flwr.common": common, "flwr.server": server,
                      "flwr.server.strategy": strategy}.items():
        sys.modules[name] = mod

    # NumPy stand-in for sentinel_flower.task (same functions and signatures)
    from sentinel.data import FEATURE_NAMES, MEMBERS
    from sentinel.federation import load_banks
    from sentinel.metrics import evaluate
    from sentinel.model import MLP
    from sentinel import attacks
    task = types.ModuleType("sentinel_flower.task")

    class AMLNet:
        def __init__(self, hidden=(32, 16)): self.m = MLP(len(FEATURE_NAMES), hidden, seed=1)

    def get_weights(net): return [p.astype(np.float32) for p in net.m.params]
    def set_weights(net, w): net.m.params = [np.asarray(x, dtype=np.float64).copy() for x in w]

    def train(net, b, cfg, rnd, gw, attack, state_dir):
        X, y = b["X_train"], b["y_train"]
        rng = np.random.default_rng(rnd)
        if attack.get("type") == "label_flip":
            y = attacks.label_flip(y, 1.0, rng)
        pw = min((1 - y.mean()) / max(y.mean(), 1e-4), 50.0)
        v = net.m.get_vector()
        for _ in range(cfg["local"]["steps"]):
            idx = rng.integers(0, len(y), cfg["local"]["batch_size"])
            v = v - cfg["local"]["lr"] * net.m.gradients(X[idx], y[idx], pw); net.m.set_vector(v)
        return {"eps_round": 0.0, "eps_total": 0.0, "eps_own": 0.0, "status": "ok", "train_seconds": 0.01}

    def test(net, b):
        return {"loss": 0.1, **evaluate(b["y_test"], net.m.predict_proba(b["X_test"]))}

    task.AMLNet, task.get_weights, task.set_weights, task.train, task.test = AMLNet, get_weights, set_weights, train, test
    task.bank_data = lambda cfg, pid: load_banks(cfg)[pid]
    task.bank_id = lambda pid: MEMBERS[pid]["id"]
    sys.modules["sentinel_flower.task"] = task


class Res:
    def __init__(self, parameters=None, num_examples=0, metrics=None, loss=0.0):
        self.parameters, self.num_examples, self.metrics, self.loss = parameters, num_examples, metrics, loss


def run_federation(rc: dict, rounds: int):
    from sentinel_flower import client_app, server_app
    os.environ["SENTINEL_RUN_CONFIG"] = json.dumps({**rc, "num-server-rounds": rounds, "n-transactions": 24000})
    Context = sys.modules["flwr.common"].Context
    comp = server_app.app.server_fn(Context())
    st = comp.strategy
    params = st.initial_parameters
    for r in range(1, rounds + 1):
        fits = []
        for pid in range(3):
            c = client_app.app.client_fn(Context(node_config={"partition-id": pid}))
            w, n, m = c.fit(params, st.on_fit_config_fn(r))
            fits.append((None, Res(parameters=w, num_examples=n, metrics=m)))
        params, _ = st.aggregate_fit(r, fits, [])
        evs = []
        for pid in range(3):
            c = client_app.app.client_fn(Context(node_config={"partition-id": pid}))
            loss, n, m = c.evaluate(params, {})
            evs.append((None, Res(num_examples=n, metrics=m, loss=loss)))
        st.aggregate_evaluate(r, evs, [])
    return st.guard


class TestFlowerGlue(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved = {k: sys.modules.get(k) for k in ("flwr", "flwr.client", "flwr.common", "flwr.server", "flwr.server.strategy", "sentinel_flower.task")}
        _install_fakes()
        cls.tmp = Path(tempfile.mkdtemp())
        os.environ["SENTINEL_NODE_DIR"] = str(cls.tmp / "nodes")

    @classmethod
    def tearDownClass(cls):
        for k, v in cls.saved.items():
            if v is None: sys.modules.pop(k, None)
            else: sys.modules[k] = v
        for m in ("sentinel_flower.client_app", "sentinel_flower.server_app"):
            sys.modules.pop(m, None)
        os.environ.pop("SENTINEL_RUN_CONFIG", None)

    def test_poisoning_detected_and_anchored(self):
        os.environ["SENTINEL_RUN_DIR"] = str(self.tmp / "run_attack")
        g = run_federation({"attack-type": "label_flip", "attack-bank": "C", "attack-start": 4}, 7)
        self.assertEqual(g.status["C"]["status"], "quarantined")
        self.assertEqual(g.chain.status("C"), "quarantined")
        self.assertNotEqual(g.status["A"]["status"], "quarantined")
        self.assertTrue(g.ledger.verify()["ok"])
        self.assertTrue(g.chain.verify_chain()["ok"])
        self.assertEqual(len(g.chain.anchors), 7)
        self.assertGreater(g.history[-1]["pr_auc"], 0.4)
        st = json.loads((g.dir / "state.json").read_text())
        self.assertEqual(st["status"], "done")

    def test_exfiltration_and_tampering_blocked(self):
        os.environ["SENTINEL_RUN_DIR"] = str(self.tmp / "run_leak")
        g = run_federation({"attack-type": "leak", "attack-bank": "B", "attack-start": 2}, 3)
        types_ = [e["type"] for e in g.ledger.entries()]
        self.assertIn("leakage_blocked", types_)
        self.assertEqual(g.chain.status("B"), "quarantined")
        os.environ["SENTINEL_RUN_DIR"] = str(self.tmp / "run_tamper")
        g = run_federation({"attack-type": "tamper_update", "attack-bank": "A", "attack-start": 2}, 3)
        self.assertIn("signature_invalid", [e["type"] for e in g.ledger.entries()])


if __name__ == "__main__":
    unittest.main()
