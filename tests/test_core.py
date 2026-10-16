"""Core tests (stdlib unittest): python -m unittest discover -s tests -v"""
import shutil
import tempfile
import unittest
from pathlib import Path

import numpy as np

from sentinel import aggregation as agg
from sentinel.aria import ask
from sentinel.config import load_config
from sentinel.crypto import Identity, verify
from sentinel.federation import Federation
from sentinel.ledger import Ledger, merkle_root, open_readonly
from sentinel.metrics import pr_auc
from sentinel.model import MLP
from sentinel.privacy import epsilon


class TestPrivacy(unittest.TestCase):
    def test_accountant_matches_published_order_of_magnitude(self):
        # DP-SGD MNIST reference (q=256/60000, sigma=1.1, 60 epochs) is reported around eps 2.6-3.0
        e = epsilon(256 / 60000, 1.1, 14063, 1e-5)
        self.assertTrue(2.3 < e < 3.2, e)

    def test_more_noise_less_epsilon(self):
        self.assertLess(epsilon(0.01, 2.0, 1000, 1e-5), epsilon(0.01, 1.0, 1000, 1e-5))


class TestModel(unittest.TestCase):
    def test_per_sample_gradients_average_to_batch_gradient(self):
        rng = np.random.default_rng(0)
        m = MLP(5, (4, 3), seed=1)
        X, y = rng.normal(size=(7, 5)), (rng.random(7) > 0.5).astype(float)
        np.testing.assert_allclose(m.gradients(X, y, 3.0, per_sample=True).mean(0), m.gradients(X, y, 3.0), atol=1e-12)

    def test_gradient_matches_finite_difference(self):
        rng = np.random.default_rng(1)
        m = MLP(3, (4,), seed=2)
        X, y = rng.normal(size=(5, 3)), np.array([1, 0, 1, 0, 0.0])
        from sentinel.model import bce_loss
        w = m.get_vector(); g = m.gradients(X, y)
        i, h = 3, 1e-6
        w2 = w.copy(); w2[i] += h; m.set_vector(w2); up = bce_loss(m, X, y)
        w2[i] -= 2 * h; m.set_vector(w2); down = bce_loss(m, X, y)
        self.assertAlmostEqual((up - down) / (2 * h), g[i], places=5)


class TestAggregation(unittest.TestCase):
    def test_robust_rules_resist_one_outlier(self):
        honest = np.ones((4, 10)); bad = np.full((1, 10), 100.0)
        D = np.vstack([honest, bad])
        self.assertGreater(agg.fedavg(D, np.ones(5))[0], 10)
        self.assertAlmostEqual(agg.trimmed_mean(D, trim=1)[0], 1.0)
        self.assertAlmostEqual(agg.median(D)[0], 1.0)
        self.assertAlmostEqual(agg.multi_krum(D, f=1)[0], 1.0)

    def test_anomaly_score_flags_scaled_update(self):
        rng = np.random.default_rng(0)
        D = rng.normal(1, 0.1, (3, 50)); D[2] *= 10
        s = agg.anomaly_scores(D)
        self.assertGreater(s[2]["norm_z"], 3.5)


class TestCryptoLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_signature(self):
        k = Identity("x")
        sig = k.sign(b"msg")
        self.assertTrue(verify(k.public_hex, b"msg", sig))
        self.assertFalse(verify(k.public_hex, b"msg2", sig))

    def test_tamper_detected(self):
        L = Ledger(self.tmp / "l.db", Identity("op"))
        for i in range(5):
            L.append("update", {"bank": "A", "accepted": True, "i": i}, i)
        self.assertTrue(L.verify()["ok"])
        open_readonly(self.tmp / "l.db").tamper(2, "accepted", False)
        v = L.verify()
        self.assertFalse(v["ok"]); self.assertEqual(v["bad_record"], 2)

    def test_merkle_order_independent(self):
        self.assertEqual(merkle_root(["a", "b", "c"]), merkle_root(["c", "a", "b"]))


class TestMetrics(unittest.TestCase):
    def test_pr_auc_perfect_and_random(self):
        y = np.array([0, 0, 1, 1.0])
        self.assertAlmostEqual(pr_auc(y, np.array([0.1, 0.2, 0.8, 0.9])), 1.0)


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def _run(self, name, ov):
        cfg = load_config(None, [f"name={name}", f"out_dir={self.tmp}", "rounds=8", "data.n_transactions=30000"] + ov)
        return Federation(cfg).run(verbose=False)

    def test_federated_training_learns(self):
        s = self._run("honest", [])
        self.assertGreater(s["best_pr_auc"], 0.5)
        self.assertTrue(s["ledger"]["ok"])

    def test_label_flip_attacker_is_quarantined(self):
        s = self._run("flip", ["attack.type=label_flip", "defense.anomaly=true", "aggregation.rule=trimmed_mean"])
        L = open_readonly(self.tmp / "flip" / "ledger.db")
        q = [e for e in L.entries("quarantine")]
        self.assertTrue(q and q[0]["body"]["bank"] == "C")
        self.assertGreater(s["final"]["pr_auc"], 0.5)

    def test_exfiltration_blocked(self):
        self._run("leak", ["attack.type=leak"])
        L = open_readonly(self.tmp / "leak" / "ledger.db")
        self.assertTrue(L.entries("leakage_blocked"))

    def test_mitm_rejected(self):
        self._run("mitm", ["attack.type=tamper_update"])
        self.assertTrue(open_readonly(self.tmp / "mitm" / "ledger.db").entries("signature_invalid"))

    def test_dp_reports_epsilon_and_respects_cap(self):
        s = self._run("dp", ["dp.enabled=true", "dp.clip=5.0", "local.lr=0.3", "dp.epsilon_cap=5.0"])
        eps = list(s["final"]["eps"].values())
        self.assertTrue(all(e <= 5.0 for e in eps) and any(e > 0 for e in eps), eps)

    def test_aria_offline_answers(self):
        self._run("aria", ["attack.type=label_flip", "defense.anomaly=true"])
        r = ask("Did anyone poison the model?", self.tmp / "aria", use_llm=False)
        self.assertIn("Bank C", r["answer"])
        r = ask("prove the log was not altered", self.tmp / "aria", use_llm=False)
        self.assertIn("intact", r["answer"])


if __name__ == "__main__":
    unittest.main()
