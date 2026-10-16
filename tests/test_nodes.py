"""Distributed test: aggregator + 3 bank nodes over real HTTP in one process (threads)."""
import json
import shutil
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

from sentinel.aggregator_node import AggregatorNode
from sentinel.bank_node import BankNode
from sentinel.config import load_config


def call(port, method, path, body=None, token="t"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode() if body is not None else None,
                                 method=method, headers={"Content-Type": "application/json", "X-Admin-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


class TestDistributed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os
        os.environ["SENTINEL_ADMIN_TOKEN"] = "t"
        cls.tmp = Path(tempfile.mkdtemp())
        cfg = load_config(None, ["data.n_transactions=24000"])
        cls.port = 18600
        cls.agg = AggregatorNode(cfg, cls.tmp / "agg", "127.0.0.1", cls.port, fresh=True)
        cls.agg.start(background=True)
        for i, b in enumerate("ABC"):
            BankNode(b, f"http://127.0.0.1:{cls.port}", cfg, cls.tmp / f"bank_{b}", "127.0.0.1", cls.port + 1 + i, email_alerts=False).start(background=True)
        for _ in range(60):
            if len(call(cls.port, "GET", "/api/registry")[1]) == 3:
                break
            time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_full_flow(self):
        p = self.port
        code, _ = call(p, "POST", "/api/control/start", {"rounds": 3})
        self.assertEqual(code, 409)                                        # nobody approved yet
        self.assertEqual(call(p, "POST", "/api/registry/action", {"bank": "A", "action": "approve"}, token="wrong")[0], 403)
        for b in "ABC":
            self.assertEqual(call(p, "POST", "/api/registry/action", {"bank": b, "action": "approve"})[0], 200)
        call(p, "POST", "/api/attack/launch", {"bank": "C", "type": "label_flip"})
        code, run = call(p, "POST", "/api/control/start", {"rounds": 6, "round_delay": 0})
        self.assertEqual(code, 200)
        for _ in range(240):
            ov = call(p, "GET", "/api/overview")[1]
            if ov["run"]["status"] != "running":
                break
            time.sleep(0.5)
        self.assertEqual(ov["run"]["status"], "done")
        status = {b["id"]: b["status"] for b in ov["banks"]}
        self.assertEqual(status["C"], "quarantined")
        self.assertGreater(ov["metrics"][-1]["pr_auc"], 0.4)
        self.assertTrue(call(p, "GET", "/api/verify")[1]["ok"])
        self.assertIn("Bank C", call(p, "GET", "/api/aria?q=did%20anyone%20poison%20the%20model")[1]["answer"])
        res = call(p + 3, "GET", "/api/residency")[1]                    # bank C portal
        self.assertEqual(res["raw_rows_sent"], 0)
        types = {e["type"] for e in call(p, "GET", "/api/ledger?limit=500")[1]}
        self.assertTrue({"register_request", "access_granted", "red_team_exercise", "quarantine", "round_commit"} <= types)
        notes = call(p, "GET", "/api/alerts")[1]["notifications"]
        self.assertTrue(any("quarantined" in n["subject"] for n in notes))
        self.assertIn("sentinel_round", urllib.request.urlopen(f"http://127.0.0.1:{p}/metrics").read().decode())


if __name__ == "__main__":
    unittest.main()
