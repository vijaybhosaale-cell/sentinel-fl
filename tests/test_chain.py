"""Smart-contract registry: the simulated backend must enforce the Solidity contract's rules."""
import json
import tempfile
import unittest
from pathlib import Path

from sentinel.registry_chain import RegistryError, SimRegistry


class TestRegistry(unittest.TestCase):
    def setUp(self):
        self.r = SimRegistry(Path(tempfile.mkdtemp()) / "chain.json")
        self.k = "ab" * 32

    def test_lifecycle_and_access(self):
        r, k = self.r, self.k
        r.request_join("A", k, "France")
        self.assertFalse(r.is_authorised("A", k))                    # pending: no access
        with self.assertRaisesRegex(RegistryError, "already registered"):
            r.request_join("A", "cd" * 32, "France")                  # impersonation attempt
        with self.assertRaisesRegex(RegistryError, "only operator"):
            r.approve("A", sender="bank-A")                           # a bank cannot approve itself
        with self.assertRaisesRegex(RegistryError, "only operator"):
            r.approve("A", sender="regulator")                        # nor can the regulator
        r.approve("A")
        self.assertTrue(r.is_authorised("A", k))
        self.assertFalse(r.is_authorised("A", "cd" * 32))            # wrong key
        r.quarantine("A", "poisoning", sender="regulator")           # regulator may quarantine
        self.assertFalse(r.is_authorised("A", k))
        with self.assertRaisesRegex(RegistryError, "bank not active"):
            r.quarantine("A", "again")
        r.reinstate("A")
        self.assertEqual(r.status("A"), "approved")
        r.revoke("A", "left consortium")
        self.assertFalse(r.is_authorised("A", k))

    def test_anchor_write_once_and_tamper_evidence(self):
        r = self.r
        r.anchor_round("run-1", 1, "11" * 32, "22" * 32)
        self.assertEqual(r.anchored("run-1", 1)["merkleRoot"], "11" * 32)
        with self.assertRaisesRegex(RegistryError, "already anchored"):
            r.anchor_round("run-1", 1, "33" * 32, "22" * 32)          # history cannot be rewritten
        self.assertTrue(r.verify_chain()["ok"])
        st = json.loads(r.path.read_text())
        st["blocks"][1]["args"]["merkleRoot"] = "33" * 32             # edit the stored chain
        r.path.write_text(json.dumps(st))
        self.assertEqual(SimRegistry(r.path).verify_chain(), {"ok": False, "bad_block": 1})


if __name__ == "__main__":
    unittest.main()
