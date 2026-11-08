"""Smart-contract registry: participant registration, access control and round anchoring.

Two interchangeable backends implement the rules of contracts/ConsortiumRegistry.sol:

* ``EthRegistry``   calls the deployed contract on a local Ethereum chain (Anvil, Hardhat or
                    Ganache) through web3.py. Select it with SENTINEL_CHAIN=eth after running
                    ``python scripts/deploy_contract.py`` (see docs/SMART_CONTRACT.md).
* ``SimRegistry``   a deterministic, in-process re-implementation of the same contract: same
                    states, same `require` checks and error messages, and an append-only,
                    hash-linked transaction log (blocks). It is the default, so the demo and the
                    tests run without a blockchain node.

The aggregator treats the registry as the source of truth for access control: an update is
only accepted if ``is_authorised(bank, public_key)`` is true.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

STATUS = ["none", "pending", "approved", "revoked", "quarantined"]


class RegistryError(Exception):
    """Raised when the contract would revert (the message is the Solidity `require` reason)."""


def _b32(hex_or_text: str) -> str:
    """Normalise to a 32-byte hex string, as the contract stores bytes32 values."""
    h = hex_or_text.lower().removeprefix("0x")
    if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
        return h
    return hashlib.sha256(hex_or_text.encode()).hexdigest()


class SimRegistry:
    backend = "simulated"
    OPERATOR, REGULATOR = "operator", "regulator"

    def __init__(self, path: str | Path, fresh: bool = False):
        self.path = Path(path)
        self.lock = threading.RLock()
        if fresh:
            self.path.unlink(missing_ok=True)
        if self.path.exists():
            st = json.loads(self.path.read_text())
            self.banks, self.anchors, self.blocks = st["banks"], st["anchors"], st["blocks"]
        else:
            self.banks, self.anchors, self.blocks = {}, {}, []
            self._mine("deploy", self.OPERATOR, {"contract": "ConsortiumRegistry", "regulator": self.REGULATOR})

    # ---- chain mechanics
    def _mine(self, fn: str, sender: str, args: dict, event: dict | None = None) -> dict:
        prev = self.blocks[-1]["hash"] if self.blocks else "0" * 64
        blk = {"number": len(self.blocks), "ts": round(time.time(), 3), "fn": fn, "from": sender, "args": args,
               "event": event, "prev": prev}
        blk["hash"] = hashlib.sha256(json.dumps(blk, sort_keys=True).encode()).hexdigest()
        self.blocks.append(blk)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"banks": self.banks, "anchors": self.anchors, "blocks": self.blocks}, indent=1))
        return {"tx": blk["hash"], "block": blk["number"]}

    @staticmethod
    def _require(cond: bool, msg: str):
        if not cond:
            raise RegistryError(msg)

    def _status(self, b: str) -> str:
        return self.banks.get(b, {}).get("status", "none")

    def _set(self, fn, sender, b, status, reason):
        self.banks[b].update(status=status, updated=time.time())
        return self._mine(fn, sender, {"bankId": b, "reason": reason},
                          {"AccessChanged": {"bankId": b, "status": status, "by": sender, "reason": reason}})

    # ---- contract functions (same rules as the Solidity source)
    def request_join(self, b: str, pub_key: str, jurisdiction: str, sender: str | None = None) -> dict:
        with self.lock:
            self._require(self._status(b) == "none", "bank already registered")
            self._require(bool(pub_key), "empty key")
            self.banks[b] = {"pubKey": _b32(pub_key), "jurisdiction": jurisdiction, "wallet": sender or f"bank-{b}",
                             "status": "pending", "updated": time.time()}
            return self._mine("requestJoin", sender or f"bank-{b}", {"bankId": b, "pubKey": _b32(pub_key), "jurisdiction": jurisdiction},
                              {"JoinRequested": {"bankId": b, "jurisdiction": jurisdiction}})

    def approve(self, b: str, sender: str = OPERATOR) -> dict:
        with self.lock:
            self._require(sender == self.OPERATOR, "only operator")
            self._require(self._status(b) in ("pending", "revoked"), "not pending or revoked")
            return self._set("approve", sender, b, "approved", "approved")

    def revoke(self, b: str, reason: str, sender: str = OPERATOR) -> dict:
        with self.lock:
            self._require(sender in (self.OPERATOR, self.REGULATOR), "only operator or regulator")
            self._require(self._status(b) != "none", "unknown bank")
            return self._set("revoke", sender, b, "revoked", reason)

    def quarantine(self, b: str, reason: str, sender: str = OPERATOR) -> dict:
        with self.lock:
            self._require(sender in (self.OPERATOR, self.REGULATOR), "only operator or regulator")
            self._require(self._status(b) == "approved", "bank not active")
            return self._set("quarantine", sender, b, "quarantined", reason)

    def reinstate(self, b: str, sender: str = OPERATOR) -> dict:
        with self.lock:
            self._require(sender == self.OPERATOR, "only operator")
            self._require(self._status(b) == "quarantined", "not quarantined")
            return self._set("reinstate", sender, b, "approved", "reinstated")

    def anchor_round(self, run_id: str, rnd: int, merkle_root: str, model_hash: str, sender: str = OPERATOR) -> dict:
        with self.lock:
            self._require(sender == self.OPERATOR, "only operator")
            key = f"{_b32(run_id)}:{rnd}"
            self._require(key not in self.anchors, "round already anchored")
            self.anchors[key] = {"merkleRoot": _b32(merkle_root), "modelHash": _b32(model_hash), "ts": time.time()}
            return self._mine("anchorRound", sender, {"runId": _b32(run_id), "round": rnd, "merkleRoot": _b32(merkle_root)},
                              {"RoundAnchored": {"round": rnd, "merkleRoot": _b32(merkle_root)}})

    def is_authorised(self, b: str, pub_key: str) -> bool:
        x = self.banks.get(b)
        return bool(x) and x["status"] == "approved" and x["pubKey"] == _b32(pub_key)

    def status(self, b: str) -> str:
        return self._status(b)

    def anchored(self, run_id: str, rnd: int) -> dict | None:
        return self.anchors.get(f"{_b32(run_id)}:{rnd}")

    def verify_chain(self) -> dict:
        prev = "0" * 64
        for blk in self.blocks:
            body = {k: v for k, v in blk.items() if k != "hash"}
            if blk["prev"] != prev or hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != blk["hash"]:
                return {"ok": False, "bad_block": blk["number"]}
            prev = blk["hash"]
        return {"ok": True, "blocks": len(self.blocks)}

    def view(self, limit: int = 60) -> dict:
        return {"backend": self.backend, "contract": "ConsortiumRegistry (simulated)", "banks": self.banks,
                "anchors": len(self.anchors), "blocks": self.blocks[-limit:][::-1], "verify": self.verify_chain()}


class EthRegistry:
    """web3.py client for the deployed ConsortiumRegistry contract on a local dev chain.

    Uses the chain's unlocked development accounts (Anvil / Hardhat / Ganache): account 0 is the
    operator, account 1 the regulator, accounts 2.. the bank wallets. Never use this on a public chain.
    """
    backend = "ethereum"

    def __init__(self, build_file: str | Path = "contracts/build/ConsortiumRegistry.json", rpc: str | None = None):
        from web3 import Web3  # optional dependency: pip install -r requirements-chain.txt
        info = json.loads(Path(build_file).read_text())
        self.w3 = Web3(Web3.HTTPProvider(rpc or os.environ.get("SENTINEL_RPC", info.get("rpc", "http://127.0.0.1:8545"))))
        self.c = self.w3.eth.contract(address=info["address"], abi=info["abi"])
        self.operator, self.regulator = info["operator"], info["regulator"]
        self.bank_wallets = info.get("bank_wallets", {})
        self.address, self.log = info["address"], []

    def _tx(self, fn, sender: str, name: str, args: list) -> dict:
        try:
            fn.call({"from": sender})              # dry run: surfaces the require() reason
        except Exception as e:
            msg = str(e)
            raise RegistryError(msg.split("reverted:", 1)[1].strip(" '\")") if "reverted:" in msg else msg)
        rcpt = self.w3.eth.wait_for_transaction_receipt(fn.transact({"from": sender}))
        rec = {"number": rcpt.blockNumber, "tx": rcpt.transactionHash.hex(), "fn": name, "args": args,
               "from": sender, "gas": rcpt.gasUsed, "ts": time.time()}
        self.log.append(rec)
        return {"tx": rec["tx"], "block": rec["number"]}

    def request_join(self, b, pub_key, jurisdiction, sender=None):
        return self._tx(self.c.functions.requestJoin(b, bytes.fromhex(_b32(pub_key)), jurisdiction),
                        self.bank_wallets.get(b, self.operator), "requestJoin", [b, jurisdiction])

    def approve(self, b, sender=None):
        return self._tx(self.c.functions.approve(b), self.operator, "approve", [b])

    def revoke(self, b, reason, sender=None):
        return self._tx(self.c.functions.revoke(b, reason), self.operator, "revoke", [b, reason])

    def quarantine(self, b, reason, sender=None):
        return self._tx(self.c.functions.quarantine(b, reason[:120]), self.operator, "quarantine", [b, reason[:120]])

    def reinstate(self, b, sender=None):
        return self._tx(self.c.functions.reinstate(b), self.operator, "reinstate", [b])

    def anchor_round(self, run_id, rnd, merkle_root, model_hash, sender=None):
        return self._tx(self.c.functions.anchorRound(bytes.fromhex(_b32(run_id)), rnd, bytes.fromhex(_b32(merkle_root)),
                                                     bytes.fromhex(_b32(model_hash))), self.operator, "anchorRound", [run_id, rnd])

    def is_authorised(self, b, pub_key) -> bool:
        return bool(self.c.functions.isAuthorised(b, bytes.fromhex(_b32(pub_key))).call())

    def status(self, b) -> str:
        return STATUS[self.c.functions.getBank(b).call()[3]]

    def anchored(self, run_id, rnd):
        a = self.c.functions.anchors(bytes.fromhex(_b32(run_id)), rnd).call()
        return {"merkleRoot": a[0].hex(), "modelHash": a[1].hex(), "ts": a[2]} if a[2] else None

    def verify_chain(self) -> dict:
        return {"ok": True, "blocks": self.w3.eth.block_number, "note": "integrity by Ethereum consensus"}

    def view(self, limit: int = 60) -> dict:
        banks = {}
        for i in range(self.c.functions.bankCount().call()):
            b = self.c.functions.bankIds(i).call()
            pk, jur, wallet, st, upd = self.c.functions.getBank(b).call()
            banks[b] = {"pubKey": pk.hex(), "jurisdiction": jur, "wallet": wallet, "status": STATUS[st], "updated": upd}
        return {"backend": self.backend, "contract": self.address, "banks": banks, "anchors": None,
                "blocks": self.log[-limit:][::-1], "verify": self.verify_chain()}


def make_registry(node_dir: str | Path, fresh: bool = False):
    if os.environ.get("SENTINEL_CHAIN", "sim").lower() == "eth":
        return EthRegistry(os.environ.get("SENTINEL_CONTRACT_BUILD", "contracts/build/ConsortiumRegistry.json"))
    return SimRegistry(Path(node_dir) / "chain.json", fresh=fresh)
