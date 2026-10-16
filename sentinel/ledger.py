"""Tamper-evident audit ledger: an append-only hash chain in SQLite.

Every entry stores the previous entry's hash and is signed by the consortium
operator key. Each round is sealed with the Merkle root of its update hashes.
Editing any stored row breaks the chain or the signature, and `verify()`
reports the first bad record. Only metadata is stored: never transactions,
labels or raw model updates (only their hashes).

This is the default "Fabric-lite" design; Hyperledger Fabric can anchor the
round seals later without changing the API.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .crypto import Identity, canonical, sha256_hex, verify as verify_sig

GENESIS = "0" * 64


def merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return sha256_hex(b"")
    level = sorted(hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256_hex((level[i] + level[i + 1]).encode()) for i in range(0, len(level), 2)]
    return level[0]


class Ledger:
    def __init__(self, path: str | Path, operator: Identity | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.execute("""CREATE TABLE IF NOT EXISTS entries(
            idx INTEGER PRIMARY KEY, ts REAL, type TEXT, round INTEGER, body TEXT,
            prev_hash TEXT, hash TEXT, signature TEXT)""")
        self.db.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)")
        self.operator = operator
        if operator is not None:
            self.db.execute("INSERT OR IGNORE INTO meta VALUES('operator_public_key', ?)", (operator.public_hex,))
        self.db.commit()

    # ---- writing
    def append(self, type_: str, body: dict, round_no: int | None = None) -> dict:
        if self.operator is None:
            raise PermissionError("read-only ledger handle")
        row = self.db.execute("SELECT idx, hash FROM entries ORDER BY idx DESC LIMIT 1").fetchone()
        idx, prev = (row[0] + 1, row[1]) if row else (0, GENESIS)
        ts = round(time.time(), 3)
        content = {"idx": idx, "ts": ts, "type": type_, "round": round_no, "body": body, "prev_hash": prev}
        h = sha256_hex(canonical(content))
        sig = self.operator.sign(bytes.fromhex(h))
        self.db.execute("INSERT INTO entries VALUES(?,?,?,?,?,?,?,?)",
                        (idx, ts, type_, round_no, json.dumps(body, sort_keys=True, default=str), prev, h, sig))
        self.db.commit()
        return {**content, "hash": h}

    # ---- reading
    def entries(self, type_: str | None = None, round_no: int | None = None, limit: int | None = None) -> list[dict]:
        q, args = "SELECT idx, ts, type, round, body, prev_hash, hash, signature FROM entries WHERE 1=1", []
        if type_:
            q += " AND type=?"; args.append(type_)
        if round_no is not None:
            q += " AND round=?"; args.append(round_no)
        q += " ORDER BY idx"
        rows = self.db.execute(q, args).fetchall()
        if limit:
            rows = rows[-limit:]
        return [{"idx": r[0], "ts": r[1], "type": r[2], "round": r[3], "body": json.loads(r[4]),
                 "prev_hash": r[5], "hash": r[6], "signature": r[7]} for r in rows]

    def operator_key(self) -> str | None:
        r = self.db.execute("SELECT value FROM meta WHERE key='operator_public_key'").fetchone()
        return r[0] if r else None

    def verify(self, trusted_operator_key: str | None = None) -> dict:
        """Recompute every hash, link and signature. Returns the first problem found."""
        key = trusted_operator_key or self.operator_key()
        prev = GENESIS
        rows = self.db.execute("SELECT idx, ts, type, round, body, prev_hash, hash, signature FROM entries ORDER BY idx").fetchall()
        for expected_idx, r in enumerate(rows):
            idx, ts, type_, rnd, body, prev_hash, h, sig = r
            if idx != expected_idx:
                return {"ok": False, "checked": expected_idx, "bad_record": expected_idx, "reason": "missing or reordered record"}
            content = {"idx": idx, "ts": ts, "type": type_, "round": rnd, "body": json.loads(body), "prev_hash": prev_hash}
            if prev_hash != prev:
                return {"ok": False, "checked": idx, "bad_record": idx, "reason": "broken link to previous record"}
            if sha256_hex(canonical(content)) != h:
                return {"ok": False, "checked": idx, "bad_record": idx, "reason": "content does not match its hash (record edited)"}
            if not key or not verify_sig(key, bytes.fromhex(h), sig):
                return {"ok": False, "checked": idx, "bad_record": idx, "reason": "invalid operator signature"}
            prev = h
        return {"ok": True, "checked": len(rows), "bad_record": None, "head": prev,
                "reason": f"all {len(rows)} records verified"}

    def tamper(self, idx: int, field: str = "accepted", value=True) -> None:
        """DEMO ONLY: simulate an insider editing a stored record without re-signing it."""
        r = self.db.execute("SELECT body FROM entries WHERE idx=?", (idx,)).fetchone()
        if not r:
            raise IndexError(idx)
        body = json.loads(r[0]); body[field] = value
        self.db.execute("UPDATE entries SET body=? WHERE idx=?", (json.dumps(body, sort_keys=True), idx))
        self.db.commit()


def open_readonly(path: str | Path) -> Ledger:
    return Ledger(path, operator=None)
