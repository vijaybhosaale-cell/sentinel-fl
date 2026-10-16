"""Ed25519 identities and signed model updates."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def vector_hash(v: np.ndarray) -> str:
    return sha256_hex(np.ascontiguousarray(v, dtype=np.float64).tobytes())


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


class Identity:
    """An Ed25519 key pair, optionally persisted as PEM under `key_dir`."""

    def __init__(self, name: str, key_dir: str | Path | None = None):
        self.name = name
        path = Path(key_dir) / f"{name}.pem" if key_dir else None
        if path and path.exists():
            self._sk = serialization.load_pem_private_key(path.read_bytes(), password=None)
        else:
            self._sk = Ed25519PrivateKey.generate()
            if path:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(self._sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
        self.public_hex = self._sk.public_key().public_bytes(serialization.Encoding.Raw,
                                                             serialization.PublicFormat.Raw).hex()

    def sign(self, message: bytes) -> str:
        return self._sk.sign(message).hex()


def verify(public_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def update_message(bank: str, round_no: int, weights_hash: str, n_samples: int, eps_round: float) -> bytes:
    return canonical({"bank": bank, "round": round_no, "weights": weights_hash, "n": n_samples, "eps": round(eps_round, 6)})
