"""A test-only Ed25519 signer, after RFC 8032 section 5.1.6, for keys a test makes on the spot.

Nothing here is a real key and nothing here ships: the package only verifies. The curve
arithmetic is the package's own (tick_verify.ed25519); what is written here is the
key derivation and the signature of section 5.1.5 and 5.1.6.
"""

from __future__ import annotations

import base64
import hashlib
import os

from tick_verify.ed25519 import _G, _L, _P, _inv, _mul

_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def _compress(point: tuple[int, int, int, int]) -> bytes:
    zinv = _inv(point[2])
    x, y = point[0] * zinv % _P, point[1] * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _expand(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_key(seed: bytes) -> bytes:
    """The 32 bytes of the public key for a 32-byte seed."""
    return _compress(_mul(_expand(seed)[0], _G))


def sign(seed: bytes, message: bytes) -> bytes:
    """The 64-byte signature of message under the seed's key, with no pre-hashing."""
    scalar, prefix = _expand(seed)
    a = _compress(_mul(scalar, _G))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    r_bytes = _compress(_mul(r, _G))
    k = int.from_bytes(hashlib.sha512(r_bytes + a + message).digest(), "little") % _L
    return r_bytes + ((r + k * scalar) % _L).to_bytes(32, "little")


class Key:
    """A key made on the spot: its seed is random and is never written anywhere."""

    def __init__(self, seed: bytes | None = None) -> None:
        self.seed = os.urandom(32) if seed is None else seed
        self.spki = _SPKI_PREFIX + public_key(self.seed)

    @property
    def key(self) -> str:
        """What a document's `key` holds: the SPKI DER in base64."""
        return base64.b64encode(self.spki).decode("ascii")

    @property
    def key_id(self) -> str:
        """What a document's `key_id` holds: 16 hexadecimal characters of the SHA-256 of the SPKI DER."""
        return hashlib.sha256(self.spki).hexdigest()[:16]

    def sign(self, message: str) -> str:
        """What a document's `signature` holds: the signature over the UTF-8 bytes of message, in base64."""
        return base64.b64encode(sign(self.seed, message.encode("utf-8"))).decode("ascii")
