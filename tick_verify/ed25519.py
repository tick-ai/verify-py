"""Ed25519 signature verification, RFC 8032 section 5.1.7, after the reference code of section 6.

Only hashlib.sha512 and Python integers are used; nothing here calls a library
for the curve, so this is an implementation independent of any other.

Edge cases, each as the RFC's reference code treats it:

- A public key or signature of the wrong length (not 32 and 64 bytes) is False.
- A point that does not decode (5.1.3) is False: y >= p, a y with no x on the
  curve, and x = 0 with the sign bit set. The reference code's recover_x refuses
  y >= p rather than reducing it, so a non-canonical y in R or A is refused, not
  accepted as y - p.
- S >= L (the group order) is False (5.1.7: "the integer s must be in the range
  0 <= s < L"), so S + L never passes as S.
- The hash is taken over the encodings exactly as received, never over a
  re-encoding of the decoded points.
- The check is the reference code's, [S]B == R + [k]A, without the cofactor 8;
  points of small order are therefore not refused as such, the RFC not refusing them.
"""

from __future__ import annotations

import hashlib

__all__ = ["verify", "public_key_from_spki"]

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


# Points are extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, xy = T/Z.
_Point = tuple[int, int, int, int]


def _add(p: _Point, q: _Point) -> _Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s: int, p: _Point) -> _Point:
    q: _Point = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _equal(p: _Point, q: _Point) -> bool:
    if (p[0] * q[2] - q[0] * p[2]) % _P != 0:
        return False
    if (p[1] * q[2] - q[1] * p[2]) % _P != 0:
        return False
    return True


def _decompress(s: bytes) -> _Point | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


_G_Y = 4 * _inv(5) % _P
_G_X = _recover_x(_G_Y, 0)
assert _G_X is not None
_G: _Point = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True if signature is a valid Ed25519 signature of message under public_key; never raises on bad input."""
    if not isinstance(public_key, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray)):
        return False
    if len(public_key) != 32 or len(signature) != 64:
        return False
    public_key, signature = bytes(public_key), bytes(signature)
    a = _decompress(public_key)
    if a is None:
        return False
    r_bytes = signature[:32]
    r = _decompress(r_bytes)
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + public_key + bytes(message)).digest(), "little") % _L
    return _equal(_mul(s, _G), _add(r, _mul(k, a)))


def public_key_from_spki(der: bytes) -> bytes:
    """The 32 key bytes of an Ed25519 SubjectPublicKeyInfo; ValueError unless it is exactly the 44-byte form."""
    if len(der) != 44 or bytes(der[:12]) != _SPKI_PREFIX:
        raise ValueError("not an Ed25519 SubjectPublicKeyInfo of 44 bytes")
    return bytes(der[12:])
