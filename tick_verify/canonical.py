"""The canonical form of a JSON value and the document hash, as SPEC.md defines them.

The form is JavaScript's own: JSON.stringify's strings and numbers, keys sorted
by UTF-16 code units, no whitespace. Python writes numbers and some strings
differently, so both are written here by the rules of ECMA-262 rather than by
Python's json module: 100.0 is "100", 1e-7 is "1e-7", -0.0 is "0", and a lone
surrogate is escaped as \\udxxx.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any

__all__ = ["CanonicalError", "canonical", "document_hash", "content_hash"]


class CanonicalError(ValueError):
    """A value no JSON document holds, so it has no canonical form."""


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _string(value: str) -> str:
    out = ['"']
    for char in value:
        code = ord(char)
        if char in _ESCAPES:
            out.append(_ESCAPES[char])
        elif code < 0x20 or 0xD800 <= code <= 0xDFFF:
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _number(value: int | float) -> str:
    if isinstance(value, bool):
        raise CanonicalError("a boolean is not a number")
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise CanonicalError("an integer past 2^53 is not one number every reader holds exactly")
        return str(value)
    if not math.isfinite(value):
        raise CanonicalError("a number that is not finite has no canonical form")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    # Python's repr gives the shortest digits that round-trip, as ECMA-262 asks;
    # only the way they are laid out differs, so read the digits and the place of
    # the decimal point from it and lay them out by the standard's rules.
    mantissa, _, exponent = repr(abs(value)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    raw = whole + fraction
    point = len(whole) + (int(exponent) if exponent else 0)
    stripped = raw.lstrip("0")
    point -= len(raw) - len(stripped)
    digits = stripped.rstrip("0")
    # The value is 0.<digits> x 10^point: ECMA-262's k digits and n.
    k, n = len(digits), point
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * (-n) + digits
    else:
        exp = n - 1
        mark = "+" if exp >= 0 else "-"
        head = digits[0] + ("." + digits[1:] if k > 1 else "")
        text = f"{head}e{mark}{abs(exp)}"
    return sign + text


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def canonical(value: Any) -> str:
    """The canonical form of value, or CanonicalError where it has none."""
    return _write(value, set())


def _write(value: Any, ancestors: set[int]) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, dict)):
        if id(value) in ancestors:
            raise CanonicalError("a structure that contains itself has no canonical form")
        ancestors.add(id(value))
        try:
            if isinstance(value, list):
                return "[" + ",".join(_write(item, ancestors) for item in value) + "]"
            if not all(isinstance(key, str) for key in value):
                raise CanonicalError("an object key that is not a string has no canonical form")
            keys = sorted(value, key=_utf16_key)
            return "{" + ",".join(_string(key) + ":" + _write(value[key], ancestors) for key in keys) + "}"
        finally:
            ancestors.discard(id(value))
    raise CanonicalError(f"a {type(value).__name__} is not a JSON value")


def document_hash(body: Any) -> str:
    """What a document's content_hash holds: SHA-256 of the canonical form written as a JSON string."""
    return hashlib.sha256(_string(canonical(body)).encode("utf-8", "surrogatepass")).hexdigest()


def content_hash(value: Any) -> str:
    """The plain SHA-256 of the canonical form alone, which no Tick document holds."""
    return hashlib.sha256(canonical(value).encode("utf-8", "surrogatepass")).hexdigest()
