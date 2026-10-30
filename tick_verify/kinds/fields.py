"""The field checks the kinds share, each written once from spec/SPEC.md.

A reason is worded exactly as the specification words it, with the typographic
apostrophe (’) it uses, so that verifiers written apart give the same text.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import math
import re
from typing import Any

from ..canonical import CanonicalError, canonical, document_hash
from ..ed25519 import public_key_from_spki, verify

_MISSING = object()

_TIME = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))",
    re.ASCII,
)
_HEX = {40: re.compile(r"[0-9a-f]{40}"), 64: re.compile(r"[0-9a-f]{64}"), 16: re.compile(r"[0-9a-f]{16}")}


def is_object(value: Any) -> bool:
    return isinstance(value, dict)


def is_list(value: Any) -> bool:
    return isinstance(value, list)


def is_string(value: Any) -> bool:
    return isinstance(value, str)


def non_empty(value: Any) -> bool:
    """A non-empty string."""
    return isinstance(value, str) and value != ""


def non_empty_strings(value: Any) -> bool:
    """A non-empty list of non-empty strings."""
    return isinstance(value, list) and len(value) > 0 and all(non_empty(item) for item in value)


def is_number(value: Any) -> bool:
    """A finite number; a boolean is not one."""
    if isinstance(value, bool):
        return False
    return isinstance(value, int) or (isinstance(value, float) and math.isfinite(value))


def is_whole(value: Any) -> bool:
    """A whole number, of either sign."""
    return is_number(value) and (isinstance(value, int) or value.is_integer())


def is_count(value: Any) -> bool:
    """A whole number of zero or more."""
    return is_whole(value) and value >= 0


def is_amount(value: Any) -> bool:
    """A finite number of zero or more."""
    return is_number(value) and value >= 0


def null_or(holder: dict[str, Any], name: str, accepts: Any) -> bool:
    """The field is there and is null or accepted: a missing field is not null."""
    return name in holder and (holder[name] is None or bool(accepts(holder[name])))


def is_hex(value: Any, length: int) -> bool:
    """`length` lowercase hexadecimal characters: 16, 40 or 64."""
    return isinstance(value, str) and _HEX[length].fullmatch(value) is not None


def is_time(value: Any) -> bool:
    """An ISO 8601 time as the specification defines it: YYYY-MM-DDTHH:MM:SS, an optional
    decimal fraction, then Z or ±HH:MM, naming a day that exists."""
    if not isinstance(value, str):
        return False
    match = _TIME.fullmatch(value)
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    try:
        datetime.date(year, month, day)
    except ValueError:
        return False
    if hour > 23 or minute > 59 or second > 59:
        return False
    if match.group(7) is not None and (int(match.group(7)) > 23 or int(match.group(8)) > 59):
        return False
    return True


def describe(document: dict[str, Any], name: str) -> str:
    """A field as a reason writes it: a string as it is, a missing field as undefined."""
    if name not in document:
        return "undefined"
    value = document[name]
    if isinstance(value, str):
        return value
    try:
        return canonical(value)
    except (CanonicalError, RecursionError):
        return "?"


def head_reasons(document: dict[str, Any], schema: str, ids: tuple[str, ...] = ()) -> list[str]:
    """Steps one to three of a signed document's check: schema, alg, issued_at, coordinator and its ids."""
    reasons = []
    if document.get("schema") != schema:
        reasons.append(f"the schema is {describe(document, 'schema')}, not {schema}")
    reasons += alg_reasons(document)
    if not is_time(document.get("issued_at")):
        reasons.append("issued_at is not an ISO 8601 time")
    for name in ("coordinator", *ids):
        if not non_empty(document.get(name)):
            reasons.append(f"{name} is not a non-empty string")
    return reasons


def alg_reasons(document: dict[str, Any]) -> list[str]:
    if document.get("alg") != "ed25519":
        return [f"the algorithm is {describe(document, 'alg')}, not ed25519"]
    return []


def hash_reasons(document: dict[str, Any], field: str, noun: str) -> list[str]:
    """The document hash of document[field] must be the document's content_hash."""
    if field not in document:
        return [f"the {noun} cannot be hashed"]
    try:
        actual = document_hash(document[field])
    except (CanonicalError, RecursionError):
        return [f"the {noun} cannot be hashed"]
    if actual != document.get("content_hash"):
        return [f"content_hash is not the hash of the {noun}"]
    return []


def _base64(value: Any) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


def key_id_of(document: dict[str, Any]) -> str | None:
    """The key_id the carried key has: 16 hexadecimal characters of the SHA-256 of its bytes; None without a key."""
    key = _base64(document.get("key"))
    return None if key is None else hashlib.sha256(key).hexdigest()[:16]


def key_id_reasons(document: dict[str, Any]) -> list[str]:
    actual = key_id_of(document)
    if actual is None or document.get("key_id") != actual:
        return ["key_id is not the carried key’s"]
    return []


def signed_bytes(label: str, document: dict[str, Any], names: tuple[str, ...]) -> bytes | None:
    """`<label>:<value>:...` as UTF-8, or None when a value is not a string and so signs nothing."""
    values = [document.get(name) for name in names]
    if not all(isinstance(value, str) for value in values):
        return None
    text = ":".join([label, *values])
    # A lone surrogate is written as U+FFFD, as a UTF-8 encoder of JavaScript strings writes it.
    return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")


def signature_reasons(document: dict[str, Any], message: bytes | None, noun: str) -> list[str]:
    """The key is an Ed25519 key and the signature verifies under it over message, with no pre-hashing."""
    key = _base64(document.get("key"))
    signature = _base64(document.get("signature"))
    if message is not None and key is not None and signature is not None:
        try:
            if verify(public_key_from_spki(key), message, signature):
                return []
        except ValueError:
            pass
    return [f"the signature is not the carried key’s over this {noun}"]


def not_a_document(noun: str) -> list[str]:
    return [f"it is not {noun}: it is not a JSON object"]
