"""The keys a company names, tick-keys/1: the key ids it stands behind. Not signed; the domain that serves it is its authority."""

from __future__ import annotations

import datetime
import re
from typing import Any

from . import fields

SCHEMA = "tick-keys/1"
KIND = "keys-file"

_DAY = re.compile(r"(\d{4})-(\d{2})-(\d{2})", re.ASCII)


def _is_day(value: Any) -> bool:
    match = _DAY.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return False
    try:
        datetime.date(*(int(part) for part in match.groups()))
    except ValueError:
        return False
    return True


def _key_reasons(key: Any, at: str) -> list[str]:
    if not fields.is_object(key):
        return [f"{at} is not an object"]
    found = []
    if not fields.is_hex(key.get("key_id"), 16):
        found.append(f"{at}.key_id is not 16 lowercase hexadecimal characters")
    if key.get("role") not in ("coordinator", "release"):
        found.append(f"{at}.role is not coordinator or release")
    if not _is_day(key.get("from")):
        found.append(f"{at}.from is not a day, YYYY-MM-DD")
    return found


def reasons(document: Any) -> list[str]:
    if not fields.is_object(document):
        return fields.not_a_document("a keys file")
    found = [] if document.get("schema") == SCHEMA else [f"the schema is {fields.describe(document, 'schema')}, not {SCHEMA}"]
    keys = document.get("keys")
    if not (fields.is_list(keys) and keys):
        return found + ["keys is not a non-empty list"]
    for i, key in enumerate(keys):
        found += _key_reasons(key, f"keys[{i}]")
    key_ids = [key["key_id"] for key in keys if fields.is_object(key) and isinstance(key.get("key_id"), str)]
    if len(set(key_ids)) != len(key_ids):
        found.append("keys names one key_id twice")
    return found


def check(document: dict[str, Any], text: str) -> tuple[str, list[str]]:
    return KIND, reasons(document)
