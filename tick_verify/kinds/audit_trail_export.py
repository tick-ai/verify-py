"""A month's audit trail export, tick.audit-trail-export.v1: stricter than the rest, the file is its own canonical form."""

from __future__ import annotations

import json
from typing import Any

from ..canonical import CanonicalError, canonical, document_hash
from . import fields

SCHEMA = "tick.audit-trail-export.v1"
KIND = "audit-trail-export"


def reasons(text: str) -> list[str]:
    """Every failure of the file's text, which the check reads for itself: its bytes are part of what it asks."""
    try:
        document = json.loads(text)
    except ValueError as error:
        return [f"it is not JSON: {error}"]
    if not (fields.is_object(document) and document.get("schema") == SCHEMA):
        return [f"it is not an audit trail export ({SCHEMA})"]
    rest = {name: value for name, value in document.items() if name != "content_hash"}
    try:
        actual = document_hash(rest)
        written = canonical(document) + "\n"
    except (CanonicalError, RecursionError) as error:
        return [f"it holds a value no export holds: {error}"]
    if actual != document.get("content_hash"):
        return [
            "its content is not what was exported: "
            f"content_hash is {fields.describe(document, 'content_hash')}, the content hashes to {actual}"
        ]
    if text != written:
        return [
            "its content matches its hash, but its bytes are not the ones written: "
            "spacing, order or line endings were changed"
        ]
    return []


def check(document: dict[str, Any], text: str) -> tuple[str, list[str]]:
    return KIND, reasons(text)
