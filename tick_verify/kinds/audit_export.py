"""One run's audit export, tick.audit-export.v1: the run's ledger and the hash that covers it alone."""

from __future__ import annotations

from typing import Any

from . import fields

SCHEMA = "tick.audit-export.v1"
KIND = "audit-export"


def reasons(document: Any) -> list[str]:
    if not fields.is_object(document):
        return fields.not_a_document("an audit export")
    found = [] if document.get("schema") == SCHEMA else [f"the schema is {fields.describe(document, 'schema')}, not {SCHEMA}"]
    return found + fields.hash_reasons(document, "ledger", "ledger")


def check(document: dict[str, Any], text: str) -> tuple[str, list[str]]:
    return KIND, reasons(document)
