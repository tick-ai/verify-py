"""A member's usage report, tick.usage-report.v1: a few numbers and one answer, signed by the member's coordinator."""

from __future__ import annotations

from typing import Any

from . import fields

SCHEMA = "tick.usage-report.v1"
KIND = "usage-report"
LABEL = "tick-usage-report:v1"

_COUNTS = ("accepted_tasks", "accepted_days_last_14", "attempts_contained", "attempts_uncontained")
_TIMES = ("record_began", "first_accepted")
_ANSWERS = ("very", "somewhat", "not", "none")
_FIELDS = (*_TIMES, *_COUNTS, "answer")


def _number_reasons(numbers: dict[str, Any]) -> list[str]:
    found = [f"numbers holds {name}, which a usage report never carries" for name in numbers if name not in _FIELDS]
    found += [f"numbers.{name} is not a count" for name in _COUNTS if not fields.is_count(numbers.get(name))]
    found += [f"numbers.{name} is neither a time nor null" for name in _TIMES if not fields.null_or(numbers, name, fields.is_time)]
    if numbers.get("answer") not in _ANSWERS:
        found.append("numbers.answer is not one of very, somewhat, not, none")
    return found


def reasons(document: Any) -> list[str]:
    if not fields.is_object(document):
        return fields.not_a_document("a usage report")
    found = [] if document.get("schema") == SCHEMA else [f"the schema is {fields.describe(document, 'schema')}, not {SCHEMA}"]
    found += fields.alg_reasons(document)
    numbers = document.get("numbers")
    if not fields.is_object(numbers):
        return found + ["the report has no numbers"]
    found += _number_reasons(numbers)
    found += fields.hash_reasons(document, "numbers", "numbers")
    found += fields.key_id_reasons(document)
    # issued_at is never read for its form: it matters only as the signed bytes carry it.
    message = fields.signed_bytes(LABEL, document, ("issued_at", "content_hash"))
    return found + fields.signature_reasons(document, message, "report")


def check(document: dict[str, Any], text: str) -> tuple[str, list[str]]:
    return KIND, reasons(document)
