"""A check record, tick.check-record.v1: what a checker found, signed by the checker's coordinator."""

from __future__ import annotations

from typing import Any

from . import fields

SCHEMA = "tick.check-record.v1"
KIND = "check-record"
LABEL = "tick-check-record:v1"

_OUTCOMES = ("passed", "failed", "not-run")


def _result_reasons(results: Any) -> list[str]:
    if not fields.is_list(results) or not results:
        return ["record.results is not a non-empty list"]
    found = []
    for i, result in enumerate(results):
        at = f"record.results[{i}]"
        if not fields.is_object(result):
            found.append(f"{at} is not an object")
            continue
        if not fields.non_empty(result.get("name")):
            found.append(f"{at}.name is not a non-empty string")
        if not fields.null_or(result, "exit_code", fields.is_whole):
            found.append(f"{at}.exit_code is not a whole number or null")
        if result.get("outcome") not in _OUTCOMES:
            found.append(f"{at}.outcome is not passed, failed or not-run")
        if not fields.null_or(result, "duration_ms", fields.is_count):
            found.append(f"{at}.duration_ms is not a whole number of zero or more, or null")
    return found


def _verdict_reasons(record: dict[str, Any]) -> list[str]:
    """The verdict must not contradict what it is a verdict on, once there is something to compare."""
    held = record.get("territory_held")
    results = record.get("results")
    if not isinstance(held, bool) or not fields.is_list(results) or not results:
        return []
    if not all(fields.is_object(r) and r.get("outcome") in _OUTCOMES for r in results):
        return []
    all_passed = all(r["outcome"] == "passed" for r in results)
    verdict = record.get("verdict")
    found = []
    if verdict == "passed" and not held:
        found.append("record.verdict is passed, but record.territory_held is false")
    if verdict == "passed" and not all_passed:
        found.append("record.verdict is passed, but a result in record.results is not passed")
    if verdict == "failed" and held and all_passed:
        found.append("record.verdict is failed, but the territory was held and every result passed")
    return found


def body_reasons(record: Any) -> list[str]:
    if not fields.is_object(record):
        return ["record is not an object"]
    found = []
    for name in ("order_hash", "checks_hash"):
        if not fields.is_hex(record.get(name), 64):
            found.append(f"record.{name} is not 64 lowercase hexadecimal characters")
    if not fields.non_empty(record.get("repository")):
        found.append("record.repository is not a non-empty string")
    for name in ("base", "commit", "tree"):
        if not fields.is_hex(record.get(name), 40):
            found.append(f"record.{name} is not 40 lowercase hexadecimal characters")
    if not isinstance(record.get("territory_held"), bool):
        found.append("record.territory_held is not true or false")
    found += _result_reasons(record.get("results"))
    if record.get("contained") not in ("container", "none"):
        found.append("record.contained is not container or none")
    if record.get("verdict") not in ("passed", "failed"):
        found.append("record.verdict is not passed or failed")
    return found + _verdict_reasons(record)


def reasons(document: Any) -> list[str]:
    if not fields.is_object(document):
        return fields.not_a_document("a check record")
    found = fields.head_reasons(document, SCHEMA, ("record_id",))
    found += body_reasons(document.get("record"))
    found += fields.hash_reasons(document, "record", "record")
    found += fields.key_id_reasons(document)
    message = fields.signed_bytes(LABEL, document, ("record_id", "content_hash"))
    return found + fields.signature_reasons(document, message, "check record")


def check(document: dict[str, Any], text: str) -> tuple[str, list[str]]:
    return KIND, reasons(document)
