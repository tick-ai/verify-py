"""A delivery, tick.delivery.v1: what the doer hands in, signed by the doer's coordinator."""

from __future__ import annotations

from typing import Any

from . import fields

SCHEMA = "tick.delivery.v1"
KIND = "delivery"
LABEL = "tick-delivery:v1"


def _try_reasons(tries: Any) -> list[str]:
    if not fields.is_list(tries) or not tries:
        return ["delivery.tries is not a non-empty list"]
    found = []
    for i, attempt in enumerate(tries):
        at = f"delivery.tries[{i}]"
        if not fields.is_object(attempt):
            found.append(f"{at} is not an object")
            continue
        if not fields.non_empty(attempt.get("agent")):
            found.append(f"{at}.agent is not a non-empty string")
        if not fields.null_or(attempt, "model", fields.is_string):
            found.append(f"{at}.model is not a string or null")
        if not fields.null_or(attempt, "minutes", fields.is_amount):
            found.append(f"{at}.minutes is not a finite number of zero or more, or null")
        if not fields.null_or(attempt, "cents", fields.is_count):
            found.append(f"{at}.cents is not a whole number of zero or more, or null")
        if attempt.get("cost") not in ("metered", "reported", "unknown"):
            found.append(f"{at}.cost is not metered, reported or unknown")
    return found


def body_reasons(delivery: Any) -> list[str]:
    if not fields.is_object(delivery):
        return ["delivery is not an object"]
    found = []
    if not fields.is_hex(delivery.get("order_hash"), 64):
        found.append("delivery.order_hash is not 64 lowercase hexadecimal characters")
    if not fields.non_empty(delivery.get("repository")):
        found.append("delivery.repository is not a non-empty string")
    for name in ("base", "commit", "tree"):
        if not fields.is_hex(delivery.get(name), 40):
            found.append(f"delivery.{name} is not 40 lowercase hexadecimal characters")
    return found + _try_reasons(delivery.get("tries"))


def reasons(document: Any) -> list[str]:
    if not fields.is_object(document):
        return fields.not_a_document("a delivery")
    found = fields.head_reasons(document, SCHEMA, ("delivery_id",))
    found += body_reasons(document.get("delivery"))
    found += fields.hash_reasons(document, "delivery", "delivery")
    found += fields.key_id_reasons(document)
    message = fields.signed_bytes(LABEL, document, ("delivery_id", "content_hash"))
    return found + fields.signature_reasons(document, message, "delivery")


def check(document: dict[str, Any], text: str) -> tuple[str, list[str]]:
    return KIND, reasons(document)
