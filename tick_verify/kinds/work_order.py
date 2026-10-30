"""A work order, tick.work-order.v1: what a buyer asks for, signed before work starts."""

from __future__ import annotations

from typing import Any

from ..canonical import CanonicalError, document_hash
from . import fields

SCHEMA = "tick.work-order.v1"
KIND = "work-order"
LABEL = "tick-work-order:v1"


def _command_reasons(commands: Any) -> list[str]:
    if not fields.is_list(commands) or not commands:
        return ["order.checks.commands is not a non-empty list"]
    found = []
    for i, command in enumerate(commands):
        at = f"order.checks.commands[{i}]"
        if not fields.is_object(command):
            found.append(f"{at} is not an object")
            continue
        if not fields.non_empty(command.get("name")):
            found.append(f"{at}.name is not a non-empty string")
        argv = command.get("argv")
        if not (fields.is_list(argv) and argv and all(fields.is_string(item) for item in argv)):
            found.append(f"{at}.argv is not a non-empty list of strings")
    return found


def _acceptor_ok(acceptor: Any) -> bool:
    if not fields.is_object(acceptor):
        return False
    if acceptor.get("kind") == "person":
        return fields.non_empty(acceptor.get("name"))
    return acceptor.get("kind") == "checks"


def _from_task_ok(from_task: Any) -> bool:
    return fields.is_object(from_task) and fields.non_empty(from_task.get("run_id")) and fields.non_empty(from_task.get("task_id"))


def body_reasons(order: Any) -> list[str]:
    if not fields.is_object(order):
        return ["order is not an object"]
    found = []
    for name in ("what", "repository"):
        if not fields.non_empty(order.get(name)):
            found.append(f"order.{name} is not a non-empty string")
    if not fields.is_hex(order.get("base"), 40):
        found.append("order.base is not 40 lowercase hexadecimal characters")
    if not fields.non_empty_strings(order.get("territory")):
        found.append("order.territory is not a non-empty list of non-empty strings")
    checks = order.get("checks")
    if not (fields.is_object(checks) and "commands" in checks):
        found.append("order.checks is not an object holding commands")
    else:
        found += _command_reasons(checks["commands"])
    budget = order.get("budget")
    if not fields.is_object(budget):
        found.append("order.budget is not an object")
    elif not fields.null_or(budget, "cap_usd", fields.is_amount):
        found.append("order.budget.cap_usd is not a finite number of zero or more, or null")
    if not fields.null_or(order, "deadline", fields.is_time):
        found.append("order.deadline is not an ISO 8601 time, or null")
    if not _acceptor_ok(order.get("acceptor")):
        found.append('order.acceptor is not { kind: "person", name } or { kind: "checks" }')
    payment = order.get("payment")
    if not (fields.is_object(payment) and payment.get("kind") == "none"):
        found.append('order.payment is not { kind: "none" }')
    if not fields.null_or(order, "from_task", _from_task_ok):
        found.append("order.from_task is not { run_id, task_id }, or null")
    return found


def _checks_hash_reasons(document: dict[str, Any]) -> list[str]:
    order = document.get("order")
    checks = order.get("checks") if fields.is_object(order) else None
    if not fields.is_object(checks):
        return []
    try:
        actual = document_hash(checks)
    except (CanonicalError, RecursionError):
        return ["order.checks cannot be hashed"]
    return [] if actual == document.get("checks_hash") else ["checks_hash is not the hash of order.checks"]


def reasons(document: Any) -> list[str]:
    if not fields.is_object(document):
        return fields.not_a_document("a work order")
    found = fields.head_reasons(document, SCHEMA, ("order_id",))
    found += body_reasons(document.get("order"))
    found += fields.hash_reasons(document, "order", "order")
    found += _checks_hash_reasons(document)
    found += fields.key_id_reasons(document)
    message = fields.signed_bytes(LABEL, document, ("order_id", "content_hash"))
    return found + fields.signature_reasons(document, message, "work order")


def check(document: dict[str, Any], text: str) -> tuple[str, list[str]]:
    return KIND, reasons(document)
