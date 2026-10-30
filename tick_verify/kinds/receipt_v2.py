"""A receipt of version two, tick.receipt.v2: the acceptance, binding the order, the delivery and the check."""

from __future__ import annotations

from typing import Any

from . import check_record, delivery, fields, work_order

SCHEMA = "tick.receipt.v2"
KIND = "receipt"
LABEL = "tick-receipt:v2"

# The role each embedded document plays, with the check that is its own.
EMBEDDED = (("order", work_order, "buyer"), ("delivery", delivery, "doer"), ("check", check_record, "checker"))
ROLES = ("buyer", "doer", "checker", "acceptor")


def _body(document: Any, name: str) -> dict[str, Any]:
    """The signed body an embedded document carries, or an empty one where it carries none."""
    body = document.get(name) if fields.is_object(document) else None
    return body if fields.is_object(body) else {}


def _acceptance_reasons(acceptance: Any) -> list[str]:
    if not fields.is_object(acceptance):
        return ["receipt.acceptance is not an object"]
    found = []
    if acceptance.get("by") not in ("person", "auto-tick", "checks"):
        found.append("receipt.acceptance.by is not person, auto-tick or checks")
    if not fields.non_empty(acceptance.get("who")):
        found.append("receipt.acceptance.who is not a non-empty string")
    if not fields.is_time(acceptance.get("at")):
        found.append("receipt.acceptance.at is not an ISO 8601 time")
    return found


def _acceptor_reasons(acceptance: Any, order: dict[str, Any]) -> list[str]:
    if not fields.is_object(acceptance):
        return []
    acceptor = _body(order, "order").get("acceptor")
    acceptor = acceptor if fields.is_object(acceptor) else {}
    by = acceptance.get("by")
    if by == "checks":
        if acceptor.get("kind") != "checks":
            return ["the acceptance is by checks, but the order’s acceptor is not checks"]
        return []
    if by not in ("person", "auto-tick"):
        return []
    who = "a person" if by == "person" else "auto tick"
    if acceptor.get("kind") != "person":
        return [f"the acceptance is by {who}, but the order’s acceptor is not a person"]
    if acceptance.get("who") != acceptor.get("name"):
        return ["the acceptance is by a person the order does not name" if by == "person" else "the acceptance is by auto tick for a person the order does not name"]
    return []


def chain_reasons(body: dict[str, Any]) -> list[str]:
    """Each broken link between the three documents, checked when both of its documents are objects."""
    order, made, ran = body.get("order"), body.get("delivery"), body.get("check")
    found = []
    if fields.is_object(order) and fields.is_object(made):
        if _body(made, "delivery").get("order_hash") != order.get("content_hash"):
            found.append("the delivery’s order_hash is not the order’s content_hash")
        if _body(made, "delivery").get("base") != _body(order, "order").get("base"):
            found.append("the delivery’s base is not the order’s")
    if fields.is_object(order) and fields.is_object(ran):
        if _body(ran, "record").get("order_hash") != order.get("content_hash"):
            found.append("the check’s order_hash is not the order’s content_hash")
        if _body(ran, "record").get("checks_hash") != order.get("checks_hash"):
            found.append("the check’s checks_hash is not the order’s checks_hash")
    if fields.is_object(made) and fields.is_object(ran):
        for name in ("repository", "base", "commit", "tree"):
            if _body(ran, "record").get(name) != _body(made, "delivery").get(name):
                found.append(f"the check’s {name} is not the delivery’s")
    if fields.is_object(order):
        found += _acceptor_reasons(body.get("acceptance"), order)
    if fields.is_object(ran) and _body(ran, "record").get("verdict") == "failed":
        found.append("the receipt accepts a check whose verdict is failed")
    return found


def reasons(document: Any) -> list[str]:
    if not fields.is_object(document):
        return fields.not_a_document("a receipt")
    found = fields.head_reasons(document, SCHEMA, ("receipt_id",))
    body = document.get("receipt")
    if not fields.is_object(body):
        found.append("receipt is not an object")
    else:
        found += _acceptance_reasons(body.get("acceptance"))
        if not (fields.is_object(body.get("money")) and body["money"].get("kind") == "none"):
            found.append('receipt.money is not { kind: "none" }')
        for role, module, _ in EMBEDDED:
            found += [f"{role}: {reason}" for reason in module.reasons(body.get(role))]
        found += chain_reasons(body)
    found += fields.hash_reasons(document, "receipt", "receipt")
    found += fields.key_id_reasons(document)
    message = fields.signed_bytes(LABEL, document, ("receipt_id", "content_hash"))
    return found + fields.signature_reasons(document, message, "receipt")


def check(document: dict[str, Any], text: str) -> tuple[str, list[str]]:
    return KIND, reasons(document)


def signers(document: dict[str, Any]) -> tuple[dict[str, str | None], list[list[str]]]:
    """The key_id behind each role, computed from the key its document carries (None where it
    carries none), and each group of roles whose documents carry one key, in role order."""
    body = _body(document, "receipt")
    carriers = {role: body.get(name) for name, _, role in EMBEDDED}
    carriers["acceptor"] = document
    roles = {role: fields.key_id_of(carriers[role]) if fields.is_object(carriers[role]) else None for role in ROLES}
    shared: list[list[str]] = []
    for key_id in dict.fromkeys(k for k in roles.values() if k is not None):
        group = [role for role in ROLES if roles[role] == key_id]
        if len(group) > 1:
            shared.append(group)
    return roles, shared
