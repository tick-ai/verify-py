"""A task receipt, tick.receipt.v1: the ledger of one accepted task, signed."""

from __future__ import annotations

from typing import Any

from . import fields

SCHEMA = "tick.receipt.v1"
KIND = "receipt"
LABEL = "tick-task-receipt:v1"


def reasons(document: Any) -> list[str]:
    if not fields.is_object(document):
        return fields.not_a_document("a task receipt")
    found = [] if document.get("schema") == SCHEMA else [f"the schema is {fields.describe(document, 'schema')}, not {SCHEMA}"]
    found += fields.alg_reasons(document)
    ledger = document.get("ledger")
    run = ledger.get("run") if fields.is_object(ledger) else None
    task = ledger.get("task") if fields.is_object(ledger) else None
    if not (fields.is_object(run) and fields.is_object(task)):
        return found + ["the ledger is missing its run or its task"]
    found += fields.hash_reasons(document, "ledger", "ledger")
    if not (document.get("run_id") == task.get("run_id") == run.get("run_id")):
        found.append("run_id is not the ledger’s run")
    if document.get("task_id") != task.get("task_id"):
        found.append("task_id is not the ledger’s task")
    found += fields.key_id_reasons(document)
    message = fields.signed_bytes(LABEL, document, ("run_id", "task_id", "content_hash"))
    return found + fields.signature_reasons(document, message, "receipt")


def check(document: dict[str, Any], text: str) -> tuple[str, list[str]]:
    return KIND, reasons(document)
