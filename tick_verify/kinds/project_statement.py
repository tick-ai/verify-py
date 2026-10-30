"""A project's statement, tick.project-receipt.v2: every try of every task of one project and what each cost, signed."""

from __future__ import annotations

from typing import Any

from . import fields

SCHEMA = "tick.project-receipt.v2"
KIND = "project-statement"
LABEL = "tick-project-receipt:v2"

_COSTS = ("metered", "reported", "unknown")
_TOTALS = ("tries", "tries_unknown", "usd_micros_reported", "usd_micros_metered")
_EXACT = 2**53


def _try_reasons(attempt: Any, at: str) -> list[str]:
    if not fields.is_object(attempt):
        return [f"{at} is not an object"]
    found = []
    for name in ("attempt_id", "agent", "outcome"):
        if not fields.non_empty(attempt.get(name)):
            found.append(f"{at}.{name} is not a non-empty string")
    if not fields.null_or(attempt, "model", fields.is_string):
        found.append(f"{at}.model is not a string or null")
    if not fields.null_or(attempt, "minutes", fields.is_amount):
        found.append(f"{at}.minutes is not a finite number of zero or more, or null")
    if not fields.null_or(attempt, "usd_micros", fields.is_count):
        found.append(f"{at}.usd_micros is not a whole number of zero or more, or null")
    cost = attempt.get("cost")
    if cost not in _COSTS:
        found.append(f"{at}.cost is not metered, reported or unknown")
    if "usd_micros" in attempt:
        if cost == "unknown" and attempt["usd_micros"] is not None:
            found.append(f"{at}.cost is unknown, but its usd_micros is not null")
        if attempt["usd_micros"] is None and cost != "unknown":
            found.append(f"{at}.usd_micros is null, but its cost is {fields.describe(attempt, 'cost')}")
    return found


def _task_reasons(task: Any, i: int, task_ids: list[Any]) -> list[str]:
    at = f"statement.tasks[{i}]"
    if not fields.is_object(task):
        return [f"{at} is not an object"]
    found = []
    for name in ("task_id", "type"):
        if not fields.non_empty(task.get(name)):
            found.append(f"{at}.{name} is not a non-empty string")
    step_of = task.get("step_of")
    others = [other for j, other in enumerate(task_ids) if j != i and fields.non_empty(other)]
    if "step_of" not in task or not (step_of is None or (isinstance(step_of, str) and step_of in others)):
        found.append(f"{at}.step_of is not the task_id of another task of the statement, or null")
    for name in ("final_state", "disposition"):
        if not fields.null_or(task, name, fields.is_string):
            found.append(f"{at}.{name} is not a string or null")
    if not fields.null_or(task, "receipt", lambda v: fields.is_hex(v, 64)):
        found.append(f"{at}.receipt is not 64 lowercase hexadecimal characters, or null")
    tries = task.get("tries")
    if not fields.is_list(tries):
        return found + [f"{at}.tries is not a list"]
    for j, attempt in enumerate(tries):
        found += _try_reasons(attempt, f"{at}.tries[{j}]")
    return found


def _total_reasons(totals: dict[str, Any], tasks: list[Any]) -> list[str]:
    """Each total added up again from the tries, once every task and try has the shape asked of it."""
    tries = [attempt for task in tasks for attempt in task["tries"]]
    sums = {
        "tries": len(tries),
        "tries_unknown": sum(1 for attempt in tries if attempt["cost"] == "unknown"),
        "usd_micros_reported": sum(a["usd_micros"] for a in tries if a["cost"] == "reported"),
        "usd_micros_metered": sum(a["usd_micros"] for a in tries if a["cost"] == "metered"),
    }
    found = []
    inexact = False
    for name in _TOTALS:
        if sums[name] > _EXACT:
            inexact = True
        elif isinstance(totals.get(name), bool) or totals.get(name) != sums[name]:
            found.append(f"statement.totals.{name} is not the sum of the tries")
    if inexact:
        found.append("statement.totals cannot be added up exactly: a sum passes 2^53")
    return found


def body_reasons(statement: Any, run_id: Any) -> list[str]:
    if not fields.is_object(statement):
        return ["statement is not an object"]
    found = []
    run = statement.get("run")
    if not (fields.is_object(run) and fields.non_empty(run.get("run_id"))):
        found.append("statement.run is not an object holding a run_id")
    elif run["run_id"] != run_id:
        found.append("run_id is not the statement’s run")
    tasks = statement.get("tasks")
    task_reasons: list[str] = []
    if not fields.is_list(tasks):
        found.append("statement.tasks is not a list")
    else:
        task_ids = [task.get("task_id") if fields.is_object(task) else None for task in tasks]
        for i, task in enumerate(tasks):
            task_reasons += _task_reasons(task, i, task_ids)
        found += task_reasons
    totals = statement.get("totals")
    if not fields.is_object(totals):
        found.append("statement.totals is not an object")
    else:
        found += [f"statement.totals.{name} is not a whole number of zero or more" for name in _TOTALS if not fields.is_count(totals.get(name))]
    if not fields.null_or(statement, "previous", lambda v: fields.is_hex(v, 64)):
        found.append("statement.previous is not 64 lowercase hexadecimal characters, or null")
    if not fields.is_hex(statement.get("ledger_hash"), 64):
        found.append("statement.ledger_hash is not 64 lowercase hexadecimal characters")
    if fields.is_list(tasks) and not task_reasons and fields.is_object(totals):
        found += _total_reasons(totals, tasks)
    return found


def reasons(document: Any) -> list[str]:
    if not fields.is_object(document):
        return fields.not_a_document("a project statement")
    found = fields.head_reasons(document, SCHEMA, ("run_id",))
    found += body_reasons(document.get("statement"), document.get("run_id"))
    found += fields.hash_reasons(document, "statement", "statement")
    found += fields.key_id_reasons(document)
    message = fields.signed_bytes(LABEL, document, ("run_id", "content_hash"))
    return found + fields.signature_reasons(document, message, "statement")


def check(document: dict[str, Any], text: str) -> tuple[str, list[str]]:
    return KIND, reasons(document)
