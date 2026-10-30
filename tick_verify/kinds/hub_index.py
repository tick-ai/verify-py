"""A company's index of its published projects, tick.hub-index.v1: which statements of which runs it shows, signed."""

from __future__ import annotations

import re
from typing import Any

from . import fields

SCHEMA = "tick.hub-index.v1"
KIND = "hub-index"
LABEL = "tick-hub-index:v1"

_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*", re.ASCII)


def _twice(values: list[Any]) -> bool:
    return len(set(values)) != len(values)


def _run_reasons(run: Any, at: str) -> list[str]:
    if not fields.is_object(run):
        return [f"{at} is not an object"]
    found = []
    if not fields.non_empty(run.get("run_id")):
        found.append(f"{at}.run_id is not a non-empty string")
    statements = run.get("statements")
    if not (fields.is_list(statements) and statements and all(fields.is_hex(s, 64) for s in statements)):
        found.append(f"{at}.statements is not a non-empty list of 64 lowercase hexadecimal characters each")
    elif _twice(statements):
        found.append(f"{at}.statements names one statement twice")
    newest = statements[-1] if fields.is_list(statements) and statements else None
    if newest is None or run.get("head") != newest:
        found.append(f"{at}.head is not the newest of its statements")
    return found


def _project_reasons(project: Any, at: str) -> list[str]:
    if not fields.is_object(project):
        return [f"{at} is not an object"]
    found = []
    slug = project.get("slug")
    if not (isinstance(slug, str) and _SLUG.fullmatch(slug)):
        found.append(f"{at}.slug is not lowercase letters and digits joined by single hyphens")
    for name in ("name", "repository"):
        if not fields.non_empty(project.get(name)):
            found.append(f"{at}.{name} is not a non-empty string")
    runs = project.get("runs")
    if not (fields.is_list(runs) and runs):
        return found + [f"{at}.runs is not a non-empty list"]
    if _twice([run["run_id"] for run in runs if fields.is_object(run) and fields.non_empty(run.get("run_id"))]):
        found.append(f"{at}.runs names one run twice")
    for j, run in enumerate(runs):
        found += _run_reasons(run, f"{at}.runs[{j}]")
    return found


def body_reasons(index: Any) -> list[str]:
    if not fields.is_object(index):
        return ["index is not an object"]
    found = []
    if not fields.non_empty(index.get("publisher")):
        found.append("index.publisher is not a non-empty string")
    if not fields.null_or(index, "previous", lambda v: fields.is_hex(v, 64)):
        found.append("index.previous is not 64 lowercase hexadecimal characters, or null")
    projects = index.get("projects")
    if not fields.is_list(projects):
        return found + ["index.projects is not a list"]
    for i, project in enumerate(projects):
        found += _project_reasons(project, f"index.projects[{i}]")
    slugs = [p["slug"] for p in projects if fields.is_object(p) and isinstance(p.get("slug"), str)]
    if _twice(slugs):
        found.append("index.projects names one slug twice")
    elif slugs != sorted(slugs, key=lambda s: s.encode("utf-16-be", "surrogatepass")):
        found.append("index.projects is not sorted by slug")
    return found


def reasons(document: Any) -> list[str]:
    if not fields.is_object(document):
        return fields.not_a_document("an index")
    found = fields.head_reasons(document, SCHEMA)
    found += body_reasons(document.get("index"))
    found += fields.hash_reasons(document, "index", "index")
    found += fields.key_id_reasons(document)
    message = fields.signed_bytes(LABEL, document, ("content_hash",))
    return found + fields.signature_reasons(document, message, "index")


def check(document: dict[str, Any], text: str) -> tuple[str, list[str]]:
    return KIND, reasons(document)
