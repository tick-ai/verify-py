"""Check a Tick document offline, without Tick's code: written from spec/SPEC.md alone.

verify_document(text) reads one document, picks its check by the document's own
"schema", and answers a Verdict: whether the document is the one that was
written, every reason it is not, and what the document says it does not
establish. It makes no network call and asks no one. Like the specification's
own verifier it cannot tell whether what a document says is true.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from .canonical import CanonicalError, canonical, content_hash, document_hash

__all__ = [
    "CanonicalError",
    "Verdict",
    "canonical",
    "content_hash",
    "document_hash",
    "verify_document",
    "CHECKS",
]


@dataclass(frozen=True)
class Verdict:
    """What a check found. kind names the document as the specification's verifier does."""

    kind: str
    valid: bool
    reasons: list[str] = field(default_factory=list)
    limits: list[str] = field(default_factory=list)


# One check per schema, each answering (kind, reasons) for a parsed document.
# The modules that fill this table are tick_verify/documents.py's: a schema
# missing from it is reported, never guessed at.
Check = Callable[[dict[str, Any], str], "tuple[str, list[str]]"]
CHECKS: dict[str, Check] = {}


def _limits(document: dict[str, Any]) -> list[str]:
    limits = document.get("limits")
    return [line for line in limits if isinstance(line, str)] if isinstance(limits, list) else []


def verify_document(text: str) -> Verdict:
    """Check one document's text; every failure is named, so a reader sees all that is wrong."""
    try:
        parsed = json.loads(text)
    except ValueError as error:
        return Verdict("unknown", False, [f"it is not JSON: {error}"])
    if not isinstance(parsed, dict):
        return Verdict("unknown", False, ["it is not a Tick document: it is not a JSON object"])
    schema = parsed.get("schema")
    check = CHECKS.get(schema) if isinstance(schema, str) else None
    if check is None:
        return Verdict(
            "unknown",
            False,
            # Written as JSON.stringify writes it (spec/SPEC.md): no ASCII escapes, no spaces.
            [f"the schema is {json.dumps(schema, ensure_ascii=False, separators=(',', ':'))}, which this verifier does not know"],
        )
    kind, reasons = check(parsed, text)
    return Verdict(kind, not reasons, reasons, _limits(parsed))
