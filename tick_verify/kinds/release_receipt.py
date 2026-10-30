"""A release receipt, tick.release-receipt.v1: what a release made, signed by the coordinator that made it."""

from __future__ import annotations

import re
from typing import Any

from . import fields

SCHEMA = "tick.release-receipt.v1"
KIND = "release-receipt"
LABEL = "tick-release-receipt:v1"

_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", re.ASCII)
_VERSION_REASON = (
    "release.version is not three dot-separated numbers and an optional - or + suffix of letters, "
    "digits, dots and hyphens, in at most 64 characters"
)
_FIELDS = (
    "version", "gated", "base", "commit", "tarball", "tarball_sha256", "shasum",
    "pushed", "record_sha256", "gate_check_sha256", "gate_summary_sha256", "task_receipt_hash",
)  # fmt: skip


def body_reasons(release: Any) -> list[str]:
    if not fields.is_object(release):
        return ["release is not an object"]
    found = []
    version = release.get("version")
    if not (isinstance(version, str) and len(version) <= 64 and _VERSION.fullmatch(version)):
        found.append(_VERSION_REASON)
    for name in ("gated", "commit", "shasum"):
        if not fields.is_hex(release.get(name), 40):
            found.append(f"release.{name} is not 40 lowercase hexadecimal characters")
    if not fields.null_or(release, "base", lambda v: fields.is_hex(v, 40)):
        found.append("release.base is not 40 lowercase hexadecimal characters or null")
    if not fields.non_empty(release.get("tarball")):
        found.append("release.tarball is not a non-empty string")
    for name in ("tarball_sha256", "record_sha256", "gate_check_sha256", "gate_summary_sha256", "task_receipt_hash"):
        if not fields.is_hex(release.get(name), 64):
            found.append(f"release.{name} is not 64 lowercase hexadecimal characters")
    if not fields.non_empty_strings(release.get("pushed")):
        found.append("release.pushed is not a non-empty list of non-empty strings")
    for name in release:
        if name not in _FIELDS:
            found.append(f"release.{name} is not a field of a release")
    return found


def reasons(document: Any) -> list[str]:
    if not fields.is_object(document):
        return fields.not_a_document("a release receipt")
    found = fields.head_reasons(document, SCHEMA, ("run_id", "task_id"))
    found += body_reasons(document.get("release"))
    found += fields.hash_reasons(document, "release", "release")
    found += fields.key_id_reasons(document)
    message = fields.signed_bytes(LABEL, document, ("run_id", "task_id", "content_hash"))
    return found + fields.signature_reasons(document, message, "release receipt")


def check(document: dict[str, Any], text: str) -> tuple[str, list[str]]:
    return KIND, reasons(document)
