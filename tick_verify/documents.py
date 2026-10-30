"""Registers each document's check under its schema in CHECKS."""

from __future__ import annotations

from . import CHECKS
from .kinds import (
    audit_export,
    audit_trail_export,
    check_record,
    delivery,
    hub_index,
    keys_file,
    project_statement,
    receipt_v1,
    receipt_v2,
    release_receipt,
    usage_report,
    work_order,
)

for _module in (
    receipt_v1,
    audit_export,
    audit_trail_export,
    usage_report,
    work_order,
    delivery,
    check_record,
    receipt_v2,
    release_receipt,
    project_statement,
    hub_index,
    keys_file,
):
    CHECKS[_module.SCHEMA] = _module.check
