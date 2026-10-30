"""Registers each document's check under its schema in CHECKS."""

from __future__ import annotations

from . import CHECKS
from .kinds import check_record, delivery, receipt_v1, receipt_v2, release_receipt, work_order

for _module in (receipt_v1, work_order, delivery, check_record, receipt_v2, release_receipt):
    CHECKS[_module.SCHEMA] = _module.check
