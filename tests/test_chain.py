"""The four documents of a receipt of version two: each checked as its own kind, and the roles it names."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tick_verify import verify_document

_VECTORS = Path(__file__).resolve().parent.parent / "vectors"
_EXPECTED = json.loads((_VECTORS / "expected.json").read_text("utf-8"))

# role in the receipt's body, kind of the document, the field holding its signed body, the reason a changed body gives
_PARTS = (
    ("order", "work-order", "order", "content_hash is not the hash of the order"),
    ("delivery", "delivery", "delivery", "content_hash is not the hash of the delivery"),
    ("check", "check-record", "record", "content_hash is not the hash of the record"),
)
_ROLES = (("buyer", "order"), ("doer", "delivery"), ("checker", "check"))


def _valid_receipts() -> list[tuple[str, dict]]:
    found = []
    for name, expected in _EXPECTED.items():
        if expected["valid"] and expected["kind"] == "receipt":
            document = json.loads((_VECTORS / name).read_text("utf-8"))
            if document["schema"] == "tick.receipt.v2":
                found.append((name, document))
    return found


def _change_a_byte(value):
    """The same body with one character of its first string changed."""
    if isinstance(value, str):
        return ("1" if value[:1] == "0" else "0") + value[1:]
    if isinstance(value, list):
        for i, item in enumerate(value):
            changed = _change_a_byte(item)
            if changed is not None:
                return value[:i] + [changed] + value[i + 1 :]
        return None
    if isinstance(value, dict):
        for key in sorted(value):
            changed = _change_a_byte(value[key])
            if changed is not None:
                return {**value, key: changed}
    return None


class Chain(unittest.TestCase):
    def test_there_are_valid_receipts_of_version_two(self) -> None:
        self.assertGreater(len(_valid_receipts()), 0)

    def test_each_embedded_document_is_valid_as_its_own_kind(self) -> None:
        for name, receipt in _valid_receipts():
            for role, kind, _, _ in _PARTS:
                with self.subTest(name, role=role):
                    verdict = verify_document(json.dumps(receipt["receipt"][role]))
                    self.assertEqual((verdict.kind, verdict.valid, verdict.reasons), (kind, True, []))

    def test_one_changed_byte_in_a_signed_body_is_invalid(self) -> None:
        for name, receipt in _valid_receipts():
            for role, kind, body, reason in _PARTS:
                with self.subTest(name, role=role):
                    document = dict(receipt["receipt"][role])
                    document[body] = _change_a_byte(document[body])
                    verdict = verify_document(json.dumps(document))
                    self.assertEqual(verdict.kind, kind)
                    self.assertFalse(verdict.valid)
                    self.assertIn(reason, verdict.reasons)

    def test_a_changed_embedded_document_is_reported_with_its_role(self) -> None:
        name, receipt = _valid_receipts()[0]
        document = json.loads(json.dumps(receipt))
        document["receipt"]["order"]["order"]["what"] += "!"
        verdict = verify_document(json.dumps(document))
        self.assertFalse(verdict.valid)
        self.assertIn("order: content_hash is not the hash of the order", verdict.reasons)

    def test_the_roles_are_the_key_ids_the_documents_carry(self) -> None:
        for name, receipt in _valid_receipts():
            with self.subTest(name):
                signers = verify_document(json.dumps(receipt)).signers
                self.assertIsNotNone(signers)
                expected = {role: receipt["receipt"][part]["key_id"] for role, part in _ROLES}
                expected["acceptor"] = receipt["key_id"]
                self.assertEqual(signers.roles, expected)
                order = ("buyer", "doer", "checker", "acceptor")
                groups = []
                for key_id in dict.fromkeys(expected.values()):
                    group = [role for role in order if expected[role] == key_id]
                    if len(group) > 1:
                        groups.append(group)
                self.assertEqual(signers.shared, groups)

    def test_only_a_receipt_of_version_two_names_signers(self) -> None:
        name = next(n for n, e in _EXPECTED.items() if e["kind"] == "release-receipt")
        self.assertIsNone(verify_document((_VECTORS / name).read_text("utf-8")).signers)

    def test_a_document_that_is_missing_is_reported_by_its_first_reason(self) -> None:
        _, receipt = _valid_receipts()[0]
        document = json.loads(json.dumps(receipt))
        del document["receipt"]["check"]
        reasons = verify_document(json.dumps(document)).reasons
        self.assertIn("check: it is not a check record: it is not a JSON object", reasons)


class Shapes(unittest.TestCase):
    """Every failure is reported, not only the first."""

    def test_a_work_order_with_every_field_wrong(self) -> None:
        _, receipt = _valid_receipts()[0]
        document = json.loads(json.dumps(receipt["receipt"]["order"]))
        document["alg"] = "rsa"
        document["issued_at"] = "2026-02-30T00:00:00Z"
        document["order"] = {"what": "", "base": "ABC", "territory": [], "checks": {"commands": [{"name": "", "argv": []}]}}
        reasons = verify_document(json.dumps(document)).reasons
        for reason in (
            "the algorithm is rsa, not ed25519",
            "issued_at is not an ISO 8601 time",
            "order.what is not a non-empty string",
            "order.repository is not a non-empty string",
            "order.base is not 40 lowercase hexadecimal characters",
            "order.territory is not a non-empty list of non-empty strings",
            "order.checks.commands[0].name is not a non-empty string",
            "order.checks.commands[0].argv is not a non-empty list of strings",
            "order.budget is not an object",
            "order.deadline is not an ISO 8601 time, or null",
            "order.acceptor is not { kind: \"person\", name } or { kind: \"checks\" }",
            "order.payment is not { kind: \"none\" }",
            "order.from_task is not { run_id, task_id }, or null",
            "content_hash is not the hash of the order",
            "checks_hash is not the hash of order.checks",
        ):
            self.assertIn(reason, reasons)

    def test_a_check_record_whose_verdict_contradicts_it(self) -> None:
        _, receipt = _valid_receipts()[0]
        document = json.loads(json.dumps(receipt["receipt"]["check"]))
        document["record"]["territory_held"] = False
        self.assertIn(
            "record.verdict is passed, but record.territory_held is false", verify_document(json.dumps(document)).reasons
        )

    def test_a_key_that_does_not_decode_is_a_reason(self) -> None:
        _, receipt = _valid_receipts()[0]
        document = json.loads(json.dumps(receipt["receipt"]["delivery"]))
        document["key"] = "not base64!"
        reasons = verify_document(json.dumps(document)).reasons
        self.assertIn("key_id is not the carried key’s", reasons)
        self.assertIn("the signature is not the carried key’s over this delivery", reasons)
