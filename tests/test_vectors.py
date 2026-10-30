"""Every vector in vectors/expected.json: the kind, the verdict and the reasons verify_document gives."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tick_verify import verify_document

_VECTORS = Path(__file__).resolve().parent.parent / "vectors"
_EXPECTED = json.loads((_VECTORS / "expected.json").read_text("utf-8"))


class Vectors(unittest.TestCase):
    def test_every_file_gets_its_kind_validity_and_reasons(self) -> None:
        self.assertGreater(len(_EXPECTED), 0)
        for name, expected in _EXPECTED.items():
            with self.subTest(name):
                verdict = verify_document((_VECTORS / name).read_text("utf-8"))
                self.assertEqual(verdict.kind, expected["kind"])
                self.assertEqual(verdict.valid, expected["valid"])
                self.assertEqual(sorted(verdict.reasons), sorted(expected["reasons"]))

    def test_the_vectors_hold_both_verdicts(self) -> None:
        verdicts = {expected["valid"] for expected in _EXPECTED.values()}
        self.assertEqual(verdicts, {True, False})
        for name, expected in _EXPECTED.items():
            self.assertEqual(expected["valid"], expected["reasons"] == [], name)

    def test_the_vectors_hold_both_receipt_kinds(self) -> None:
        self.assertIn("receipt", {e["kind"] for e in _EXPECTED.values()})
        self.assertIn("release-receipt", {e["kind"] for e in _EXPECTED.values()})


class Unreadable(unittest.TestCase):
    def test_what_is_not_a_document_is_unknown(self) -> None:
        self.assertEqual(verify_document("[]").reasons, ["it is not a Tick document: it is not a JSON object"])
        self.assertEqual(
            verify_document('{"schema":"tick.nope"}').reasons,
            ['the schema is "tick.nope", which this verifier does not know'],
        )

    def test_a_bad_key_or_signature_is_a_reason_not_an_exception(self) -> None:
        path = next(n for n, e in _EXPECTED.items() if e["valid"] and e["kind"] == "release-receipt")
        document = json.loads((_VECTORS / path).read_text("utf-8"))
        for field, value in (("key", "!!"), ("key", 5), ("signature", "AAAA"), ("signature", None)):
            with self.subTest(field=field, value=value):
                verdict = verify_document(json.dumps({**document, field: value}))
                self.assertFalse(verdict.valid)
                self.assertIn("the signature is not the carried key’s over this release receipt", verdict.reasons)
