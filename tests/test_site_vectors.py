"""verify_document held to a real `tick export --hub` folder and to one-field changes to it.

vectors/site-expected.json names each document with the verdict Tick's own
verifier gave it when these vectors were made. This repository's verifier was
written from spec/SPEC.md alone, so agreeing on documents it was never shown is
the proof that the specification is enough.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tick_verify import verify_document

VECTORS = Path(__file__).resolve().parent.parent / "vectors"


class SiteVectors(unittest.TestCase):
    def setUp(self) -> None:
        self.expected = json.loads((VECTORS / "site-expected.json").read_text(encoding="utf-8"))

    def test_every_document_gets_the_verdict_tick_gave_it(self) -> None:
        self.assertGreater(len(self.expected), 0)
        for name, want in sorted(self.expected.items()):
            with self.subTest(vector=name):
                verdict = verify_document((VECTORS / name).read_text(encoding="utf-8"))
                self.assertEqual(
                    (verdict.kind, verdict.valid, sorted(verdict.reasons)),
                    (want["kind"], want["valid"], sorted(want["reasons"])),
                )

    def test_the_vectors_hold_both_verdicts(self) -> None:
        self.assertEqual({want["valid"] for want in self.expected.values()}, {True, False})


if __name__ == "__main__":
    unittest.main()
