"""The canonical form and the document hash, held to spec/SPEC.md's own examples and to JavaScript's way of writing numbers."""

from __future__ import annotations

import math
import unittest

from tick_verify import CanonicalError, canonical, content_hash, document_hash


class Canonical(unittest.TestCase):
    def test_the_specifications_example(self) -> None:
        self.assertEqual(canonical({"a": 1}), '{"a":1}')
        self.assertEqual(
            document_hash({"a": 1}),
            "3dc4eef510cec9eda1ca361042e8152bd62c44288af2d9cc465cc217c381facd",
        )
        self.assertEqual(
            content_hash({"a": 1}),
            "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862",
        )

    def test_numbers_are_written_as_javascript_writes_them(self) -> None:
        cases = {
            100.0: "100",
            -0.0: "0",
            0.1: "0.1",
            1e21: "1e+21",
            1e20: "100000000000000000000",
            1e-7: "1e-7",
            1e-6: "0.000001",
            1.5e22: "1.5e+22",
            5e-324: "5e-324",
            9.621933333333333: "9.621933333333333",
        }
        for value, text in cases.items():
            with self.subTest(value=value):
                self.assertEqual(canonical(value), text)

    def test_keys_are_sorted_by_utf16_code_units_and_order_of_insertion_changes_nothing(self) -> None:
        self.assertEqual(canonical({"b": 1, "a": [2, None, True]}), '{"a":[2,null,true],"b":1}')
        # U+FF61 sorts after U+1F600 by code point, but before it by UTF-16 code units.
        self.assertEqual(canonical({"\U0001f600": 1, "｡": 2}), '{"\U0001f600":1,"｡":2}')

    def test_strings_escape_as_json_stringify_does(self) -> None:
        self.assertEqual(canonical('a"b\\c\n\u0001é'), '"a\\"b\\\\c\\n\\u0001é"')

    def test_a_value_no_json_holds_has_no_canonical_form(self) -> None:
        loop: list[object] = []
        loop.append(loop)
        for value in (math.nan, math.inf, loop, {1: "x"}, object()):
            with self.subTest(value=repr(value)[:20]):
                with self.assertRaises(CanonicalError):
                    canonical(value)


if __name__ == "__main__":
    unittest.main()
