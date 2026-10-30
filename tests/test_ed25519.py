"""Ed25519 verification against RFC 8032 section 7.1's vectors and cases derived from them."""

from __future__ import annotations

import base64
import json
import unittest
from pathlib import Path

from tick_verify.ed25519 import public_key_from_spki, verify

_L = 2**252 + 27742317777372353535851937790883648493
_VECTORS = json.loads((Path(__file__).resolve().parent.parent / "vectors" / "ed25519.json").read_text("utf-8"))["vectors"]


def _flip(data: bytes, bit: int) -> bytes:
    out = bytearray(data)
    out[bit // 8] ^= 1 << (bit % 8)
    return bytes(out)


class Ed25519(unittest.TestCase):
    def cases(self):
        """The cases the file marks valid; the ones derived below start from these."""
        for i, v in enumerate(_VECTORS):
            if not v["valid"]:
                continue
            yield i, bytes.fromhex(v["public_key_raw"]), bytes.fromhex(v["message_hex"]), bytes.fromhex(v["signature_hex"]), v

    def test_there_are_six_cases(self) -> None:
        self.assertEqual(len(_VECTORS), 6)

    def test_the_case_marked_invalid_is_refused(self) -> None:
        # vectors/ed25519.json's case 5 is case 1 with the signature's first byte changed, and says "valid": false,
        # whatever the task's text says of all six; the file is what is held to.
        for i, v in enumerate(_VECTORS):
            if v["valid"]:
                continue
            with self.subTest(case=i):
                pk, msg, sig = (bytes.fromhex(v[k]) for k in ("public_key_raw", "message_hex", "signature_hex"))
                self.assertFalse(verify(pk, msg, sig), f"case {i}")
                good = bytes.fromhex(_VECTORS[1]["signature_hex"])
                self.assertEqual(sig[1:], good[1:], f"case {i}")
                self.assertTrue(verify(pk, msg, good), f"case {i}: the case it was made from")

    def test_every_valid_case_verifies(self) -> None:
        for i, pk, msg, sig, v in self.cases():
            with self.subTest(case=i):
                self.assertTrue(verify(pk, msg, sig), f"case {i}: raw key")
                spki = base64.b64decode(v["public_key_spki_base64"])
                self.assertEqual(public_key_from_spki(spki), pk, f"case {i}: SPKI key")
                self.assertTrue(verify(public_key_from_spki(spki), msg, sig), f"case {i}: SPKI key")

    def test_a_flipped_signature_bit_fails(self) -> None:
        for i, pk, msg, sig, _ in self.cases():
            for bit in (0, 100, 255, 256, 300, 511):
                with self.subTest(case=i, bit=bit):
                    self.assertFalse(verify(pk, msg, _flip(sig, bit)), f"case {i}, bit {bit}")

    def test_a_flipped_key_bit_fails(self) -> None:
        for i, pk, msg, sig, _ in self.cases():
            for bit in (0, 100, 254, 255):
                with self.subTest(case=i, bit=bit):
                    self.assertFalse(verify(_flip(pk, bit), msg, sig), f"case {i}, bit {bit}")

    def test_a_changed_or_added_message_byte_fails(self) -> None:
        for i, pk, msg, sig, _ in self.cases():
            with self.subTest(case=i):
                self.assertFalse(verify(pk, msg + b"\x00", sig), f"case {i}: added byte")
                if msg:
                    self.assertFalse(verify(pk, _flip(msg, 0), sig), f"case {i}: changed byte")

    def test_s_plus_l_fails(self) -> None:
        for i, pk, msg, sig, _ in self.cases():
            with self.subTest(case=i):
                s = int.from_bytes(sig[32:], "little")
                self.assertLess(s, _L)
                bad = sig[:32] + (s + _L).to_bytes(32, "little")
                self.assertFalse(verify(pk, msg, bad), f"case {i}")

    def test_s_equal_to_l_fails(self) -> None:
        _, pk, msg, sig, _ = next(self.cases())
        self.assertFalse(verify(pk, msg, sig[:32] + _L.to_bytes(32, "little")))

    def test_wrong_lengths_are_false(self) -> None:
        for i, pk, msg, sig, _ in self.cases():
            with self.subTest(case=i):
                self.assertFalse(verify(pk[:31], msg, sig), f"case {i}: 31-byte key")
                self.assertFalse(verify(pk + b"\x00", msg, sig), f"case {i}: 33-byte key")
                self.assertFalse(verify(pk, msg, sig[:31]), f"case {i}: 31-byte signature")
                self.assertFalse(verify(pk, msg, sig[:63]), f"case {i}: 63-byte signature")
                self.assertFalse(verify(pk, msg, sig + b"\x00"), f"case {i}: 65-byte signature")
                self.assertFalse(verify(b"\x00" * 65, msg, sig), f"case {i}: 65-byte key")

    def test_a_point_that_does_not_decode_is_false(self) -> None:
        _, pk, msg, sig, _ = next(self.cases())
        # y = 2 has no x on the curve; y = p is non-canonical; x = 0 (y = 1) with the sign bit set.
        p = 2**255 - 19
        for name, enc in (
            ("y=2", (2).to_bytes(32, "little")),
            ("y=p", p.to_bytes(32, "little")),
            ("x=0, sign set", ((1 << 255) | 1).to_bytes(32, "little")),
        ):
            with self.subTest(name=name):
                self.assertFalse(verify(enc, msg, sig))
                self.assertFalse(verify(pk, msg, enc + sig[32:]))

    def test_the_spki_prefix_is_accepted(self) -> None:
        key = bytes(range(32))
        prefix = bytes.fromhex("302a300506032b6570032100")
        self.assertEqual(public_key_from_spki(prefix + key), key)

    def test_a_wrong_spki_prefix_or_length_is_refused(self) -> None:
        key = bytes(range(32))
        prefix = bytes.fromhex("302a300506032b6570032100")
        bad = [
            b"",
            key,
            prefix + key[:31],
            prefix + key + b"\x00",
            _flip(prefix, 0) + key,
            bytes.fromhex("302a300506032b6571032100") + key,  # another OID (X25519 is ...656e; this is not Ed25519 either)
            bytes.fromhex("302a300506032b656e032100") + key,  # X25519
            bytes.fromhex("302a300506032b6570032101") + key,  # a bit string with unused bits
        ]
        for i, der in enumerate(bad):
            with self.subTest(i=i):
                with self.assertRaises(ValueError):
                    public_key_from_spki(der)


if __name__ == "__main__":
    unittest.main()
