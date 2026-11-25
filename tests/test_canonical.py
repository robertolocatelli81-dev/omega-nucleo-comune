# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""The two canonical forms. Unit cases from aee-verifier tests/test_units.py (0d8cee1) that are not RFC text; the
RFC 8785 vectors are in test_vectors_rfc8785.py."""
import json
import math
import random
import unittest

import _common  # noqa: F401
from nucleo.canonical import JCSError, canonical_json_jcs, canonical_json_sorted_ascii, format_number, utf16_key


def rand_value(rnd, depth=0):
    r = rnd.random()
    if depth > 4 or r < 0.4:
        return rnd.choice([None, True, False, rnd.randint(-2 ** 53 + 1, 2 ** 53 - 1), rnd.randint(-9, 9),
                           rnd.uniform(-1e6, 1e6), rnd.choice([1e-7, 1e21, 5e-324, 1.7976931348623157e308, -0.0]),
                           rand_str(rnd)])
    if r < 0.7:
        return [rand_value(rnd, depth + 1) for _ in range(rnd.randint(0, 4))]
    return {rand_str(rnd): rand_value(rnd, depth + 1) for _ in range(rnd.randint(0, 4))}


def rand_str(rnd):
    return "".join(rnd.choice('aZ0"\\/\b\f\n\r\t\x00\x1f\x7f é€ דּ\U0001F600') for _ in range(rnd.randint(0, 5)))


class SortedAscii(unittest.TestCase):
    def test_same_bytes_as_the_current_formats(self):
        """Generative: the bytes of json.dumps(sort_keys=True, separators=(",", ":")).encode() for every value
        without NaN / Infinity (cryptovalid canonical_payload, ap2-evidence-pack)."""
        rnd = random.Random(20261125)
        for i in range(2000):
            v = rand_value(rnd)
            old = json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
            self.assertEqual(canonical_json_sorted_ascii(v), old, i)

    def test_nan_and_infinity_refused(self):
        for x in (float("nan"), float("inf"), float("-inf")):
            self.assertIn(b"N" if math.isnan(x) else b"Infinity", json.dumps([x]).encode())   # control: the old form
            with self.assertRaises(ValueError):
                canonical_json_sorted_ascii({"a": [x]})

    def test_ascii_only(self):
        self.assertEqual(canonical_json_sorted_ascii({"b": "\U0001F600", "a": "é"}), b'{"a":"\\u00e9","b":"\\ud83d\\ude00"}')


class Jcs(unittest.TestCase):
    def test_number_boundaries(self):
        cases = {1e21: "1e+21", 1e20: "100000000000000000000", 123456789012345680000.0: "123456789012345680000",
                 1e-7: "1e-7", 1e-6: "0.000001", 0.1: "0.1", 123.456: "123.456", -123.456: "-123.456",
                 1.5e-10: "1.5e-10", 2.5e22: "2.5e+22", 1.0: "1", 10.0: "10", -0.0: "0", 0.5: "0.5", 100.25: "100.25",
                 12345678901234567890.0: "12345678901234567000"}
        for x, expected in cases.items():
            self.assertEqual(format_number(x), expected, repr(x))
        self.assertEqual(format_number(0), "0")
        self.assertEqual(format_number(-7), "-7")
        self.assertEqual(format_number(9007199254740991), "9007199254740991")

    def test_integers_outside_the_i_json_range_are_refused(self):
        for bad in (2 ** 53, -(2 ** 53), 2 ** 53 + 1, 21772799756798912, 10 ** 21, -(10 ** 21), 10 ** 400):
            with self.assertRaises(JCSError, msg=repr(bad)):
                format_number(bad)
        self.assertEqual(format_number(2 ** 53 - 1), "9007199254740991")

    def test_number_errors(self):
        for bad in (float("nan"), float("inf"), float("-inf"), True, False):
            with self.assertRaises(JCSError):
                format_number(bad)

    def test_string_escapes(self):
        self.assertEqual(canonical_json_jcs("\b\t\n\f\r"), b'"\\b\\t\\n\\f\\r"')
        self.assertEqual(canonical_json_jcs("\x00\x01\x1f"), b'"\\u0000\\u0001\\u001f"')
        self.assertEqual(canonical_json_jcs('"\\/'), b'"\\"\\\\/"')
        self.assertEqual(canonical_json_jcs("\x7f é"), '"\x7f é"'.encode("utf-8"))
        with self.assertRaises(JCSError):
            canonical_json_jcs("\ud800")

    def test_structures(self):
        self.assertEqual(canonical_json_jcs({}), b"{}")
        self.assertEqual(canonical_json_jcs([]), b"[]")
        self.assertEqual(canonical_json_jcs({"b": [1, {"d": None, "c": True}], "a": False}),
                         b'{"a":false,"b":[1,{"c":true,"d":null}]}')
        for bad in ({1: 2}, object(), (1, 2), {"a": {1}}, b"x"):
            with self.assertRaises(JCSError, msg=repr(bad)):
                canonical_json_jcs(bad)

    def test_utf16_order_differs_from_code_point_order(self):
        self.assertLess(utf16_key("\U0001F600"), utf16_key("דּ"))
        self.assertGreater("\U0001F600", "דּ")   # control: Python's own order (sort_keys) is the other one
        self.assertNotEqual(canonical_json_jcs({"\U0001F600": 1, "דּ": 2}),
                            json.dumps({"\U0001F600": 1, "דּ": 2}, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False).encode())

    def test_generative_round_trip_and_fixed_point(self):
        rnd = random.Random(20261126)
        for i in range(2000):
            v = rand_value(rnd)
            out = canonical_json_jcs(v)
            back = json.loads(out.decode("utf-8"))
            self.assertEqual(back, json.loads(json.dumps(v)), i)
            self.assertEqual(canonical_json_jcs(back), out, i)
            for obj in _objects(back):
                keys = list(obj)
                self.assertEqual(keys, sorted(keys, key=utf16_key), i)


def _objects(v):
    stack = [v]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            yield x
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)


if __name__ == "__main__":
    unittest.main()
