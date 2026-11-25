# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""json_loads_bounded: one depth bound on every Python and every encoding json.loads reads."""
import json
import random
import sys
import threading
import traceback
import tracemalloc
import unittest

import _common  # noqa: F401
from nucleo import jsonio
from nucleo.jsonio import (MAX_JSON_DEPTH, JsonTooDeep, JsonTooDeepToRead, json_loads_bounded,
                           json_nesting_depth)

ENCODINGS = ("utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be")


def ref_depth(value) -> int:
    """Nesting depth of a Python value (iterative): the oracle."""
    best, stack = 0, [(value, 1)]
    while stack:
        v, d = stack.pop()
        if isinstance(v, (list, dict)):
            best = max(best, d)
            stack.extend((x, d + 1) for x in (v.values() if isinstance(v, dict) else v))
    return best


def rand_str(rnd):
    return "".join(rnd.choice('ab"\\[]{}:,\u2201\u5b5b\U0001F600\n\t\x00 ') for _ in range(rnd.randint(0, 6)))


def rand_tree(rnd, depth):
    """A random value nested exactly `depth` deep (0 = a scalar)."""
    if depth == 0:
        return rnd.choice([None, True, False, 0, -7, 1.5, rand_str(rnd)])
    inner = rand_tree(rnd, depth - 1)
    siblings = [rand_tree(rnd, rnd.randint(0, min(2, depth - 1))) for _ in range(rnd.randint(0, 2))]
    if rnd.random() < 0.5:
        items = siblings + [inner]
        rnd.shuffle(items)
        return items
    d = {rand_str(rnd) + str(i): s for i, s in enumerate(siblings)}
    d[rand_str(rnd) + "#"] = inner
    return d


def deep(n):
    """A text nested n deep (n = 0: a scalar)."""
    return "[" * n + "]" * n if n else "1"


class Bound(unittest.TestCase):
    def test_positive_control_json_loads_has_no_bound_of_ours(self):
        self.assertEqual(ref_depth(json.loads(deep(MAX_JSON_DEPTH + 1))), MAX_JSON_DEPTH + 1)   # read: the bound is ours

    def test_the_bound(self):
        self.assertEqual(MAX_JSON_DEPTH, 512)
        self.assertEqual(json_loads_bounded(deep(512)), json.loads(deep(512)))
        for n in (513, 995, 10000, 100000):
            with self.assertRaises(JsonTooDeepToRead, msg=n) as cm:
                json_loads_bounded(deep(n))
            self.assertIsInstance(cm.exception, ValueError)
            self.assertIsInstance(cm.exception, RecursionError)
            self.assertIsInstance(cm.exception, JsonTooDeep)
        with self.assertRaises(RecursionError):   # control: what the bound spares the reader
            json.loads(deep(100000))

    def test_configurable(self):
        for bound in (0, 1, 2, 7, 600):
            self.assertEqual(json_loads_bounded(deep(bound), max_depth=bound), json.loads(deep(bound)))
            with self.assertRaises(JsonTooDeepToRead):
                json_loads_bounded(deep(bound + 1), max_depth=bound)
        self.assertEqual(json_loads_bounded("1", max_depth=0), 1)
        for bad in (-1, True, 1.0, "3", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                json_loads_bounded("1", max_depth=bad)

    def test_kwargs_reach_json_loads(self):
        self.assertEqual(json_loads_bounded('{"a":1,"a":2}', object_pairs_hook=list), [("a", 1), ("a", 2)])


class Encodings(unittest.TestCase):
    def test_every_encoding_json_loads_reads(self):
        for enc in ENCODINGS:
            for n in (0, 1, 512, 513):
                raw = deep(n).encode(enc)
                if n <= 512:
                    self.assertEqual(json_loads_bounded(raw), json.loads(raw), (enc, n))
                    self.assertEqual(json_loads_bounded(bytearray(raw)), json.loads(raw), (enc, n))
                else:
                    with self.assertRaises(JsonTooDeepToRead, msg=(enc, n)):
                        json_loads_bounded(raw)

    def test_brackets_hidden_from_a_byte_scan(self):
        """cryptovalid 0.29.0: in UTF-16 the code unit of U+2201 holds the byte 0x22 ("), so a scan of the bytes saw
        a string open and missed the brackets after it."""
        text = '["\u2201",' * 600 + "1" + "]" * 600
        for enc in ("utf-16-le", "utf-16-be", "utf-16"):
            raw = text.encode(enc)
            self.assertLess(json_nesting_depth(raw.decode("latin-1")), 513, enc)   # positive control: the byte scan
            with self.assertRaises(JsonTooDeepToRead, msg=enc):
                json_loads_bounded(raw)

    def test_lone_surrogates_decode_as_json_loads_does(self):
        raw = '["\ud800"]'.encode("utf-16-le", "surrogatepass")
        self.assertEqual(json_loads_bounded(raw), json.loads(raw))


class Generative(unittest.TestCase):
    def test_depth_matches_the_oracle(self):
        rnd = random.Random(20261125)
        for _ in range(400):
            tree = rand_tree(rnd, rnd.randint(0, 40))
            for ensure_ascii in (True, False):
                text = json.dumps(tree, ensure_ascii=ensure_ascii, indent=rnd.choice([None, 0, 1]))
                self.assertEqual(json_nesting_depth(text), ref_depth(tree), text[:80])

    def test_same_answer_as_json_loads_below_the_bound(self):
        """Random texts, many not JSON: below the bound the answer (value or exception class) is json.loads's."""
        rnd = random.Random(20261126)
        alphabet = '[]{}",:\\ 0123truefalsenul\u2201\U0001F600'
        for _i in range(3000):
            text = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 40)))
            if json_nesting_depth(text) > MAX_JSON_DEPTH:
                continue
            try:
                want = ("ok", json.loads(text))
            except Exception as e:  # noqa: BLE001
                want = ("err", type(e))
            try:
                got = ("ok", json_loads_bounded(text))
            except Exception as e:  # noqa: BLE001
                got = ("err", type(e))
            self.assertEqual(got, want, repr(text))

    def test_deep_random_trees_in_every_encoding(self):
        rnd = random.Random(20261127)
        for i in range(60):
            n = rnd.choice([rnd.randint(500, 512), rnd.randint(513, 700)])
            text = json.dumps(rand_tree(rnd, n), ensure_ascii=rnd.random() < 0.5)
            raw = text.encode(rnd.choice(ENCODINGS), "surrogatepass")
            if n <= MAX_JSON_DEPTH:
                self.assertEqual(json_loads_bounded(raw), json.loads(raw), i)
            else:
                with self.assertRaises(JsonTooDeepToRead, msg=i):
                    json_loads_bounded(raw)


class ConstantMemory(unittest.TestCase):
    def test_the_scan_does_not_grow_with_the_text(self):
        text = ('{"a":["x\\"[[[",' + '"\u2201"' + "]}") * 200000   # ~4 M characters, depth 2
        tracemalloc.start()
        try:
            self.assertEqual(json_nesting_depth(text), 2)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 64 * 1024)


class EveryInputIsScanned(unittest.TestCase):
    def test_a_bytearray_and_an_unterminated_string(self):
        with self.assertRaises(JsonTooDeepToRead):
            json_loads_bounded(bytearray(deep(513).encode("utf-8")))
        with self.assertRaises(JsonTooDeepToRead):   # the brackets before a string that never ends still count
            json_loads_bounded("[" * 513 + '"')
        with self.assertRaises(json.JSONDecodeError):
            json_loads_bounded("[" * 512 + '"')


def _from_frames_down(n, call):
    return _from_frames_down(n - 1, call) if n else call()


class TheCallersStack(unittest.TestCase):
    """A text within the bound is read wherever the caller stands in its own stack, on every Python."""

    def test_512_levels_from_600_frames_down(self):
        if sys.version_info < (3, 12):   # positive control: there the parser's levels count against the limit
            with self.assertRaises(RecursionError):
                _from_frames_down(600, lambda: json.loads(deep(512)))
        limit = sys.getrecursionlimit()
        self.assertEqual(_from_frames_down(600, lambda: json_loads_bounded(deep(512))), json.loads(deep(512)))
        self.assertEqual(sys.getrecursionlimit(), limit)   # put back
        with self.assertRaises(JsonTooDeepToRead):
            _from_frames_down(600, lambda: json_loads_bounded(deep(513)))
        with self.assertRaises(json.JSONDecodeError):      # put back after an error too
            _from_frames_down(600, lambda: json_loads_bounded(deep(512)[:-1]))
        self.assertEqual(sys.getrecursionlimit(), limit)

    def test_a_parse_inside_a_parse_leaves_the_limit_as_it_was(self):
        limit = sys.getrecursionlimit()
        inner = []
        got = _from_frames_down(600, lambda: json_loads_bounded(
            '{"a":' * 400 + "1" + "}" * 400, object_hook=lambda d: inner.append(json_loads_bounded(deep(512))) or d))
        self.assertEqual(len(inner), 400)
        self.assertEqual(ref_depth(got), 400)
        self.assertEqual(sys.getrecursionlimit(), limit)
        with jsonio._RecursionHeadroom(512), jsonio._RecursionHeadroom(512):
            self.assertGreater(sys.getrecursionlimit(), limit)
        self.assertEqual(sys.getrecursionlimit(), limit)

    def test_threads_leave_the_limit_as_it_was(self):
        limit = sys.getrecursionlimit()
        self.addCleanup(sys.setrecursionlimit, limit)
        low = len(traceback.extract_stack()) + 200      # so that 100 levels need the limit raised
        sys.setrecursionlimit(low)
        want, errors = json.loads(deep(100)), []

        def work():
            try:
                for _ in range(200):
                    if json_loads_bounded(deep(100)) != want:
                        errors.append("value")
            except BaseException as e:   # a thread's exception would be lost
                errors.append(repr(e))
        threads = [threading.Thread(target=work) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(sys.getrecursionlimit(), low)


if __name__ == "__main__":
    unittest.main()
