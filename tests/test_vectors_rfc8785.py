# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""canonical_json_jcs against the vectors of RFC 8785, read at test time from the RFC itself.

RFC 8785 is on the Independent Submission stream: the IETF Trust Legal Provisions 5.0 (§8.c.iii, §8.f) give neither
the licence for portions (§3.c) nor the code-component licence (§4) to that stream, so no part of its text is kept in
this repository. The test reads the official text from the file named by NUCLEO_RFC8785 (the CI downloads
https://www.rfc-editor.org/rfc/rfc8785.txt), checks its sha256, and extracts: the Appendix B number table, the
sample object of §3.2.2 with its UTF-8 bytes of §3.2.4, and the sort vector of §3.2.3."""
import hashlib
import json
import os
import re
import struct
import unittest

import _common  # noqa: F401
from nucleo.canonical import canonical_json_jcs, format_number

SHA256 = "63d52294eb0e3f0014174288186d388b4ddbf2c67d1ce8af1d9726eb0c3ab240"   # rfc8785.txt, read 2026-11-25


def _text():
    path = os.environ.get("NUCLEO_RFC8785")
    if not path:
        raise unittest.SkipTest("NUCLEO_RFC8785 not set: the RFC text is not kept here (TLP 5.0 §8), the CI downloads it")
    with open(path, "rb") as f:
        raw = f.read()
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise AssertionError("%s is not rfc8785.txt of 2026-11-25 (sha256)" % path)
    # the page breaks: a form feed, the footer and the header lines
    return [ln for ln in raw.decode("utf-8").splitlines()
            if "\f" not in ln and not re.match(r"(Rundgren, et al\.|RFC 8785 )", ln)]


def _between(lines, start, end):
    i = next(k for k, ln in enumerate(lines) if start in ln) + 1
    j = next(k for k in range(i, len(lines)) if end in lines[k])
    return [ln for ln in lines[i:j] if ln.strip()]


class Rfc8785(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lines = _text()

    def test_appendix_b(self):
        rows = [m.groups() for m in (re.match(r"\s*\| ([0-9a-f]{16}) \| (\S*)\s+\|", ln) for ln in self.lines) if m]
        self.assertEqual(len(rows), 26)   # 24 numbers, NaN and Infinity
        self.assertEqual(sum(1 for _, e in rows if not e), 2)
        for hexbits, expected in rows:
            x = struct.unpack(">d", bytes.fromhex(hexbits))[0]
            if expected:
                self.assertEqual(format_number(x), expected, hexbits)
            else:   # NaN and Infinity: the RFC gives no form, JCS refuses them
                with self.assertRaises(ValueError, msg=hexbits):
                    format_number(x)

    def test_sample_to_its_bytes(self):
        sample = "\n".join(_between(self.lines, "Assume the following JSON object is parsed:", "If the parsed data"))
        hexlines = _between(self.lines, "following bytes, here shown in hexadecimal notation:", "4.  IANA Considerations")
        want = bytes.fromhex("".join(ln for ln in hexlines if re.fullmatch(r"\s*([0-9a-f]{2} ?)+\s*", ln)))
        self.assertEqual(len(want), 118)
        self.assertEqual(canonical_json_jcs(json.loads(sample)), want)

    def test_sort_vector(self):
        start = "correctness of the sorting scheme in a JCS implementation:"
        data = "\n".join(_between(self.lines, start, "Expected argument order"))
        order = [json.loads(ln.strip()) for ln in _between(self.lines, "Expected argument order", "Note: For the purpose")]
        out = canonical_json_jcs(json.loads(data))
        self.assertEqual(list(json.loads(out.decode("utf-8")).values()), order)
        self.assertEqual(len(order), 7)
        # positive control: Python's code-point order (sort_keys) is not the RFC's
        plain = json.dumps(json.loads(data), sort_keys=True, ensure_ascii=False)
        self.assertNotEqual(list(json.loads(plain).values()), order)

    def test_positive_control_repr_is_not_ecmascript(self):
        rows = [m.groups() for m in (re.match(r"\s*\| ([0-9a-f]{16}) \| (\S+)\s+\|", ln) for ln in self.lines) if m]
        wrong = [h for h, e in rows if repr(struct.unpack(">d", bytes.fromhex(h))[0]) != e]
        self.assertEqual(len(wrong), 10)   # Python's repr misses 10 of the 24 forms (measured 2026-11-25)


if __name__ == "__main__":
    unittest.main()
