# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""A secret given to the core does not come out of it. The core is a library: it writes no file of its own, prints
nothing and logs nothing; what comes out of it is the return value, the exception (its message, its repr, its
arguments, the whole traceback) and, for run_program, the argv and the environment of the child. The inputs that can
hold a secret (counted with grep on v0.1.0, 83d3972, 28/11/2026: every raise, %r, print, environ of nucleo/):

  run_program   argv[1:] (a password, a token, a URL with user info given to the program: the child receives them,
                that is the call), env (the child receives it, and only it), input (the child's standard input); the
                caller's own environment, which must NOT reach the child
  json_loads_bounded   the text read (a key file, a JWK, a token response)
  create_private / private_tmpdir   what the caller writes in them: the file and folder are the owner's alone
                (0600 / 0700 whatever the umask; on Windows the access list of the owner alone)

Not secrets, and repeated by the errors on purpose: a program name (argv[0]), the prefix, suffix and folder of a new
file, a type name. canonicalize's errors name types and code points only. The attribute `doc` of a JSONDecodeError holds
the text read, as Python's json defines it; it is in none of the outputs above.

Searched raw, as any 12-character piece, in hex, HEX, decimal, base64 and base64url at each offset. Positive control:
the search finds each form, and a producer that leaks (subprocess.run's own TimeoutExpired) is found. On v0.1.0 the
tests marked "fails on 0.1.0" fail."""
import base64
import hashlib
import os
import re
import stat
import subprocess
import sys
import tempfile
import traceback
import unittest
from unittest import mock

import _common
from nucleo.files import create_private, private_tmpdir
from nucleo.jsonio import json_loads_bounded
from nucleo.programs import run_program

_H = hashlib.sha256(b"omega-nucleo-comune test_secrets canary").digest()        # a test value, not anyone's
_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
TOKEN = "ghp_" + "".join(_ALNUM[b % 62] for b in hashlib.sha512(b"t" + _H).digest()[:36])   # GitHub's format: 4 + 36
PASSWORD = "Pw" + base64.urlsafe_b64encode(hashlib.sha256(b"pw" + _H).digest()).decode()[:30]
KEY = hashlib.sha256(b"key" + _H).digest()
URL = "https://robot:%s@example.invalid/x" % PASSWORD
CANARIES = (TOKEN.encode(), PASSWORD.encode(), KEY)


def forms(secret):
    out = {"raw": secret, "hex": secret.hex().encode(), "HEX": secret.hex().upper().encode(),
           "decimal": str(int.from_bytes(secret, "big")).encode()}
    for k in range(3):          # base64 of the secret inside a longer text: what depends on the secret alone, at each offset
        whole = base64.b64encode(b"\0" * k + secret + b"\0" * ((3 - (k + len(secret)) % 3) % 3))
        part = whole[(k * 8 + 5) // 6:(k + len(secret)) * 8 // 6]
        out["base64+%d" % k], out["base64url+%d" % k] = part, part.replace(b"+", b"-").replace(b"/", b"_")
    for name, text in (("raw", secret), ("hex", secret.hex().encode())):   # a message cut at a length keeps a piece
        for i in range(0, len(text) - 12 + 1):
            out["%s[%d:]" % (name, i)] = text[i:i + 12]
    return out


def found(secret, *outputs):
    blob = b"\n".join(o if isinstance(o, bytes) else str(o).encode("utf-8", "surrogatepass") for o in outputs)
    blob += b"\n" + blob.replace(b"\\/", b"/")
    blob += b"\n" + blob.replace(b"\\\\", b"\\")    # repr doubles a backslash
    return sorted(n for n, f in forms(secret).items() if f in blob)


def what_an_error_shows(e):
    """Everything an exception shows when printed, logged with %r or as a traceback, and the same of every exception
    chained to it (a reader of __context__ shows its repr)."""
    shown = ["".join(traceback.format_exception(type(e), e, e.__traceback__))]
    seen = set()
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        shown += [str(e), repr(e), repr(e.args)]
        for a in e.args:   # bytes in the arguments are shown by repr in full: read them in each encoding JSON may have
            if isinstance(a, (bytes, bytearray)):
                shown += [bytes(a).decode(enc, "ignore") for enc in ("utf-8", "utf-16-le", "utf-16-be", "utf-32-le",
                                                                      "utf-32-be")]
        e = e.__cause__ or e.__context__
    return shown


def python():
    """PATH holding only the folder of this Python, its bare name, the environment Python needs to start."""
    folder, exe = os.path.split(sys.executable)
    env = {"SystemRoot": os.environ["SystemRoot"]} if os.name == "nt" else {}
    return folder, (os.path.splitext(exe)[0] if os.name == "nt" else exe), env


class Base(unittest.TestCase):
    def none(self, what, *outputs):
        for c in CANARIES:
            self.assertEqual(found(c, *outputs), [], what)


class TheSearchFinds(Base):
    """Positive control of the search, and of a producer that leaks."""

    def test_every_form(self):
        for c in CANARIES:
            for name, f in forms(c).items():
                self.assertIn(name, found(c, b"<" + f + b">"), name)
        self.assertEqual(found(KEY, os.urandom(4096)), [])
        self.assertEqual(len(TOKEN), 40)

    def test_a_bare_timeout_leaks_the_arguments(self):
        """subprocess.run's own TimeoutExpired names the whole argv: the leak run_program closes."""
        with self.assertRaises(subprocess.TimeoutExpired) as cm:
            subprocess.run([sys.executable, "-c", "import time; time.sleep(60)", TOKEN, URL], timeout=1,
                           capture_output=True)
        self.assertIn("raw", found(TOKEN.encode(), *what_an_error_shows(cm.exception)))
        self.assertIn("raw", found(PASSWORD.encode(), *what_an_error_shows(cm.exception)))

    def test_a_bytes_decode_error_shows_the_text(self):
        try:
            (b'{"t":"' + TOKEN.encode() + b'\xff"}').decode("utf-8")
        except UnicodeDecodeError as e:
            self.assertIn("raw", found(TOKEN.encode(), repr(e)))


class RunProgram(Base):
    def test_the_callers_environment_does_not_reach_the_child(self):
        folder, name, env = python()
        code = "import os, sys; print(repr(dict(os.environ))); print(repr(sys.argv))"
        secret_env = {"PATH": folder, "GITHUB_TOKEN": TOKEN, "DB_PASSWORD": PASSWORD, "PROXY": URL,
                      "SIGNING_KEY": KEY.hex()}
        with mock.patch.dict(os.environ, secret_env):
            r = run_program([name, "-c", code], env=env, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.none("the child's environment", r.stdout, r.stderr, r.args)
            # control: what the caller gives in env is what the child shows (the search reads the real output)
            r = run_program([name, "-c", code], env=dict(env, T=TOKEN), timeout=60)
            self.assertIn("raw", found(TOKEN.encode(), r.stdout))

    def test_a_timeout_names_the_program_alone(self):   # fails on 0.1.0
        folder, name, env = python()
        with mock.patch.dict(os.environ, {"PATH": folder}):
            with self.assertRaises(subprocess.TimeoutExpired) as cm:
                run_program([name, "-c", "import time; time.sleep(60)", "--token", TOKEN, URL, KEY.hex()],
                            env=env, timeout=1)
        e = cm.exception
        self.none("TimeoutExpired", *what_an_error_shows(e), e.cmd)
        self.assertEqual(len(e.cmd), 1)
        self.assertEqual(os.path.normcase(os.path.dirname(e.cmd[0])), os.path.normcase(folder))
        self.assertEqual(e.timeout, 1)

    def test_a_refusal_repeats_no_value(self):
        folder, name, env = python()
        calls = [
            lambda: run_program([name, TOKEN.encode()], env=env, timeout=60),
            lambda: run_program([name, "-c", "pass"], env={"K": TOKEN.encode()}, timeout=60),
            lambda: run_program([name, "-c", "pass"], env={TOKEN.encode(): "v"}, timeout=60),
            lambda: run_program([name, "-c", "pass"], env={"K": PASSWORD}, timeout=60, input=TOKEN),
            lambda: run_program([name, TOKEN], env={"K": PASSWORD}, timeout=0),
            lambda: run_program(["nucleo-no-such-program", TOKEN, URL], env={"K": PASSWORD}, timeout=60),
        ]
        with mock.patch.dict(os.environ, {"PATH": folder}):
            for i, call in enumerate(calls):
                with self.assertRaises((TypeError, ValueError, OSError)) as cm:
                    call()
                self.none("refusal %d" % i, *what_an_error_shows(cm.exception))


class JsonLoadsBounded(Base):
    TEXT = '{"kty":"OKP","d":"%s","token":"%s","url":"%s"}' % (
        base64.urlsafe_b64encode(KEY).decode().rstrip("="), TOKEN, URL)

    def cases(self):
        t, half = self.TEXT, len(self.TEXT) // 2
        cut_in_token = t.index(TOKEN) + 20
        yield "truncated", t[:cut_in_token]
        yield "extra data", t + t
        yield "bad escape in the token", t.replace(TOKEN, TOKEN[:20] + "\\q" + TOKEN[20:])
        yield "control character in the token", t.replace(TOKEN, TOKEN[:20] + "\x01" + TOKEN[20:])
        yield "too deep", "[" * 600 + t + "]" * 600
        yield "not JSON", t[half:]
        yield "bytes, invalid UTF-8 in the token", t.encode().replace(TOKEN.encode(), TOKEN[:20].encode() + b"\xff")
        yield "bytes, UTF-16 cut in a code unit", t.encode("utf-16-le")[:-1]
        yield "bytes, UTF-32 with a bad code point", t.encode("utf-32-be")[:-4] + b"\x7f\xff\xff\xff"
        yield "bytearray, invalid UTF-8", bytearray(t.encode() + b"\xc3")

    def test_an_error_repeats_no_piece_of_the_text(self):   # fails on 0.1.0 (the three bytes decoding cases)
        for what, text in self.cases():
            with self.subTest(what):
                with self.assertRaises(ValueError) as cm:
                    json_loads_bounded(text)
                self.none(what, *what_an_error_shows(cm.exception))

    def test_a_decode_error_keeps_its_type_and_position(self):
        bad = self.TEXT.encode().replace(TOKEN.encode(), TOKEN[:20].encode() + b"\xff")
        with self.assertRaises(UnicodeDecodeError) as cm:
            json_loads_bounded(bad)
        try:
            bad.decode("utf-8")
        except UnicodeDecodeError as e:
            want = e
        self.assertEqual(str(cm.exception), str(want))
        self.assertEqual((cm.exception.start, cm.exception.end), (want.start, want.end))

    def test_the_text_is_read(self):   # control: the bench reads a text that holds the secrets
        self.assertEqual(json_loads_bounded(self.TEXT.encode("utf-16"))["token"], TOKEN)


class PrivateFiles(Base):
    def _private(self, path, folder):
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o700 if folder else 0o600, path)
            return
        aces, who, out = _common.windows_aces(path)
        self.assertEqual(len(aces), 1, out)
        self.assertEqual(aces[0].partition(":")[0].lower(), who.lower(), out)

    def test_the_owners_alone_whatever_the_umask(self):
        um = os.umask(0)    # the widest umask: nothing taken away from the mode asked
        try:
            with tempfile.TemporaryDirectory() as d:
                fd, p = create_private(d, "key-", ".pem")
                with os.fdopen(fd, "wb") as f:
                    f.write(KEY)
                self._private(p, folder=False)
                q = private_tmpdir("sec-", d)
                self._private(q, folder=True)
                self.none("the name of the new file and folder", p, q)
        finally:
            os.umask(um)


class TheCoreSaysNothingElse(unittest.TestCase):
    """The census, fixed: the only variables of the caller's environment the core reads are PATH, PATHEXT and
    SystemRoot (the location of programs, never handed to a child); nothing in it prints, logs or opens a file to
    write; a child is started only by run_program and by the access-list setter (whoami, fixed arguments)."""

    def source(self):
        folder = os.path.join(_common.ROOT, "nucleo")
        return {n: open(os.path.join(folder, n), encoding="utf-8").read() for n in sorted(os.listdir(folder))
                if n.endswith(".py")}

    def test_census(self):
        src = self.source()
        self.assertEqual(sorted(src), ["__init__.py", "canonical.py", "files.py", "jsonio.py", "programs.py"])
        every = "\n".join(src.values())
        self.assertEqual(set(re.findall(r"""environ(?:\.get\(|\[)\s*["'](\w+)["']""", every)),
                         {"PATH", "PATHEXT", "SystemRoot"})
        self.assertEqual(len(re.findall(r"\bos\.environ\b", every)), 3)
        for word in (r"\bprint\(", r"\blogging\b", r"\bsys\.std(out|err)\b", r"\bwarnings\b", r"(?<![.\w])open\(",
                     r"getenv"):
            self.assertIsNone(re.search(word, every), word)
        self.assertEqual(sorted(n for n, s in src.items() if re.search(r"subprocess\.(run|Popen|call|check_)", s)),
                         ["files.py", "programs.py"])
        self.assertEqual(len(re.findall(r"subprocess\.run\(", src["files.py"])), 1)
        self.assertIn('[os.path.join(sysdir, "whoami.exe"), "/user", "/fo", "csv", "/nh"]', src["files.py"])


if __name__ == "__main__":
    unittest.main()
