# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""which_absolute and run_program, on Linux, macOS and Windows."""
import ntpath
import os
import posixpath
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import _common
from nucleo import programs
from nucleo.programs import run_program, which_absolute


def old_which(name):
    """cryptovalid verifier.which at f7883c9, as it was: the positive control for the changes of the core."""
    exe = shutil.which(name)
    if exe is None or os.path.isabs(exe):
        return exe
    exts = [e for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(os.pathsep) if e] if os.name == "nt" else [""]
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        if os.path.isabs(folder):
            for ext in exts:
                path = os.path.join(folder, name + ext)
                if os.path.isfile(path) and os.access(path, os.X_OK):
                    return path
    return None


def _program(folder, name):
    """A program file named `name` (with .exe on Windows unless `name` has an extension already)."""
    os.makedirs(folder, exist_ok=True)
    if os.name == "nt":
        p = os.path.join(folder, name if "." in name else name + ".exe")
        shutil.copy(sys.executable, p)
    else:
        p = os.path.join(folder, name)
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(p, 0o700)
    return p


class _InTmp(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)


class NeverTheProgramOfTheCurrentFolder(_InTmp):
    """From cryptovalid test_platforms_20261124.py (f7883c9): shutil.which looks in the current folder first on
    Windows, and at an empty PATH entry everywhere; which_absolute drops an answer that is not absolute."""

    def test_the_one_on_path_is_named_not_the_one_beside_the_evidence(self):
        here, there = os.path.join(self.d, "evidence"), os.path.join(self.d, "bin")
        _program(here, "openssl")
        good = _program(there, "openssl")
        # Windows: the current folder comes first by itself; POSIX: an empty PATH entry is the current folder, and a
        # file that is not executable, in a folder before the good one, is not a program; nor is a folder of that name
        dirf = os.path.join(self.d, "dirf")
        os.makedirs(os.path.join(dirf, "openssl.exe" if os.name == "nt" else "openssl"))
        path = dirf + os.pathsep + there
        if os.name != "nt":
            nox = os.path.join(self.d, "nox")
            os.chmod(_program(nox, "openssl"), 0o644)
            path = os.pathsep + nox + os.pathsep + path
        os.chdir(here)
        with mock.patch.dict(os.environ, {"PATH": path}):
            planted = shutil.which("openssl")
            self.assertFalse(os.path.isabs(planted), planted)   # positive control: shutil.which names the planted one
            self.assertEqual(os.path.normcase(which_absolute("openssl")), os.path.normcase(good))
        with mock.patch.dict(os.environ, {"PATH": os.path.join(self.d, "nobody") if os.name == "nt" else os.pathsep}):
            self.assertIsNotNone(shutil.which("openssl"))     # control: the planted one only
            self.assertIsNone(which_absolute("openssl"))

    def test_a_relative_path_entry_is_never_searched(self):
        _program(os.path.join(self.d, "rel"), "tool")
        os.chdir(self.d)
        with mock.patch.dict(os.environ, {"PATH": "rel"}):
            self.assertIsNotNone(shutil.which("tool"))       # control: shutil.which takes the relative folder
            self.assertIsNone(which_absolute("tool"))

    def test_a_name_with_its_extension(self):
        """Windows: "tool.exe" is looked up as it is (cryptovalid f7883c9 looked for "tool.exe.EXE" once the planted
        one was dropped, and found none). POSIX: a name with a dot is a name like any other."""
        name = "tool.exe" if os.name == "nt" else "tool.sh"
        _program(os.path.join(self.d, "here"), name)
        good = _program(os.path.join(self.d, "bin"), name)
        os.chdir(os.path.join(self.d, "here"))
        path = os.path.join(self.d, "bin") if os.name == "nt" else os.pathsep + os.path.join(self.d, "bin")
        with mock.patch.dict(os.environ, {"PATH": path}):
            self.assertEqual(os.path.normcase(which_absolute(name)), os.path.normcase(good))
            if os.name == "nt":
                self.assertIsNone(old_which(name))           # positive control: the old code misses it

    def test_only_a_bare_name(self):
        """Generative: a path, a separator anywhere, a NUL, "", "." and ".." are refused before any lookup."""
        rnd = random.Random(20261125)
        bad = ["", ".", "..", "a\0b", "./x", "../x", "x/", "/bin/sh", "a/b", "a\\b", "\\x", "C:x", "c:\\x"]
        alphabet = "ab.-_ /\\\0:é"
        for _ in range(400):
            s = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 8)))
            if s in ("", ".", "..") or any(c in s for c in "/\\\0") or (os.name == "nt" and ":" in s):
                bad.append(s)
        for s in bad:
            if os.name != "nt" and ":" in s and not any(c in s for c in "/\\\0") and s not in ("", ".", ".."):
                continue   # POSIX: ":" is a character of a name
            with self.assertRaises(ValueError, msg=repr(s)):
                which_absolute(s)
        for s in (None, b"sh", 1, ["sh"]):
            with self.assertRaises(TypeError, msg=repr(s)):
                which_absolute(s)
        with mock.patch.dict(os.environ, {"PATH": os.pathsep}):
            os.chdir(self.d)
            _program(os.path.join(self.d, "sub"), "x")
            # control: shutil.which takes a path (on Windows up to Python 3.11 with its extension written)
            path = os.path.join("sub", "x.exe" if os.name == "nt" else "x")
            self.assertIsNotNone(shutil.which(path))
            with self.assertRaises(ValueError):
                which_absolute(path)


class RunProgram(_InTmp):
    def _python(self):
        """PATH holding only the folder of this Python, and its bare name."""
        folder, exe = os.path.split(sys.executable)
        name = os.path.splitext(exe)[0] if os.name == "nt" else exe
        return folder, name

    def _env(self, **kw):
        env = {"SystemRoot": os.environ["SystemRoot"]} if os.name == "nt" else {}   # Python on Windows needs it
        env.update(kw)
        return env

    def test_explicit_environment_and_no_shell(self):
        folder, name = self._python()
        code = "import os, sys; print(sorted(os.environ)); print(sys.argv[1:])"
        with mock.patch.dict(os.environ, {"PATH": folder, "NUCLEO_LEAK": "1"}):
            r = run_program([name, "-c", code, "a;b", "$(echo x)", "`x`", "&", "|"], env=self._env(A="1"), timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout.decode("utf-8").splitlines()
        self.assertIn("'A'", out[0])
        self.assertNotIn("NUCLEO_LEAK", out[0])
        self.assertNotIn("PATH", out[0].replace("'PATHEXT'", ""))
        self.assertEqual(out[1], repr(["a;b", "$(echo x)", "`x`", "&", "|"]))

    def test_stdin_is_empty_or_the_input(self):
        folder, name = self._python()
        code = "import sys; sys.stdout.write(repr(sys.stdin.buffer.read()))"
        with mock.patch.dict(os.environ, {"PATH": folder}):
            self.assertEqual(run_program([name, "-c", code], env=self._env(), timeout=60).stdout, b"b''")
            self.assertEqual(run_program([name, "-c", code], env=self._env(), timeout=60, input=b"x\n").stdout,
                             repr(b"x\n").encode())

    def test_the_callers_stdin_is_not_passed_on(self):
        """The caller's own standard input holds data: the program still reads nothing."""
        folder, name = self._python()
        inner = ("import sys; sys.path.insert(0, sys.argv[1]); from nucleo.programs import run_program; "
                 "r = run_program([sys.argv[2], '-c', 'import sys; print(len(sys.stdin.buffer.read()))'], "
                 "env=eval(sys.argv[3]), timeout=60); sys.stdout.write(r.stdout.decode())")
        with mock.patch.dict(os.environ, {"PATH": folder}):
            r = subprocess.run([sys.executable, "-I", "-c", inner, _common.ROOT, name, repr(self._env())],
                               input=b"the caller's data", capture_output=True, timeout=120)
        self.assertEqual(r.stdout.strip(), b"0", r.stderr)

    def test_timeout(self):
        folder, name = self._python()
        t = time.monotonic()
        with mock.patch.dict(os.environ, {"PATH": folder}):
            with self.assertRaises(subprocess.TimeoutExpired):
                run_program([name, "-c", "import time; time.sleep(60)"], env=self._env(), timeout=1)
        self.assertLess(time.monotonic() - t, 30)

    def test_the_program_of_the_current_folder_is_not_run(self):
        _program(self.d, "nucleo-planted")
        os.chdir(self.d)
        with mock.patch.dict(os.environ, {"PATH": os.path.join(self.d, "nobody") if os.name == "nt" else os.pathsep}):
            with self.assertRaises(FileNotFoundError):
                run_program(["nucleo-planted"], env=self._env(), timeout=10)

    def test_arguments_are_checked(self):
        folder, name = self._python()
        good = dict(env=self._env(), timeout=10)
        for argv in ([], "python", b"python", [name, 1], [None], (name, b"x")):
            with self.assertRaises(TypeError, msg=repr(argv)):
                run_program(argv, **good)
        for env in (None, [("A", "1")], {"A": 1}, {1: "A"}, {"A": b"1"}):
            with self.assertRaises(TypeError, msg=repr(env)):
                run_program([name], env=env, timeout=10)
        for timeout in (0, -1, float("nan"), True, "1", None):
            with self.assertRaises((ValueError, TypeError), msg=repr(timeout)):
                run_program([name], env=self._env(), timeout=timeout)
        with self.assertRaises(TypeError):
            run_program([name], input="text", **good)
        with self.assertRaises(ValueError):
            run_program(["a/b"], **good)


class AbsoluteNamesItsDrive(unittest.TestCase):
    def test_a_rooted_path_without_a_drive_is_not_absolute_on_windows(self):
        """`\\tools` in PATH is a folder of the current drive. ntpath.isabs alone answers True before Python 3.13 and
        False from 3.13, and ntpath.splitdrive reads `\\\\server` as a share from Python 3.11 and not under 3.9: the
        rule is written here, one answer on every Python."""
        for path, want in (("\\tools", False), ("/tools", False), ("C:tools", False), ("tools", False), ("", False),
                           ("C:", False), ("\\tools\\bin", False),
                           ("\\\\", False), ("\\\\server", False), ("\\\\server\\", False), ("//.", False),
                           ("\\\\\\server\\share", False), ("1:\\tools", False), ("CC:\\tools", False),
                           (" C:\\tools", False),
                           ("C:\\tools", True), ("c:/tools", True), ("z:\\", True), ("\\\\server\\share\\tools", True),
                           ("//server/share", True), ("\\\\?\\C:\\tools", True), ("\\\\server\\\\share", True)):
            self.assertIs(programs._is_absolute(path, True), want, path)
            if want and sys.version_info >= (3, 11):   # never wider than Python's own reading (3.9: no share in //a/b)
                self.assertTrue(ntpath.isabs(path) and ntpath.splitdrive(path)[0] != "", path)
        for path, want in (("/usr/bin", True), ("usr/bin", False), ("", False), (".", False), ("./bin", False),
                           ("C:\\tools", False), ("\\\\server\\share", False)):
            self.assertIs(programs._is_absolute(path, False), want, path)
            self.assertIs(posixpath.isabs(path), want, path)
        self.assertIs(programs._is_absolute(os.path.abspath(os.curdir)), True)   # this system's own rule by default
        self.assertIs(programs._is_absolute(os.curdir), False)

    def test_which_absolute_asks_the_rule_of_windows_there(self):
        """os.name patched: a rooted PATH entry without a drive is not searched, whatever os.path.isabs says of it."""
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            with open(os.path.join(d, "tool.EXE"), "w") as f:
                f.write("")
            os.chmod(os.path.join(d, "tool.EXE"), 0o700)
            if os.name != "nt":
                self.assertTrue(os.path.isabs(d) and not programs._is_absolute(d, True), d)   # control: /tmp/...
            with mock.patch.dict(os.environ, {"PATH": d, "PATHEXT": ".EXE"}):
                with mock.patch.object(os, "name", "nt"):
                    found = which_absolute("tool")
                self.assertIs(found is None, os.name != "nt", found)


class WindowsRulesOnEverySystem(_InTmp):
    """The Windows branches, run on every system with os.name patched (on Windows the patch changes nothing)."""

    def test_a_colon_is_not_a_bare_name_on_windows(self):
        with mock.patch.object(os, "name", "nt"):
            for s in ("C:x", "a:b", ":", "x:"):
                with self.assertRaises(ValueError, msg=s):
                    programs._bare_name(s)
        if os.name != "nt":
            self.assertEqual(programs._bare_name("a:b"), "a:b")   # POSIX: ":" is a character of a name

    def test_a_batch_file_is_found_and_not_run(self):
        """Windows hands a .bat or .cmd file to cmd.exe, which reads the arguments as a shell does, whatever
        shell=False says (Python's subprocess documentation): run_program refuses it before anything is started."""
        folder = os.path.join(self.d, "bin")
        os.makedirs(folder)
        cases = (("t1.BAT", "t1"), ("t2.CMD", "t2"), ("t3.bat", "t3.bat"), ("t4.Cmd", "t4.Cmd"))
        for filename, _ in cases:
            p = os.path.join(folder, filename)
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(p, 0o700)
        pathext = os.pathsep.join((".COM", ".EXE", ".BAT", ".CMD"))
        native = os.name == "nt"
        with mock.patch.dict(os.environ, {"PATH": folder, "PATHEXT": pathext}):
            for filename, name in cases:
                p = os.path.join(folder, filename)
                if native:   # found there by PATHEXT; elsewhere the folder is not one of Windows: handed over
                    self.assertEqual(os.path.normcase(which_absolute(name)), os.path.normcase(p))
                with mock.patch.object(os, "name", "nt"), mock.patch.object(subprocess, "run") as run, \
                        mock.patch.object(programs, "which_absolute", side_effect=which_absolute if native else lambda n: p):
                    with self.assertRaisesRegex(ValueError, "batch file", msg=filename):
                        run_program([name, "&", "calc"], env={}, timeout=10)
                    run.assert_not_called()
            if os.name != "nt":   # control: the same file is a program like any other where no cmd.exe reads it
                self.assertEqual(run_program(["t3.bat"], env={}, timeout=60).returncode, 0)


class RunProgramRunsWhatWasFound(_InTmp):
    def test_the_file_found_is_the_file_run(self):
        """env={} has no PATH: a bare name handed to the system would be looked up in its default folders."""
        if os.name == "nt":
            folder, exe = os.path.split(sys.executable)
            argv, env = [os.path.splitext(exe)[0], "-c", "pass"], {"SystemRoot": os.environ["SystemRoot"]}
        else:
            folder = os.path.join(self.d, "bin")
            _program(folder, "nucleo-tool")
            argv, env = ["nucleo-tool"], {}
        with mock.patch.dict(os.environ, {"PATH": folder}):
            self.assertEqual(run_program(argv, env=env, timeout=60).returncode, 0)
            self.assertEqual(run_program(argv, env=env, timeout=programs.MAX_TIMEOUT).returncode, 0)   # the bound is taken

    def test_a_relative_path_in_env_is_not_searched(self):
        """The PATH of `env` is the program's own: it is never where argv[0] is looked up."""
        _program(self.d, "nucleo-planted")
        os.chdir(self.d)
        env = {"PATH": os.curdir}
        if os.name == "nt":
            env["SystemRoot"] = os.environ["SystemRoot"]
        with mock.patch.dict(os.environ, {"PATH": os.path.join(self.d, "nobody") if os.name == "nt" else os.pathsep}):
            with self.assertRaises(FileNotFoundError):
                run_program(["nucleo-planted"], env=env, timeout=10)

    def test_timeout_is_finite_and_input_is_bytes(self):
        self.assertEqual(programs.MAX_TIMEOUT, 2000000)   # the value DIFFERENZE.md names
        for timeout in (float("inf"), 1e30, 10 ** 30, programs.MAX_TIMEOUT + 1):
            with self.assertRaises(ValueError, msg=repr(timeout)):
                run_program(["nucleo-tool"], env={}, timeout=timeout)
        with self.assertRaises(TypeError):
            run_program(["nucleo-tool"], env={}, timeout=10, input=bytearray(b"x"))


if __name__ == "__main__":
    unittest.main()
