# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""create_exclusive / create_private / private_tmpdir, on Linux, macOS and Windows (the access list there)."""
import contextlib
import ntpath
import os
import re
import secrets
import shutil
import stat
import tempfile
import unittest
from unittest import mock

import _common
from nucleo import files
from nucleo.files import create_exclusive, create_private, private_tmpdir


def _denied(counter):
    """The Windows conditions of tempfile's loop: os.name nt, os.access true, every creation refused."""
    def deny(*a, **k):
        counter.append(1)
        raise PermissionError(13, "Permission denied")
    return [mock.patch.object(os, "open", deny), mock.patch.object(os, "mkdir", deny),
            mock.patch.object(os, "access", lambda *a, **k: True), mock.patch.object(os, "name", "nt")]


def _with(patches, fn):
    with contextlib.ExitStack() as st:
        for p in patches:
            st.enter_context(p)
        return fn()


CALLS = {
    "create_exclusive": lambda d: create_exclusive(d, "x-"),
    "create_private": lambda d: create_private(d, "x-"),
    "private_tmpdir": lambda d: private_tmpdir("x-", d),
}


class TemporaryNamesOnWindows(unittest.TestCase):
    """From cryptovalid test_platforms_20261124.py (f7883c9) and ap2-evidence-pack 5df7cb4."""

    def test_mkstemp_loops_there(self):   # positive control: the defect is what the bench sees
        n = []
        with tempfile.TemporaryDirectory() as d, mock.patch.object(tempfile, "TMP_MAX", 10000):
            with self.assertRaises((PermissionError, FileExistsError)):
                _with(_denied(n), lambda: tempfile.mkstemp(dir=d))
        self.assertEqual(len(n), 10000)

    def test_one_try_on_a_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            for name, call in CALLS.items():
                n = []
                with self.assertRaises(PermissionError, msg=name):
                    _with(_denied(n), lambda: call(d))
                self.assertEqual(len(n), 1, name)

    def test_every_other_oserror_at_once(self):
        import errno
        for code in (errno.ENOENT, errno.ENOSPC, errno.EROFS, errno.EACCES, errno.ENAMETOOLONG, errno.EIO):
            n = []

            def fail(*a, **k):
                n.append(1)
                raise OSError(code, os.strerror(code))
            with tempfile.TemporaryDirectory() as d:
                for name, call in CALLS.items():
                    del n[:]
                    with mock.patch.object(os, "open", fail), mock.patch.object(os, "mkdir", fail):
                        with self.assertRaises(OSError, msg=(name, code)) as cm:
                            call(d)
                    self.assertEqual(cm.exception.errno, code)
                    self.assertEqual(len(n), 1, (name, code))

    def test_a_taken_name_is_tried_again_64_times(self):
        for name, call in CALLS.items():
            n = []

            def taken(*a, **k):
                n.append(1)
                raise FileExistsError(17, "File exists")
            with tempfile.TemporaryDirectory() as d, mock.patch.object(os, "open", taken), \
                    mock.patch.object(os, "mkdir", taken):
                with self.assertRaises(FileExistsError, msg=name):
                    call(d)
            self.assertEqual(len(n), 64, name)


class WhatStandsAtTheName(unittest.TestCase):
    def test_on_windows_the_name_is_looked_at_before_it_is_opened(self):
        """Windows: O_CREAT|O_EXCL on a link to nothing makes the file the link points to, and a folder at the name is
        a PermissionError (CI run 45583189095). The Windows branch, run on every system with os.name patched: where
        anything stands, os.open is not asked at all; at a free name it is asked once."""
        for kind in ("folder", "dangling"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "x-" + "00" * 8)
                if kind == "folder":
                    os.mkdir(p)
                else:
                    try:
                        os.symlink(os.path.join(d, "target"), p)
                    except OSError:
                        if os.name == "nt":
                            self.skipTest("Windows without the right to make links (SeCreateSymbolicLinkPrivilege)")
                        raise
                with mock.patch.object(secrets, "token_hex", lambda n: "00" * n), \
                        mock.patch.object(os, "name", "nt"), mock.patch.object(os, "open", side_effect=os.open) as opened:
                    with self.assertRaises(FileExistsError):
                        create_exclusive(d, "x-")
                    opened.assert_not_called()
                    fd, q = create_exclusive(d, "y-")
                    self.assertEqual(opened.call_count, 1)
                os.close(fd)
                self.assertEqual(sorted(os.listdir(d)), ["x-" + "00" * 8, "y-" + "00" * 8])

    def test_never_opened(self):
        """O_EXCL: a file, a link (to a file, to nothing), a folder or a FIFO already at the name is not opened, not
        followed, not written: the name counts as taken (cryptovalid review of 2026-11-25: without O_EXCL the suite
        stayed green). A FIFO would block an open without O_EXCL: here the call returns at once."""
        kinds = ["file", "link", "dangling", "folder", "fifo"]
        for kind in kinds:
            for name, call in CALLS.items():
                with self.subTest(kind=kind, call=name), tempfile.TemporaryDirectory() as d:
                    p, target = os.path.join(d, "x-" + "00" * 8), os.path.join(d, "target")
                    if kind == "file":
                        with open(p, "wb") as f:
                            f.write(b"kept")
                    elif kind == "folder":
                        os.mkdir(p)
                    elif kind == "fifo":
                        if not hasattr(os, "mkfifo"):
                            self.skipTest("Windows: a named pipe lives in \\\\.\\pipe\\, never at a name inside a folder")
                        os.mkfifo(p)
                    else:
                        if kind == "link":
                            with open(target, "wb") as f:
                                f.write(b"kept")
                        try:
                            os.symlink(target, p)
                        except OSError:
                            if os.name == "nt":
                                self.skipTest("Windows without the right to make links (SeCreateSymbolicLinkPrivilege)")
                            raise
                    with mock.patch.object(secrets, "token_hex", lambda n: "00" * n):
                        with self.assertRaises(FileExistsError, msg=(kind, name)):
                            call(d)
                    if kind == "link":
                        with open(target, "rb") as f:
                            self.assertEqual(f.read(), b"kept")
                    if kind == "dangling":
                        self.assertFalse(os.path.exists(target))
                    if kind == "file":
                        with open(p, "rb") as f:
                            self.assertEqual(f.read(), b"kept")
                    if kind == "fifo":
                        self.assertTrue(stat.S_ISFIFO(os.lstat(p).st_mode))


class PrivateForReal(unittest.TestCase):
    def _assert_private(self, path, folder):
        if os.name != "nt":
            um = os.umask(0)
            os.umask(um)
            want = (0o700 if folder else 0o600) & ~um
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), want, path)
            return
        aces, who, out = _common.windows_aces(path)
        self.assertEqual(len(aces), 1, out)
        name, _, rights = aces[0].partition(":")
        self.assertEqual(name.lower(), who.lower(), out)
        self.assertEqual(rights, "(OI)(CI)(F)" if folder else "(F)", out)

    def test_a_private_file_and_folder(self):
        with tempfile.TemporaryDirectory() as d:
            fd, p = create_private(d, "y-", ".z")
            os.close(fd)
            self.assertRegex(os.path.basename(p), r"\Ay-[0-9a-f]{16}\.z\Z")
            self.assertTrue(os.path.isfile(p))
            self._assert_private(p, folder=False)
            q = private_tmpdir("w-", d)
            self.assertRegex(os.path.basename(q), r"\Aw-[0-9a-f]{16}\Z")
            self.assertTrue(os.path.isdir(q))
            self._assert_private(q, folder=True)

    def test_mkstemp_is_not_private_on_windows(self):
        """Positive control of the Windows measure: tempfile.mkstemp's file keeps the inherited access list."""
        if os.name != "nt":
            self.skipTest("Windows only: on POSIX mkstemp's 0600 is private, the mode is the measure")
        with tempfile.TemporaryDirectory() as d:
            fd, p = tempfile.mkstemp(dir=d)
            os.close(fd)
            aces, _, out = _common.windows_aces(p)
            self.assertGreater(len(aces), 1, out)

    def test_create_exclusive_mode_less_umask(self):
        with tempfile.TemporaryDirectory() as d:
            fd, p = create_exclusive(d, ".pack-", ".tmp", 0o666)
            os.close(fd)
            if os.name != "nt":
                um = os.umask(0)
                os.umask(um)
                self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o666 & ~um)

    def test_names_are_unpredictable_and_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            seen = set()
            for _ in range(200):
                fd, p = create_exclusive(d, "n-")
                os.close(fd)
                seen.add(p)
            self.assertEqual(len(seen), 200)
            self.assertTrue(all(re.fullmatch(r"n-[0-9a-f]{16}", os.path.basename(p)) for p in seen))

    def test_the_descriptor_is_read_write_and_binary(self):
        with tempfile.TemporaryDirectory() as d:
            fd, p = create_private(d, "b-")
            try:
                self.assertEqual(os.write(fd, b"a\nb\r\n"), 5)
                os.lseek(fd, 0, 0)
                self.assertEqual(os.read(fd, 10), b"a\nb\r\n")   # O_BINARY on Windows: no newline translation
            finally:
                os.close(fd)


class ErrorsCloseAndRemove(unittest.TestCase):
    """When the access list cannot be set (Windows), the descriptor is closed and the file or folder removed."""

    def test_private_file(self):
        opened = []
        real_open = os.open

        def spy(*a, **k):
            fd = real_open(*a, **k)
            opened.append(fd)
            return fd

        def acl_fails(path, folder):
            raise OSError("access list refused")
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(os, "open", spy), mock.patch.object(files, "_owner_only", acl_fails), \
                    mock.patch.object(os, "name", "nt"):
                with self.assertRaises(OSError):
                    create_private(d, "p-")
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                os.fstat(opened[0])            # closed
            self.assertEqual(os.listdir(d), [])   # removed
            fd, p = create_private(d, "p-")  # control: a descriptor that is returned is open
            self.assertTrue(os.fstat(fd))
            os.close(fd)

    def test_private_folder(self):
        def acl_fails(path, folder):
            raise OSError("access list refused")
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(files, "_owner_only", acl_fails), mock.patch.object(os, "name", "nt"):
                with self.assertRaises(OSError):
                    private_tmpdir("q-", d)
            self.assertEqual(os.listdir(d), [])


class DeniedFolderForReal(unittest.TestCase):
    """A folder this user may not write to: one try, PermissionError (POSIX mode 0500; Windows a read-only access
    list, the equivalent)."""

    def test_one_try(self):
        if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root writes in a folder of mode 0500: no POSIX way to deny it here")
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        if os.name == "nt":
            files._set_dacl(d, "D:P(A;OICI;FR;;;%s)")
            self.addCleanup(files._set_dacl, d, "D:P(A;OICI;FA;;;%s)")
        else:
            os.chmod(d, 0o500)
            self.addCleanup(os.chmod, d, 0o700)
        n = []
        real_open, real_mkdir = os.open, os.mkdir

        def count_open(*a, **k):
            n.append(1)
            return real_open(*a, **k)

        def count_mkdir(*a, **k):
            n.append(1)
            return real_mkdir(*a, **k)
        for name, call in CALLS.items():
            del n[:]
            with mock.patch.object(os, "open", count_open), mock.patch.object(os, "mkdir", count_mkdir):
                with self.assertRaises(PermissionError, msg=name):
                    call(d)
            self.assertEqual(len(n), 1, name)


class PartsOfTheName(unittest.TestCase):
    def test_the_error_names_the_part(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError, "^prefix is a str"):
                create_exclusive(d, "x\0")
            with self.assertRaisesRegex(ValueError, "^suffix is a str"):
                create_exclusive(d, "p-", "\0")
            with self.assertRaisesRegex(ValueError, "^prefix is a str"):
                private_tmpdir("\0x", d)
            self.assertEqual(os.listdir(d), [])

    def test_a_name_windows_reserves(self):
        """The Windows branch, run on every system with os.name patched (on Windows the patch changes nothing)."""
        bad = [("C:", ""), ("a:", ""), ("p-", ":x"), ("nul.", ""), ("NUL.", ""), ("con .", ""), ("COM1.", ""),
               ("lpt\u00b9.", ""), ("conout$.", ""), ("p-", "."), ("p-", " "), ("p-", ".tmp."), ("a*", ""), ("p-", "?"),
               ("p\x01", ""), ("p-", "\x1f"), ("p-", "|"), ('"', ""), ("<", ""), (">", "")]
        good = [("p-", ""), ("", ""), (".pack-", ".tmp"), ("NUL", ""), ("nul-", ".txt"), ("\u00e9 ", ".x"), ("com", "")]
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(os, "name", "nt"):
                for prefix, suffix in bad:
                    with self.assertRaisesRegex(ValueError, "Windows reserves", msg=repr((prefix, suffix))):
                        create_exclusive(d, prefix, suffix)
                    with self.assertRaisesRegex(ValueError, "Windows reserves", msg=repr((prefix, suffix))):
                        create_private(d, prefix, suffix)
                    if not suffix:
                        with self.assertRaisesRegex(ValueError, "Windows reserves", msg=repr(prefix)):
                            private_tmpdir(prefix, d)
                for prefix, suffix in good:
                    files._check_name(prefix, suffix)
            self.assertEqual(os.listdir(d), [])
            if os.name != "nt":   # control: on POSIX each of them is a name like any other
                for prefix, suffix in bad:
                    os.close(create_exclusive(d, prefix, suffix)[0])
                self.assertEqual(len(os.listdir(d)), len(bad))

    @unittest.skipUnless(hasattr(ntpath, "isreserved"), "ntpath.isreserved, the oracle, is of Python 3.13")
    def test_the_rules_are_those_of_ntpath_isreserved(self):
        """Generative. The colon is not in the alphabet: ntpath reads "a:" as a drive, here it is refused (above)."""
        import random
        rnd = random.Random(20261125)
        parts = ["nul", "NUL", "con", "aux", "prn", "com1", "LPT9", "com\u00b9", "lpt\u00b2", "conin$", "com0", "a", "p-",
                 ".", " ", "*", "?", '"', "<", ">", "|", "\x01", "\x1f", "\x7f", "\u00e9", "-", "_", "x.y"]
        reserved = 0
        for _ in range(20000):
            name = ("".join(rnd.choice(parts) for _ in range(rnd.randint(0, 3))) + "0123456789abcdef"
                    + "".join(rnd.choice(parts) for _ in range(rnd.randint(0, 2))))
            self.assertEqual(files._windows_reserved(name), ntpath.isreserved(name), repr(name))
            reserved += files._windows_reserved(name)
        self.assertTrue(2000 < reserved < 18000, reserved)

    def test_prefix_and_suffix_never_a_path(self):
        import random
        rnd = random.Random(20261125)
        bad = ["a/b", "/", "\\", "a\\b", "\0", "x\0", "../x"]
        for _ in range(300):
            s = "".join(rnd.choice("ab-._/\\\0é") for _ in range(rnd.randint(1, 6)))
            if any(c in s for c in "/\\\0"):
                bad.append(s)
        with tempfile.TemporaryDirectory() as d:
            for s in bad:
                with self.assertRaises(ValueError, msg=repr(s)):
                    create_exclusive(d, s)
                with self.assertRaises(ValueError, msg=repr(s)):
                    create_exclusive(d, "p-", s)
                with self.assertRaises(ValueError, msg=repr(s)):
                    private_tmpdir(s, d)
            for s in (None, b"p-", 1):
                with self.assertRaises(ValueError):
                    create_exclusive(d, s)
            self.assertEqual(os.listdir(d), [])
            # control: tempfile takes a prefix with a separator and creates elsewhere than `d`
            sub = os.path.join(d, "sub")
            os.mkdir(sub)
            fd, p = tempfile.mkstemp(prefix="sub" + os.sep, dir=d)
            os.close(fd)
            self.assertEqual(os.path.dirname(p), sub)


class ColonOnWindowsAndDefaultBase(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_a_colon_is_refused_on_windows(self):
        """Control: there, joining a folder and a name with a drive drops the folder; `a:x` is a stream of file a."""
        self.assertEqual(ntpath.join("D:\\safe", "C:0123456789abcdef"), "C:0123456789abcdef")
        with mock.patch.object(os, "name", "nt"):
            for call in (lambda: create_exclusive(self.d, "C:"), lambda: create_exclusive(self.d, "a", ":x"),
                         lambda: create_private(self.d, "a:"), lambda: private_tmpdir("C:", self.d)):
                with self.assertRaises(ValueError):
                    call()
        self.assertEqual(os.listdir(self.d), [])

    def test_the_default_base_is_the_temporary_folder(self):
        with mock.patch.object(files.tempfile, "gettempdir", lambda: self.d):
            path = private_tmpdir("nucleo-")
        self.assertEqual(os.path.dirname(path), self.d)
        self.assertTrue(os.path.isdir(path))


if __name__ == "__main__":
    unittest.main()
