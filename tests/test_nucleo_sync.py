# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""nucleo_sync.py: a copy is the core, unmodified and current, or a refusal with its reason; the manifest is closed."""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

import _common
import nucleo_sync as S
from nucleo.programs import which_absolute

COMMIT = "0123456789abcdef0123456789abcdef01234567"


def make_copy(folder, core=None, **override):
    """A copy of this checkout's core in `folder`, with its manifest (the fields of `override` replaced)."""
    os.makedirs(folder, exist_ok=True)
    for n in S.FILES:
        shutil.copyfile(S._source(n), os.path.join(folder, n))
    m = {"files": dict(core or S.core_files()), "format": S.FORMAT, "nucleo_commit": COMMIT, "nucleo_version": S.__version__}
    m.update(override)
    write_manifest(folder, m)
    return m


def write_manifest(folder, m, raw=None):
    with open(os.path.join(folder, S.MANIFEST), "wb") as f:
        f.write(raw if raw is not None else json.dumps(m, indent=2, sort_keys=True).encode("utf-8"))


def reason(folder, core=None):
    try:
        S.check_copy(folder, core or S.core_files())
    except S.Refused as e:
        return str(e)
    return "OK"


class _Tmp(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.copy = os.path.join(self.d, "pkg", "_nucleo")


class CheckCopy(_Tmp):
    def test_identical(self):
        make_copy(self.copy)
        self.assertEqual(reason(self.copy), "OK")
        os.mkdir(os.path.join(self.copy, "__pycache__"))   # written by Python on import: tolerated
        self.assertEqual(reason(self.copy), "OK")

    def test_modified_file(self):
        for name in S.FILES:
            with self.subTest(name=name):
                make_copy(self.copy)
                with open(os.path.join(self.copy, name), "ab") as f:
                    f.write(b"\n")
                self.assertEqual(reason(self.copy), "file_modified:%s" % name)

    def test_extra_and_missing(self):
        make_copy(self.copy)
        with open(os.path.join(self.copy, "extra.py"), "wb") as f:
            f.write(b"")
        # positive control: every file the manifest names is still unmodified; only the closed listing sees it
        self.assertTrue(all(S._sha256(os.path.join(self.copy, n)) == h for n, h in S.core_files().items()))
        self.assertEqual(reason(self.copy), "file_extra:extra.py")
        os.unlink(os.path.join(self.copy, "extra.py"))
        os.mkdir(os.path.join(self.copy, "sub"))
        self.assertEqual(reason(self.copy), "file_extra:sub")
        os.rmdir(os.path.join(self.copy, "sub"))
        os.unlink(os.path.join(self.copy, "jsonio.py"))
        self.assertEqual(reason(self.copy), "file_missing:jsonio.py")

    def test_a_link_is_not_a_file(self):
        make_copy(self.copy)
        p = os.path.join(self.copy, "files.py")
        os.unlink(p)
        try:
            os.symlink(S._source("files.py"), p)
        except OSError:
            if os.name == "nt":
                self.skipTest("Windows without the right to make links (SeCreateSymbolicLinkPrivilege)")
            raise
        self.assertEqual(reason(self.copy), "file_not_regular:files.py")

    def test_stale(self):
        make_copy(self.copy, nucleo_version="0.0.9")
        self.assertEqual(reason(self.copy), "stale_version:0.0.9!=%s" % S.__version__)
        core = S.core_files()
        newer = dict(core, **{"files.py": "f" * 64})   # the core moved on, the copy did not
        make_copy(self.copy)
        self.assertEqual(reason(self.copy, newer), "stale_file:files.py")


class ClosedManifest(_Tmp):
    def _reason_for(self, m=None, raw=None):
        make_copy(self.copy)
        write_manifest(self.copy, m, raw)
        return reason(self.copy)

    def good(self):
        return {"files": S.core_files(), "format": S.FORMAT, "nucleo_commit": COMMIT, "nucleo_version": S.__version__}

    def test_unknown_key_at_every_level(self):
        rnd = random.Random(20261125)
        for _ in range(200):
            k = "".join(rnd.choice("abz_-.0é  ") for _ in range(rnd.randint(0, 8)))
            m = self.good()
            if k not in S.KEYS:
                m[k] = rnd.choice([None, 1, "x", [], {}])
                self.assertEqual(self._reason_for(m), "manifest_unknown_key:%s" % k, repr(k))
            m = self.good()
            if k not in S.FILES:
                m["files"][k] = "0" * 64
                self.assertEqual(self._reason_for(m), "manifest_unknown_file:%s" % k, repr(k))

    def test_missing_keys(self):
        for k in S.KEYS:
            m = self.good()
            del m[k]
            self.assertEqual(self._reason_for(m), "manifest_missing_key:%s" % k)
        for n in S.FILES:
            m = self.good()
            del m["files"][n]
            self.assertEqual(self._reason_for(m), "manifest_missing_file:%s" % n)

    def test_wrong_types_and_shapes(self):
        wrong = [None, True, 0, 1.5, "", [], {}, "0.1", "v0.1.0", "0.1.0 ", "0.1.0\n", "A" * 64, "0" * 63, "0" * 65,
                 "G" * 40, COMMIT.upper(), "0" * 64, "٠.1.0"]
        for k in ("format", "nucleo_version", "nucleo_commit", "files"):
            for v in wrong:
                m = self.good()
                if v == m[k] or (k == "nucleo_commit" and v == "0" * 64) or (k == "files" and v == {}):
                    continue   # a SHA-256 object name is a commit of the right shape; {} names no file (missing_file)
                m[k] = v
                self.assertEqual(self._reason_for(m), "manifest_bad_value:%s" % k, (k, v))
        for v in wrong + ["F" * 64, " " + "0" * 63]:
            m = self.good()
            m["files"]["jsonio.py"] = v
            want = ("manifest_unreadable:JsonTooDeepToRead" if isinstance(v, (list, dict)) else
                    "file_modified:jsonio.py" if v == "0" * 64 else "manifest_bad_value:files.jsonio.py")
            self.assertEqual(self._reason_for(m), want, repr(v))   # a container there is a third level: too deep

    def test_duplicates_and_encodings(self):
        body = json.dumps(self.good(), sort_keys=True)
        self.assertEqual(self._reason_for(raw=body.encode()), "OK")   # control
        dup = '{"format": "x", ' + body[1:]
        self.assertEqual(self._reason_for(raw=dup.encode()), "manifest_duplicate_key:format")
        files_dup = body.replace('"files": {', '"files": {"jsonio.py": "%s", ' % ("0" * 64), 1)
        self.assertEqual(self._reason_for(raw=files_dup.encode()), "manifest_duplicate_key:jsonio.py")
        for raw in (b"\xef\xbb\xbf" + body.encode(), body.encode("utf-16"), body.encode("utf-32-le"),
                    b"\xff" + body.encode(),
                    b"", b"{", b"[" * 5 + b"]" * 5, b"{}" + b" " * (1 << 20)):
            self.assertTrue(self._reason_for(raw=raw).startswith(("manifest_unreadable", "manifest_too_large")), raw[:8])
        for raw in (b"[]", b"1", b'"x"', b"null"):
            self.assertEqual(self._reason_for(raw=raw), "manifest_not_an_object", raw)
        self.assertEqual(self._reason_for(raw=b'{"files": {"a": {"b": 1}}}'), "manifest_unreadable:JsonTooDeepToRead")

    def test_a_destination_on_another_drive_is_a_usage_error(self):
        """Windows: os.path.commonpath raises ValueError for paths of two drives (control with ntpath)."""
        import ntpath
        from unittest import mock
        with self.assertRaises(ValueError):
            ntpath.commonpath(["C:\\repo", "D:\\repo\\pkg"])
        with mock.patch.object(os.path, "commonpath", side_effect=ValueError("Paths don't have the same drive")):
            with self.assertRaisesRegex(S.UsageError, "not a folder inside"):
                S.cmd_copy(self.d, "pkg")
        self.assertEqual(os.listdir(self.d), [])

    def test_manifest_missing(self):
        make_copy(self.copy)
        os.unlink(os.path.join(self.copy, S.MANIFEST))
        self.assertEqual(S.find_copies(self.d), [])


class EndToEnd(_Tmp):
    """copy and check run as Roberto's works will run them, from a core that is a git checkout of its own."""

    def setUp(self):
        super().setUp()
        self.core = os.path.join(self.d, "core")
        os.makedirs(self.core)
        for n in ("nucleo", "LICENSE", "NOTICE", "nucleo_sync.py", ".gitattributes", ".gitignore"):
            src = os.path.join(_common.ROOT, n)
            (shutil.copytree(src, os.path.join(self.core, n), ignore=shutil.ignore_patterns("__pycache__"))
             if os.path.isdir(src) else shutil.copyfile(src, os.path.join(self.core, n)))
        self.git("init", "-q")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "core")
        self.work = os.path.join(self.d, "work")
        os.makedirs(os.path.join(self.work, "pkg"))

    def git(self, *args):
        env = {"LC_ALL": "C"}
        if os.name == "nt":
            env["SystemRoot"] = os.environ["SystemRoot"]
        r = subprocess.run([which_absolute("git"), "-C", self.core, "-c", "user.name=t",
                            "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *args],
                           env=env, capture_output=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.decode()

    def sync(self, *args, **more_env):
        r = subprocess.run([sys.executable, "-I", os.path.join(self.core, "nucleo_sync.py"), *args],
                           capture_output=True, timeout=120, env=dict(os.environ, **more_env))
        return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace")

    def test_copy_then_check(self):
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))
        self.assertEqual(rc, 0, out)
        m = json.loads(open(os.path.join(self.work, "pkg", "_nucleo", S.MANIFEST), encoding="utf-8").read())
        self.assertEqual(m["nucleo_commit"], self.git("rev-parse", "HEAD").strip())
        rc, out = self.sync("check", self.work)
        self.assertEqual(rc, 0, out)
        self.assertIn("OK ", out)
        # the copy is importable as a package of the work, with no other path
        r = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); "
                            "import pkg._nucleo.jsonio as j, pkg._nucleo as n; "
                            "print(n.__version__, j.json_loads_bounded('[1]'))",
                            self.work], capture_output=True, timeout=60)
        self.assertEqual(r.stdout.decode().split(), [S.__version__, "[1]"], r.stderr)
        rc, out = self.sync("check", self.work)   # __pycache__ written by that import: tolerated
        self.assertEqual(rc, 0, out)
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))   # again: an update in place
        self.assertEqual(rc, 0, out)

    def test_check_names_the_reason(self):
        self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))
        with open(os.path.join(self.work, "pkg", "_nucleo", "programs.py"), "ab") as f:
            f.write(b"# local change\n")
        rc, out = self.sync("check", self.work)
        self.assertEqual((rc, out.strip().split(": ")[-1]), (1, "file_modified:programs.py"), out)

    def test_old_copy_after_a_new_core(self):
        self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))
        p = os.path.join(self.core, "nucleo", "__init__.py")
        with open(p, encoding="utf-8") as f:
            s = f.read()
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(s.replace('__version__ = "%s"' % S.__version__, '__version__ = "9.9.9"'))
        self.git("commit", "-q", "-am", "9.9.9")
        rc, out = self.sync("check", self.work)
        self.assertEqual(rc, 1, out)
        self.assertIn("stale_version:%s!=9.9.9" % S.__version__, out)

    def test_no_copy(self):
        rc, out = self.sync("check", self.work)
        self.assertEqual(rc, 1, out)
        self.assertIn("no_copy", out)

    def test_usage_errors(self):
        self.assertEqual(self.sync()[0], 2)
        self.assertEqual(self.sync("check")[0], 2)
        self.assertEqual(self.sync("verify", self.work)[0], 2)
        self.assertEqual(self.sync("check", os.path.join(self.d, "nowhere"))[0], 2)
        self.assertEqual(self.sync("copy", self.work, os.path.join("..", "outside"))[0], 2)
        self.assertEqual(self.sync("copy", self.work, ".")[0], 2)
        os.makedirs(os.path.join(self.work, "pkg", "own"))
        with open(os.path.join(self.work, "pkg", "own", "code.py"), "w") as f:
            f.write("x = 1\n")
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "own"))
        self.assertEqual(rc, 2, out)
        self.assertTrue(os.path.isfile(os.path.join(self.work, "pkg", "own", "code.py")))   # not overwritten
        self.assertEqual(sorted(os.listdir(os.path.join(self.work, "pkg", "own"))), ["code.py"])
        # a folder of the work whose files only bear the core's names, with no manifest: not a copy, not overwritten
        os.makedirs(os.path.join(self.work, "pkg", "same"))
        with open(os.path.join(self.work, "pkg", "same", "files.py"), "w") as f:
            f.write("mine = 1\n")
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "same"))
        self.assertEqual(rc, 2, out)
        self.assertEqual(sorted(os.listdir(os.path.join(self.work, "pkg", "same"))), ["files.py"])
        with open(os.path.join(self.work, "pkg", "same", "files.py")) as f:
            self.assertEqual(f.read(), "mine = 1\n")

    def test_a_dirty_core_is_not_copied(self):
        with open(os.path.join(self.core, "nucleo", "files.py"), "ab") as f:
            f.write(b"\n")
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))
        self.assertEqual(rc, 2, out)
        self.assertFalse(os.path.exists(os.path.join(self.work, "pkg", "_nucleo")))
        os.unlink(os.path.join(self.core, "nucleo", "files.py"))
        self.git("checkout", "--", "nucleo/files.py")
        with open(os.path.join(self.core, "nucleo", "new.py"), "w") as f:
            f.write("")
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))
        self.assertEqual(rc, 2, out)
        os.unlink(os.path.join(self.core, "nucleo", "new.py"))
        self.assertEqual(self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))[0], 0)   # control: clean again
        # a file of the core that its commit does not hold, in a checkout set not to show untracked files
        self.git("rm", "-q", "--cached", "NOTICE")
        self.git("commit", "-q", "-m", "without NOTICE")
        self.git("config", "status.showUntrackedFiles", "no")
        self.assertEqual(self.git("status", "--porcelain"), "")   # control: git alone calls this checkout clean
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))
        self.assertEqual(rc, 2, out)
        self.assertIn("the core differs from its commit", out)
        self.assertIn("?? NOTICE", out)


    # --- closed against links, pipes, folders that hide a copy, and names that write lines (review 25/11/2026)

    def _link(self, target, at):
        try:
            os.symlink(target, at)
        except OSError:
            if os.name == "nt":
                self.skipTest("Windows without the right to make links (SeCreateSymbolicLinkPrivilege)")
            raise

    def _copied(self):
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))
        self.assertEqual(rc, 0, out)
        return os.path.join(self.work, "pkg", "_nucleo")

    def test_copy_never_writes_through_a_link(self):
        copy = self._copied()
        victim = os.path.join(self.d, "victim.txt")
        for name in ("files.py", S.MANIFEST, "LICENSE"):
            with self.subTest(name=name):
                with open(victim, "w") as f:
                    f.write("not the core\n")
                os.unlink(os.path.join(copy, name))
                self._link(victim, os.path.join(copy, name))
                rc, out = self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))
                self.assertEqual(rc, 0, out)
                with open(victim) as f:
                    self.assertEqual(f.read(), "not the core\n")   # until 25/11 the core's file was written here
                self.assertFalse(os.path.islink(os.path.join(copy, name)))
                self.assertEqual(self.sync("check", self.work)[0], 0)
        self.assertEqual(sorted(os.listdir(copy)), sorted(S.FILES + (S.MANIFEST,)))   # no temporary file left

    def test_copy_errors_are_usage_errors_not_tracebacks(self):
        copy = self._copied()
        os.unlink(os.path.join(copy, "files.py"))
        os.mkdir(os.path.join(copy, "files.py"))            # a folder at the name of a file
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))
        self.assertEqual(rc, 2, out)
        self.assertNotIn("Traceback", out)
        self.assertEqual([n for n in os.listdir(copy) if n.endswith(".tmp")], [])
        os.rmdir(os.path.join(copy, "files.py"))
        with open(os.path.join(copy, "mine.py"), "w") as f:  # a copy holding a file of the work
            f.write("x = 1\n")
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))
        self.assertEqual(rc, 2, out)
        self.assertIn("holds files the core does not", out)   # refused before a file is written
        os.unlink(os.path.join(copy, "mine.py"))
        with open(os.path.join(copy, "__pycache__"), "w") as f:   # __pycache__ is passed over only as a folder
            f.write("")
        before = {n: os.stat(os.path.join(copy, n)).st_mtime_ns for n in os.listdir(copy)}
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))
        self.assertEqual(rc, 2, out)
        self.assertIn("holds files the core does not: ['__pycache__']", out)
        self.assertEqual({n: os.stat(os.path.join(copy, n)).st_mtime_ns for n in os.listdir(copy)}, before)
        self.assertNotIn("Traceback", out)
        os.unlink(os.path.join(copy, "__pycache__"))
        # what was written is read again: a file that did not arrive as it is in the core is a refusal, not a copy
        r = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); "
                            "import nucleo_sync as S; put = S._put; "
                            "S._put = lambda d, n, data: put(d, n, data[:-1] if n == 'files.py' else data); "
                            "sys.exit(S.main(['copy', sys.argv[2], sys.argv[3]]))",
                            self.core, self.work, os.path.join("pkg", "_nucleo")], capture_output=True, timeout=120)
        out = (r.stdout + r.stderr).decode("utf-8", "replace")
        self.assertEqual(r.returncode, 2, out)
        self.assertIn("the copy failed: Refused: file_modified:files.py", out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("copied nucleo", out)
        with open(os.path.join(self.work, "pkg", "afile"), "w") as f:
            f.write("")
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "afile"))   # the destination is a file
        self.assertEqual(rc, 2, out)
        self.assertNotIn("Traceback", out)
        empty = os.path.join(self.d, "empty")
        os.mkdir(empty)
        self.assertEqual(self.sync("copy", empty, ".")[0], 2)                  # the repository itself, even empty
        self.assertEqual(os.listdir(empty), [])

    def test_a_file_git_ignores_in_the_core_is_not_copied(self):
        with open(os.path.join(self.core, "nucleo", "stray.pyc"), "w") as f:   # *.pyc: git status does not show it
            f.write("")
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))
        self.assertEqual(rc, 2, out)

    def test_git_of_the_core_ignores_the_callers_environment(self):
        other = os.path.join(self.d, "other.git")
        os.mkdir(other)
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "_nucleo"), GIT_DIR=other, GIT_WORK_TREE=other)
        self.assertEqual(rc, 0, out)
        self.assertIn(self.git("rev-parse", "HEAD").strip(), out)

    def test_a_manifest_that_is_not_a_file(self):
        copy = self._copied()
        os.unlink(os.path.join(copy, S.MANIFEST))
        os.mkdir(os.path.join(copy, S.MANIFEST))
        rc, out = self.sync("check", self.work)
        self.assertEqual((rc, out.strip().split(": ")[-1]), (1, "file_not_regular:%s" % S.MANIFEST), out)
        os.rmdir(os.path.join(copy, S.MANIFEST))
        if hasattr(os, "mkfifo"):       # Windows: a named pipe lives in \\.\pipe\, never at a name inside a folder
            os.mkfifo(os.path.join(copy, S.MANIFEST))
            rc, out = self.sync("check", self.work)   # until 25/11 the open never ended
            self.assertEqual((rc, out.strip().split(": ")[-1]), (1, "file_not_regular:%s" % S.MANIFEST), out)
            os.unlink(os.path.join(copy, S.MANIFEST))
        os.rename(os.path.join(copy, "NOTICE"), os.path.join(copy, S.MANIFEST.lower()))   # another letter case
        rc, out = self.sync("check", self.work)
        self.assertEqual(rc, 1, out)
        self.assertNotIn("no_copy", out)

    def test_a_second_copy_that_cannot_be_checked_is_a_refusal(self):
        copy = self._copied()
        bad = os.path.join(self.d, "elsewhere")
        shutil.copytree(copy, bad)
        with open(os.path.join(bad, "programs.py"), "ab") as f:
            f.write(b"# changed\n")
        os.mkdir(os.path.join(self.work, "other"))
        self._link(bad, os.path.join(self.work, "other", "_nucleo"))
        rc, out = self.sync("check", self.work)       # until 25/11: exit 0, the linked copy was not seen
        self.assertEqual(rc, 1, out)
        self.assertIn("copy_behind_a_link", out)
        self.assertIn("OK ", out)                     # the good copy is still reported
        shutil.rmtree(copy)
        rc, out = self.sync("check", self.work)       # the linked copy alone: named, not "no_copy"
        self.assertEqual(rc, 1, out)
        self.assertIn("copy_behind_a_link", out)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "a mode does not deny listing to root")
    def test_a_folder_that_cannot_be_listed_is_a_refusal(self):
        copy = self._copied()
        shutil.copytree(copy, os.path.join(self.work, "other", "_nucleo"))
        other = os.path.join(self.work, "other")
        if os.name == "nt":   # a mode does not deny listing there: a deny entry on reading the folder does
            icacls, who = os.path.join(_common.SYSDIR, "icacls.exe"), os.environ["USERNAME"]
            subprocess.run([icacls, other, "/deny", who + ":(RD)"], check=True, capture_output=True)
            self.addCleanup(subprocess.run, [icacls, other, "/remove:d", who], capture_output=True)
        else:
            os.chmod(other, 0)
            self.addCleanup(os.chmod, other, 0o700)
        rc, out = self.sync("check", self.work)       # until 25/11: exit 0
        self.assertEqual(rc, 1, out)
        self.assertIn("folder_unreadable:PermissionError", out)

    def test_hidden_folders_and_node_modules_are_not_entered(self):
        copy = self._copied()
        for sub in (".hidden", "node_modules", "__pycache__"):
            shutil.copytree(copy, os.path.join(self.work, sub, "_nucleo"))
        self.assertEqual(S.find_copies(self.work), [copy])

    def test_copy_passes_over_pycache_only_as_a_folder(self):
        copy = self._copied()
        self._link(self.d, os.path.join(copy, "__pycache__"))
        before = {n: os.lstat(os.path.join(copy, n)).st_mtime_ns for n in os.listdir(copy)}
        rc, out = self.sync("copy", self.work, os.path.join("pkg", "_nucleo"))
        self.assertEqual(rc, 2, out)
        self.assertIn("holds files the core does not: ['__pycache__']", out)   # refused before a file is written
        self.assertEqual({n: os.lstat(os.path.join(copy, n)).st_mtime_ns for n in os.listdir(copy)}, before)

    def test_pycache_is_tolerated_only_as_a_folder(self):
        copy = self._copied()
        with open(os.path.join(copy, "__pycache__"), "w") as f:
            f.write("")
        self.assertEqual(reason(copy), "file_extra:__pycache__")
        os.unlink(os.path.join(copy, "__pycache__"))
        self._link(self.d, os.path.join(copy, "__pycache__"))
        self.assertEqual(reason(copy), "file_extra:__pycache__")

    def test_a_name_cannot_write_a_line_of_its_own(self):
        copy = self._copied()
        with open(os.path.join(copy, S.MANIFEST), encoding="utf-8") as f:
            m = json.load(f)
        for key in ("x\nOK /forged: nucleo 0.1.0", "x\rOK", "x\u2028OK", "\ud800"):
            with self.subTest(key=ascii(key)):
                write_manifest(copy, None, json.dumps(dict(m, **{key: 1})).encode("utf-8"))
                rc, out = self.sync("check", self.work)
                self.assertEqual(rc, 1, out)
                self.assertNotIn("Traceback", out)
                self.assertEqual(len(out.splitlines()), 1, out)
                self.assertTrue(out.startswith("FAIL "), out)

    def test_the_commit_printed_is_the_manifests(self):
        self._copied()
        rc, out = self.sync("check", self.work)
        self.assertEqual(rc, 0, out)
        self.assertIn("(manifest: commit %s)" % self.git("rev-parse", "HEAD").strip(), out)


if __name__ == "__main__":
    unittest.main()
