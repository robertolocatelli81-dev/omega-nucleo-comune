#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""Copy the common core into a work (vendoring) and check a copy.

  nucleo_sync.py copy <repo> <dest_pkg_dir>   copy the core into <repo>/<dest_pkg_dir> with NUCLEO_MANIFEST.json
  nucleo_sync.py check <repo>                 every copy under <repo> is the core of this checkout, unmodified

Exit status of check: 0 every copy is identical to this core; 1 a copy is modified, stale, or there is none (each
reason named); 2 a usage error (also for copy: a dirty core, a destination outside the repo or not a copy).

Closed by construction: in a copy, a file the manifest does not name, a file it names that is missing, a file or a
manifest that is a link, a pipe or a folder, a key of the manifest that is not in its format, a duplicate key or a
value of the wrong shape is a refusal. The one entry tolerated beside the files is a folder named __pycache__ (written
by Python when the copy is imported; not checked). Under <repo>, a folder that cannot be listed and a linked folder
that holds a manifest are refusals too. Not entered, and so not checked: hidden folders (.git, .venv), __pycache__ and
node_modules. The commit printed by check is the one the manifest names: check compares the files, not the commit.
copy never writes through a link: each file is written beside its place and moved onto it."""
import argparse
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
from nucleo import __version__  # noqa: E402
from nucleo.files import create_exclusive  # noqa: E402
from nucleo.jsonio import json_loads_bounded  # noqa: E402
from nucleo.programs import run_program  # noqa: E402

FORMAT = "omega-nucleo-manifest/1"
MANIFEST = "NUCLEO_MANIFEST.json"
MODULES = ("__init__.py", "canonical.py", "files.py", "jsonio.py", "programs.py")
LEGAL = ("LICENSE", "NOTICE")   # Apache-2.0 §4: a copy carries the licence and the NOTICE
FILES = MODULES + LEGAL
KEYS = ("files", "format", "nucleo_commit", "nucleo_version")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}([0-9a-f]{24})?")   # SHA-1 or SHA-256 object names
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_UNPRINTABLE = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029\ud800-\udfff]")


def _show(s) -> str:
    """`s` on one line: a name from a manifest or a folder cannot write a line of its own ("OK ...") or stop print."""
    return _UNPRINTABLE.sub(lambda m: "\\u%04x" % ord(m.group()), str(s))


class Refused(Exception):
    """A copy that is not this core; the message is the named reason."""


class UsageError(Exception):
    pass


def _source(name: str) -> str:
    return os.path.join(ROOT, name) if name in LEGAL else os.path.join(ROOT, "nucleo", name)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 16), b""):
            h.update(block)
    return h.hexdigest()


def core_files() -> dict:
    """name -> sha256 of this checkout's core. The source folder holds exactly MODULES (and __pycache__)."""
    found = set(os.listdir(os.path.join(ROOT, "nucleo"))) - {"__pycache__"}
    if found != set(MODULES):
        raise UsageError("nucleo/ holds %s, nucleo_sync.MODULES names %s" % (sorted(found), sorted(MODULES)))
    return {n: _sha256(_source(n)) for n in FILES}


def _git(*args: str) -> str:
    env = {"LC_ALL": "C"}
    if os.name == "nt" and "SystemRoot" in os.environ:
        env["SystemRoot"] = os.environ["SystemRoot"]
    try:
        r = run_program(["git", "-C", ROOT, *args], env=env, timeout=60)
    except FileNotFoundError as e:
        raise UsageError(str(e)) from None
    if r.returncode != 0:
        raise UsageError("git %s: exit %d: %s" % (" ".join(args), r.returncode, r.stderr.decode("utf-8", "replace").strip()))
    return r.stdout.decode("utf-8", "replace")


def core_commit() -> str:
    """The commit of this checkout; UsageError if the core differs from it (the manifest would name the wrong commit)."""
    dirty = _git("status", "--porcelain", "--untracked-files=all", "--", "nucleo", *LEGAL)
    if dirty.strip():
        raise UsageError("the core differs from its commit:\n" + dirty)
    commit = _git("rev-parse", "HEAD").strip()
    if not _COMMIT.fullmatch(commit):
        raise UsageError("git rev-parse HEAD: %r" % commit)
    return commit


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise Refused("manifest_duplicate_key:%s" % k)
        out[k] = v
    return out


def read_manifest(path: str) -> dict:
    """The manifest at `path`, checked against its closed format; Refused with the reason otherwise."""
    try:
        with open(path, "rb") as f:
            raw = f.read(1 << 20)
        if len(raw) >= 1 << 20:
            raise Refused("manifest_too_large")
        m = json_loads_bounded(raw.decode("utf-8"), max_depth=2, object_pairs_hook=_no_duplicates)
    except Refused:
        raise
    except (OSError, ValueError, UnicodeDecodeError) as e:
        raise Refused("manifest_unreadable:%s" % type(e).__name__) from None
    if not isinstance(m, dict):
        raise Refused("manifest_not_an_object")
    for k in sorted(m):
        if k not in KEYS:
            raise Refused("manifest_unknown_key:%s" % k)
    for k in KEYS:
        if k not in m:
            raise Refused("manifest_missing_key:%s" % k)
    if m["format"] != FORMAT:
        raise Refused("manifest_bad_value:format")
    if not isinstance(m["nucleo_version"], str) or not _VERSION.fullmatch(m["nucleo_version"]):
        raise Refused("manifest_bad_value:nucleo_version")
    if not isinstance(m["nucleo_commit"], str) or not _COMMIT.fullmatch(m["nucleo_commit"]):
        raise Refused("manifest_bad_value:nucleo_commit")
    files = m["files"]
    if not isinstance(files, dict):
        raise Refused("manifest_bad_value:files")
    for name in sorted(files):
        if name not in FILES:
            raise Refused("manifest_unknown_file:%s" % name)
        if not isinstance(files[name], str) or not _HEX64.fullmatch(files[name]):
            raise Refused("manifest_bad_value:files.%s" % name)
    for name in FILES:
        if name not in files:
            raise Refused("manifest_missing_file:%s" % name)
    return m


def check_copy(folder: str, core: dict) -> dict:
    """Refused (named reason) unless `folder` holds exactly the files its manifest names, unmodified, and they are
    the files of `core` (name -> sha256) at version __version__. Returns the manifest."""
    mp = os.path.join(folder, MANIFEST)
    if os.path.lexists(mp) and (os.path.islink(mp) or not os.path.isfile(mp)):
        raise Refused("file_not_regular:%s" % MANIFEST)   # before it is opened: a pipe there would never end
    m = read_manifest(mp)
    for entry in sorted(os.listdir(folder)):
        p = os.path.join(folder, entry)
        if entry == "__pycache__" and os.path.isdir(p) and not os.path.islink(p):
            continue
        if entry != MANIFEST and entry not in m["files"]:
            raise Refused("file_extra:%s" % entry)
        if os.path.islink(p) or not os.path.isfile(p):
            raise Refused("file_not_regular:%s" % entry)
    for name, digest in sorted(m["files"].items()):
        p = os.path.join(folder, name)
        if not os.path.isfile(p):
            raise Refused("file_missing:%s" % name)
        if _sha256(p) != digest:
            raise Refused("file_modified:%s" % name)
    if m["nucleo_version"] != __version__:
        raise Refused("stale_version:%s!=%s" % (m["nucleo_version"], __version__))
    for name in FILES:
        if m["files"][name] != core[name]:
            raise Refused("stale_file:%s" % name)
    return m


def find_copies(repo: str, problems=None) -> list:
    """Every folder under `repo` holding a manifest (a file, or anything else at that name, in any letter case);
    hidden folders, __pycache__ and node_modules are not entered. What cannot be checked is appended to `problems`
    as (folder, reason): a folder that cannot be listed, a linked folder with a manifest in it (os.walk does not
    enter links)."""
    out = []
    problems = [] if problems is None else problems
    for dirpath, dirnames, filenames in os.walk(repo, onerror=lambda e: problems.append(
            (e.filename, "folder_unreadable:%s" % type(e).__name__))):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in ("__pycache__", "node_modules"))
        for d in dirnames:
            p = os.path.join(dirpath, d)
            if os.path.islink(p) and os.path.lexists(os.path.join(p, MANIFEST)):
                problems.append((p, "copy_behind_a_link"))
        if any(n.lower() == MANIFEST.lower() for n in filenames + dirnames):
            out.append(dirpath)
    return out


def cmd_check(repo: str) -> int:
    if not os.path.isdir(repo):
        raise UsageError("%s: not a folder" % repo)
    core = core_files()
    problems = []
    copies = find_copies(repo, problems)
    if not copies and not problems:
        print("FAIL %s: no_copy" % _show(repo))
        return 1
    status = 0
    for folder, why in problems:
        print("FAIL %s: %s" % (_show(folder), why))
        status = 1
    for folder in copies:
        try:
            m = check_copy(folder, core)
            print("OK %s: nucleo %s (manifest: commit %s)" % (_show(folder), m["nucleo_version"], m["nucleo_commit"]))
        except Refused as e:
            print("FAIL %s: %s" % (_show(folder), _show(e)))
            status = 1
        except OSError as e:
            print("FAIL %s: unreadable:%s" % (_show(folder), type(e).__name__))
            status = 1
    return status


def _put(folder: str, name: str, data: bytes) -> None:
    """`data` at folder/name, written to a new file beside it and moved onto it: a link, a pipe or a read-only file
    already at the name is replaced, never written through."""
    fd, tmp = create_exclusive(folder, ".nucleo-", ".tmp", 0o666)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, os.path.join(folder, name))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def cmd_copy(repo: str, dest: str) -> int:
    if not os.path.isdir(repo):
        raise UsageError("%s: not a folder" % repo)
    target = os.path.realpath(os.path.join(repo, dest))
    top = os.path.realpath(repo)
    try:
        inside = os.path.commonpath([top, target]) == top and target != top
    except ValueError:        # Windows: a destination on another drive
        inside = False
    if not inside:
        raise UsageError("%s: not a folder inside %s" % (dest, repo))
    if os.path.lexists(target):
        if not os.path.isdir(target) or os.path.islink(target):
            raise UsageError("%s: exists and is not a folder" % target)
        present = set(e for e in os.listdir(target) if not (
            e == "__pycache__" and os.path.isdir(os.path.join(target, e)) and not os.path.islink(os.path.join(target, e))))
        if present and MANIFEST not in present:
            raise UsageError("%s: a folder that is not a copy of the core (no %s): not overwritten" % (target, MANIFEST))
        if present - set(FILES) - {MANIFEST}:
            raise UsageError("%s: holds files the core does not: %s" % (target, sorted(present - set(FILES) - {MANIFEST})))
    core = core_files()
    commit = core_commit()
    manifest = {"files": core, "format": FORMAT, "nucleo_commit": commit, "nucleo_version": __version__}
    try:
        os.makedirs(target, exist_ok=True)
        for name in FILES:
            with open(_source(name), "rb") as f:
                _put(target, name, f.read())
        _put(target, MANIFEST, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        check_copy(target, core)   # what was written is what check will read
    except (OSError, Refused) as e:
        raise UsageError("%s: the copy failed: %s: %s" % (target, type(e).__name__, e)) from None
    print("copied nucleo %s (commit %s) to %s" % (__version__, commit, target))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="nucleo_sync.py", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("copy", help="copy the core into <repo>/<dest_pkg_dir>")
    c.add_argument("repo")
    c.add_argument("dest_pkg_dir")
    k = sub.add_parser("check", help="check every copy under <repo>")
    k.add_argument("repo")
    a = ap.parse_args(argv)
    try:
        return cmd_copy(a.repo, a.dest_pkg_dir) if a.cmd == "copy" else cmd_check(a.repo)
    except UsageError as e:
        print("error: %s" % _show(e).replace("\\u000a", "\n"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
