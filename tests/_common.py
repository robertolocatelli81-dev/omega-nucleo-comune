# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""Shared by the tests: the repository root on sys.path, the Windows access-list reader."""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

SYSDIR = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")


def windows_aces(path: str):
    """Windows: the entries of the access list of `path` as icacls prints them, and this user's name (whoami)."""
    out = subprocess.run([os.path.join(SYSDIR, "icacls.exe"), path], capture_output=True).stdout.decode("utf-8", "replace")
    who = subprocess.run([os.path.join(SYSDIR, "whoami.exe")], capture_output=True).stdout.decode("utf-8", "replace").strip()
    return [x.strip() for x in out.replace(path, "", 1).splitlines() if re.search(r":\(", x)], who, out
