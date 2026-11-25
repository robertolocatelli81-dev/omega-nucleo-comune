# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Roberto Locatelli
"""Every test file: nothing after `if __name__ == "__main__":` (a test written below unittest.main() never runs);
every .py file starts with its SPDX line. Exit 1 with the places, 0 otherwise."""
import ast
import pathlib
import sys

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
bad = 0
for p in sorted(root.rglob("*.py")):
    if any(x in p.parts for x in (".git", "__pycache__")):
        continue
    text = p.read_text(encoding="utf-8")
    if "SPDX-License-Identifier: Apache-2.0" not in "\n".join(text.splitlines()[:3]):
        print("%s: no SPDX line" % p)
        bad += 1
    if p.name.startswith("test"):
        main_at = None
        for n in ast.parse(text).body:
            if isinstance(n, ast.If) and "__main__" in ast.dump(n.test):
                main_at = n.lineno
            elif main_at:
                print("%s:%d after the __main__ block (line %d)" % (p, n.lineno, main_at))
                bad += 1
print("found:", bad)
sys.exit(1 if bad else 0)
