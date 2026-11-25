# omega-nucleo-comune

The common core of Roberto Locatelli's works. The works stay separate; the core lives here and `nucleo_sync.py`
copies it into each of them (vendoring), with a manifest of sha256 digests: every work stays installable alone, with
no new dependency, and its CI tells a copy that was changed or left behind.

Version 0.1.0. Standard library only, Python >= 3.9, Linux, macOS and Windows. Licence Apache-2.0 (LICENSE, NOTICE).

| Module | Functions |
|---|---|
| `nucleo/programs.py` | `which_absolute(name)`: a program of an absolute PATH folder (on Windows one that names its drive), never the current folder; `run_program(argv, env=, timeout=)`: no shell (on Windows a `.bat` or `.cmd` file is refused: the system would run it through `cmd.exe`), the environment given and nothing else, stdin empty |
| `nucleo/files.py` | `create_exclusive`, `create_private`, `private_tmpdir`: a random name, `O_CREAT\|O_EXCL\|O_NOFOLLOW`, at most 64 tries and only on a name already taken; on Windows the access list of the owner alone, and a name the system reserves is refused |
| `nucleo/jsonio.py` | `json_loads_bounded(s, max_depth=512)`: nesting refused by a linear scan before the parser, the same bound on every Python, every encoding json.loads reads and wherever the caller stands in its stack |
| `nucleo/canonical.py` | `canonical_json_sorted_ascii` (the form of the current formats, NaN refused) and `canonical_json_jcs` (RFC 8785) |

## Copy and check

```
python3 nucleo_sync.py copy <repo> <pkg>/_nucleo    # from a clean checkout of this repository
python3 nucleo_sync.py check <repo>                 # 0 identical, 1 modified/stale/none (reason named), 2 usage
```

`check` looks for copies in every folder under `<repo>` but hidden ones (`.git`, `.venv`), `__pycache__` and
`node_modules`; a folder it cannot list, or a linked folder with a manifest in it, is a refusal. The commit it prints is
the one the manifest names: what it compares is the files. `copy` never writes through a link.

The vendored folder holds the five modules, LICENSE, NOTICE and `NUCLEO_MANIFEST.json`. The work marks it
`<pkg>/_nucleo/** -text` in `.gitattributes`, so that every system checks out the bytes the manifest names.

## Tests

```
python3 -m unittest discover -s tests -v
```

`tests/test_vectors_rfc8785.py` runs when `NUCLEO_RFC8785` names the official `rfc8785.txt` (the CI downloads it and
checks its sha256); its vectors are not kept here (DIFFERENZE.md, section «Vettori di RFC 8785»).

Where each function comes from and what changed: DIFFERENZE.md.
