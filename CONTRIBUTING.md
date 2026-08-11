# contributing

Patches welcome. Keep it in the spirit of the thing.

## the rules

- **stdlib first.** a new pip dependency has to earn its place; "it was easier" doesn't
  count. shelling out to a tool that's already on the box (nmap, snmpwalk, testssl) is fine.
- **degrade, don't die.** no root, no nmap, no network? the feature turns itself off and the
  rest keeps working. wrap probes in try/except, use short timeouts, never raise to the caller.
- **read-only by default.** this enumerates and enriches, it does not exploit. anything that
  touches auth stays opt-in and rate-limited.
- **every module has a `--selftest`** that runs offline, needs no root, and exits 0. add one
  for whatever you build.
- **match the house style.** terse. lowercase comments only where the code can't speak for
  itself. no banner blocks, no dividers, no docstrings restating the obvious.

## before you open a PR

```bash
python3 <module>.py --selftest        # green for anything you touched
bash -n netdeep.sh scan-8006.sh
python3 -c "import py_compile,glob; [py_compile.compile(f,doraise=True) for f in glob.glob('*.py')]"
```

And scan your own gear only. See the authorization note in the README.

## where to start

`ROADMAP.md` has the todo list. Two open threads worth grabbing: feed the fingerprint and
WS-Discovery signals back into `classify()` so device types get them for free, and a launchd
watch daemon so the thing can run unattended.
