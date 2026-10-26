#!/usr/bin/env python3
"""winspawn - hidden-by-default background process spawning on Windows.

Two halves:

  RUNTIME   popen_hidden() / run_hidden() wrap subprocess so a background
            child does not allocate a console window. They inject
            CREATE_NO_WINDOW (+ CREATE_NEW_PROCESS_GROUP for services) and
            STRIP the two flags that cause visible windows / orphaned
            consoles: DETACHED_PROCESS and CREATE_NEW_CONSOLE.

  AUDIT     BANNED_PATTERNS + audit() are the source-contract half: a tree
            walk that reports every spawn site written the visible way, in
            Python, Node, PowerShell, and Task Scheduler registrations.

Escape hatch: put `spawn-hidden-ok: <reason>` on the offending line (or the
line directly above it) and the auditor skips it.

    import sys, winspawn
    p = winspawn.popen_hidden([sys.executable, "server.py"],
                              creationflags=winspawn.SERVICE_FLAGS)

CLI:  python -m winspawn --audit <root> [--json] [--exclude DIR]   (exit 1 if findings, 2 on bad path)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

__all__ = [
    "HIDDEN_FLAGS",
    "SERVICE_FLAGS",
    "BAD_FLAGS",
    "popen_hidden",
    "run_hidden",
    "hidden_kwargs",
    "BANNED_PATTERNS",
    "ESCAPE_MARKER",
    "DEFAULT_EXCLUDE_DIRS",
    "audit",
    "scan_text",
    "safe_replacement",
    "main",
]

_WIN = os.name == "nt"

# -- flags --------------------------------------------------------------------
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if _WIN else 0
CREATE_NEW_PROCESS_GROUP = (
    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200) if _WIN else 0
)
DETACHED_PROCESS = getattr(subprocess, "DETACHED_PROCESS", 0x00000008) if _WIN else 0
CREATE_NEW_CONSOLE = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x00000010) if _WIN else 0

#: Minimum for any background child: no console window, ever.
HIDDEN_FLAGS = CREATE_NO_WINDOW
#: For long-lived services: also isolate from the parent's Ctrl-C group.
SERVICE_FLAGS = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
#: Flags that produce a visible window or an orphaned console - always stripped.
BAD_FLAGS = DETACHED_PROCESS | CREATE_NEW_CONSOLE


def hidden_kwargs(kw: dict | None = None, service: bool = False) -> dict:
    """Return kwargs with creationflags merged to the hidden form.

    The caller's own creationflags are preserved except DETACHED_PROCESS and
    CREATE_NEW_CONSOLE, which are stripped. On non-Windows this is a no-op.
    """
    kw = dict(kw or {})
    if not _WIN:
        kw.pop("creationflags", None)
        return kw
    flags = int(kw.get("creationflags", 0) or 0)
    flags &= ~BAD_FLAGS
    flags |= SERVICE_FLAGS if service else HIDDEN_FLAGS
    kw["creationflags"] = flags
    kw.setdefault("close_fds", True)
    return kw


def popen_hidden(cmd, *, service: bool = False, **kw):
    """subprocess.Popen with CREATE_NO_WINDOW (no console allocated)."""
    return subprocess.Popen(cmd, **hidden_kwargs(kw, service=service))


def run_hidden(cmd, *, service: bool = False, **kw):
    """subprocess.run with CREATE_NO_WINDOW (no console allocated)."""
    return subprocess.run(cmd, **hidden_kwargs(kw, service=service))


# -- audit half --------------------------------------------------------------
ESCAPE_MARKER = "spawn-hidden-ok:"

PY = (".py",)
JS = (".js", ".cjs", ".mjs", ".ts", ".mts")
JSTS = JS
PS1 = (".ps1", ".psm1")

#: (name, compiled regex, file-suffixes, safe_replacement)
BANNED_PATTERNS = [
    (
        "DETACHED_PROCESS",
        re.compile(r"\bDETACHED_PROCESS\b"),
        PY,
        "import winspawn; winspawn.popen_hidden(cmd, service=True)  "
        "(or creationflags=winspawn.SERVICE_FLAGS)",
    ),
    (
        "CREATE_NEW_CONSOLE",
        re.compile(r"\bCREATE_NEW_CONSOLE\b"),
        PY,
        "import winspawn; winspawn.popen_hidden(cmd)  "
        "(creationflags=winspawn.HIDDEN_FLAGS)",
    ),
    (
        "child_process exec",
        # exec( / execSync( (bare or child_process./cp. receiver), not execFile(
        re.compile(r"(?:(?<![\w.$])|(?i:\b(?:child_?process|cp)\.))exec(?:Sync)?\s*\("),
        JSTS,
        "execFileHidden()/spawnHidden() from node/spawn_hidden.cjs "
        "(execFile + windowsHide: true)",
    ),
    (
        "detached without windowsHide",
        re.compile(r"detached\s*:\s*true"),
        JS,
        "spawnHidden(cmd, args, opts) from node/spawn_hidden.cjs "
        "(windowsHide: true, no detached)",
    ),
    (
        "Start-Process without -WindowStyle",
        re.compile(r"\bStart-Process\b", re.IGNORECASE),
        PS1,
        "Start-Process -WindowStyle Hidden ...",
    ),
    (
        "ScheduledTaskAction with console exe",
        re.compile(
            r"New-ScheduledTaskAction\b[^\n]*-Execute\s+"
            r"['\"]?[^'\"\s]*\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd\.exe|"
            r"py\.exe|python(?:w)?\.exe|[^'\"\s]+\.(?:cmd|bat))['\"]?",
            re.IGNORECASE,
        ),
        PS1,
        "New-ScheduledTaskAction -Execute wscript.exe "
        "-Argument '\"<path>\\run-hidden.vbs\" ...'",
    ),
]

DEFAULT_EXCLUDE_DIRS = (
    "node_modules",
    ".venv",
    "venv",
    "site-packages",
    "__pycache__",
    ".git",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
)

_SELF_NAMES = {"winspawn.py", "hidden_spawn_guard.py", "spawn_hidden.cjs"}
_ALL_SUFFIXES = tuple(sorted({s for _, _, sufs, _ in BANNED_PATTERNS for s in sufs}))


#: Leading comment tokens per language - a line that only *talks about* a
#: banned flag (a comment, or a docstring bullet) is not a spawn site.
_COMMENT_PREFIXES = {
    ".py": ("#",),
    ".ps1": ("#",),
    ".psm1": ("#",),
    ".js": ("//", "*", "/*"),
    ".cjs": ("//", "*", "/*"),
    ".mjs": ("//", "*", "/*"),
    ".ts": ("//", "*", "/*"),
    ".mts": ("//", "*", "/*"),
}


_EXEC_DEF = re.compile(r"\s*(?:async\s+|static\s+|function\s+)*exec(?:Sync)?\s*\([^)]*\)\s*\{")


def _is_comment(line: str, suffix: str) -> bool:
    stripped = line.strip()
    return stripped.startswith(_COMMENT_PREFIXES.get(suffix, ()))


def _escaped(lines: list[str], idx: int) -> bool:
    """Marker on the flagged line, or on the line directly above it."""
    if ESCAPE_MARKER in lines[idx]:
        return True
    return idx > 0 and ESCAPE_MARKER in lines[idx - 1]


def _windows_hide_nearby(lines: list[str], idx: int) -> bool:
    """Approximate same statement: 6 lines up and 6 down."""
    window = "\n".join(lines[max(0, idx - 6) : idx + 7])
    return "windowsHide" in window and re.search(
        r"windowsHide\s*:\s*true", window
    ) is not None


def scan_text(text: str, suffix: str) -> list[tuple[int, str, str]]:
    """Scan one file's text. Returns [(lineno, pattern_name, line_text)]."""
    suffix = suffix.lower()
    lines = text.splitlines()
    out: list[tuple[int, str, str]] = []
    for name, rx, suffixes, _safe in BANNED_PATTERNS:
        if suffix not in suffixes:
            continue
        for i, line in enumerate(lines):
            if not rx.search(line):
                continue
            if _is_comment(line, suffix):
                continue
            if _escaped(lines, i):
                continue
            if name == "child_process exec" and _EXEC_DEF.match(line):
                continue
            if name in ("detached without windowsHide", "child_process exec") and _windows_hide_nearby(lines, i):
                continue
            if name == "Start-Process without -WindowStyle" and re.search(
                r"-WindowStyle\s+Hidden", line, re.IGNORECASE
            ):
                continue
            out.append((i + 1, name, line.strip()))
    out.sort()
    return out


def audit(root, exclude_dirs=DEFAULT_EXCLUDE_DIRS, extra_excludes=()):
    """Walk `root`, return [(path, lineno, pattern_name, line_text)]."""
    root = Path(root)
    skip = {d.lower() for d in tuple(exclude_dirs) + tuple(extra_excludes)}
    findings: list[tuple[str, int, str, str]] = []
    if root.is_file():
        files = [root]
    else:
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames
                if d.lower() not in skip
            ]
            for fn in filenames:
                if fn.lower().endswith(_ALL_SUFFIXES):
                    files.append(Path(dirpath) / fn)
    for path in files:
        if path.name.lower() in _SELF_NAMES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, name, line in scan_text(text, path.suffix):
            findings.append((str(path), lineno, name, line))
    findings.sort()
    return findings


def safe_replacement(pattern_name: str) -> str:
    for name, _rx, _sufs, safe in BANNED_PATTERNS:
        if name == pattern_name:
            return safe
    return "use winspawn.popen_hidden() / spawn_hidden.cjs"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="winspawn")
    ap.add_argument("--audit", metavar="ROOT", required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--exclude", action="append", default=[], metavar="DIR",
                    help="extra directory name to skip (repeatable)")
    args = ap.parse_args(argv)

    if not os.path.exists(args.audit):
        print(f"winspawn: no such path: {args.audit}", file=sys.stderr)
        return 2
    findings = audit(args.audit, extra_excludes=args.exclude)
    if args.json:
        print(json.dumps(
            [{"path": p, "line": n, "pattern": k, "text": t} for p, n, k, t in findings],
            indent=2,
        ))
    else:
        print(f"winspawn audit: {args.audit}")
        if not findings:
            print("  findings: 0 - no visible-window spawn sites.")
        else:
            print(f"  findings: {len(findings)}")
            for p, n, k, t in findings:
                print(f"  {p}:{n}: {k}")
                print(f"      {t}")
                print(f"      safe form: {safe_replacement(k)}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
