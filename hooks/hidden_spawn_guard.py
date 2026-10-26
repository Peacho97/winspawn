#!/usr/bin/env python3
"""hidden_spawn_guard.py - visible-window spawn TRIPWIRE (PreToolUse).

Windows background processes must never flash or own a console window. This
hook watches Write / Edit content and Bash / PowerShell commands for the
spawn forms that produce one (DETACHED_PROCESS, CREATE_NEW_CONSOLE,
child_process.exec, detached without windowsHide, bare Start-Process, and
scheduled tasks registered against a console exe).

REMIND-ONCE, not a gate: the first time a given (pattern, file) combination
shows up in a session it exits 2 with the safe replacement; a retry passes.
A different file, or a different pattern, reminds again.

Escape: put `# spawn-hidden-ok: <reason>` on the offending line.

FAIL-OPEN EVERYWHERE - a malformed payload, missing winspawn, or any other
exception must never brick a tool call.
"""
import hashlib
import json
import os
import re
import sys
from pathlib import Path

STATE_ROOT = Path.home() / ".claude" / "gate-state"
ESCAPE_MARKER = "spawn-hidden-ok:"

# -- pattern source: winspawn is the single definition ------------------------
try:
    sys.path.append(str(Path(__file__).resolve().parents[1]))  # repo checkout
    from winspawn import BANNED_PATTERNS  # type: ignore
except Exception:  # minimal fallback if winspawn is not importable
    _PY = (".py",)
    BANNED_PATTERNS = [
        ("DETACHED_PROCESS", re.compile(r"\bDETACHED_PROCESS\b"), _PY,
         "winspawn.popen_hidden(cmd, service=True)"),
        ("CREATE_NEW_CONSOLE", re.compile(r"\bCREATE_NEW_CONSOLE\b"), _PY,
         "winspawn.popen_hidden(cmd)"),
        ("Start-Process without -WindowStyle",
         re.compile(r"\bStart-Process\b", re.IGNORECASE), (".ps1", ".psm1"),
         "Start-Process -WindowStyle Hidden ..."),
    ]

_COMMENT_PREFIXES = {
    ".py": ("#",), ".ps1": ("#",), ".psm1": ("#",),
    ".js": ("//", "*", "/*"), ".cjs": ("//", "*", "/*"),
    ".mjs": ("//", "*", "/*"), ".ts": ("//", "*", "/*"), ".mts": ("//", "*", "/*"),
}

#: The hook must not fire on the very files that define/test the contract.
_SKIP_NAMES = {"winspawn.py", "hidden_spawn_guard.py"}

TEXT_FIELD = {
    "Write": "content",
    "Edit": "new_string",
    "Bash": "command",
    "PowerShell": "command",
}


def _session_id(payload: dict) -> str:
    return str(payload.get("session_id") or os.environ.get("CLAUDE_CODE_SESSION_ID", "")
               or "no-session")


def _already_prompted(session_id: str, key: str) -> bool:
    """Once-per-(session, pattern, file). Returns True if already reminded."""
    h = hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:16]
    marker = STATE_ROOT / session_id / f"hidden_spawn_{h}.prompted"
    if marker.exists():
        return True
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(key, encoding="utf-8")
    return False


def _skip_path(file_path: str) -> bool:
    if not file_path:
        return False
    p = file_path.replace("\\", "/").lower()
    if Path(p).name in _SKIP_NAMES:
        return True
    return "/tests/" in p or p.endswith("/tests") or "/test_" in p


def _scan(text: str, suffixes_filter):
    """Yield (pattern_name, lineno, line, safe) for the first hit per pattern."""
    lines = text.splitlines()
    for name, rx, suffixes, safe in BANNED_PATTERNS:
        if suffixes_filter is not None and suffixes_filter not in suffixes:
            continue
        for i, line in enumerate(lines):
            if not rx.search(line):
                continue
            if ESCAPE_MARKER in line or (i > 0 and ESCAPE_MARKER in lines[i - 1]):
                continue
            stripped = line.strip()
            prefixes = _COMMENT_PREFIXES.get(suffixes_filter or "", ())
            if prefixes and stripped.startswith(prefixes):
                continue
            if name in ("detached without windowsHide", "child_process exec") and re.search(
                    r"windowsHide\s*:\s*true", "\n".join(lines[max(0, i - 6):i + 7])):
                continue
            if name == "Start-Process without -WindowStyle" and re.search(
                    r"-WindowStyle\s+Hidden", line, re.IGNORECASE):
                continue
            return name, i + 1, stripped, safe
    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    try:
        tool = payload.get("tool_name")
        field = TEXT_FIELD.get(tool)
        if not field:
            return 0
        tool_input = payload.get("tool_input") or {}
        text = tool_input.get(field, "") or ""
        if not text:
            return 0
        file_path = tool_input.get("file_path", "") or ""
        if _skip_path(file_path):
            return 0
        if tool in ("Write", "Edit"):
            suffix = Path(file_path).suffix.lower() if file_path else None
            if not suffix:
                return 0
            hit = _scan(text, suffix)
        else:
            hit = None
            for suffix in (".py", ".cjs", ".ps1"):
                hit = _scan(text, suffix)
                if hit:
                    break
        if not hit:
            return 0
        name, lineno, line, safe = hit
        target = file_path or f"<{tool} command>"
        if _already_prompted(_session_id(payload), f"{name}|{target}"):
            return 0
        return _remind(name, lineno, line, safe, target)
    except Exception:
        return 0


def _remind(name: str, lineno: int, line: str, safe: str, target: str) -> int:
    sys.stderr.write(
        f"HIDDEN SPAWN GUARD: '{name}' at {target}:{lineno}\n"
        f"    {line}\n\n"
        "Background processes on Windows spawn HIDDEN by default -- this form "
        "flashes or owns a console window.\n"
        f"Safe replacement: {safe}\n\n"
        "This is a REMIND-ONCE tripwire, not a gate: fix it, or RETRY THE SAME "
        "CALL and it will pass.\n"
        "If the visible form is genuinely required, mark the line with "
        "`# spawn-hidden-ok: <reason>` (`// spawn-hidden-ok:` in JS) and both "
        "this hook and `python -m winspawn --audit` will skip it.\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
