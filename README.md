# winspawn

[![test](https://github.com/Peacho97/winspawn/actions/workflows/test.yml/badge.svg)](https://github.com/Peacho97/winspawn/actions/workflows/test.yml)

Hidden-by-default background process spawning on Windows, with a source auditor
that finds spawn sites written the visible way. Python standard library only.

## Problem

On Windows, a background child process can flash a console window or leave an
orphaned console on screen. This showed up in a multi-service local AI fleet
where many scheduled and long-running processes start unattended. Common causes:

- Python: `DETACHED_PROCESS` gives the child no console, so any console program
  it launches allocates a new visible one. `CREATE_NEW_CONSOLE` opens a window
  directly.
- Node: `detached: true` and `exec()` / `execSync()` (which go through `cmd.exe`)
  open windows unless `windowsHide: true` is set.
- PowerShell: `Start-Process` without `-WindowStyle Hidden`.
- Task Scheduler: actions that run `powershell.exe`, `cmd.exe`, `py.exe`,
  `python.exe` or a `.bat` / `.cmd` directly show a console at each run.

## Contents

| Path | Purpose |
|------|---------|
| `winspawn.py` | `popen_hidden`, `run_hidden`, `hidden_kwargs`, flag constants, and the `--audit` scanner |
| `node/spawn_hidden.cjs` | `spawnHidden`, `execFileHidden`: `child_process` wrappers that force `windowsHide: true` and drop `detached` |
| `hooks/hidden_spawn_guard.py` | Claude Code `PreToolUse` hook that reminds once per session (see `hooks/README.md`) |
| `tests/` | `unittest` suite |

## Install

```
pip install git+https://github.com/Peacho97/winspawn
```

Or clone and install from the checkout:

```
git clone https://github.com/Peacho97/winspawn
cd winspawn
pip install .
```

Or copy `winspawn.py` onto your import path. Copy `node/spawn_hidden.cjs` into
your Node project.

## Usage

Python:

```python
import sys, winspawn
p = winspawn.popen_hidden([sys.executable, "server.py"], service=True)
r = winspawn.run_hidden(["tool.exe", "--flag"], capture_output=True, text=True)
```

`HIDDEN_FLAGS` is `CREATE_NO_WINDOW`: the child is not given a console. `SERVICE_FLAGS` adds
`CREATE_NEW_PROCESS_GROUP` so the child is isolated from the parent's Ctrl-C.
Any `DETACHED_PROCESS` or `CREATE_NEW_CONSOLE` in a caller-supplied
`creationflags` is stripped. On non-Windows the `creationflags` argument is
dropped.

Limits: this controls console allocation only. A GUI child program still shows
its own windows, and `startupinfo` (for example `wShowWindow`) is not modified.

Node:

```js
const { spawnHidden, execFileHidden } = require('./node/spawn_hidden.cjs');
spawnHidden('node', ['server.js'], { cwd: __dirname });
execFileHidden('git', ['status'], (err, stdout) => console.log(stdout));
```

PowerShell:

```powershell
Start-Process -WindowStyle Hidden -FilePath python -ArgumentList 'server.py'
```

Task Scheduler: register `wscript.exe` (no console) as the action and have a
small wrapper start the real command with window style 0. `run-hidden.vbs` is a
file you provide, for example:

```vbs
' run-hidden.vbs <command> [args...]
' Joins all arguments, quoting each; arguments that themselves contain
' double quotes are not escaped.
Dim i, cmd
For i = 0 To WScript.Arguments.Count - 1
  cmd = cmd & """" & WScript.Arguments(i) & """ "
Next
CreateObject("WScript.Shell").Run cmd, 0, False
```

```powershell
$a = New-ScheduledTaskAction -Execute wscript.exe -Argument '"C:\tools\run-hidden.vbs" python C:\jobs\nightly.py'
```

## Audit

```
python -m winspawn --audit <root> [--json] [--exclude DIR ...]
```

Walks `<root>` (skipping `node_modules`, `.venv`, `.git`, `build`, `dist`,
`__pycache__` and similar; add more directory names with repeatable
`--exclude`) and reports: `DETACHED_PROCESS` and `CREATE_NEW_CONSOLE` in `.py`;
`exec(` / `execSync(` (bare, or called on `child_process` / `cp`) and
`detached: true` without a `windowsHide: true` within 6 lines above or below,
in `.js` / `.cjs` / `.mjs` / `.ts` / `.mts`; method definitions named `exec`
are ignored; `Start-Process` without `-WindowStyle Hidden`
and `New-ScheduledTaskAction` against a console executable in `.ps1` / `.psm1`.
Comment-only lines are ignored. Exit code is 1 if there are findings, 2 if
`<root>` does not exist, else 0.

Escape: put `spawn-hidden-ok: <reason>` in a comment on the line or the line
above it.

CI (GitHub Actions):

```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: pip install git+https://github.com/Peacho97/winspawn
- run: python -m winspawn --audit .
```

Alternatively check out this repository next to yours and run
`python path/to/winspawn/winspawn.py --audit .`.

## Hook

`hooks/hidden_spawn_guard.py` applies the same patterns to code a Claude Code
session is about to write or run. See `hooks/README.md` for the registration
JSON and the escape comment.

## Tests

```
python -m unittest discover tests
```

## License

MIT. See `LICENSE`.
