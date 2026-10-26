import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT))
import winspawn  # noqa: E402

WIN = os.name == "nt"


def fixture(name):
    return (FIX / name).read_text(encoding="utf-8")


class FlagTests(unittest.TestCase):
    @unittest.skipUnless(WIN, "Windows creation flags")
    def test_flags(self):
        bad = winspawn.BAD_FLAGS
        for service in (False, True):
            f = winspawn.hidden_kwargs({"creationflags": bad}, service=service)["creationflags"]
            self.assertTrue(f & winspawn.CREATE_NO_WINDOW)
            self.assertFalse(f & winspawn.DETACHED_PROCESS)
            self.assertFalse(f & winspawn.CREATE_NEW_CONSOLE)
        self.assertTrue(winspawn.SERVICE_FLAGS & winspawn.CREATE_NO_WINDOW)
        self.assertFalse(winspawn.SERVICE_FLAGS & winspawn.BAD_FLAGS)


class AuditTests(unittest.TestCase):
    def names(self, fixture_name, suffix):
        return [x[1] for x in winspawn.scan_text(fixture(fixture_name), suffix)]

    def test_flags_detached(self):
        self.assertEqual(self.names("detached.txt", ".py"), ["DETACHED_PROCESS"])

    def test_escape_comment_passes(self):
        self.assertEqual(self.names("escaped.txt", ".py"), [])

    def test_dotted_exec_caught(self):
        self.assertEqual(self.names("dotted_exec.txt", ".js"), ["child_process exec"] * 3)

    def test_exec_exemptions(self):
        self.assertEqual(self.names("exec_ok.txt", ".js"), [])

    def test_windowshide_above(self):
        text = "const o = { windowsHide: true };\ncp.exec('dir', o);\n"
        self.assertEqual(winspawn.scan_text(text, ".js"), [])

    def test_ts_scanned(self):
        self.assertEqual(self.names("dotted_exec.txt", ".ts"), ["child_process exec"] * 3)

    def _cli(self, *args):
        return subprocess.run([sys.executable, "-m", "winspawn", "--audit", *args],
                              cwd=ROOT, capture_output=True, text=True)

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copy(FIX / "detached.txt", Path(d) / "x.py")
            self.assertEqual(self._cli(d).returncode, 1)
            self.assertEqual(self._cli(d, "--exclude", Path(d).name).returncode, 1)  # root is not excluded
            sub = Path(d) / "skipme"
            sub.mkdir()
            shutil.move(str(Path(d) / "x.py"), sub / "x.py")
            self.assertEqual(self._cli(d).returncode, 1)
            self.assertEqual(self._cli(d, "--exclude", "skipme").returncode, 0)

    def test_missing_path_exit_2(self):
        r = self._cli(str(ROOT / "does-not-exist"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("no such path", r.stderr)


class SpawnTests(unittest.TestCase):
    def test_spawn_and_read(self):
        p = winspawn.popen_hidden([sys.executable, "-c", "print(1)"],
                                  stdout=subprocess.PIPE, text=True)
        out, _ = p.communicate(timeout=30)
        self.assertEqual(out.strip(), "1")
        r = winspawn.run_hidden([sys.executable, "-c", "print(2)"],
                                capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "2")


class HookTests(unittest.TestCase):
    def test_hook_reminds(self):
        payload = {"session_id": "winspawn-test-" + str(os.getpid()),
                   "tool_name": "Bash",
                   "tool_input": {"command": fixture("detached.txt")}}
        with tempfile.TemporaryDirectory() as home:
            env = dict(os.environ, HOME=home, USERPROFILE=home)
            r = subprocess.run([sys.executable, str(ROOT / "hooks" / "hidden_spawn_guard.py")],
                               input=json.dumps(payload), capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 2)
        self.assertIn("HIDDEN SPAWN GUARD", r.stderr)
        self.assertIn("DETACHED_PROCESS", r.stderr)


@unittest.skipUnless(shutil.which("node"), "node not on PATH")
class NodeTests(unittest.TestCase):
    def test_spawn_hidden(self):
        js = (
            "const cp = require('child_process');"
            "let seen; const orig = cp.spawn;"
            "cp.spawn = (c, a, o) => { seen = o; return orig(c, a, o); };"
            "const { spawnHidden } = require(process.argv[1]);"
            "const ch = spawnHidden('node', ['-e', 'console.log(1)'], { detached: true });"
            "let out = ''; ch.stdout.on('data', d => out += d);"
            "ch.on('close', () => console.log(JSON.stringify({ out: out.trim(), seen })));"
        )
        r = subprocess.run(["node", "-e", js, str(ROOT / "node" / "spawn_hidden.cjs")],
                           capture_output=True, text=True, timeout=60)
        res = json.loads(r.stdout)
        self.assertEqual(res["out"], "1")
        self.assertTrue(res["seen"]["windowsHide"])
        self.assertNotIn("detached", res["seen"])


if __name__ == "__main__":
    unittest.main()
