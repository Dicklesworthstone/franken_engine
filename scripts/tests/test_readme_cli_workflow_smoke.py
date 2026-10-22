#!/usr/bin/env python3
"""Real-binary smoke plus harness fault injection; all artifacts are retained.

FRANKENCTL_BIN=/absolute/path/frankenctl python3 scripts/tests/test_readme_cli_workflow_smoke.py
The clock/command/event faults test the wrapper, not JavaScript or security claims.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SMOKE = ROOT / "scripts/e2e/readme_cli_workflow_smoke.sh"
EXPECTED_STEPS = [
    "version", "setup_artifacts_dir", "setup_demo_source", "compile",
    "verify_compile_artifact", "run", "stage_replay_fixture", "replay_run",
]


class ReadmeWorkflowSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = Path(os.environ["FRANKENCTL_BIN"]).resolve()
        if not cls.binary.is_file() or not os.access(cls.binary, os.X_OK):
            raise RuntimeError(f"FRANKENCTL_BIN is not executable: {cls.binary}")
        parent = ROOT / "artifacts/readme_cli_workflow_smoke_tests"
        parent.mkdir(parents=True, exist_ok=True)
        cls.work = Path(tempfile.mkdtemp(prefix="real-binary-", dir=parent))
        cls.jq = shutil.which("jq")
        if cls.jq is None:
            raise RuntimeError("jq is required")
        print(f"readme_smoke_test_artifacts={cls.work}", flush=True)

    def invoke(self, label, bash_path="/bin/bash", injection=None):
        directory = self.work / label
        directory.mkdir()
        env = dict(os.environ, FRANKENCTL_BIN=str(self.binary),
                   README_CLI_WORKFLOW_RUN_DIR=str(directory / "run"))
        if injection:
            name, body = injection
            shim = directory / "bin"
            shim.mkdir()
            program = shim / name
            program.write_text(f"#!{sys.executable}\n" + body)
            program.chmod(0o755)
            env["PATH"] = str(shim) + os.pathsep + env["PATH"]
        with (directory / "stdout.log").open("w", encoding="utf-8") as stdout, \
                (directory / "stderr.log").open("w", encoding="utf-8") as stderr:
            result = subprocess.run([bash_path, str(SMOKE)], cwd=ROOT, env=env,
                                    stdout=stdout, stderr=stderr, timeout=45, check=False)
        return result.returncode, directory, (directory / "stderr.log").read_text()

    def assert_no_pass(self, directory):
        manifest = directory / "run/manifest.json"
        if manifest.exists():
            self.assertNotEqual(json.loads(manifest.read_text()).get("status"), "pass")

    def clock_fault(self, action):
        # Only the wrapper's clock process is faulted; proof tooling still uses
        # the real interpreter, and the runtime binary is never substituted.
        return ("python3", "import os, sys\n"
                "if len(sys.argv) > 2 and sys.argv[1] == '-c' and "
                "'time.monotonic_ns' in sys.argv[2]:\n" + action +
                f"os.execv({sys.executable!r}, [{sys.executable!r}] + sys.argv[1:])\n")

    def test_complete_real_workflow_and_corrupt_artifact(self):
        shells = dict.fromkeys(["/bin/bash", shutil.which("bash")])
        for index, bash_path in enumerate(shells):
            if bash_path is None:
                continue
            with self.subTest(bash_path=bash_path):
                code, directory, stderr = self.invoke(f"complete-{index}", bash_path)
                self.assertEqual(code, 0, stderr)
                self.assertEqual(stderr, "")
                run = directory / "run"
                manifest = json.loads((run / "run_manifest.json").read_text())
                events = [json.loads(line) for line in (run / "events.jsonl").read_text().splitlines()]
                self.assertEqual([event["step_name"] for event in events], EXPECTED_STEPS)
                self.assertEqual(manifest["steps"], events)
                self.assertTrue(all(event["decision"] == "passed" for event in events))
                self.assertTrue(all(event["exit_code"] == event["expected_exit_code"] for event in events))
                self.assertTrue(all(isinstance(event["duration_ms"], int) and event["duration_ms"] >= 0 for event in events))
                self.assertTrue(any(event["duration_ms"] > 0 for event in events))
                self.assertEqual(json.loads((run / "manifest.json").read_text())["status"], "pass")
                artifact = json.loads((run / "workspace/artifacts/demo.compile.json").read_text())
                artifact["hashes"]["parse_event_ir"] = "sha256:" + "0" * 64
                corrupt = directory / "corrupt-compile.json"
                corrupt.write_text(json.dumps(artifact))
                result = subprocess.run([str(self.binary), "verify", "compile-artifact", "--input", str(corrupt)],
                                        capture_output=True, text=True, timeout=20, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(json.loads(result.stdout)["passed"])

    def test_clock_process_failure_cannot_pass(self):
        code, directory, stderr = self.invoke("clock-failed", injection=self.clock_fault("    sys.exit(23)\n"))
        self.assertNotEqual(code, 0)
        self.assertIn("could not read the monotonic clock", stderr)
        self.assert_no_pass(directory)

    def test_invalid_clock_cannot_pass(self):
        code, directory, stderr = self.invoke("clock-invalid", injection=self.clock_fault("    print('17926289463N'); sys.exit(0)\n"))
        self.assertNotEqual(code, 0)
        self.assertIn("invalid monotonic clock value", stderr)
        self.assert_no_pass(directory)

    def test_regressing_clock_cannot_pass(self):
        counter = self.work / "clock-counter"
        action = (f"    from pathlib import Path\n    counter = Path({str(counter)!r})\n"
                  "    first = not counter.exists()\n    counter.write_text('read')\n"
                  "    print(1000 if first else 999); sys.exit(0)\n")
        code, directory, stderr = self.invoke("clock-regressed", injection=self.clock_fault(action))
        self.assertNotEqual(code, 0)
        self.assertIn("monotonic clock regressed", stderr)
        self.assert_no_pass(directory)

    def test_failed_compile_cannot_pass(self):
        body = ("import os, sys\nif sys.argv[1:2] == ['compile']:\n"
                "    print('injected compile failure', file=sys.stderr); sys.exit(17)\n"
                f"os.execv({str(self.binary)!r}, [{str(self.binary)!r}] + sys.argv[1:])\n")
        directory = self.work / "failing-frankenctl"
        directory.write_text(f"#!{sys.executable}\n" + body)
        directory.chmod(0o755)
        original = self.binary
        try:
            self.binary = directory
            code, run, stderr = self.invoke("compile-failed")
        finally:
            self.binary = original
        self.assertNotEqual(code, 0)
        self.assertIn("failed at step compile", stderr)
        event = json.loads((run / "run/events.jsonl").read_text().splitlines()[-1])
        self.assertEqual(event["exit_code"], 17)
        self.assertEqual(event["decision"], "failed")
        self.assert_no_pass(run)

    def test_missing_step_events_cannot_pass(self):
        body = ("import os, sys\n"
                "if 'readme_cli_workflow.step_completed' in sys.argv:\n    sys.exit(0)\n"
                f"os.execv({self.jq!r}, [{self.jq!r}] + sys.argv[1:])\n")
        code, directory, stderr = self.invoke("events-lost", injection=("jq", body))
        self.assertNotEqual(code, 0)
        self.assertIn("incomplete or invalid step evidence", stderr)
        self.assertEqual((directory / "run/events.jsonl").read_text(), "")
        self.assert_no_pass(directory)


if __name__ == "__main__":
    if not os.environ.get("FRANKENCTL_BIN"):
        raise SystemExit("Set FRANKENCTL_BIN to an executable real binary; this test never builds or substitutes a passing runtime.")
    unittest.main(verbosity=2)
