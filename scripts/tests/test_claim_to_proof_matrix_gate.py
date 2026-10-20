#!/usr/bin/env python3
"""Portable, real-script regressions; synthetic receipts are gate tests only.

Run with python3 scripts/tests/test_claim_to_proof_matrix_gate.py. Scratch
inputs and subprocess stdout/stderr remain under artifacts for diagnosis.
This does not establish any runtime performance or theorem claim.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone


ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts/run_claim_to_proof_matrix_gate.sh"
FIXTURE = ROOT / "scripts/testdata/claim_to_proof_matrix_repro_lock"


class ClaimGatePortability(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parent = ROOT / "artifacts/claim_to_proof_matrix_gate_tests"
        parent.mkdir(parents=True, exist_ok=True)
        cls.work = Path(tempfile.mkdtemp(prefix="portability-", dir=parent))
        print(f"claim_gate_test_artifacts={cls.work}", flush=True)
        cls.now = datetime.now(timezone.utc).replace(microsecond=0)
        cls.shells = [Path("/bin/bash")]
        homebrew = Path("/opt/homebrew/bin/bash")
        if homebrew.exists():
            cls.shells.append(homebrew)
        cls.template = json.loads(
            (FIXTURE / "claim_to_proof_matrix_fixture.json").read_text()
        )["claims"][0]

    def receipt(self, directory, name="run_manifest.json", age=2, **fields):
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        generated = (self.now - timedelta(days=age)).strftime("%Y-%m-%dT%H:%M:%SZ")
        path.write_text(json.dumps({"generated_utc": generated, **fields}))
        return path

    def claim(self, name, artifact, scope="fixture", lock=True):
        if lock:
            # The explicit override below only bypasses git tracking for these
            # retained synthetic inputs; it does not bypass lock presence.
            artifact.mkdir(parents=True, exist_ok=True)
            (artifact / "repro.lock").write_text("synthetic portability regression\n")
        row = copy.deepcopy(self.template)
        row.update(claim_id=name, artifact_path=str(artifact), claim_scope=scope)
        return row

    def invoke(self, shell, matrix, mode, label):
        outdir = self.work / label / shell.parent.parent.name / mode
        outdir.mkdir(parents=True, exist_ok=True)
        matrix_path = outdir / "matrix.json"
        matrix_path.write_text(json.dumps({
            "schema_version": "franken-engine.claim-to-proof-matrix.v1",
            "claims": matrix,
        }))
        env = dict(os.environ, CLAIM_TO_PROOF_MATRIX_PATH=str(matrix_path),
                   CLAIM_TO_PROOF_MATRIX_ARTIFACT_ROOT=str(outdir / "output"),
                   CLAIM_TO_PROOF_MATRIX_ALLOW_UNTRACKED_REPRO_LOCK="1")
        with (outdir / "stdout.log").open("w") as stdout, \
                (outdir / "stderr.log").open("w") as stderr:
            process = subprocess.Popen([str(shell), str(GATE), mode], cwd=ROOT,
                                       env=env, stdout=stdout, stderr=stderr,
                                       start_new_session=True)
            try:
                code = process.wait(timeout=45)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
                self.fail(f"gate timed out: {shell}; logs: {outdir}")
        reports = list((outdir / "output").glob("*/claim_to_proof_gate_report.json"))
        self.assertEqual(len(reports), 1, f"complete report missing: {outdir}")
        report = json.loads(reports[0].read_text())
        self.assertEqual(report["claim_count"], len(matrix))
        return code, {event["claim_id"]: event for event in report["events"]}

    def test_manifest_discovery_dates_and_file_mtime(self):
        rows, expected = [], {}
        for name in ("iso", "compact", "nested", "empty", "malformed", "multiple",
                     "canonical-first", "skip-unreadable-json", "timestamp-field",
                     "malformed-newest", "empty-field-skips"):
            directory = self.work / "inputs" / f"{name} with spaces"
            rows.append(self.claim(name, directory))
            expected[name] = 2
            if name == "empty":
                expected[name] = 999
                continue
            if name == "nested":
                self.receipt(directory / "nested space", age=2)
                continue
            receipt = self.receipt(directory)
            if name == "compact":
                receipt.write_text(json.dumps({"generated_utc":
                    (self.now - timedelta(days=2)).strftime("%Y%m%dT%H%M%SZ")}))
            elif name == "malformed":
                receipt.write_text('{"generated_utc":"not a date"}')
                expected[name] = 999
            elif name == "multiple":
                older = self.receipt(directory / "older", "manifest.json", age=80)
                newer = self.receipt(directory / "newer", "manifest.json", age=2)
                os.utime(older, (100, 100))
                os.utime(newer, (200, 200))
            elif name == "canonical-first":
                older = self.receipt(directory, "manifest.json", age=80)
                newer = self.receipt(directory, "other_manifest.json", age=2)
                os.utime(older, (100, 100))
                os.utime(newer, (200, 200))
                expected[name] = 80
            elif name == "skip-unreadable-json":
                (directory / "manifest.json").write_text("{broken json")
            elif name == "timestamp-field":
                receipt.write_text(json.dumps({"freshness": {"generated_utc":
                    (self.now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")}}))
            elif name == "empty-field-skips":
                self.receipt(directory, "manifest.json", age=80,
                             freshness={"generated_utc": ""})
            elif name == "malformed-newest":
                bad = self.receipt(directory / "bad", "manifest.json", generated_utc="invalid")
                self.receipt(directory / "old", "manifest.json", age=2)
                os.utime(bad, (time.time() + 10, time.time() + 10))
                expected[name] = 999
        filedir = self.work / "inputs/file artifact"
        row = self.claim("file-mtime", filedir)
        path = self.receipt(filedir, "evidence.json")
        old = time.time() - 80 * 86400
        os.utime(path, (old, old))
        row["artifact_path"] = str(path)
        rows.append(row)
        expected["file-mtime"] = 80
        for shell in self.shells:
            with self.subTest(shell=shell):
                code, events = self.invoke(shell, rows, "ci", "dates")
                self.assertEqual(code, 0)
                for name, age in expected.items():
                    event = events[name]
                    self.assertEqual(event["status"], "pass", event)
                    self.assertEqual(event["actual_freshness_days"], age, event)
                    self.assertEqual(event["freshness_status"], "stale" if age > 30 else "ok")

    def test_integrity_quality_missing_lock_and_source_span(self):
        rows = []
        for name in ("valid", "missing-lock", "missing-artifact", "tamper", "failed-receipt",
                     "fixture", "failed-latest", "bad-source"):
            directory = self.work / "negative-inputs" / name
            row = self.claim(name, directory, lock=name not in {"missing-lock", "missing-artifact"})
            rows.append(row)
            if name == "missing-artifact":
                continue
            self.receipt(directory)
            if name == "tamper":
                body = {"generated_utc": self.now.strftime("%Y-%m-%dT%H:%M:%SZ")}
                seal = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                body.update(schema_hash="sha256:" + seal, changed_after_seal=True)
                (directory / "manifest.json").write_text(json.dumps(body))
            elif name == "failed-receipt":
                self.receipt(directory, "manifest.json", outputs={"verification_result": "failed"})
            elif name in {"fixture", "failed-latest"}:
                row["claim_scope"] = "performance"
                if name == "fixture":
                    self.receipt(directory, "quality.json", outcome="pass", uses_placeholder_baselines=True)
                else:
                    self.receipt(directory, "older.json", age=10, outcome="pass")
                    self.receipt(directory, "latest.json", age=2, outcome="fail")
            elif name == "bad-source":
                row["source_span"]["must_contain"] = "absent regression sentinel"
                self.receipt(directory, age=80)
        for shell in self.shells:
            with self.subTest(shell=shell):
                code, events = self.invoke(shell, rows, "ci", "negative")
                self.assertEqual(code, 1)
                self.assertEqual(events["valid"]["status"], "pass")
                for name in (row["claim_id"] for row in rows if row["claim_id"] != "valid"):
                    self.assertEqual(events[name]["status"], "fail", events[name])
                self.assertIn("MissingReproducibilityBundle", events["missing-lock"]["reason"])
                self.assertIn("integrity failure", events["tamper"]["reason"])
                self.assertEqual(events["fixture"]["artifact_quality_status"], "placeholder")
                self.assertEqual(events["failed-latest"]["artifact_quality_status"], "failed")
                self.assertIn("source_span no longer contains required text", events["bad-source"]["reason"])
                self.assertIn("proof artifact is stale", events["bad-source"]["reason"])

    def test_release_rejects_staleness_without_changing_ci(self):
        directory = self.work / "stale-release"
        row = self.claim("stale-release", directory)
        self.receipt(directory, age=80)
        for shell in self.shells:
            with self.subTest(shell=shell):
                ci_code, ci = self.invoke(shell, [row], "ci", "release")
                release_code, release = self.invoke(shell, [row], "release", "release")
                self.assertEqual(ci_code, 0)
                self.assertEqual(release_code, 1)
                for events in (ci, release):
                    self.assertEqual(events["stale-release"]["decision"], "downgrade_stale_proof")


if __name__ == "__main__":
    unittest.main(verbosity=2)
