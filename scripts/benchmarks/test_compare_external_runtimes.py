#!/usr/bin/env python3
"""Unit tests for the external CLI driver, not JS-engine performance evidence."""
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "compare_external_runtimes", Path(__file__).with_name("compare_external_runtimes.py"))
assert SPEC and SPEC.loader
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


class ComparisonTests(unittest.TestCase):
    def report(self, entries=None, **extra):
        document = {"schema_version": "franken-engine.frankenctl.run.v2",
                    "containment_action": "allow", "lane": "baseline_deterministic_profile",
                    "instructions_executed": 42, "console_output": entries or []}
        document.update(extra)
        return {"status": "ok", "elapsed_ns": 1000,
                "stdout": json.dumps(document).encode(), "stderr": b""}

    def manifest(self, root, cases=None):
        source = root / "work.js"
        source.write_text("console.log(42);\n")
        path = root / "manifest.json"
        path.write_text(json.dumps({"cases": cases if cases is not None else [
            {"benchmark_id": "case", "category": "macro", "program_path": "work.js", "args": []}]}))
        return path

    def arguments(self, manifest, out):
        binary = str(Path(sys.executable).resolve())
        digest = bench.digest_file(Path(binary))
        args = ["--manifest", str(manifest), "--out", str(out), "--samples", "2", "--warmups", "0"]
        for name in bench.NAMES:
            args.extend(["--" + name, binary, "--" + name + "-sha256", digest])
        return args

    def test_console_mapping_matches_exact_peer_streams(self):
        raw = self.report([{"level": "Log", "message": "hello\nworld"},
                           {"level": "Warn", "message": "warning"}])
        actual = bench.decode_observable("frankenengine", raw)
        peer = bench.decode_observable("quickjs", {"status": "ok", "elapsed_ns": 100,
                                                   "stdout": b"hello\nworld\n", "stderr": b"warning\n"})
        self.assertEqual(actual["observable_sha256"], peer["observable_sha256"])
        self.assertEqual(actual["lane"], "baseline_deterministic_profile")
        self.assertEqual(actual["instructions_executed"], 42)
        self.assertIn("stdout", raw, "decoding must not mutate caller-owned raw data")
        self.assertNotEqual(bench.output_digest(b"ab", b"c"), bench.output_digest(b"a", b"bc"))

    def test_malformed_reports_never_produce_timing_admission(self):
        for document in [None, [], 42, "not an object", {}, {"schema_version": "old"}]:
            raw = {"status": "ok", "stdout": json.dumps(document).encode(), "stderr": b""}
            result = bench.decode_observable("frankenengine", raw)
            self.assertEqual(result["status"], "invalid_report", document)
            self.assertNotIn("observable_sha256", result)
        malformed = {"status": "ok", "stdout": b"not JSON", "stderr": b""}
        self.assertEqual(bench.decode_observable("frankenengine", malformed)["status"], "invalid_report")

    def test_containment_and_invalid_console_entries_are_refused(self):
        for raw in [self.report(containment_action="terminate"),
                    self.report(console_output="not an array"),
                    self.report([{"level": "Unknown", "message": "x"}]),
                    self.report([{"level": "Log", "message": 3}])]:
            self.assertEqual(bench.decode_observable("frankenengine", raw)["status"], "invalid_report")
        failure = {"status": "exit_error", "exit_code": 2, "stderr": "failed"}
        self.assertEqual(bench.decode_observable("frankenengine", failure), failure)

    def test_real_subprocess_success_failure_and_timeout(self):
        success = bench.execute([sys.executable, "-c", "print(42)"], 5)
        self.assertEqual(success["status"], "ok")
        self.assertEqual(success["stdout"], b"42\n")
        self.assertGreater(success["elapsed_ns"], 0)
        failure = bench.execute([sys.executable, "-c", "import sys;sys.stderr.write('bad');sys.exit(3)"], 5)
        self.assertEqual(failure["status"], "exit_error")
        self.assertEqual(failure["exit_code"], 3)
        self.assertEqual(failure["stderr"], "bad")
        timeout = bench.execute([sys.executable, "-c", "import time;time.sleep(10)"], 0.05)
        self.assertEqual(timeout["status"], "timeout")
        self.assertEqual(timeout["timeout_seconds"], 0.05)

    def test_checksum_and_availability_precede_any_execution(self):
        with patch.object(bench, "execute", side_effect=AssertionError("must not execute")):
            self.assertEqual(bench.runtime("quickjs", sys.executable, "bad")["status"], "invalid_checksum")
            self.assertEqual(bench.runtime("quickjs", sys.executable, "0" * 64)["status"], "checksum_mismatch")
            self.assertEqual(bench.runtime("quickjs", "/not/a/real/runtime", "0" * 64)["status"], "unavailable")

    def test_manifest_selection_and_duplicate_ids_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest(root)
            selected = bench.load_cases(manifest, ["case"], ["macro"])
            self.assertEqual(selected[0]["source_sha256"], bench.digest_file(root / "work.js"))
            for requested, categories in [(["missing"], []), ([], ["missing"])]:
                with self.assertRaises(ValueError):
                    bench.load_cases(manifest, requested, categories)
            case = {"benchmark_id": "same", "category": "macro", "program_path": "work.js"}
            self.manifest(root, [case, case])
            with self.assertRaises(ValueError):
                bench.load_cases(manifest, [], [])

    def test_manifest_shape_paths_and_guest_arguments_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for cases in [None, [], [None], [7]]:
                path = root / "manifest.json"
                path.write_text(json.dumps({"cases": cases}))
                with self.assertRaises(ValueError):
                    bench.load_cases(path, [], [])
            for case in [{"benchmark_id": "escape", "program_path": "../escape.js"},
                         {"benchmark_id": "args", "program_path": "work.js", "args": ["extra"]}]:
                path = self.manifest(root, [case])
                with self.assertRaises(ValueError):
                    bench.load_cases(path, [], [])
            path.write_text("[]")
            with self.assertRaises(ValueError):
                bench.load_cases(path, [], [])

    def test_stats_never_mix_warmup_or_failure_with_measured_samples(self):
        rows = [{"runtime": "node", "phase": phase, "status": status, "elapsed_ns": value}
                for phase, status, value in [("warmup", "ok", 99_000_000),
                                              ("preflight", "ok", 99_000_000),
                                              ("measured", "ok", 1_000_000),
                                              ("measured", "ok", 3_000_000),
                                              ("measured", "timeout", 10_000_000)]]
        stats = bench.summarize(rows)
        self.assertEqual(stats["node"]["count"], 2)
        self.assertEqual(stats["node"]["median_ms"], 2)
        self.assertNotIn("quickjs", stats)

    def test_measurement_failure_stays_visible_and_all_peers_are_attempted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest(root)
            binary = str(Path(sys.executable).resolve())
            digest = bench.digest_file(Path(binary))
            counter = 0

            def fake_execution(command, timeout):
                nonlocal counter
                counter += 1
                return {"status": "ok", "elapsed_ns": counter * 1_000_000,
                        "observable_sha256": "different" if counter == 5 else "equal"}

            with patch.object(bench, "runtime", side_effect=lambda name, *_: {
                "name": name, "status": "ready", "binary": binary, "sha256": digest}), \
                patch.object(bench, "execute", side_effect=fake_execution), \
                patch.object(bench, "decode_observable", side_effect=lambda _, raw: raw), \
                patch.object(bench, "environment", return_value={}), contextlib.redirect_stdout(io.StringIO()):
                code = bench.main(self.arguments(manifest, root / "result"))
            report = json.loads((root / "result/report.json").read_text())
            row = report["cases"][0]
            self.assertEqual(code, 2)
            self.assertEqual(counter, 6)
            self.assertEqual(row["status"], "not_comparable")
            self.assertNotIn("frankenengine_elapsed_ratio", row)
            self.assertEqual(report["coverage"], {"selected": 1, "comparable": 0, "not_comparable": 1})
            self.assertEqual(len((root / "result/samples.jsonl").read_text().splitlines()), 6)

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest(root)
            output = root / "existing"
            output.mkdir()
            marker = output / "marker"
            marker.write_text("retain evidence")
            with self.assertRaises(ValueError):
                bench.main(self.arguments(manifest, output))
            self.assertEqual(marker.read_text(), "retain evidence")


if __name__ == "__main__":
    unittest.main()
