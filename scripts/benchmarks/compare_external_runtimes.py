#!/usr/bin/env python3
"""Compare trusted standalone JS workloads using fresh, checksum-pinned processes.

This is an end-to-end CLI diagnostic, not a steady-state VM throughput claim.
FrankenEngine includes parse/lower, execution, policy and report serialization;
Node and QuickJS include their own startup, execution and shutdown. No runtime
is linked into or used to execute a FrankenEngine guest. See bd-9vouw.16.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

NAMES = ("frankenengine", "node", "quickjs")
MAX_OUTPUT = 16 * 1024 * 1024


def digest_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def output_digest(stdout: bytes, stderr: bytes) -> str:
    return hashlib.sha256(len(stdout).to_bytes(8, "big") + stdout + stderr).hexdigest()


def execute(command: list[str], timeout: float, accepted_exit_codes: tuple[int, ...] = (0,)) -> dict[str, Any]:
    start = time.perf_counter_ns()
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=(os.name == "posix"))
    except OSError as error:
        return {"status": "launch_error", "detail": str(error), "command": command}
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        stdout, stderr = process.communicate()
        return {"status": "timeout", "elapsed_ns": time.perf_counter_ns() - start,
                "timeout_seconds": timeout, "command": command,
                "stderr": stderr[:4096].decode("utf-8", "replace")}
    elapsed = time.perf_counter_ns() - start
    result: dict[str, Any] = {"status": "ok" if process.returncode in accepted_exit_codes else "exit_error",
                             "elapsed_ns": elapsed, "exit_code": process.returncode,
                             "command": command, "stdout_bytes": len(stdout),
                             "stderr_bytes": len(stderr)}
    if len(stdout) + len(stderr) > MAX_OUTPUT:
        result.update(status="output_limit", detail="captured output exceeds diagnostic limit")
    if result["status"] != "ok":
        result["stderr"] = stderr[:4096].decode("utf-8", "replace")
        return result
    result.update(stdout=stdout, stderr=stderr)
    return result


def decode_observable(name: str, raw: dict[str, Any]) -> dict[str, Any]:
    result = dict(raw)
    if result["status"] != "ok":
        return result
    stdout, stderr = result.pop("stdout"), result.pop("stderr")
    if name == "frankenengine":
        try:
            report = json.loads(stdout)
            if not isinstance(report, dict):
                raise ValueError("frankenctl run report is not an object")
            if report.get("schema_version") != "franken-engine.frankenctl.run.v2":
                raise ValueError("unsupported frankenctl run report schema")
            if report.get("containment_action") != "allow":
                raise ValueError("execution was not allowed to complete normally")
            entries = report["console_output"]
            if not isinstance(entries, list):
                raise ValueError("console_output is not an array")
            out, err = [], []
            for entry in entries:
                level, message = entry["level"], entry["message"]
                if not isinstance(message, str):
                    raise ValueError("console message is not a string")
                if level in ("Log", "Info", "Debug", "Trace"):
                    out.append(message + "\n")
                elif level in ("Error", "Warn"):
                    err.append(message + "\n")
                else:
                    raise ValueError("unknown console level")
            stdout = "".join(out).encode("utf-8")
            stderr = "".join(err).encode("utf-8") + stderr
            result["lane"] = report.get("lane")
            result["instructions_executed"] = report.get("instructions_executed")
        except (ValueError, TypeError, KeyError, UnicodeError) as error:
            result.update(status="invalid_report", detail=str(error))
            return result
    result["observable_sha256"] = output_digest(stdout, stderr)
    result["observable_stdout"] = stdout[:4096].decode("utf-8", "replace")
    result["observable_stderr"] = stderr[:4096].decode("utf-8", "replace")
    return result


def runtime(name: str, binary: str, expected_sha256: str) -> dict[str, Any]:
    result: dict[str, Any] = {"name": name, "requested_binary": binary,
                             "expected_sha256": expected_sha256}
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        return dict(result, status="invalid_checksum")
    resolved = shutil.which(binary)
    if resolved is None:
        return dict(result, status="unavailable")
    path = Path(resolved).resolve()
    result["binary"] = str(path)
    try:
        actual = digest_file(path)
    except OSError as error:
        return dict(result, status="unavailable", detail=str(error))
    result["sha256"] = actual
    if actual != expected_sha256.lower():
        return dict(result, status="checksum_mismatch")
    version_args = {"frankenengine": ["version"], "node": ["-p", "JSON.stringify({release:process.release.name,versions:process.versions})"],
                    "quickjs": ["--help"]}[name]
    # QuickJS's help intentionally exits 1. This exception applies ONLY to
    # the version probe; every measured guest must still exit successfully.
    version_codes = (0, 1) if name == "quickjs" else (0,)
    probe = execute([str(path), *version_args], 10, accepted_exit_codes=version_codes)
    if probe["status"] != "ok":
        return dict(result, status="version_unavailable", version_probe=probe)
    text = (probe["stdout"] + probe["stderr"]).decode("utf-8", "replace")
    result["version_output"] = text[:8192]
    result["version_exit_code"] = probe["exit_code"]
    if name == "node":
        try:
            info = json.loads(text)
            if info["release"] != "node" or not info["versions"].get("v8") or info["versions"].get("bun"):
                raise ValueError("not a genuine Node/V8 runtime")
            result["versions"] = info["versions"]
        except (ValueError, TypeError, KeyError):
            return dict(result, status="wrong_runtime")
    elif name == "quickjs" and not text.startswith("QuickJS version "):
        return dict(result, status="wrong_runtime")
    elif name == "frankenengine" and not text.startswith("frankenctl "):
        return dict(result, status="wrong_runtime")
    return dict(result, status="ready")


def load_cases(manifest: Path, requested: list[str], categories: list[str]) -> list[dict[str, Any]]:
    document = json.loads(manifest.read_text())
    if not isinstance(document, dict):
        raise ValueError("manifest must be an object")
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("manifest must contain a nonempty cases array")
    ids: set[str] = set()
    admitted = []
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("each benchmark case must be an object")
        name = case.get("benchmark_id")
        if not isinstance(name, str) or name in ids:
            raise ValueError("invalid or duplicate benchmark ID")
        ids.add(name)
        if requested and name not in requested:
            continue
        if categories and case.get("category") not in categories:
            continue
        if case.get("args", []) != []:
            raise ValueError(f"{name}: guest arguments are not supported equally by all three CLIs")
        source = (manifest.parent / case["program_path"]).resolve()
        if not source.is_relative_to(manifest.parent.resolve()) or not source.is_file():
            raise ValueError(f"{name}: source must be a file within the manifest directory")
        admitted.append(dict(case, source=str(source), source_sha256=digest_file(source)))
    unknown = set(requested) - ids
    if unknown:
        raise ValueError(f"unknown cases: {sorted(unknown)}")
    if not admitted:
        raise ValueError("selection contains no cases")
    return admitted


def command_for(name: str, spec: dict[str, Any], source: str, options: argparse.Namespace) -> list[str]:
    if name != "frankenengine":
        return [spec["binary"], source]
    command = [spec["binary"], "run", "--input", source, "--extension-id", "runtime-comparison",
               "--instruction-budget", str(options.instruction_budget)]
    if options.max_heap_objects is not None:
        command.extend(["--max-heap-objects", str(options.max_heap_objects)])
    if options.max_heap_bytes is not None:
        command.extend(["--max-heap-bytes", str(options.max_heap_bytes)])
    return command


def summarize(samples: list[dict[str, Any]], names: tuple[str, ...] = NAMES) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in names:
        values = [row["elapsed_ns"] / 1e6 for row in samples
                  if row["runtime"] == name and row["phase"] == "measured" and row["status"] == "ok"]
        if not values:
            continue
        mean = statistics.mean(values)
        result[name] = {"count": len(values), "median_ms": statistics.median(values),
                        "min_ms": min(values), "max_ms": max(values), "mean_ms": mean,
                        "cv": statistics.stdev(values) / mean if len(values) > 1 and mean else None}
    return result


def environment() -> dict[str, Any]:
    result: dict[str, Any] = {"platform": platform.platform(), "python": sys.version,
                             "cpu_count": os.cpu_count(), "cpu_affinity": None}
    if hasattr(os, "sched_getaffinity"):
        result["cpu_affinity"] = sorted(os.sched_getaffinity(0))
    for key, path in [("cpuinfo", "/proc/cpuinfo"), ("meminfo", "/proc/meminfo"),
                      ("cpu_governor", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")]:
        try:
            text = Path(path).read_text()
            result[key] = text.split("\n\n")[0] if key == "cpuinfo" else text
        except OSError:
            result[key] = "unavailable"
    if hasattr(os, "getloadavg"):
        result["load_average"] = os.getloadavg()
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    for name in NAMES:
        parser.add_argument("--" + name, required=True)
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--category", action="append", default=[])
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--instruction-budget", type=int, default=2_000_000_000)
    parser.add_argument("--max-heap-objects", type=int)
    parser.add_argument("--max-heap-bytes", type=int)
    parser.add_argument("--cpu", type=int)
    args = parser.parse_args(argv)
    if args.warmups < 0 or args.samples < 2 or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("warmups must be nonnegative, samples >= 2 and timeout finite and positive")
    for name in ("instruction_budget", "max_heap_objects", "max_heap_bytes"):
        value = getattr(args, name)
        if value is not None and value <= 0:
            parser.error(name + " must be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.out.exists():
        raise ValueError("output directory already exists; choose a new path to preserve prior runs")
    cases = load_cases(args.manifest.resolve(), args.case, args.category)
    if args.cpu is not None:
        if not hasattr(os, "sched_setaffinity") or args.cpu not in os.sched_getaffinity(0):
            raise ValueError("requested CPU affinity is unavailable")
        os.sched_setaffinity(0, {args.cpu})
    args.out.mkdir(parents=True)
    specs = {name: runtime(name, getattr(args, name), getattr(args, name + "_sha256")) for name in NAMES}
    report: dict[str, Any] = {
        "schema_version": "franken-engine.external-cli-comparison.v1",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "measurement": "fresh_process_end_to_end_wall_time",
        "claim_scope": "diagnostic_only_not_steady_state_or_full_application_performance",
        "limitations": ["FrankenEngine includes security orchestration and JSON report serialization.",
                        "Fresh processes do not preserve JIT or realm state between samples.",
                        "Per-runtime memory limits and allocator accounting are not equivalent.",
                        "Host scheduling, virtualization and CPU frequency may affect timings.",
                        "Only behavior-equivalent completed samples qualify; failures stay visible."],
        "protocol": {"warmups": args.warmups, "samples": args.samples, "timeout_seconds": args.timeout,
                     "instruction_budget": args.instruction_budget,
                     "frankenengine_max_heap_objects": args.max_heap_objects,
                     "frankenengine_max_heap_bytes": args.max_heap_bytes,
                     "order": "runtime order rotates each round; one fresh process per sample"},
        "manifest_sha256": digest_file(args.manifest), "runtimes": specs,
        "environment_start": environment(), "selection": [case["benchmark_id"] for case in cases], "cases": []}
    result_path = args.out / "report.json"

    def save() -> None:
        result_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    save()
    with (args.out / "samples.jsonl").open("w") as events:
        for case in cases:
            row: dict[str, Any] = dict(case, samples=[], status="running")
            report["cases"].append(row)
            source = Path(case["source"])
            if digest_file(source) != case["source_sha256"]:
                row.update(status="source_changed")
                save()
                continue
            copy = args.out / (case["source_sha256"] + ".js")
            if not copy.exists():
                copy.write_bytes(source.read_bytes())
            expected = None
            for phase, rounds in (("preflight", 1), ("warmup", args.warmups), ("measured", args.samples)):
                for iteration in range(rounds):
                    failed = False
                    for offset in range(len(NAMES)):
                        name = NAMES[(offset + iteration) % len(NAMES)]
                        spec = specs[name]
                        if spec["status"] != "ready":
                            sample = {"status": spec["status"]}
                        elif digest_file(source) != case["source_sha256"]:
                            sample = {"status": "source_changed"}
                        else:
                            sample = decode_observable(name, execute(command_for(name, spec, str(source), args), args.timeout))
                        sample.update(runtime=name, phase=phase, iteration=iteration, benchmark_id=case["benchmark_id"])
                        if sample["status"] == "ok":
                            actual = sample["observable_sha256"]
                            if expected is None:
                                expected = actual
                            elif actual != expected:
                                sample["status"] = "behavior_mismatch"
                        failed |= sample["status"] != "ok"
                        row["samples"].append(sample)
                        events.write(json.dumps(sample, sort_keys=True) + "\n")
                        events.flush()
                    if failed:
                        row["status"] = "not_comparable"
                        break
                if row["status"] == "not_comparable":
                    break
            row["stats"] = summarize(row["samples"])
            if row["status"] == "running":
                row["status"] = "comparable"
                elapsed = row["stats"]["frankenengine"]["median_ms"]
                row["frankenengine_elapsed_ratio"] = {name: elapsed / row["stats"][name]["median_ms"]
                                                       for name in ("node", "quickjs")}
            save()
            print(json.dumps({"case": case["benchmark_id"], "status": row["status"],
                              "stats": row["stats"], "ratios": row.get("frankenengine_elapsed_ratio")}), flush=True)
    for spec in specs.values():
        if spec["status"] == "ready":
            try:
                spec["final_sha256"] = digest_file(Path(spec["binary"]))
            except OSError:
                spec["final_sha256"] = None
            if spec["final_sha256"] != spec["sha256"]:
                spec["status"] = "binary_changed"
    report["environment_end"] = environment()
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    report["status"] = "complete" if all(spec["status"] == "ready" for spec in specs.values()) else "invalid_runtime"
    comparable = [row for row in report["cases"] if row["status"] == "comparable"]
    report["coverage"] = {"selected": len(cases), "comparable": len(comparable),
                          "not_comparable": len(cases) - len(comparable)}
    if report["status"] != "complete":
        for row in comparable:
            row["status"] = "invalid_runtime"
            row.pop("frankenengine_elapsed_ratio", None)
        report["coverage"] = {"selected": len(cases), "comparable": 0, "not_comparable": len(cases)}
    save()
    return 0 if report["status"] == "complete" and len(comparable) == len(cases) else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        print(f"comparison refused: {error}", file=sys.stderr)
        raise SystemExit(2)
