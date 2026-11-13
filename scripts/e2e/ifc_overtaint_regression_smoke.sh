#!/usr/bin/env bash
# bd-9vouw.1: IFC static over-taint regression smoke gate.
# Runs the 13 benign compute/closure/recursion shapes and 5 negative
# secret-egress shapes through `frankenctl run` and records structured JSONL
# telemetry (case, verdict, denial_op, source_label, sink_clearance) without
# silencing stderr.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}" || exit 1

FRANKENCTL_BIN="${FRANKENCTL_BIN:-}"
if [[ -z "${FRANKENCTL_BIN}" ]]; then
  if [[ -x "${ROOT_DIR}/target/release/frankenctl" ]]; then
    FRANKENCTL_BIN="${ROOT_DIR}/target/release/frankenctl"
  elif [[ -x "${ROOT_DIR}/target/debug/frankenctl" ]]; then
    FRANKENCTL_BIN="${ROOT_DIR}/target/debug/frankenctl"
  else
    echo "ERROR: frankenctl binary not found in target/{release,debug}/frankenctl" >&2
    exit 2
  fi
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${IFC_OVERTAINT_OUT_DIR:-${ROOT_DIR}/artifacts/ifc_overtaint_regression_smoke/${STAMP}}"
mkdir -p "${OUT_DIR}/cases"

export FRANKENCTL_BIN OUT_DIR

python3 - <<'PY'
import json
import os
import re
import subprocess
import sys

bin_path = os.environ["FRANKENCTL_BIN"]
out_dir = os.environ["OUT_DIR"]
cases_dir = os.path.join(out_dir, "cases")
jsonl_path = os.path.join(out_dir, "results.jsonl")
summary_path = os.path.join(out_dir, "summary.json")

benign_cases = [
    ("literal", "console.log(1 + 2);", "3"),
    ("local_var", "let a = 40; console.log(a + 2);", "42"),
    ("fn_call_const", "function f(){ return 1 } console.log(f());", "1"),
    ("fn_call_arg", "function f(x){ return x + 1 } console.log(f(1));", "2"),
    ("arrow_call", "const g = (x) => x * 2; console.log(g(21));", "42"),
    ("closure_capture", "function mk(){ let c = 0; return () => ++c } const h = mk(); console.log(h());", "1"),
    ("method_call_builtin", "console.log(Math.max(1, 2));", "2"),
    ("array_method", "console.log([3,1,2].sort().join(','));", "1,2,3"),
    ("object_prop", "const o = { a: 1 }; console.log(o.a);", "1"),
    ("string_method", "console.log('abc'.toUpperCase());", "ABC"),
    ("fn_result_to_var_then_log", "function f(){ return 1 } const r = f(); console.log(r);", "1"),
    ("no_console_fn_call", "function f(){ return 1 } f();", ""),
    ("recursion_fib15", "function fib(n){ return n < 2 ? n : fib(n - 1) + fib(n - 2) } console.log(fib(15));", "610"),
]

secret_prefix = "const crypto = require('crypto'); const secret = crypto.randomUUID(); "
negative_cases = [
    ("neg_direct_secret", secret_prefix + "console.log(secret);"),
    ("neg_secret_closure", secret_prefix + "function mk(){ return (x) => x } const f = mk(); console.log(f(secret));"),
    ("neg_secret_math_max", secret_prefix + "const s = secret; console.log(Math.max(s.length, 1));"),
    ("neg_secret_nested_capture", secret_prefix + "const t = secret; function g(){ console.log(t) } g();"),
    ("neg_secret_replace_cb", secret_prefix + "console.log('abc'.replace(/a/, () => secret));"),
]

flow_re = re.compile(r"unauthorized flow detected at op (\d+):\s*(\w+)\s*->\s*(\w+)")
records = []
failures = []

with open(jsonl_path, "w", encoding="utf-8") as jsonl_out:
    for name, source, expected_console in benign_cases:
        js_file = os.path.join(cases_dir, f"{name}.js")
        with open(js_file, "w", encoding="utf-8") as fh:
            fh.write(source + "\n")
        proc = subprocess.run(
            [bin_path, "run", "--input", js_file, "--extension-id", f"bd-9vouw-1-{name}", "--instruction-budget", "2000000"],
            capture_output=True,
            text=True,
        )
        if proc.stderr:
            sys.stderr.write(f"[{name}] stderr: {proc.stderr}")
        verdict = "pass" if proc.returncode == 0 else "fail"
        observed_console = ""
        if proc.returncode == 0:
            report = json.loads(proc.stdout)
            entries = report.get("console_output") or []
            observed_console = "\n".join(
                e["message"] if isinstance(e, dict) else str(e) for e in entries
            )
            if observed_console != expected_console:
                verdict = "output_mismatch"
                failures.append(f"{name}: expected {expected_console!r}, got {observed_console!r}")
        else:
            failures.append(f"{name}: unexpected exit {proc.returncode}: {proc.stderr.strip()}")
        rec = {
            "case": name,
            "kind": "benign",
            "verdict": verdict,
            "exit_code": proc.returncode,
            "expected_console": expected_console,
            "observed_console": observed_console,
            "denial_op": None,
            "source_label": None,
            "sink_clearance": None,
        }
        records.append(rec)
        jsonl_out.write(json.dumps(rec) + "\n")

    for name, source in negative_cases:
        js_file = os.path.join(cases_dir, f"{name}.js")
        with open(js_file, "w", encoding="utf-8") as fh:
            fh.write(source + "\n")
        proc = subprocess.run(
            [bin_path, "run", "--input", js_file, "--goal", "script", "--extension-id", f"bd-9vouw-1-{name}"],
            capture_output=True,
            text=True,
        )
        if proc.stderr:
            sys.stderr.write(f"[{name}] stderr: {proc.stderr}")
        combined = (proc.stderr or "") + "\n" + (proc.stdout or "")
        m = flow_re.search(combined)
        denial_op = int(m.group(1)) if m else None
        src_lbl = m.group(2) if m else None
        sink_clr = m.group(3) if m else None
        if proc.returncode != 0 and m is not None and sink_clr == "Internal":
            verdict = "denied_as_expected"
        else:
            verdict = "unexpected_allow_or_error"
            failures.append(f"{name}: expected IFC denial -> Internal, exit={proc.returncode}, match={bool(m)}")
        rec = {
            "case": name,
            "kind": "negative_secret_egress",
            "verdict": verdict,
            "exit_code": proc.returncode,
            "denial_op": denial_op,
            "source_label": src_lbl,
            "sink_clearance": sink_clr,
        }
        records.append(rec)
        jsonl_out.write(json.dumps(rec) + "\n")

summary = {
    "schema_version": "franken-engine.ifc-overtaint-regression-smoke.v1",
    "binary": bin_path,
    "benign_count": len(benign_cases),
    "negative_count": len(negative_cases),
    "total_cases": len(records),
    "failures": failures,
    "pass": len(failures) == 0,
    "results_jsonl": jsonl_path,
}
with open(summary_path, "w", encoding="utf-8") as fh:
    json.dump(summary, fh, indent=2)
print(json.dumps(summary, indent=2))
if failures:
    sys.exit(1)
PY
