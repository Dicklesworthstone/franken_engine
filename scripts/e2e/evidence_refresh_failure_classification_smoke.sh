#!/usr/bin/env bash
# Failure-classification smoke for the scheduled evidence refresh (bd-566x4).
#
# Pins ADR-0012 §5.1: a verification command that could not RUN is reported as
# `infrastructure`, not `regression`, and neither one may write a receipt.
#
# What this actually protects
# ---------------------------
# The dangerous failure of a classifier like this is not missing an infrastructure
# signature -- that just costs a false alarm. It is the reverse: a regex loose
# enough to swallow a genuine regression, which would silently downgrade "this
# claim is broken" to "the machine is flaky" on the project's most
# identity-critical surface. So the negative controls below are the load-bearing
# half of this file, and they are deliberately drawn from what a REAL failure of
# these gates looks like: an assertion failure, a rustc type error, a gate verdict
# rejection, and an empty transcript.
#
# The fail-closed property is asserted structurally rather than by trusting prose:
# the smoke greps the one and only receipt-writing call site and fails if it is
# ever reachable on a non-zero exit.
#
# Usage:  ./scripts/e2e/evidence_refresh_failure_classification_smoke.sh
# Exit:   0 all assertions pass; 1 an assertion failed; 2 usage/environment error.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '2,23p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
fi

command -v python3 >/dev/null 2>&1 || { echo "error: python3 is required" >&2; exit 2; }

contract="docs/infrastructure_failure_signatures_v1.json"
[[ -f "$contract" ]] || { echo "error: missing $contract" >&2; exit 2; }

echo "== evidence-refresh failure classification smoke =="

python3 - <<'PY'
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, "scripts")
from reemit_evidence_receipts import classify_failure, load_signatures

failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "ok  " if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(name)


sigs = load_signatures()

# ---------------------------------------------------------------- contract shape
print("\ncontract validity")
check("contract declares signatures", len(sigs.get("signatures", [])) > 0)
check("contract declares exit-code rules", len(sigs.get("exit_code_rules", [])) > 0)
for sig in sigs.get("signatures", []):
    try:
        re.compile(sig["regex"])
        ok = True
        detail = ""
    except re.error as exc:
        ok, detail = False, str(exc)
    check(f"regex compiles: {sig['id']}", ok, detail)
for rule in sigs.get("exit_code_rules", []):
    check(
        f"exit rule well-formed: {rule.get('id')}",
        isinstance(rule.get("exit_code"), int) and bool(rule.get("reason")),
    )

# ------------------------------------------------- positive: real recorded shapes
# The first two are verbatim from the 2026-07-26 run that motivated bd-566x4:
# FE-CLAIM-006 and FE-CLAIM-022 both died when a concurrent agent deleted the
# shared /data/tmp/cargo-target out from under a running build.
print("\ninfrastructure signatures (must NOT be reported as regressions)")
positive = [
    (
        "target tree deleted mid-build (FE-CLAIM-022, real)",
        101,
        "   Compiling frankenengine-engine v0.2.0\n"
        "error: failed to write `/data/tmp/cargo-target/release/.fingerprint/"
        "frankenengine-engine-2e4c08df79114136/invoked.timestamp`\n\n"
        "Caused by:\n  No such file or directory (os error 2)\n",
    ),
    (
        "target tree deleted mid-build (FE-CLAIM-006, real)",
        1,
        'error: failed to write `/data/tmp/cargo-target/debug/.fingerprint/'
        'fsqlite-types-2786f601f9375c54/invoked.timestamp`\n'
        "Caused by:\n  No such file or directory (os error 2)\n",
    ),
    ("timeout", 124, "TIMEOUT after 900s"),
    ("OOM kill", 137, "some build output"),
    ("disk exhausted", 1, "error: No space left on device (os error 28)"),
    (
        "stale crate metadata",
        1,
        "error[E0514]: found crate `serde` compiled by an incompatible version",
    ),
    (
        "missing /dp sibling checkout",
        1,
        "error: failed to read /dp/sqlmodel_rust/Cargo.toml",
    ),
]
for name, code, output in positive:
    kind, reason = classify_failure(code, output, sigs)
    check(name, kind == "infrastructure", f"got {kind} ({reason})")

# ------------------------------------- negative: the half that actually matters
print("\nreal failures (MUST still be reported as regressions)")
negative = [
    (
        "assertion failure in a gate test",
        1,
        "test capability::tests::rejects_ambient_authority ... FAILED\n"
        "assertion `left == right` failed\n  left: Allow\n right: Reject\n"
        "test result: FAILED. 812 passed; 1 failed",
    ),
    (
        "gate verdict rejection",
        1,
        "ERROR: FE-CLAIM-006 asserted observed but committed evidence tier is Simulated\n"
        "claim_to_proof_matrix_gate=fail",
    ),
    (
        "compile error in our own source",
        101,
        "error[E0308]: mismatched types\n --> crates/franken-engine/src/capability.rs:42:9",
    ),
    ("bare non-zero exit, no output", 1, ""),
    (
        "replay divergence",
        1,
        "replay divergence at event 41: recorded hash 9f2a... != replayed 0b17...",
    ),
    (
        "test writing its own fixture failed",
        1,
        "thread 'main' panicked at: failed to write /tmp/fixture_out.json",
    ),
]
for name, code, output in negative:
    kind, reason = classify_failure(code, output, sigs)
    check(name, kind == "regression", f"got {kind} ({reason})")

# ------------------------------------------------------------------- fail-closed
print("\nfail-closed structure")
src = Path("scripts/reemit_evidence_receipts.py").read_text()
# There must be exactly one call site that writes a receipt, and it must sit under
# `if code == 0:`. Prose in an ADR cannot enforce this; a grep can.
reemit_calls = [
    line.strip()
    for line in src.splitlines()
    if "reemit(cid" in line and not line.strip().startswith("#")
]
check("exactly one receipt-writing call site", len(reemit_calls) == 1, str(reemit_calls))
guarded = "if code == 0:\n            reemit(cid, command, commit)" in src
check("receipt write is guarded by `code == 0`", guarded)
check(
    "infrastructure branch writes no receipt",
    'result["status"] = "infrastructure"' in src
    and "reemit(cid" not in src.split('elif kind == "infrastructure":')[1].split("else:")[0],
)

# ------------------------------------------------------------------- exit codes
print("\nexit-code contract")
check("regression exits 1", "if failed:\n        return 1" in src)
check("infrastructure-only exits 3", "return 3 if blocked else 0" in src)

print()
if failures:
    print(f"FAIL: {len(failures)} assertion(s) failed:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("evidence_refresh_failure_classification_smoke=pass")
PY

echo "== smoke passed =="
