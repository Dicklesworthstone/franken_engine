#!/usr/bin/env bash
# No-mock negative drill for the material/advisory split in
# scripts/check_evidence_drift.py::environment_drift (ADR-0012 5.3, BRIDGE-19.18).
#
# Why this drill exists
# ---------------------
# The environment signal originally compared the whole fingerprint digest, so ANY
# field difference meant `drifted` -> stale -> provisional. On an unpinned nightly
# that fires daily on every claim: on 2026-07-26 a single rustc build-id roll
# (da86f4d07 -> 008fa22ce) took all 16 OBSERVED claims from fresh to stale within
# hours of a refresh. A signal that is always on distinguishes nothing.
#
# The fix compares each field at the granularity at which a change plausibly
# changes a build's RESULT. That is a deliberate LOOSENING of a safety check, and a
# loosened check is exactly the kind that quietly becomes a no-op. A passing run on
# a healthy tree proves nothing here -- it would pass just as well if
# environment_drift() had been replaced by `return {"status": "clean"}`.
#
# So this drill asserts BOTH directions:
#   (A) every advisory-precision change is NOT stale        (the fix works)
#   (B) every material change IS still `drifted`            (the fix did not gut it)
#   (C) an unprojectable receipt stays conservative         (no silent fail-open)
#
# (B) is the load-bearing half. Without it, "clean" is unfalsifiable.
#
# Hermetic: imports the module directly, builds fingerprints in memory, touches no
# receipt, runs no cargo, needs no /dp siblings.
#
# Usage: ./scripts/e2e/evidence_environment_drift_precision_drill.sh
# Exit:  0 every case behaved as asserted; 1 the drill failed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

python3 - <<'PYEOF'
import sys
from pathlib import Path

sys.path.insert(0, str(Path("scripts").resolve()))
from check_evidence_drift import environment_drift, material_digest  # noqa: E402

BASE = {
    "rustc_version": "rustc 1.99.0-nightly (da86f4d07 2026-07-24)",
    "cargo_version": "cargo 1.99.0-nightly (3efb1f477 2026-07-17)",
    "rustc_host_triple": "x86_64-unknown-linux-gnu",
    "kernel_release": "6.17.0-41-generic",
    "architecture": "x86_64",
    "platform": "linux",
}


def fingerprint(fields):
    # `digest` is deliberately a value that is NOT the material digest, so a case
    # can only pass by projecting -- never by the byte-identical fast path.
    return {
        "schema_version": "franken-engine.evidence-environment-fingerprint.v1",
        "digest": "sha256:" + "0" * 64,
        "material_digest": material_digest(fields),
        "fields": dict(fields),
    }


def receipt(fields):
    return {"outputs": {"environment_fingerprint": fingerprint(fields)}}


def current(fields):
    return {"digest": "sha256:" + "1" * 64, "fields": dict(fields)}


def mutate(**changes):
    fields = dict(BASE)
    fields.update(changes)
    return fields


failures = []


def check(label, recorded, live, expect_status, expect_advisory):
    got = environment_drift(receipt(recorded), current(live))
    status = got.get("status")
    advisory = bool(got.get("advisory_drift"))
    ok = status == expect_status and advisory == expect_advisory
    print(
        f"  [{'PASS' if ok else 'FAIL'}] {label}: status={status} "
        f"advisory={'yes' if advisory else 'no'} "
        f"(expected status={expect_status} advisory={'yes' if expect_advisory else 'no'})"
    )
    if not ok:
        failures.append(label)


# --- (A) advisory-precision changes must NOT be stale ---------------------
print("A. advisory-precision changes -> clean, and recorded as advisory:")
check(
    "rustc nightly build id rolls (the 2026-07-26 incident)",
    BASE,
    mutate(rustc_version="rustc 1.99.0-nightly (008fa22ce 2026-07-25)"),
    "clean",
    True,
)
check(
    "cargo nightly build id rolls",
    BASE,
    mutate(cargo_version="cargo 1.99.0-nightly (aaaaaaaaa 2026-08-01)"),
    "clean",
    True,
)
check(
    "kernel ABI/distro suffix bumps within a series",
    BASE,
    mutate(kernel_release="6.17.0-49-generic"),
    "clean",
    True,
)
check(
    "all three advisory fields move at once",
    BASE,
    mutate(
        rustc_version="rustc 1.99.0-nightly (008fa22ce 2026-07-25)",
        cargo_version="cargo 1.99.0-nightly (bbbbbbbbb 2026-08-02)",
        kernel_release="6.17.2-9-generic",
    ),
    "clean",
    True,
)

# --- (B) material changes must STILL be drifted ---------------------------
# Without this half, the loosening above is unfalsifiable.
print("\nB. material changes -> still drifted (the check was not gutted):")
check(
    "rustc MINOR version bump (1.99 -> 2.00)",
    BASE,
    mutate(rustc_version="rustc 2.00.0-nightly (da86f4d07 2026-07-24)"),
    "drifted",
    False,
)
check(
    "rustc CHANNEL change (nightly -> stable)",
    BASE,
    mutate(rustc_version="rustc 1.99.0 (da86f4d07 2026-07-24)"),
    "drifted",
    False,
)
check(
    "cargo minor version bump",
    BASE,
    mutate(cargo_version="cargo 2.00.0-nightly (3efb1f477 2026-07-17)"),
    "drifted",
    False,
)
check(
    "host triple change (gnu -> musl)",
    BASE,
    mutate(rustc_host_triple="x86_64-unknown-linux-musl"),
    "drifted",
    False,
)
check(
    "architecture change (x86_64 -> aarch64)",
    BASE,
    mutate(architecture="aarch64"),
    "drifted",
    False,
)
check("platform change (linux -> darwin)", BASE, mutate(platform="darwin"), "drifted", False)
check(
    "kernel MINOR series bump (6.17 -> 6.18)",
    BASE,
    mutate(kernel_release="6.18.0-1-generic"),
    "drifted",
    False,
)
check(
    "kernel MAJOR series bump (6.x -> 7.x)",
    BASE,
    mutate(kernel_release="7.1.0-1-generic"),
    "drifted",
    False,
)

# A material change must win even when advisory noise is present alongside it:
# the disjunction must not be swallowed by the projection.
got = environment_drift(
    receipt(BASE),
    current(
        mutate(
            architecture="aarch64",
            rustc_version="rustc 1.99.0-nightly (008fa22ce 2026-07-25)",
        )
    ),
)
ok = got.get("status") == "drifted" and "architecture" in (got.get("changed_fields") or {})
print(
    f"  [{'PASS' if ok else 'FAIL'}] material change is not masked by concurrent advisory noise: "
    f"status={got.get('status')} changed={sorted((got.get('changed_fields') or {}))}"
)
if not ok:
    failures.append("material change masked by advisory noise")

# --- (C) unprojectable / absent receipts stay conservative ----------------
print("\nC. cannot-compute cases stay conservative (never silently clean):")
got = environment_drift({"outputs": {}}, current(BASE))
ok = got.get("status") == "unknown"
print(f"  [{'PASS' if ok else 'FAIL'}] receipt predating fingerprinting -> unknown: {got.get('status')}")
if not ok:
    failures.append("missing fingerprint not unknown")

# A digest with no fields cannot be projected. Guessing which side of the
# material line it fell on would be exactly the fail-open this system must not have.
got = environment_drift(
    {
        "outputs": {
            "environment_fingerprint": {
                "schema_version": "franken-engine.evidence-environment-fingerprint.v1",
                "digest": "sha256:" + "2" * 64,
            }
        }
    },
    current(BASE),
)
ok = got.get("status") == "drifted"
print(f"  [{'PASS' if ok else 'FAIL'}] digest present but no fields -> drifted: {got.get('status')}")
if not ok:
    failures.append("fieldless fingerprint not conservative")

# An unknown field must be compared verbatim, so extending the fingerprint
# cannot silently widen what the projection ignores.
extended = dict(BASE)
extended["libc_version"] = "glibc 2.41"
got = environment_drift(receipt(extended), current({**extended, "libc_version": "glibc 2.42"}))
ok = got.get("status") == "drifted"
print(f"  [{'PASS' if ok else 'FAIL'}] unrecognised field compared verbatim -> drifted: {got.get('status')}")
if not ok:
    failures.append("unknown field not treated as material")

print()
if failures:
    print(f"DRILL FAILED: {len(failures)} case(s): {failures}")
    sys.exit(1)
print("DRILL PASSED: advisory changes are not stale, material changes still are.")
PYEOF
