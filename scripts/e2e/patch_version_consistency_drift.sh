#!/usr/bin/env bash
# No-mock negative drill for scripts/check_patch_version_consistency.py (bd-h5cl7).
#
# The guard's whole value is that it fails closed on a skewed `[patch.*]` entry.
# In the healthy tree it reports `patch_entries=0` and exits 0, which proves
# nothing about its ability to detect anything. This drill constructs a synthetic
# workspace carrying the exact bd-h5cl7 shape and asserts the guard rejects it.
#
# The shape being reproduced: a patch substitutes a crate whose version is
# SEMVER-COMPATIBLE with what the consumer declares but is not the same release.
# That is precisely the case Cargo accepts silently -- `^0.1.18` admitting
# `0.1.19` is what let the engine's default build go red -- so a drill that used
# an incompatible version would exercise Cargo's own rejection instead of ours.
#
# Hermetic: no /dp sibling checkout is required and nothing outside the temp dir
# is touched.
#
# Usage: ./scripts/e2e/patch_version_consistency_drift.sh
# Exit:  0 the guard correctly rejected the skew; 1 the drill failed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GUARD="${REPO_ROOT}/scripts/check_patch_version_consistency.py"
WORK="$(mktemp -d -t patch_version_drift.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# The patched crate ships a version that is semver-compatible with, but not equal
# to, the version the consumer declares. `^1.0.200` admits `1.0.999`.
DECLARED_REQ="1.0.200"
PATCHED_VERSION="1.0.999"
VICTIM_CRATE="serde"

mkdir -p "${WORK}/consumer/src" \
         "${WORK}/patched-${VICTIM_CRATE}/src" \
         "${WORK}/crates/franken-engine/fuzz"

cat >"${WORK}/Cargo.toml" <<EOF
[workspace]
members = ["consumer"]
resolver = "2"

[patch.crates-io]
${VICTIM_CRATE} = { path = "patched-${VICTIM_CRATE}" }
EOF

# The guard names both manifests explicitly; the fuzz one must exist or it
# reports FE-PATCH-MANIFEST-MISSING and we would not be testing skew detection.
cat >"${WORK}/crates/franken-engine/fuzz/Cargo.toml" <<'EOF'
[package]
name = "drill-fuzz-placeholder"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]
EOF

cat >"${WORK}/consumer/Cargo.toml" <<EOF
[package]
name = "consumer"
version = "0.1.0"
edition = "2021"

[dependencies]
${VICTIM_CRATE} = "${DECLARED_REQ}"
EOF
: >"${WORK}/consumer/src/lib.rs"

cat >"${WORK}/patched-${VICTIM_CRATE}/Cargo.toml" <<EOF
[package]
name = "${VICTIM_CRATE}"
version = "${PATCHED_VERSION}"
edition = "2021"

[workspace]
EOF
: >"${WORK}/patched-${VICTIM_CRATE}/src/lib.rs"

report="${WORK}/report.json"
set +e
RCH_CARGO_WRAPPER_BYPASS=1 python3 "$GUARD" --repo-root "$WORK" --json "$report" >"${WORK}/stdout.txt" 2>"${WORK}/stderr.txt"
guard_exit=$?
set -e

fail() {
  echo "DRILL FAILED: $1" >&2
  echo "--- guard stdout ---" >&2; cat "${WORK}/stdout.txt" >&2 || true
  echo "--- guard stderr ---" >&2; cat "${WORK}/stderr.txt" >&2 || true
  exit 1
}

if [[ "$guard_exit" -eq 2 ]]; then
  # cargo metadata could not resolve. That is an environment problem (no registry
  # index for the victim crate), not a guard defect -- report it honestly as a
  # skip rather than claiming the drill passed.
  echo "patch_version_consistency_drift=skipped reason=cargo_metadata_unavailable"
  cat "${WORK}/stderr.txt" >&2 || true
  exit 0
fi

[[ "$guard_exit" -eq 1 ]] || fail "expected exit 1 (skew detected), got ${guard_exit}"
[[ -f "$report" ]] || fail "guard wrote no JSON report"

python3 - "$report" "$VICTIM_CRATE" "$PATCHED_VERSION" "$DECLARED_REQ" <<'PY' || fail "report did not describe the injected skew"
import json, sys
report_path, crate, patched_version, declared_req = sys.argv[1:5]
report = json.load(open(report_path))

assert report["decision"] == "fail_closed", f"decision={report['decision']!r}"

skews = [f for f in report["findings"] if f["code"] == "FE-PATCH-VERSION-SKEW"]
assert skews, f"no FE-PATCH-VERSION-SKEW finding; got {[f['code'] for f in report['findings']]}"
assert any(f["crate"] == crate for f in skews), f"skew not attributed to {crate}"

pairs = [p for p in report["checked_pairs"] if p["crate"] == crate and p["verdict"] == "skew"]
assert pairs, "no checked_pair marked skew"
pair = pairs[0]
assert pair["resolved_version"] == patched_version, pair
assert pair["declared_req"].lstrip("^=") == declared_req, pair
assert pair["consumer"] == "consumer", pair

# The finding must be actionable, not just a boolean.
assert skews[0]["remediation"].strip(), "finding carries no remediation"
print(
    f"  verified: patch resolved {crate} to {pair['resolved_version']} while "
    f"{pair['consumer']} declares {pair['declared_req']} -> {pair['verdict']}"
)
PY

echo "patch_version_consistency_drift=passed guard_exit=1 skew_detected=1"
