#!/usr/bin/env bash
# No-mock negative drill for scripts/check_isa_path_registration.py (BRIDGE-18.10).
#
# The gate passes on the live tree because there are currently ZERO real
# ISA-specific execution paths -- which proves nothing about its ability to detect
# one. That is the whole hazard here: this gate is installed BEFORE the paths exist
# (BRIDGE-10.2 NEON, BRIDGE-11.2 AVX-512, BRIDGE-07.20 guarded vectorization), so it
# will sit green for months before it is ever exercised in anger. A guard in that
# position has to be falsified deliberately or it is indistinguishable from a
# guard that always returns 0.
#
# Six injected faults, each a thing that will actually be attempted, plus the
# unparseable-inventory case:
#   1. a new file uses core::arch intrinsics without registering  (the bd-2noh9 class)
#   2. an architecture fingerprint type escapes its owning module
#   3. a function that feeds a content hash reads a CPU feature flag (falsifies
#      FE-CLAIM-023 cross-platform identical-hash reproducibility)
#   4. a target_arch cfg site appears without the inventory acknowledging it
#   5. the hash-input extractor matches nothing, so check 3 would pass vacuously
#   6. a registration names a file that no longer exists
#
# Fault 3 is the one that matters most and the least likely to be noticed by
# review: it produces correct-looking code that passes every test on one machine.
# Fault 5 is the one that would make the gate worthless without anyone noticing.
#
# Hermetic: no cargo, no /dp siblings, nothing outside the temp dir is touched.
#
# Usage: ./scripts/e2e/isa_path_registration_drift.sh
# Exit:  0 the gate rejected every injected fault; 1 the drill failed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GUARD="${REPO_ROOT}/scripts/check_isa_path_registration.py"
WORK="$(mktemp -d -t isa_path_drift.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

SRC="${WORK}/crates/franken-engine/src"
mkdir -p "$SRC" "${WORK}/docs"

# A minimal healthy tree: one registered file holding the fingerprint type and a
# hash function that does NOT consult it, plus one ordinary module.
reset_tree() {
  rm -rf "$SRC"
  mkdir -p "$SRC"
  cat >"${SRC}/simd_lexer.rs" <<'EOF'
pub struct ArchCapabilityProfile {
    pub avx2_available: bool,
}

fn compute_token_witness_hash(input_hash: &str, token_count: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"franken-engine.simd-lexer.token-witness.v1");
    hasher.update(input_hash.as_bytes());
    hasher.update(token_count.to_le_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}
EOF
  cat >"${SRC}/ordinary_module.rs" <<'EOF'
pub fn add(a: u64, b: u64) -> u64 {
    a.saturating_add(b)
}
EOF
  write_inventory 0 0
}

# $1 target_arch site count, $2 core::arch intrinsic count
write_inventory() {
  cat >"${WORK}/docs/isa_specific_path_inventory_v1.json" <<EOF
{
  "schema_id": "franken-engine.isa-specific-path-inventory.v1",
  "registered_paths": [
    {
      "id": "swar-lexer",
      "path": "crates/franken-engine/src/simd_lexer.rs",
      "portable_counterpart": "scalar reference lexer in the same module"
    }
  ],
  "fingerprint_owner_files": ["crates/franken-engine/src/simd_lexer.rs"],
  "totals": {
    "core_arch_intrinsics": ${2},
    "std_arch_intrinsics": 0,
    "std_simd_or_core_simd": 0,
    "is_x86_feature_detected": 0,
    "is_aarch64_feature_detected": 0,
    "is_arm_feature_detected": 0,
    "target_arch_cfg_sites": ${1},
    "target_feature_sites": 0
  }
}
EOF
}

run_guard() {
  set +e
  python3 "$GUARD" --repo-root "$WORK" --json "${WORK}/report.json" \
    >"${WORK}/stdout.txt" 2>"${WORK}/stderr.txt"
  guard_exit=$?
  set -e
}

fail() {
  echo "DRILL FAILED: $1" >&2
  echo "--- guard stdout ---" >&2; cat "${WORK}/stdout.txt" >&2 || true
  echo "--- guard stderr ---" >&2; cat "${WORK}/stderr.txt" >&2 || true
  exit 1
}

assert_rejected() {
  local label="$1" check="$2"
  run_guard
  [[ "$guard_exit" -eq 1 ]] || fail "${label}: expected exit 1, got ${guard_exit}"
  python3 - "${WORK}/report.json" "$check" <<'PY' || fail "${label}: report did not name the right check"
import json, sys
report = json.load(open(sys.argv[1]))
want = sys.argv[2]
assert report["summary"]["verdict"] == "fail_closed", report["summary"]
checks = [f["check"] for f in report["findings"]]
assert want in checks, f"expected a {want!r} finding; got {checks}"
for finding in report["findings"]:
    if finding["check"] == want:
        assert finding.get("remedy"), f"{want} finding carries no remedy"
PY
  echo "  rejected: ${label}"
}

# Baseline: the healthy tree must pass, or every rejection below proves nothing.
reset_tree
run_guard
[[ "$guard_exit" -eq 0 ]] || fail "healthy synthetic tree rejected (exit ${guard_exit})"
echo "  baseline: healthy tree accepted"

# 1. An unregistered file reaches for ISA intrinsics.
reset_tree
cat >"${SRC}/fast_kernel.rs" <<'EOF'
pub fn sum_avx(values: &[u64]) -> u64 {
    unsafe { core::arch::x86_64::_mm256_setzero_si256() };
    values.iter().sum()
}
EOF
write_inventory 0 1
assert_rejected "unregistered ISA path (core::arch intrinsic)" registration

# 2. The fingerprint type escapes its owning module.
reset_tree
cat >"${SRC}/leaky_module.rs" <<'EOF'
use crate::simd_lexer::ArchCapabilityProfile;

pub fn describe(profile: &ArchCapabilityProfile) -> &'static str {
    if profile.avx2_available { "wide" } else { "narrow" }
}
EOF
assert_rejected "fingerprint type outside its owner" fingerprint_containment

# 3. A CPU feature flag reaches a content hash. This is the FE-CLAIM-023 killer:
#    it looks like a reasonable "record what we ran on" change and passes every
#    test on a single machine.
reset_tree
cat >"${SRC}/simd_lexer.rs" <<'EOF'
pub struct ArchCapabilityProfile {
    pub avx2_available: bool,
}

fn compute_token_witness_hash(input_hash: &str, profile: &ArchCapabilityProfile) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input_hash.as_bytes());
    hasher.update([profile.avx2_available as u8]);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}
EOF
assert_rejected "CPU feature flag mixed into a content hash" fingerprint_in_hash

# 4. A new target_arch cfg site the inventory has not acknowledged.
reset_tree
cat >>"${SRC}/ordinary_module.rs" <<'EOF'

#[cfg(target_arch = "aarch64")]
pub fn page_size() -> usize { 16384 }
EOF
assert_rejected "unacknowledged target_arch cfg site" totals

# 5. The vacuity guard. Check 3 is structural: if the function-body extractor
#    stops matching -- a change in how functions are written, a bad brace match --
#    it inspects nothing and still exits 0, which is the worst outcome available
#    to a gate. Strip every hash sink and the guard must notice it checked nothing.
reset_tree
cat >"${SRC}/simd_lexer.rs" <<'EOF'
pub struct ArchCapabilityProfile {
    pub avx2_available: bool,
}
EOF
assert_rejected "no hash-input function found (check 3 would be vacuous)" coverage

# 6. A registration naming a file that no longer exists. This rots in the
#    dangerous direction: the entry keeps asserting a portable counterpart for
#    code that is gone, and a reader counts it as covered.
reset_tree
rm -f "${SRC}/simd_lexer.rs"
assert_rejected "registration names a deleted file" stale_registration

# A missing inventory is exit 2, not a silent pass.
reset_tree
rm -f "${WORK}/docs/isa_specific_path_inventory_v1.json"
run_guard
[[ "$guard_exit" -eq 2 ]] || fail "missing inventory: expected exit 2, got ${guard_exit}"
echo "  rejected: missing inventory (exit 2, not a silent pass)"

echo "isa_path_registration_drift=passed faults_rejected=6 unparseable_rejected=1 baseline_accepted=1"
