#!/usr/bin/env bash
#
# CEI track H.4 (bd-sde5e.8.4) — Lean 4 claim⇄evidence soundness proof runner.
#
# Drives a *targeted* `lake build` of `proofs/lean4/ClaimEvidenceSoundness.lean`
# (the pure-core monotonicity/soundness lemma — no Mathlib import, so it builds
# independently of the heavier Mathlib-backed isomorphism libraries), then runs a
# `#print axioms` no-mock check and emits a gate-compatible proof bundle for
# `FE-CLAIM-025`.
#
# The single property this proves and re-checks:
#   the asserted claim state never exceeds the evidence ceiling, preserved by the
#   gate's corrective transition, and only strengthened by committing more
#   evidence (mirrors crates/franken-engine/src/claim_evidence_lattice.rs and
#   crates/franken-engine/src/claim_integrity_flow.rs).
#
# NO-MOCK GUARANTEE: this runner fails closed unless the proof *kernel-checks* and
# the keystone theorems depend on NO `sorryAx` axiom. A `sorry`-backed or absent
# proof can never make this gate green.
#
# Modes:
#   ci | verify   build + axiom-check proofs/lean4/ClaimEvidenceSoundness.lean and
#                 emit the proof bundle on success; refuse / no-emit on failure
#   selftest      structural smoke (no lake/lean required) — asserts the proof
#                 source declares the required theorems and contains no `sorry`,
#                 and that the bundle round-trips its canonical-body hash
#   -h | --help   usage
#
# Requires (ci mode): elan + lake + lean on PATH (or at ~/.elan/bin), python3.
#
# Output (ci mode):
#   artifacts/cei_soundness_lean_proof/FE-CLAIM-025.proof.json
#     — schema: franken-engine.theorem-backed-compiler.proof.v1 (same as the
#       FE-CLAIM-016 runner, so the existing gate/bundle tooling can consume it)
#     — verdict: "proven" iff lake build exits 0 AND no keystone theorem depends
#       on `sorryAx`
#     — proof_kind: "lean-mechanised"; source_module: "frankenengine.proofs.lean4"
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_DIR}"

readonly BEAD="bd-sde5e.8.4"
readonly CLAIM_ID="FE-CLAIM-025"
readonly BUNDLE_SCHEMA="franken-engine.theorem-backed-compiler.proof.v1"
readonly BUNDLE_KIND="lean-mechanised"
readonly BUNDLE_SOURCE="frankenengine.proofs.lean4"
readonly LEAN_PROOFS_DIR="${PROJECT_DIR}/proofs/lean4"
readonly LEAN_MODULE="ClaimEvidenceSoundness"
readonly LEAN_SRC="${LEAN_PROOFS_DIR}/${LEAN_MODULE}.lean"
readonly DEFAULT_BUNDLE_DIR="${PROJECT_DIR}/artifacts/cei_soundness_lean_proof"
readonly ELAN_BIN_DIR="${HOME}/.elan/bin"
readonly TIMEOUT_SECONDS="${LEAN_PROOF_TIMEOUT_SECONDS:-300}"

# The theorems the H.4 acceptance and FE-CLAIM-025 reference depend on. The gate
# refuses to emit unless every one is declared in the source AND (ci mode) the
# keystone theorems are confirmed `sorryAx`-free.
readonly REQUIRED_THEOREMS=(
    "ceiling_monotone"
    "gate_transition_sound"
    "gate_fixes_sound"
    "gate_transition_idempotent"
    "sound_monotone_in_tier"
    "tier_monotone"
    "flow_legal_iff_sound"
    "claim_evidence_integrity_is_sound"
)
# The keystone theorems whose proof terms must not reference `sorryAx`.
readonly KEYSTONE_THEOREMS=(
    "gate_transition_sound"
    "tier_monotone"
    "flow_legal_iff_sound"
    "claim_evidence_integrity_is_sound"
)

MODE="${1:-ci}"

log() { printf '[cei-soundness] %s\n' "$*"; }
err() { printf '[cei-soundness] ERROR: %s\n' "$*" >&2; }
refuse() { err "$*"; exit 2; }

usage() {
    cat >&2 <<EOF
usage: $0 [ci|verify|selftest]

Modes:
  ci | verify   build + axiom-check ${LEAN_MODULE}.lean + emit ${CLAIM_ID}.proof.json
  selftest      structural smoke (no lake/lean required)

Environment:
  LEAN_PROOF_BUNDLE_DIR        override default bundle output dir
  LEAN_PROOF_TIMEOUT_SECONDS   per-run lake build timeout in seconds (default: 300)
EOF
}

case "${MODE}" in
    -h|--help) usage; exit 0 ;;
    ci|verify|selftest) ;;
    *) usage; exit 2 ;;
esac

#-------------------------------------------------------------------------
# Source-shape assertions shared by ci + selftest.
#-------------------------------------------------------------------------
assert_source_shape() {
    [[ -f "$LEAN_SRC" ]] || refuse "${LEAN_SRC#"$PROJECT_DIR"/} missing"
    # No `sorry`/`admit`/`native_decide` allowed in the soundness proof.
    if grep -nE '\bsorry\b|\badmit\b|\bnative_decide\b' "$LEAN_SRC" >/dev/null 2>&1; then
        refuse "soundness proof contains a sorry/admit/native_decide — refusing"
    fi
    local missing=()
    local thm
    for thm in "${REQUIRED_THEOREMS[@]}"; do
        if ! grep -qE "^\s*theorem\s+${thm}\b" "$LEAN_SRC"; then
            missing+=("$thm")
        fi
    done
    if (( ${#missing[@]} > 0 )); then
        refuse "soundness proof is missing required theorem(s): ${missing[*]}"
    fi
}

#-------------------------------------------------------------------------
# Input artifact hashes (proof source + lakefile + toolchain pin).
#-------------------------------------------------------------------------
proof_input_hashes_json() {
    LEAN_INPUT_DIR="$LEAN_PROOFS_DIR" LEAN_MOD="$LEAN_MODULE" python3 <<'PY'
import hashlib
import json
import os

root = os.environ["LEAN_INPUT_DIR"]
module = os.environ["LEAN_MOD"]
paths = {f"{module}.lean", "lakefile.lean", "lean-toolchain"}

hashes = {}
for rel in sorted(paths):
    path = os.path.join(root, *rel.split("/"))
    if not os.path.isfile(path):
        continue
    with open(path, "rb") as fh:
        hashes[rel] = "sha256:" + hashlib.sha256(fh.read()).hexdigest()

print(json.dumps(hashes, sort_keys=True, separators=(",", ":")))
PY
}

#-------------------------------------------------------------------------
# Emit a proof bundle (byte-compatible with the FE-CLAIM-016 runner schema).
#-------------------------------------------------------------------------
emit_proof_bundle() {
    local out_path="$1"; local verdict="$2"; shift 2
    local theorem_ids=("$@")
    local now_utc
    now_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    mkdir -p "$(dirname "$out_path")"

    # Compute defaults explicitly (a `${VAR:-{}}` inline default appends a stray
    # `}` because bash closes the expansion at the first brace).
    local input_hashes="${PROOF_INPUT_HASHES_JSON:-}"
    [[ -n "$input_hashes" ]] || input_hashes="{}"
    local command_default="cd proofs/lean4 && lake build ${LEAN_MODULE}"
    local command_desc="${PROOF_COMMAND:-$command_default}"

    PROOF_OUT="$out_path" \
    PROOF_CLAIM="$CLAIM_ID" \
    PROOF_BEAD="$BEAD" \
    PROOF_SCHEMA="$BUNDLE_SCHEMA" \
    PROOF_KIND="$BUNDLE_KIND" \
    PROOF_VERDICT="$verdict" \
    PROOF_GENERATED="$now_utc" \
    PROOF_SOURCE="$BUNDLE_SOURCE" \
    PROOF_IDS="$(printf '%s\n' "${theorem_ids[@]}" | tr '\n' '|' | sed 's/|$//')" \
    PROOF_PRODUCER_TOOL="${PROOF_PRODUCER_TOOL:-lean4}" \
    PROOF_PRODUCER_VERSION="${PROOF_PRODUCER_VERSION:-lean:unknown;lake:unknown}" \
    PROOF_TIMEOUT_POLICY="${PROOF_TIMEOUT_POLICY:-per-run lake build timeout}" \
    PROOF_TIMEOUT_SECONDS="${PROOF_TIMEOUT_SECONDS:-$TIMEOUT_SECONDS}" \
    PROOF_INPUT_HASHES_JSON="$input_hashes" \
    PROOF_COMMAND="$command_desc" \
    PROOF_AXIOM_NOTE="${PROOF_AXIOM_NOTE:-}" \
    python3 <<'PY'
import hashlib
import json
import os
import sys

theorem_ids = [s for s in os.environ.get("PROOF_IDS", "").split("|") if s]
try:
    input_artifact_hashes = json.loads(os.environ.get("PROOF_INPUT_HASHES_JSON", "{}"))
except json.JSONDecodeError as exc:
    print(f"[cei-soundness] invalid PROOF_INPUT_HASHES_JSON: {exc}", file=sys.stderr)
    sys.exit(2)
if not isinstance(input_artifact_hashes, dict):
    print("[cei-soundness] PROOF_INPUT_HASHES_JSON must decode to an object", file=sys.stderr)
    sys.exit(2)

body = {
    "schema_version": os.environ["PROOF_SCHEMA"],
    "claim_id": os.environ["PROOF_CLAIM"],
    "owning_bead": os.environ["PROOF_BEAD"],
    "track": "track-h",
    "proof_kind": os.environ["PROOF_KIND"],
    "verdict": os.environ["PROOF_VERDICT"],
    "generated_utc": os.environ["PROOF_GENERATED"],
    "source_module": os.environ["PROOF_SOURCE"],
    "producer_tool": os.environ["PROOF_PRODUCER_TOOL"],
    "producer_version": os.environ["PROOF_PRODUCER_VERSION"],
    "timeout_policy": os.environ["PROOF_TIMEOUT_POLICY"],
    "timeout_seconds": int(os.environ["PROOF_TIMEOUT_SECONDS"]),
    "input_artifact_hashes": input_artifact_hashes,
    "command": os.environ["PROOF_COMMAND"],
    "axiom_note": os.environ.get("PROOF_AXIOM_NOTE", ""),
    "theorem_count": len(theorem_ids),
    "theorem_ids": theorem_ids,
}
encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
body["content_hash"] = "sha256:" + hashlib.sha256(encoded).hexdigest()

with open(os.environ["PROOF_OUT"], "w", encoding="utf-8") as fh:
    json.dump(body, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"[cei-soundness] wrote {os.environ['PROOF_OUT']}")
PY
}

#-------------------------------------------------------------------------
# selftest — no lake/lean. Source-shape + bundle round-trip.
#-------------------------------------------------------------------------
if [[ "$MODE" == "selftest" ]]; then
    log "selftest: starting (no lake/lean invocation)"
    command -v python3 >/dev/null 2>&1 || refuse "python3 required"
    assert_source_shape
    log "selftest: source declares all ${#REQUIRED_THEOREMS[@]} required theorems, no sorry"

    tmp_dir="$(mktemp -d -t cei-soundness-selftest.XXXXXXXX)"
    trap 'rm -rf "$tmp_dir"' EXIT
    fixture_out="${tmp_dir}/${CLAIM_ID}.proof.json"
    PROOF_PRODUCER_VERSION="lean:structural-check;lake:structural-check" \
    PROOF_TIMEOUT_POLICY="structural check without external theorem command" \
    PROOF_TIMEOUT_SECONDS="0" \
    PROOF_INPUT_HASHES_JSON="$(proof_input_hashes_json)" \
    PROOF_COMMAND="structural check: emit proof bundle without invoking lake" \
    PROOF_AXIOM_NOTE="selftest does not run #print axioms" \
    emit_proof_bundle "$fixture_out" "proven" "${REQUIRED_THEOREMS[@]}"

    BUNDLE="$fixture_out" python3 <<'PY'
import hashlib, json, os, sys
proof = json.load(open(os.environ["BUNDLE"]))
body = {k: v for k, v in proof.items() if k != "content_hash"}
encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
expected = "sha256:" + hashlib.sha256(encoded).hexdigest()
if proof["content_hash"] != expected:
    print(f"[cei-soundness] selftest: content_hash MISMATCH", file=sys.stderr); sys.exit(1)
if proof["theorem_count"] != len(proof["theorem_ids"]):
    print("[cei-soundness] selftest: theorem_count mismatch", file=sys.stderr); sys.exit(1)
print("[cei-soundness] selftest: bundle canonical-body recompute MATCHES")
PY
    log "selftest: PASS"
    exit 0
fi

#-------------------------------------------------------------------------
# ci/verify — targeted lake build + axiom no-mock check + emit bundle.
#-------------------------------------------------------------------------
bundle_dir="${LEAN_PROOF_BUNDLE_DIR:-$DEFAULT_BUNDLE_DIR}"
proof_out="${bundle_dir}/${CLAIM_ID}.proof.json"

assert_source_shape
command -v python3 >/dev/null 2>&1 || refuse "python3 required"
[[ "$TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || refuse "LEAN_PROOF_TIMEOUT_SECONDS must be a non-negative integer"

# Detect lake/lean; fall back to elan's bin dir.
for tool in lake lean; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        if [[ -x "${ELAN_BIN_DIR}/${tool}" ]]; then
            export PATH="${ELAN_BIN_DIR}:${PATH}"
            log "added ${ELAN_BIN_DIR} to PATH for ${tool}"
        else
            refuse "${tool} not on PATH — install with scripts/install_lean_toolchain.sh install"
        fi
    fi
done

lean_version="$(lean --version 2>/dev/null | sed -n '1p' || true)"
lake_version="$(lake --version 2>/dev/null | sed -n '1p' || true)"
producer_version="lean:${lean_version:-unknown};lake:${lake_version:-unknown}"
input_hashes_json="$(proof_input_hashes_json)"
timeout_policy="per-run lake build timeout ${TIMEOUT_SECONDS}s"
command_desc="cd ${LEAN_PROOFS_DIR} && lake build ${LEAN_MODULE}"

# --- 1. targeted build (only the soundness lib; never the Mathlib isomorphisms) ---
log "lake build ${LEAN_MODULE} in ${LEAN_PROOFS_DIR} (${timeout_policy})"
build_log="$(mktemp -t cei-soundness-build.XXXXXXXX.log)"
trap 'rm -f "$build_log"' EXIT
build_status=0
if (( TIMEOUT_SECONDS > 0 )) && command -v timeout >/dev/null 2>&1; then
    (cd "$LEAN_PROOFS_DIR" && timeout "${TIMEOUT_SECONDS}s" lake build "$LEAN_MODULE" 2>&1) | tee "$build_log" || build_status=$?
else
    (cd "$LEAN_PROOFS_DIR" && lake build "$LEAN_MODULE" 2>&1) | tee "$build_log" || build_status=$?
fi
if (( build_status != 0 )); then
    err "lake build exited non-zero (rc=${build_status}) — refusing to emit ${CLAIM_ID}.proof.json"
    exit "$build_status"
fi
log "lake build succeeded"

# --- 2. NO-MOCK axiom check: keystone theorems must not depend on sorryAx ---
log "verifying keystone theorems are sorryAx-free (#print axioms)"
axcheck="$(mktemp -t cei-soundness-axioms.XXXXXXXX.lean)"
trap 'rm -f "$build_log" "$axcheck"' EXIT
{
    echo "import ${LEAN_MODULE}"
    echo "open FrankenEngine.ClaimEvidence"
    for thm in "${KEYSTONE_THEOREMS[@]}"; do
        echo "#print axioms ${thm}"
    done
} >"$axcheck"

ax_log="$(mktemp -t cei-soundness-axout.XXXXXXXX.log)"
trap 'rm -f "$build_log" "$axcheck" "$ax_log"' EXIT
ax_status=0
# `lake env lean` runs lean with lake's LEAN_PATH so `import ${LEAN_MODULE}`
# resolves the freshly-built .olean.
( cd "$LEAN_PROOFS_DIR" && lake env lean "$axcheck" 2>&1 ) | tee "$ax_log" || ax_status=$?
if (( ax_status != 0 )); then
    err "#print axioms invocation failed (rc=${ax_status}) — refusing to emit"
    exit "$ax_status"
fi
if grep -qiE 'sorryAx|sorry' "$ax_log"; then
    err "a keystone theorem depends on sorryAx — the proof is NOT genuinely checked. Refusing."
    exit 1
fi
axiom_note="$(grep -E "depends on axioms|does not depend" "$ax_log" | tr '\n' ' ' | sed 's/  */ /g' | cut -c1-480)"
log "no-mock axiom check PASSED (no sorryAx in keystone theorems)"

# --- 3. theorem ids actually declared in the source ---
mapfile -t theorem_ids < <(
    grep -hE '^\s*theorem\s+[A-Za-z_][A-Za-z0-9_]+' "$LEAN_SRC" \
        | awk '{print $2}' | sort -u
)
(( ${#theorem_ids[@]} > 0 )) || refuse "no theorem declarations found — refusing empty bundle"

PROOF_PRODUCER_TOOL="lean4" \
PROOF_PRODUCER_VERSION="$producer_version" \
PROOF_TIMEOUT_POLICY="$timeout_policy" \
PROOF_TIMEOUT_SECONDS="$TIMEOUT_SECONDS" \
PROOF_INPUT_HASHES_JSON="$input_hashes_json" \
PROOF_COMMAND="$command_desc" \
PROOF_AXIOM_NOTE="$axiom_note" \
emit_proof_bundle "$proof_out" "proven" "${theorem_ids[@]}"
log "ci: emitted ${proof_out} (${#theorem_ids[@]} theorems, verdict=proven)"
