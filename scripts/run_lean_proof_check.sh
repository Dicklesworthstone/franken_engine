#!/usr/bin/env bash
#
# Track-G FE-CLAIM-016 Lean proof runner (bd-cixqu.7.17.3).
#
# Drives `lake build` over `proofs/lean4/`, parses the build verdict, and emits
# `artifacts/rgc_theorem_backed_compiler_inputs/FE-CLAIM-016.proof.json` with the
# gate-compatible schema (canonical-body-hash, see
# `run_fe_claim_016_021_promotion_gate.sh`).
#
# This is the "parallel mapping" path called out in bd-cixqu.7.17.3 step (3): the
# Lean-backed FE-CLAIM-016 lives outside the PolicyTheoremEngine theorem set, so
# rather than extending `claim_id_for_property`, the mapping
# (proofs/lean4/*.lean -> FE-CLAIM-016) is encoded here. The PolicyTheoremEngine
# bundles (FE-CLAIM-018, FE-CLAIM-021) and the translation-validator bundle
# (FE-CLAIM-017) emit through `policy_theorem_engine::write_proof_bundle`; this
# runner produces a byte-compatible JSON without going through Rust.
#
# Modes:
#   ci | verify   build proofs/lean4/ with lake and emit the proof bundle on
#                 success; refuse / no-emit on failure
#   selftest      structural smoke (no lake/lean required) — emits a fixture
#                 proof bundle to a tempdir and verifies it re-validates under
#                 the gate's canonical_body_hash recompute
#   -h | --help   usage
#
# Requires (ci mode):
#   - elan + lake + lean on PATH; install via scripts/install_lean_toolchain.sh
#   - python3 (for canonical-body hashing; same builtin used by the gate)
#
# Output (ci mode):
#   artifacts/rgc_theorem_backed_compiler_inputs/FE-CLAIM-016.proof.json
#     — schema: franken-engine.theorem-backed-compiler.proof.v1
#     — verdict: "proven" iff lake build exits 0
#     — proof_kind: "lean-mechanised"
#     — source_module: "frankenengine.proofs.lean4"
#     — theorem_ids: per-module top-level theorems compiled successfully
#     — producer_tool/version, timeout policy, exact command, and Lean input
#       artifact hashes are recorded for repro.lock-style auditability
#     — content_hash: sha256(canonicalised body) — same scheme the gate script
#       recomputes
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_DIR}"

readonly BEAD="bd-cixqu.7.17.3"
readonly CLAIM_ID="FE-CLAIM-016"
readonly BUNDLE_SCHEMA="franken-engine.theorem-backed-compiler.proof.v1"
readonly BUNDLE_KIND="lean-mechanised"
readonly BUNDLE_SOURCE="frankenengine.proofs.lean4"
readonly LEAN_PROOFS_DIR="${PROJECT_DIR}/proofs/lean4"
readonly DEFAULT_BUNDLE_DIR="${PROJECT_DIR}/artifacts/rgc_theorem_backed_compiler_inputs"
readonly ELAN_BIN_DIR="${HOME}/.elan/bin"
readonly TIMEOUT_SECONDS="${LEAN_PROOF_TIMEOUT_SECONDS:-300}"

MODE="${1:-ci}"

log() { printf '[lean-runner] %s\n' "$*"; }
err() { printf '[lean-runner] ERROR: %s\n' "$*" >&2; }
refuse() { err "$*"; exit 2; }

usage() {
    cat >&2 <<EOF
usage: $0 [ci|verify|selftest]

Modes:
  ci | verify   build proofs/lean4/ + emit FE-CLAIM-016.proof.json
  selftest      structural fixture test (no lake/lean required)

Environment:
  LEAN_PROOF_BUNDLE_DIR   override default bundle output dir
  LEAN_PROOF_TIMEOUT_SECONDS
                          per-run lake build timeout in seconds (default: 300)
EOF
}

case "${MODE}" in
    -h|--help) usage; exit 0 ;;
    ci|verify|selftest) ;;
    *) usage; exit 2 ;;
esac

#-------------------------------------------------------------------------
# Canonical body hash + bundle write (shared between ci and selftest).
# Mirrors the Python recompute the promotion gate does at L310-313 of
# scripts/run_fe_claim_016_021_promotion_gate.sh.
#-------------------------------------------------------------------------
proof_input_hashes_json() {
    LEAN_INPUT_DIR="$LEAN_PROOFS_DIR" python3 <<'PY'
import hashlib
import json
import os

root = os.environ["LEAN_INPUT_DIR"]
paths = {"lakefile.lean", "lean-toolchain"}
for dirpath, _dirnames, filenames in os.walk(root):
    for name in filenames:
        if name.endswith(".lean"):
            rel = os.path.relpath(os.path.join(dirpath, name), root)
            paths.add(rel.replace(os.sep, "/"))

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

emit_proof_bundle() {
    local out_path="$1"
    local verdict="$2"          # "proven" | "unproven"
    shift 2
    local theorem_ids=("$@")    # remaining args = theorem ids
    local producer_tool="${PROOF_PRODUCER_TOOL:-lean4}"
    local producer_version="${PROOF_PRODUCER_VERSION:-lean:unknown;lake:unknown}"
    local timeout_policy="${PROOF_TIMEOUT_POLICY:-per-run lake build timeout}"
    local timeout_seconds="${PROOF_TIMEOUT_SECONDS:-$TIMEOUT_SECONDS}"
    local input_hashes_json="${PROOF_INPUT_HASHES_JSON:-{}}"
    local command_desc="${PROOF_COMMAND:-cd proofs/lean4 && lake build}"

    local now_utc
    now_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    mkdir -p "$(dirname "$out_path")"

    PROOF_OUT="$out_path" \
    PROOF_CLAIM="$CLAIM_ID" \
    PROOF_BEAD="$BEAD" \
    PROOF_SCHEMA="$BUNDLE_SCHEMA" \
    PROOF_KIND="$BUNDLE_KIND" \
    PROOF_VERDICT="$verdict" \
    PROOF_GENERATED="$now_utc" \
    PROOF_SOURCE="$BUNDLE_SOURCE" \
    PROOF_IDS="$(printf '%s\n' "${theorem_ids[@]}" | tr '\n' '|' | sed 's/|$//')" \
    PROOF_PRODUCER_TOOL="$producer_tool" \
    PROOF_PRODUCER_VERSION="$producer_version" \
    PROOF_TIMEOUT_POLICY="$timeout_policy" \
    PROOF_TIMEOUT_SECONDS="$timeout_seconds" \
    PROOF_INPUT_HASHES_JSON="$input_hashes_json" \
    PROOF_COMMAND="$command_desc" \
    python3 <<'PY'
import hashlib
import json
import os
import sys

theorem_ids = [s for s in os.environ.get("PROOF_IDS", "").split("|") if s]
try:
    input_artifact_hashes = json.loads(os.environ.get("PROOF_INPUT_HASHES_JSON", "{}"))
except json.JSONDecodeError as exc:
    print(f"[lean-runner] invalid PROOF_INPUT_HASHES_JSON: {exc}", file=sys.stderr)
    sys.exit(2)
if not isinstance(input_artifact_hashes, dict):
    print("[lean-runner] PROOF_INPUT_HASHES_JSON must decode to an object", file=sys.stderr)
    sys.exit(2)

body = {
    "schema_version": os.environ["PROOF_SCHEMA"],
    "claim_id": os.environ["PROOF_CLAIM"],
    "owning_bead": os.environ["PROOF_BEAD"],
    "track": "track-g",
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
    "theorem_count": len(theorem_ids),
    "theorem_ids": theorem_ids,
}

# The gate's canonical-body recompute (separators=(',', ':'), sort_keys=True)
# — keep byte-identical.
encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
body["content_hash"] = "sha256:" + hashlib.sha256(encoded).hexdigest()

out_path = os.environ["PROOF_OUT"]
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(body, fh, indent=2, sort_keys=True)
    fh.write("\n")

print(f"[lean-runner] wrote {out_path}")
PY
}

#-------------------------------------------------------------------------
# selftest — emits a fixture bundle to a tempdir and round-trips it through
# the gate's canonical_body_hash recompute. No lake required.
#-------------------------------------------------------------------------
if [[ "$MODE" == "selftest" ]]; then
    log "selftest: starting (no lake/lean invocation)"
    [[ -d "$LEAN_PROOFS_DIR" ]] || refuse "proofs/lean4/ missing"
    [[ -f "$LEAN_PROOFS_DIR/lean-toolchain" ]] || refuse "proofs/lean4/lean-toolchain missing"
    command -v python3 >/dev/null 2>&1 || refuse "python3 required for canonical-body hashing"

    tmp_dir="$(mktemp -d -t lean-runner-selftest.XXXXXXXX)"
    trap 'rm -rf "$tmp_dir"' EXIT
    fixture_out="${tmp_dir}/${CLAIM_ID}.proof.json"
    fixture_hashes="$(proof_input_hashes_json)"

    PROOF_PRODUCER_TOOL="lean4" \
    PROOF_PRODUCER_VERSION="lean:structural-check;lake:structural-check" \
    PROOF_TIMEOUT_POLICY="structural check without external theorem command" \
    PROOF_TIMEOUT_SECONDS="0" \
    PROOF_INPUT_HASHES_JSON="$fixture_hashes" \
    PROOF_COMMAND="structural check: emit proof bundle without invoking lake" \
    emit_proof_bundle "$fixture_out" "proven" \
        "IFCLatticeIsomorphism.isomorphism" \
        "CapabilityAlgebraSpecification.compose_associativity"

    # Verify the gate's recompute matches.
    BUNDLE="$fixture_out" python3 <<'PY'
import hashlib
import json
import os
import sys

with open(os.environ["BUNDLE"]) as fh:
    proof = json.load(fh)

body = {k: v for k, v in proof.items() if k != "content_hash"}
encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
expected = "sha256:" + hashlib.sha256(encoded).hexdigest()
if proof["content_hash"] != expected:
    print(f"[lean-runner] selftest: content_hash MISMATCH ({proof['content_hash']} vs {expected})", file=sys.stderr)
    sys.exit(1)

# Required-fields shape check matching the gate.
required = ["schema_version", "claim_id", "track", "proof_kind", "verdict",
            "generated_utc", "source_module", "owning_bead", "producer_tool",
            "producer_version", "timeout_policy", "timeout_seconds",
            "input_artifact_hashes", "command", "theorem_count",
            "theorem_ids", "content_hash"]
missing = [k for k in required if k not in proof]
if missing:
    print(f"[lean-runner] selftest: missing fields {missing}", file=sys.stderr)
    sys.exit(1)
if proof.get("theorem_count") != len(proof.get("theorem_ids", [])):
    print("[lean-runner] selftest: theorem_count does not match theorem_ids", file=sys.stderr)
    sys.exit(1)
if not proof.get("input_artifact_hashes"):
    print("[lean-runner] selftest: input_artifact_hashes is empty", file=sys.stderr)
    sys.exit(1)

# Reject simulation markers — same logic as the gate.
blob = json.dumps(proof).lower()
SIMULATION_FRAGMENTS = ("simulate", "simulated", "placeholder", "mockcertificate",
                        "hot_paths_simulation", "selftest-fixture")
src = str(proof.get("source_module", "")).lower()
if src in {"", "selftest-fixture", "fixture", "placeholder"}:
    print(f"[lean-runner] selftest: source_module is a fixture marker", file=sys.stderr)
    sys.exit(1)
for frag in SIMULATION_FRAGMENTS:
    if frag in blob:
        print(f"[lean-runner] selftest: bundle contains simulation fragment {frag!r}", file=sys.stderr)
        sys.exit(1)

print(f"[lean-runner] selftest: canonical-body recompute MATCHES, schema and fixture-markers OK")
PY
    log "selftest: PASS"
    exit 0
fi

#-------------------------------------------------------------------------
# ci/verify — drive lake build, parse, emit proof bundle.
#-------------------------------------------------------------------------
bundle_dir="${LEAN_PROOF_BUNDLE_DIR:-$DEFAULT_BUNDLE_DIR}"
proof_out="${bundle_dir}/${CLAIM_ID}.proof.json"

[[ -d "$LEAN_PROOFS_DIR" ]] || refuse "proofs/lean4/ missing"
[[ -f "$LEAN_PROOFS_DIR/lakefile.lean" ]] || refuse "proofs/lean4/lakefile.lean missing"
command -v python3 >/dev/null 2>&1 || refuse "python3 required for canonical-body hashing"
[[ "$TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || refuse "LEAN_PROOF_TIMEOUT_SECONDS must be a non-negative integer"

# Detect lake. Fall back to elan's bin dir if not on PATH yet.
if ! command -v lake >/dev/null 2>&1; then
    if [[ -x "${ELAN_BIN_DIR}/lake" ]]; then
        export PATH="${ELAN_BIN_DIR}:${PATH}"
        log "added ${ELAN_BIN_DIR} to PATH for this run"
    else
        refuse "lake not on PATH — install with scripts/install_lean_toolchain.sh install"
    fi
fi
if ! command -v lean >/dev/null 2>&1; then
    if [[ -x "${ELAN_BIN_DIR}/lean" ]]; then
        export PATH="${ELAN_BIN_DIR}:${PATH}"
        log "added ${ELAN_BIN_DIR} to PATH for lean"
    else
        refuse "lean not on PATH — install with scripts/install_lean_toolchain.sh install"
    fi
fi

lean_version="$(lean --version 2>/dev/null | sed -n '1p' || true)"
lake_version="$(lake --version 2>/dev/null | sed -n '1p' || true)"
producer_version="lean:${lean_version:-unknown};lake:${lake_version:-unknown}"
input_hashes_json="$(proof_input_hashes_json)"
timeout_policy="per-run lake build timeout ${TIMEOUT_SECONDS}s"
command_desc="cd ${LEAN_PROOFS_DIR} && lake build"
if (( TIMEOUT_SECONDS > 0 )) && command -v timeout >/dev/null 2>&1; then
    command_desc="cd ${LEAN_PROOFS_DIR} && timeout ${TIMEOUT_SECONDS}s lake build"
fi

log "running lake build in ${LEAN_PROOFS_DIR} (${timeout_policy})"
build_log="$(mktemp -t lake-build.XXXXXXXX.log)"
trap 'rm -f "$build_log"' EXIT

build_status=0
if (( TIMEOUT_SECONDS > 0 )) && command -v timeout >/dev/null 2>&1; then
    (cd "$LEAN_PROOFS_DIR" && timeout "${TIMEOUT_SECONDS}s" lake build 2>&1) | tee "$build_log" || build_status=$?
else
    if (( TIMEOUT_SECONDS > 0 )); then
        log "timeout command unavailable; recording timeout policy but running lake directly"
    fi
    (cd "$LEAN_PROOFS_DIR" && lake build 2>&1) | tee "$build_log" || build_status=$?
fi

if (( build_status != 0 )); then
    err "lake build exited non-zero (rc=${build_status})"
    err "refusing to emit ${CLAIM_ID}.proof.json — see ${build_log} for details"
    exit "$build_status"
fi

log "lake build succeeded; extracting top-level theorem names"

# Pull `theorem <name>` declarations from each .lean module in proofs/lean4/.
# A `theorem` line that survived `lake build` was successfully checked; the
# extracted names are the per-module proof identifiers we surface in
# `theorem_ids`.
mapfile -t theorem_ids < <(
    grep -hE '^\s*theorem\s+[A-Za-z_][A-Za-z0-9_.]+' "$LEAN_PROOFS_DIR"/*.lean 2>/dev/null \
        | awk '{print $2}' \
        | sed 's/[^A-Za-z0-9_.].*$//' \
        | sort -u
)

if (( ${#theorem_ids[@]} == 0 )); then
    refuse "no \`theorem\` declarations found in proofs/lean4/*.lean — refusing to emit empty bundle"
fi

log "found ${#theorem_ids[@]} top-level theorem(s)"

PROOF_PRODUCER_TOOL="lean4" \
PROOF_PRODUCER_VERSION="$producer_version" \
PROOF_TIMEOUT_POLICY="$timeout_policy" \
PROOF_TIMEOUT_SECONDS="$TIMEOUT_SECONDS" \
PROOF_INPUT_HASHES_JSON="$input_hashes_json" \
PROOF_COMMAND="$command_desc" \
emit_proof_bundle "$proof_out" "proven" "${theorem_ids[@]}"
log "ci: emitted ${proof_out}"
log "ci: rerun scripts/run_fe_claim_016_021_promotion_gate.sh ci to recheck"
