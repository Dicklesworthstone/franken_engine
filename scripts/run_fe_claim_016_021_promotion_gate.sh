#!/usr/bin/env bash
set -euo pipefail

# G.10 — FE-CLAIM-016..021 matrix-promotion umbrella gate (bd-cixqu.7.13)
#
# Track G promotes SIX claims simultaneously from `hypothesis` to `observed`:
#
#   FE-CLAIM-016  IFC lattice + capability-algebra isomorphism (G.2/G.3)
#   FE-CLAIM-017  proof-carrying compilation / translation validation (G.6)
#   FE-CLAIM-018  formal policy-semantics proofs (G.6/G.7)
#   FE-CLAIM-019  optimization-pass equivalence proof carriers (G.8)
#   FE-CLAIM-020  theorem-backed compiler end-to-end (G.7/G.8)
#   FE-CLAIM-021  SMT-backed monotonicity/non-interference/attenuation (G.7)
#
# This gate is the single fail-closed checkpoint that DECIDES — and ENFORCES —
# that promotion. It is the umbrella's anti-fudging guard, sitting on top of the
# G.9 proof-recheck gate (run_rgc_theorem_backed_compiler.sh):
#
#   * For each claim it rechecks the live theorem-proof artifact at
#     <bundle>/<FE-CLAIM-NNN>.proof.json (the same artifact G.9 consumes):
#     presence, schema, claim-id, verdict == "proven", content-hash integrity,
#     and freshness (<= 30 days). A claim is "proven" iff that recheck passes.
#   * It ADDITIONALLY rejects fixture / simulated proofs: a proof whose
#     source_module is a fixture marker, or whose body still carries a
#     simulation fragment (`simulate`/`simulated`/`placeholder`/`MockCertificate`
#     /`hot_paths_simulation`), is NOT a real machine-checked theorem and is
#     treated as not-proven. This is the reality-check teeth: the current
#     Track-G Rust verifiers SIMULATE SMT/model-checking (they pattern-match
#     formula strings / return Verified unconditionally), so a proof minted from
#     them is a fixture, not evidence.
#   * It cross-checks the claim-to-proof matrix entry for each claim and fails
#     closed if the matrix OVER-CLAIMS (allowed_state == observed) without a
#     real, proven, non-fixture theorem proof. Under-claiming (a real proof
#     exists but the matrix still reads hypothesis) is surfaced as an advisory,
#     not a failure — honesty is the conservative direction.
#
# Umbrella rule (bd-cixqu.7.13): the six rows promote SIMULTANEOUSLY. The
# aggregate decision is PROMOTE_ALL_TO_OBSERVED iff ALL six carry a real proven
# theorem proof; otherwise STAY_HYPOTHESIS.
#
# Honest outcome documented in docs/operator-gates/FE_CLAIM_016_021_PROMOTION_DECISION.md:
# four of six claims (018/019/020/021) are backed only by simulated verification,
# 016's Lean proofs are not wired to the gate, and 017 emits no proof artifact —
# so the matrix correctly stays `hypothesis` and this gate exits 0 because the
# matrix state is consistent with the (absent) live proof evidence.
#
# Pure bash + jq + python3 so it is verifiable even while the Rust crate is
# mid-refactor and cannot link.
#
# Modes:
#   ci        Evaluate the live tree and emit a decision artifact (default).
#   verify    Validate an existing decision artifact's schema/bead identity.
#   selftest  Drive synthetic honest/over-claim/fixture/tamper/under-claim
#             fixtures through `ci` and assert the decision + fail-closed
#             behaviour in each case (no cargo, no engine build).

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"

bead_id="bd-cixqu.7.13"
component="fe_claim_016_021_promotion_gate"
schema_version="franken-engine.fe-claim-016-021-promotion-gate.v1"
proof_schema="franken-engine.theorem-backed-compiler.proof.v1"
max_freshness_days=30

claim_ids=("FE-CLAIM-016" "FE-CLAIM-017" "FE-CLAIM-018" "FE-CLAIM-019" "FE-CLAIM-020" "FE-CLAIM-021")

matrix_path="${CLAIM_TO_PROOF_MATRIX_PATH:-docs/claim_to_proof_matrix_v1.json}"
proof_bundle_dir="${FE_CLAIM_016_021_PROOF_BUNDLE_DIR:-${RGC_THEOREM_BACKED_COMPILER_BUNDLE_DIR:-artifacts/rgc_theorem_backed_compiler_inputs}}"
artifact_root="${FE_CLAIM_016_021_PROMOTION_ARTIFACT_ROOT:-artifacts/fe_claim_016_021_promotion}"

# Stable error codes routed on by downstream structured-event consumers.
ERR_OVERCLAIM="FeClaim016_021PromotionError::ObservedWithoutProvenTheorem"
ERR_FIXTURE="FeClaim016_021PromotionError::ObservedWithFixtureProof"
ERR_MATRIX_SHAPE="FeClaim016_021PromotionError::MatrixEntryMissing"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for the FE-CLAIM-016..021 promotion gate" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for the FE-CLAIM-016..021 promotion gate" >&2
  exit 2
fi

# ── verify mode ───────────────────────────────────────────────────────────
if [[ "$mode" == "verify" ]]; then
  verify_path="${2:-}"
  if [[ -z "$verify_path" || ! -f "$verify_path" ]]; then
    echo "Error: verify mode needs an existing decision artifact path" >&2
    exit 1
  fi
  if ! jq empty <"$verify_path" 2>/dev/null; then
    echo "Error: invalid JSON in artifact: $verify_path" >&2
    exit 1
  fi
  got_schema="$(jq -r '.schema_version // empty' <"$verify_path")"
  got_bead="$(jq -r '.bead_id // empty' <"$verify_path")"
  if [[ "$got_schema" != "$schema_version" ]]; then
    echo "Error: schema mismatch. expected $schema_version got $got_schema" >&2
    exit 1
  fi
  if [[ "$got_bead" != "$bead_id" ]]; then
    echo "Error: bead identity mismatch. expected $bead_id got $got_bead" >&2
    exit 1
  fi
  echo "✓ FE-CLAIM-016..021 promotion decision artifact verified: $verify_path"
  exit 0
fi

# ── shared: build a synthetic proof with a valid content_hash (selftest) ────
# args: <dir> <claim_id> <verdict> <source_module> <tamper:0|1>
write_proof_fixture() {
  FX_DIR="$1" FX_CLAIM="$2" FX_VERDICT="$3" FX_SRC="$4" FX_TAMPER="$5" \
  FX_SCHEMA="$proof_schema" python3 <<'PY'
import hashlib, json, os
d = os.environ["FX_DIR"]
os.makedirs(d, exist_ok=True)
from datetime import datetime, timezone
proof = {
    "schema_version": os.environ["FX_SCHEMA"],
    "claim_id": os.environ["FX_CLAIM"],
    "track": "selftest",
    "proof_kind": "selftest",
    "verdict": os.environ["FX_VERDICT"],
    "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_module": os.environ["FX_SRC"],
}
body = {k: v for k, v in proof.items()}
encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
proof["content_hash"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
if os.environ["FX_TAMPER"] == "1":
    # change the body AFTER hashing -> content_hash no longer matches.
    proof["source_module"] = proof["source_module"] + "-tampered-after-hash"
with open(os.path.join(d, proof["claim_id"] + ".proof.json"), "w", encoding="utf-8") as fh:
    json.dump(proof, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

# ── selftest mode ───────────────────────────────────────────────────────────
if [[ "$mode" == "selftest" ]]; then
  work="$(mktemp -d "${TMPDIR:-/tmp}/fe-claim-016-021-selftest.XXXXXX")"
  trap 'rm -rf "$work"' EXIT
  failures=0

  matrix_with_state() {
    # $1 = state (hypothesis|observed). Emits a matrix with all six claims.
    jq -n --arg state "$1" '{
      schema_version: "franken-engine.claim-to-proof-matrix.v1",
      claims: [ "FE-CLAIM-016","FE-CLAIM-017","FE-CLAIM-018","FE-CLAIM-019","FE-CLAIM-020","FE-CLAIM-021" ]
        | map({ claim_id: ., claim_scope: "compiler",
                actual_wording_state: $state, allowed_state: $state })
    }'
  }
  # build a bundle of six proofs. $1 dir  $2 verdict  $3 source_module  $4 tamper
  build_bundle() {
    local dir="$1" verdict="$2" src="$3" tamper="$4" c
    for c in "${claim_ids[@]}"; do
      write_proof_fixture "$dir" "$c" "$verdict" "$src" "$tamper"
    done
  }

  run_case() {
    # $1 label  $2 matrix_state  $3 bundle_mode(none|real|fixture|tamper|notproven)
    # $4 expect_decision  $5 expect_exit
    local label="$1" mstate="$2" bmode="$3" exp_dec="$4" exp_exit="$5"
    local cdir; cdir="$(mktemp -d "${work}/case.XXXXXX")"
    matrix_with_state "$mstate" >"${cdir}/matrix.json"
    local bdir="${cdir}/bundle"
    mkdir -p "$bdir"
    case "$bmode" in
      none) : ;;  # no proofs emitted
      real) build_bundle "$bdir" "proven" "track-g-live-verifier" "0" ;;
      fixture) build_bundle "$bdir" "proven" "selftest-fixture" "0" ;;
      tamper) build_bundle "$bdir" "proven" "track-g-live-verifier" "1" ;;
      notproven) build_bundle "$bdir" "unknown" "track-g-live-verifier" "0" ;;
    esac
    local out exit_code
    set +e
    out="$(CLAIM_TO_PROOF_MATRIX_PATH="${cdir}/matrix.json" \
           FE_CLAIM_016_021_PROOF_BUNDLE_DIR="$bdir" \
           FE_CLAIM_016_021_PROMOTION_ARTIFACT_ROOT="${cdir}/out" \
           "$0" ci 2>&1)"
    exit_code=$?
    set -e
    local report; report="$(printf '%s\n' "$out" | grep -oE 'fe_claim_016_021_promotion_gate_report=.*' | tail -1 | cut -d= -f2-)"
    local got_dec=""
    [[ -n "$report" && -f "$report" ]] && got_dec="$(jq -r '.decision' "$report")"
    if [[ "$exit_code" != "$exp_exit" ]]; then
      echo "FAIL selftest [$label]: expected exit $exp_exit got $exit_code" >&2
      printf '%s\n' "$out" | sed 's/^/    /' >&2
      failures=$((failures + 1))
    elif [[ "$got_dec" != "$exp_dec" ]]; then
      echo "FAIL selftest [$label]: expected decision $exp_dec got '$got_dec'" >&2
      failures=$((failures + 1))
    else
      echo "PASS selftest [$label]: decision=$got_dec exit=$exit_code"
    fi
  }

  # A: six real proven proofs + matrix observed -> PROMOTE_ALL, consistent, 0.
  run_case "real-and-observed"        observed   real      PROMOTE_ALL_TO_OBSERVED 0
  # B: no proofs + matrix honestly hypothesis -> STAY_HYPOTHESIS, consistent, 0.
  run_case "none-and-hypothesis"      hypothesis none      STAY_HYPOTHESIS         0
  # C: FUDGE — matrix observed but no proofs -> over-claim, fail closed, 1.
  run_case "none-but-observed-fudge"  observed   none      STAY_HYPOTHESIS         1
  # D: FIXTURE FUDGE — matrix observed + selftest-fixture proofs -> fail closed.
  run_case "fixture-but-observed"     observed   fixture   STAY_HYPOTHESIS         1
  # E: TAMPER — matrix observed + content-hash-broken proofs -> fail closed.
  run_case "tampered-but-observed"    observed   tamper    STAY_HYPOTHESIS         1
  # F: not-proven verdict + matrix observed -> fail closed.
  run_case "notproven-but-observed"   observed   notproven STAY_HYPOTHESIS         1
  # G: UNDER-CLAIM — six real proofs but matrix still hypothesis -> advisory, 0.
  run_case "real-but-hypothesis"      hypothesis real      PROMOTE_ALL_TO_OBSERVED 0

  # Confirm the over-claim case routes the fixture error code distinctly.
  fxdir="$(mktemp -d "${work}/fxcase.XXXXXX")"
  matrix_with_state observed >"${fxdir}/matrix.json"
  mkdir -p "${fxdir}/bundle"
  build_bundle "${fxdir}/bundle" "proven" "selftest-fixture" "0"
  set +e
  fxout="$(CLAIM_TO_PROOF_MATRIX_PATH="${fxdir}/matrix.json" \
           FE_CLAIM_016_021_PROOF_BUNDLE_DIR="${fxdir}/bundle" \
           FE_CLAIM_016_021_PROMOTION_ARTIFACT_ROOT="${fxdir}/out" \
           "$0" ci 2>&1)"
  set -e
  if printf '%s\n' "$fxout" | grep -Fq "$ERR_FIXTURE"; then
    echo "PASS selftest [fixture-error-code]: ${ERR_FIXTURE} surfaced"
  else
    echo "FAIL selftest [fixture-error-code]: ${ERR_FIXTURE} not surfaced" >&2
    failures=$((failures + 1))
  fi

  if [[ "$failures" -ne 0 ]]; then
    echo "FE-CLAIM-016..021 promotion gate selftest: ${failures} failure(s)" >&2
    exit 1
  fi
  echo "FE-CLAIM-016..021 promotion gate selftest: all cases passed"
  exit 0
fi

if [[ "$mode" != "ci" ]]; then
  echo "Usage: $0 [ci|verify <artifact>|selftest]" >&2
  exit 64
fi

# ── ci mode: evaluate the live tree ─────────────────────────────────────────
if [[ ! -f "$matrix_path" ]]; then
  echo "missing claim matrix: $matrix_path" >&2
  exit 1
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${artifact_root}/${timestamp}"
mkdir -p "$run_dir"
report_path="${run_dir}/promotion_decision.json"
commands_path="${run_dir}/commands.txt"
printf './scripts/run_fe_claim_016_021_promotion_gate.sh %s\n' "$mode" >"$commands_path"

# The whole evaluation runs in one python pass: read the matrix + recheck each
# proof + compute per-claim decisions, the aggregate umbrella decision, and the
# fail-closed consistency status; write the decision artifact; print a summary.
FECP_MATRIX_PATH="$matrix_path" \
FECP_BUNDLE_DIR="$proof_bundle_dir" \
FECP_REPORT_PATH="$report_path" \
FECP_SCHEMA="$schema_version" \
FECP_BEAD="$bead_id" \
FECP_COMPONENT="$component" \
FECP_PROOF_SCHEMA="$proof_schema" \
FECP_MAX_FRESH="$max_freshness_days" \
FECP_GENERATED_UTC="$timestamp" \
FECP_CLAIMS="$(printf '%s\n' "${claim_ids[@]}")" \
FECP_ERR_OVERCLAIM="$ERR_OVERCLAIM" \
FECP_ERR_FIXTURE="$ERR_FIXTURE" \
FECP_ERR_MATRIX_SHAPE="$ERR_MATRIX_SHAPE" \
python3 <<'PY'
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

matrix_path = os.environ["FECP_MATRIX_PATH"]
bundle_dir = os.environ["FECP_BUNDLE_DIR"]
report_path = os.environ["FECP_REPORT_PATH"]
schema = os.environ["FECP_SCHEMA"]
bead = os.environ["FECP_BEAD"]
component = os.environ["FECP_COMPONENT"]
proof_schema = os.environ["FECP_PROOF_SCHEMA"]
max_fresh = int(os.environ["FECP_MAX_FRESH"])
generated_utc = os.environ["FECP_GENERATED_UTC"]
claim_ids = [c for c in os.environ["FECP_CLAIMS"].splitlines() if c.strip()]
ERR_OVERCLAIM = os.environ["FECP_ERR_OVERCLAIM"]
ERR_FIXTURE = os.environ["FECP_ERR_FIXTURE"]
ERR_MATRIX_SHAPE = os.environ["FECP_ERR_MATRIX_SHAPE"]

# Markers that disqualify a proof as a real machine-checked theorem.
FIXTURE_SOURCE_MARKERS = {"", "selftest-fixture", "fixture", "placeholder"}
SIMULATION_FRAGMENTS = (
    "simulate", "simulated", "placeholder", "mockcertificate",
    "hot_paths_simulation", "selftest-fixture",
)

now = datetime.now(timezone.utc)


def canonical_body_hash(proof: dict) -> str:
    body = {k: v for k, v in proof.items() if k != "content_hash"}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def recheck_proof(claim_id):
    """Return (proven: bool, status: str, detail: str, fixture: bool)."""
    path = os.path.join(bundle_dir, f"{claim_id}.proof.json")
    rel = os.path.relpath(path, os.getcwd()) if os.path.isabs(path) else path
    if not os.path.isfile(path):
        return (False, "absent", f"proof artifact {rel} is absent", False)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
            proof = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        return (False, "unreadable", f"proof not valid JSON: {exc}", False)

    if proof.get("schema_version") != proof_schema:
        return (False, "schema_mismatch",
                f"schema_version {proof.get('schema_version')!r} != {proof_schema!r}", False)
    if proof.get("claim_id") != claim_id:
        return (False, "claim_id_mismatch",
                f"proof claim_id {proof.get('claim_id')!r} != {claim_id!r}", False)
    if proof.get("verdict") != "proven":
        return (False, "not_proven",
                f"verdict is {proof.get('verdict')!r}, expected 'proven'", False)
    if proof.get("content_hash") != canonical_body_hash(proof):
        return (False, "content_hash_mismatch",
                "content_hash does not match canonical body (tampered)", False)
    gen = proof.get("generated_utc")
    try:
        gen_dt = datetime.strptime(gen, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return (False, "bad_timestamp", f"generated_utc {gen!r} not ISO-8601 UTC", False)
    fresh_days = (now - gen_dt).days
    if fresh_days < 0:
        return (False, "future_timestamp", f"generated_utc {gen!r} is in the future", False)
    if fresh_days > max_fresh:
        return (False, "stale", f"proof is {fresh_days}d old (> {max_fresh}d budget)", False)

    # Reality-check teeth: reject fixture / simulated proofs.
    src = str(proof.get("source_module", "")).strip().lower()
    blob = raw.lower()
    if src in FIXTURE_SOURCE_MARKERS or any(f in blob for f in SIMULATION_FRAGMENTS):
        return (False, "fixture",
                f"proof is fixture/simulated (source_module={proof.get('source_module')!r}); "
                "not a real machine-checked theorem", True)

    return (True, "proven", "present, proven, fresh, content-hash intact, non-fixture", False)


# Read matrix entries.
try:
    with open(matrix_path, "r", encoding="utf-8") as fh:
        matrix = json.load(fh)
except (OSError, json.JSONDecodeError) as exc:
    print(f"{ERR_MATRIX_SHAPE}: cannot read matrix {matrix_path}: {exc}", file=sys.stderr)
    sys.exit(1)
by_id = {c.get("claim_id"): c for c in matrix.get("claims", [])}

claims_out = []
any_overclaim = False
overclaim_codes = set()
all_proven = True
any_underclaim = False

for cid in claim_ids:
    entry = by_id.get(cid)
    if entry is None:
        print(f"{ERR_MATRIX_SHAPE}: no {cid} entry in {matrix_path}", file=sys.stderr)
        sys.exit(1)
    allowed_state = entry.get("allowed_state", "")
    wording_state = entry.get("actual_wording_state", "")
    matrix_observed = (allowed_state == "observed")

    proven, pstatus, detail, is_fixture = recheck_proof(cid)
    all_proven = all_proven and proven

    claim_decision = "PROMOTE_TO_OBSERVED" if proven else "STAY_HYPOTHESIS"
    consistency = "consistent"
    error_code = None
    if matrix_observed and not proven:
        any_overclaim = True
        consistency = "over_claim"
        error_code = ERR_FIXTURE if is_fixture else ERR_OVERCLAIM
        overclaim_codes.add(error_code)
    elif proven and not matrix_observed:
        any_underclaim = True
        consistency = "under_claim_advisory"

    claims_out.append({
        "claim_id": cid,
        "matrix_allowed_state": allowed_state,
        "matrix_actual_wording_state": wording_state,
        "proof_status": pstatus,
        "proof_proven": proven,
        "proof_is_fixture": is_fixture,
        "claim_decision": claim_decision,
        "consistency": consistency,
        "error_code": error_code,
        "detail": detail,
    })

decision = "PROMOTE_ALL_TO_OBSERVED" if all_proven else "STAY_HYPOTHESIS"
proven_count = sum(1 for c in claims_out if c["proof_proven"])
if decision == "PROMOTE_ALL_TO_OBSERVED":
    decision_reason = (
        f"all {len(claim_ids)} theorem-backed-compiler proofs recheck clean "
        "(present, proven, fresh, content-hash intact, non-fixture); "
        "simultaneous promotion to observed is warranted."
    )
else:
    decision_reason = (
        f"only {proven_count}/{len(claim_ids)} claims carry a real proven theorem proof; "
        "the umbrella requires all six simultaneously, so the matrix honestly stays hypothesis."
    )

status = "fail" if any_overclaim else "pass"
exit_code = 1 if any_overclaim else 0
consistency_error = sorted(overclaim_codes)[0] if overclaim_codes else (
    "advisory: real proofs present; promote claims to observed" if any_underclaim else None
)

artifact = {
    "schema_version": schema,
    "bead_id": bead,
    "component": component,
    "generated_utc": generated_utc,
    "matrix_path": matrix_path,
    "proof_bundle_dir": bundle_dir,
    "proof_bundle_present": os.path.isdir(bundle_dir),
    "max_freshness_days": max_fresh,
    "claim_count": len(claim_ids),
    "proven_count": proven_count,
    "decision": decision,
    "decision_reason": decision_reason,
    "status": status,
    "consistent": (not any_overclaim),
    "consistency_error": consistency_error,
    "claims": claims_out,
}

with open(report_path, "w", encoding="utf-8") as fh:
    json.dump(artifact, fh, indent=2, sort_keys=True)
    fh.write("\n")

print(f"fe_claim_016_021_promotion_gate_report={report_path}")
print(f"FE-CLAIM-016..021 promotion decision: {decision} "
      f"({proven_count}/{len(claim_ids)} proven, status: {status})")
print(f"  {decision_reason}")
for c in claims_out:
    line = (f"  {c['claim_id']}: matrix={c['matrix_allowed_state']} "
            f"proof={c['proof_status']} -> {c['consistency']}")
    if c["error_code"]:
        line += f" [{c['error_code']}]"
    print(line)

if exit_code != 0:
    print(f"{consistency_error}: matrix over-claims one or more of FE-CLAIM-016..021 "
          "relative to the live theorem-proof evidence", file=sys.stderr)
elif consistency_error:
    print(consistency_error, file=sys.stderr)

sys.exit(exit_code)
PY
