#!/usr/bin/env bash
#
# G.9 — RGC theorem-backed-compiler proof-recheck gate (bd-cixqu.7.12).
#
# Consumes the G.2..G.8 proof artifacts for the theorem-backed-compiler claims
# FE-CLAIM-016..021, rechecks each (presence, schema, verdict, freshness,
# content-hash integrity), and emits a run_manifest.json with the checked-proof
# inventory and a per-claim recheck verdict. Fail-closed: a missing, stale,
# tampered, or unproven artifact fails the gate.
#
# Runs WITHOUT a cargo/engine build (bash + python3 only). A `selftest` mode
# builds a fixture proof bundle and proves both the positive (intact bundle ->
# pass) and the fail-closed negatives (tampered / missing artifact -> fail).
#
# Modes:
#   ci | verify   recheck the real proof bundle (default bundle: artifacts/
#                 rgc_theorem_backed_compiler_inputs, override with arg 2 or
#                 RGC_THEOREM_BACKED_COMPILER_BUNDLE_DIR)
#   selftest      fixture-driven smoke + fail-closed proof (no bundle required)
#   -h | --help   usage
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly PROJECT_DIR
cd "${PROJECT_DIR}"

export TZ=UTC
export LC_ALL=C
export LANG=C

readonly GATE_NAME="rgc_theorem_backed_compiler"
readonly SCHEMA_MANIFEST="franken-engine.rgc-theorem-backed-compiler.run-manifest.v1"
readonly SCHEMA_EVENT="franken-engine.rgc-theorem-backed-compiler.event.v1"
readonly SCHEMA_PROOF="franken-engine.theorem-backed-compiler.proof.v1"
readonly MAX_FRESHNESS_DAYS=30

# The six theorem-backed-compiler claims and the Track-G proof each requires.
# Format: claim_id|tracks|proof_kind|description
readonly CLAIMS=(
  "FE-CLAIM-016|G.2,G.3|formal-spec-isomorphism|IFC lattice + capability algebra formal spec with isomorphism to the Rust implementation"
  "FE-CLAIM-017|G.6|translation-validation|proof-carrying compilation: each lowering preserves source semantics"
  "FE-CLAIM-018|G.6,G.7|policy-semantics|formal policy semantics proofs"
  "FE-CLAIM-019|G.8|optimization-isomorphism|optimization-pass equivalence via proof carriers"
  "FE-CLAIM-020|G.7,G.8|theorem-backed-compiler|theorem-backed compiler end-to-end"
  "FE-CLAIM-021|G.7|policy-theorem-engine|SMT-backed monotonicity / non-interference / attenuation"
)

readonly ARTIFACT_ROOT="${RGC_THEOREM_BACKED_COMPILER_ARTIFACT_ROOT:-${PROJECT_DIR}/artifacts/${GATE_NAME}}"

usage() {
  cat >&2 <<EOF
usage: $0 [ci|verify|selftest] [bundle_dir]

  ci | verify   recheck the proof bundle at bundle_dir (default:
                artifacts/rgc_theorem_backed_compiler_inputs)
  selftest      fixture-driven smoke + fail-closed proof (no bundle required)
  -h | --help   this message

Environment:
  RGC_THEOREM_BACKED_COMPILER_BUNDLE_DIR    default proof-bundle dir
  RGC_THEOREM_BACKED_COMPILER_ARTIFACT_ROOT default artifact output root
EOF
}

# Recheck a proof bundle. Args: <bundle_dir> <out_dir> <mode>.
# Writes run_manifest.json, events.jsonl, proof_inventory.json,
# claim_recheck_verdicts.json, summary.md into out_dir. Returns 0 iff verdict=pass.
recheck_bundle() {
  local bundle_dir="$1"
  local out_dir="$2"
  local mode="$3"
  mkdir -p "${out_dir}"
  RTBC_BUNDLE_DIR="${bundle_dir}" \
  RTBC_OUT_DIR="${out_dir}" \
  RTBC_MODE="${mode}" \
  RTBC_GATE_NAME="${GATE_NAME}" \
  RTBC_SCHEMA_MANIFEST="${SCHEMA_MANIFEST}" \
  RTBC_SCHEMA_EVENT="${SCHEMA_EVENT}" \
  RTBC_SCHEMA_PROOF="${SCHEMA_PROOF}" \
  RTBC_MAX_FRESHNESS_DAYS="${MAX_FRESHNESS_DAYS}" \
  RTBC_CLAIMS="$(printf '%s\n' "${CLAIMS[@]}")" \
  python3 <<'PY'
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

bundle_dir = os.environ["RTBC_BUNDLE_DIR"]
out_dir = os.environ["RTBC_OUT_DIR"]
mode = os.environ["RTBC_MODE"]
gate = os.environ["RTBC_GATE_NAME"]
schema_manifest = os.environ["RTBC_SCHEMA_MANIFEST"]
schema_event = os.environ["RTBC_SCHEMA_EVENT"]
schema_proof = os.environ["RTBC_SCHEMA_PROOF"]
max_fresh = int(os.environ["RTBC_MAX_FRESHNESS_DAYS"])
claims = [
    line.split("|", 3)
    for line in os.environ["RTBC_CLAIMS"].splitlines()
    if line.strip()
]

now = datetime.now(timezone.utc)
ts = now.strftime("%Y%m%dT%H%M%SZ")
trace_id = f"trace-{gate}-{ts}"
decision_id = f"decision-{gate}-{ts}"


def canonical_body_hash(proof: dict) -> str:
    body = {k: v for k, v in proof.items() if k != "content_hash"}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def recheck_claim(claim_id, tracks, proof_kind, description):
    path = os.path.join(bundle_dir, f"{claim_id}.proof.json")
    rel = os.path.relpath(path, os.getcwd())
    if not os.path.isfile(path):
        return {
            "claim_id": claim_id, "tracks": tracks, "proof_kind": proof_kind,
            "description": description, "artifact_path": rel,
            "status": "fail", "reason_code": "proof_missing",
            "reason": f"proof artifact {rel} is absent",
        }
    try:
        with open(path, "r", encoding="utf-8") as fh:
            proof = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "claim_id": claim_id, "tracks": tracks, "proof_kind": proof_kind,
            "description": description, "artifact_path": rel,
            "status": "fail", "reason_code": "proof_unreadable",
            "reason": f"proof artifact is not valid JSON: {exc}",
        }

    def fail(code, reason):
        return {
            "claim_id": claim_id, "tracks": tracks, "proof_kind": proof_kind,
            "description": description, "artifact_path": rel,
            "status": "fail", "reason_code": code, "reason": reason,
        }

    if proof.get("schema_version") != schema_proof:
        return fail("schema_mismatch",
                    f"schema_version {proof.get('schema_version')!r} != {schema_proof!r}")
    if proof.get("claim_id") != claim_id:
        return fail("claim_id_mismatch",
                    f"proof claim_id {proof.get('claim_id')!r} != {claim_id!r}")
    if proof.get("verdict") != "proven":
        return fail("not_proven", f"verdict is {proof.get('verdict')!r}, expected 'proven'")

    expected_hash = canonical_body_hash(proof)
    if proof.get("content_hash") != expected_hash:
        return fail("content_hash_mismatch",
                    "content_hash does not match the canonical proof body (tampered)")

    gen = proof.get("generated_utc")
    try:
        gen_dt = datetime.strptime(gen, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return fail("bad_timestamp", f"generated_utc {gen!r} is not ISO-8601 UTC")
    freshness_days = (now - gen_dt).days
    if freshness_days < 0:
        return fail("future_timestamp", f"generated_utc {gen!r} is in the future")
    if freshness_days > max_fresh:
        return fail("stale",
                    f"proof is {freshness_days}d old (> {max_fresh}d freshness budget)")

    return {
        "claim_id": claim_id, "tracks": tracks, "proof_kind": proof_kind,
        "description": description, "artifact_path": rel,
        "status": "pass", "reason_code": None,
        "reason": "present, proven, fresh, content-hash intact",
        "freshness_days": freshness_days, "source_module": proof.get("source_module"),
    }


verdicts = [recheck_claim(*c) for c in claims]
pass_count = sum(1 for v in verdicts if v["status"] == "pass")
fail_count = len(verdicts) - pass_count
verdict = "pass" if fail_count == 0 else "fail"
verdict_reason = (
    f"all {pass_count} theorem-backed-compiler proofs rechecked clean"
    if verdict == "pass"
    else f"{fail_count}/{len(verdicts)} claim proofs failed recheck"
)

# events.jsonl — one event per claim + a terminal gate_completed event.
events = []
for v in verdicts:
    events.append({
        "schema_version": schema_event, "trace_id": trace_id,
        "decision_id": decision_id, "policy_id": f"policy-{v['claim_id'].lower()}",
        "component": gate, "event": "claim_proof_rechecked",
        "claim_id": v["claim_id"], "outcome": v["status"],
        "reason_code": v["reason_code"], "detail": v["reason"],
    })
events.append({
    "schema_version": schema_event, "trace_id": trace_id,
    "decision_id": decision_id, "policy_id": "policy-fe-claim-016-021",
    "component": gate, "event": "gate_completed", "outcome": verdict,
    "reason_code": None, "detail": verdict_reason,
})

inventory = {
    "schema_version": "franken-engine.theorem-backed-compiler.proof-inventory.v1",
    "bundle_dir": os.path.relpath(bundle_dir, os.getcwd()),
    "claim_count": len(verdicts),
    "pass_count": pass_count, "fail_count": fail_count,
    "claims": [
        {"claim_id": v["claim_id"], "tracks": v["tracks"],
         "proof_kind": v["proof_kind"], "artifact_path": v["artifact_path"],
         "status": v["status"]}
        for v in verdicts
    ],
}

manifest = {
    "schema_version": schema_manifest, "bead_id": "bd-cixqu.7.12",
    "component": gate, "mode": mode, "trace_id": trace_id,
    "decision_id": decision_id, "policy_id": "policy-fe-claim-016-021",
    "generated_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "freshness": {"generated_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "max_freshness_days": max_fresh},
    "verdict": verdict, "verdict_reason": verdict_reason,
    "claim_recheck_verdicts": verdicts,
    "replay_command": "./scripts/e2e/rgc_theorem_backed_compiler_replay.sh ci",
    "artifacts": {
        "events_jsonl": "events.jsonl",
        "commands_txt": "commands.txt",
        "summary_md": "summary.md",
        "proof_inventory_json": "proof_inventory.json",
        "claim_recheck_verdicts_json": "claim_recheck_verdicts.json",
    },
}


def write(name, obj):
    with open(os.path.join(out_dir, name), "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


write("run_manifest.json", manifest)
write("proof_inventory.json", inventory)
write("claim_recheck_verdicts.json", {"verdicts": verdicts})
with open(os.path.join(out_dir, "events.jsonl"), "w", encoding="utf-8") as fh:
    for ev in events:
        fh.write(json.dumps(ev, sort_keys=True) + "\n")

lines = [f"# Theorem-Backed Compiler Proof Recheck ({verdict.upper()})", ""]
lines.append(f"- bundle: `{inventory['bundle_dir']}`")
lines.append(f"- verdict: **{verdict}** — {verdict_reason}")
lines.append(f"- proofs: {pass_count} pass / {fail_count} fail / {len(verdicts)} total")
lines.append("")
lines.append("| claim | tracks | proof_kind | status | reason |")
lines.append("|---|---|---|---|---|")
for v in verdicts:
    lines.append(f"| {v['claim_id']} | {v['tracks']} | {v['proof_kind']} | {v['status']} | {v['reason']} |")
with open(os.path.join(out_dir, "summary.md"), "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")

print(f"[{gate}] verdict={verdict} ({pass_count}/{len(verdicts)} proofs ok) -> {out_dir}")
sys.exit(0 if verdict == "pass" else 1)
PY
}

# Write a single valid fixture proof for a claim into <dir>.
write_fixture_proof() {
  local dir="$1" claim_id="$2" tracks="$3" proof_kind="$4"
  mkdir -p "${dir}"
  RTBC_FX_DIR="${dir}" RTBC_FX_CLAIM="${claim_id}" RTBC_FX_TRACKS="${tracks}" \
  RTBC_FX_KIND="${proof_kind}" RTBC_FX_SCHEMA="${SCHEMA_PROOF}" \
  python3 <<'PY'
import hashlib, json, os
from datetime import datetime, timezone

d = os.environ["RTBC_FX_DIR"]
proof = {
    "schema_version": os.environ["RTBC_FX_SCHEMA"],
    "claim_id": os.environ["RTBC_FX_CLAIM"],
    "track": os.environ["RTBC_FX_TRACKS"],
    "proof_kind": os.environ["RTBC_FX_KIND"],
    "verdict": "proven",
    "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_module": "selftest-fixture",
}
body = {k: v for k, v in proof.items()}
encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
proof["content_hash"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
with open(os.path.join(d, proof["claim_id"] + ".proof.json"), "w", encoding="utf-8") as fh:
    json.dump(proof, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

build_fixture_bundle() {
  local dir="$1"
  mkdir -p "${dir}"
  local entry claim_id tracks proof_kind
  for entry in "${CLAIMS[@]}"; do
    IFS='|' read -r claim_id tracks proof_kind _ <<<"${entry}"
    write_fixture_proof "${dir}" "${claim_id}" "${tracks}" "${proof_kind}"
  done
}

run_selftest() {
  local ts run_dir
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  run_dir="${ARTIFACT_ROOT}/${ts}-selftest"
  local fx_root="${run_dir}/fixtures"
  mkdir -p "${run_dir}"

  echo "[${GATE_NAME}] selftest: building fixture proof bundle"
  local intact="${fx_root}/intact"
  build_fixture_bundle "${intact}"

  # 1. Positive: intact bundle must PASS. Its artifacts are the run's artifacts.
  local positive_rc=0
  recheck_bundle "${intact}" "${run_dir}" "selftest" || positive_rc=$?
  if [[ "${positive_rc}" -ne 0 ]]; then
    echo "[${GATE_NAME}] SELFTEST FAIL: intact fixture bundle did not pass" >&2
    return 1
  fi

  # 2. Negative — tampered proof body must FAIL (content-hash mismatch).
  local tampered="${fx_root}/tampered"
  build_fixture_bundle "${tampered}"
  # Flip the verdict of one proof without recomputing its content_hash.
  RTBC_T_FILE="${tampered}/FE-CLAIM-019.proof.json" python3 <<'PY'
import json, os
p = os.environ["RTBC_T_FILE"]
with open(p) as fh:
    proof = json.load(fh)
proof["source_module"] = "tampered-after-signing"   # body changed, hash stale
with open(p, "w") as fh:
    json.dump(proof, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  local tampered_rc=0
  recheck_bundle "${tampered}" "${run_dir}/tampered" "selftest" || tampered_rc=$?
  if [[ "${tampered_rc}" -eq 0 ]]; then
    echo "[${GATE_NAME}] SELFTEST FAIL: tampered bundle was accepted (not fail-closed)" >&2
    return 1
  fi

  # 3. Negative — missing proof must FAIL.
  local missing="${fx_root}/missing"
  build_fixture_bundle "${missing}"
  RTBC_RM="${missing}/FE-CLAIM-021.proof.json" python3 -c 'import os; os.remove(os.environ["RTBC_RM"])'
  local missing_rc=0
  recheck_bundle "${missing}" "${run_dir}/missing" "selftest" || missing_rc=$?
  if [[ "${missing_rc}" -eq 0 ]]; then
    echo "[${GATE_NAME}] SELFTEST FAIL: bundle with a missing proof was accepted" >&2
    return 1
  fi

  echo "[${GATE_NAME}] SELFTEST PASS: intact->pass, tampered->fail, missing->fail"
  echo "[${GATE_NAME}] artifacts: ${run_dir}"
  return 0
}

main() {
  local mode="${1:-ci}"
  case "${mode}" in
    -h|--help)
      usage
      exit 0
      ;;
    selftest)
      run_selftest
      exit $?
      ;;
    ci|verify)
      local bundle_dir ts run_dir
      bundle_dir="${2:-${RGC_THEOREM_BACKED_COMPILER_BUNDLE_DIR:-${PROJECT_DIR}/artifacts/rgc_theorem_backed_compiler_inputs}}"
      ts="$(date -u +%Y%m%dT%H%M%SZ)"
      run_dir="${ARTIFACT_ROOT}/${ts}"
      mkdir -p "${run_dir}"
      {
        echo "# command transcript for ${GATE_NAME} (${mode})"
        echo "./scripts/run_rgc_theorem_backed_compiler.sh ${mode} ${bundle_dir}"
        echo "./scripts/e2e/rgc_theorem_backed_compiler_replay.sh ${mode}"
      } >"${run_dir}/commands.txt"
      if [[ ! -d "${bundle_dir}" ]]; then
        echo "[${GATE_NAME}] proof bundle directory not found: ${bundle_dir}" >&2
        echo "[${GATE_NAME}] G.2..G.8 must emit proof artifacts there first; run 'selftest' to exercise the gate mechanism." >&2
      fi
      local rc=0
      recheck_bundle "${bundle_dir}" "${run_dir}" "${mode}" || rc=$?
      exit "${rc}"
      ;;
    *)
      echo "unknown mode: ${mode}" >&2
      usage
      exit 2
      ;;
  esac
}

main "$@"
