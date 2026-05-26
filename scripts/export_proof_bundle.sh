#!/usr/bin/env bash
#
# Y.1 — Export a third-party-verifiable proof bundle alongside the release
# artifact (bd-cixqu.25.1, Track Y).
#
# The bundle is the trust artifact: a self-contained tar that an external party
# can re-check WITHOUT the FrankenEngine source tree (see Y.2). It contains
#
#   * proof_source/                  the theorem-backed-compiler proof artifacts
#                                    (<FE-CLAIM-NNN>.proof.json, schema
#                                    franken-engine.theorem-backed-compiler.proof.v1)
#                                    plus any Lean 4 / Coq proof sources present;
#   * proof_assistant_versions.json  the proof-assistant + recheck-tool version
#                                    pins a verifier must reproduce;
#   * recheck_expected.sha256        the expected sha256 of the deterministic
#                                    recheck output (the trust anchor);
#   * bundle_manifest.json           schema franken-engine.proof-bundle.v1 —
#                                    per-proof content hashes, the recheck digest,
#                                    the claim inventory, and the recheck command.
#
# The recheck digest is a pure function of the proof-source content (each proof's
# content_hash + stated verdict), so it is reproducible across machines and
# independent of wall-clock freshness — a verifier with the same proof source
# recomputes the identical sha256.
#
# Modes:
#   export <proof_source_dir> [out_dir]   build the bundle
#   selftest                              fixture-driven smoke + tamper proof
#   -h | --help                           usage
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

readonly TOOL_NAME="export_proof_bundle"
readonly BUNDLE_SCHEMA="franken-engine.proof-bundle.v1"
readonly PROOF_SCHEMA="franken-engine.theorem-backed-compiler.proof.v1"
readonly RECHECK_TOOL="scripts/run_rgc_theorem_backed_compiler.sh"
# Proof-assistant version pins a third-party verifier must reproduce.
readonly LEAN4_VERSION_PIN="leanprover/lean4:v4.9.0"
readonly COQ_VERSION_PIN="coq-8.19.2"
readonly ARTIFACT_ROOT="${EXPORT_PROOF_BUNDLE_ARTIFACT_ROOT:-${PROJECT_DIR}/artifacts/${TOOL_NAME}}"

usage() {
  cat >&2 <<EOF
usage: $0 export <proof_source_dir> [out_dir]
       $0 selftest
       $0 -h | --help

  export    package a proof bundle tar from the proof-source directory
  selftest  fixture-driven smoke + tamper-detection proof (no engine build)
EOF
}

# Build the bundle. Args: <proof_source_dir> <out_dir>. Returns 0 on success.
build_bundle() {
  local proof_source="$1"
  local out_dir="$2"
  mkdir -p "${out_dir}"
  EPB_PROOF_SOURCE="${proof_source}" \
  EPB_OUT_DIR="${out_dir}" \
  EPB_BUNDLE_SCHEMA="${BUNDLE_SCHEMA}" \
  EPB_PROOF_SCHEMA="${PROOF_SCHEMA}" \
  EPB_RECHECK_TOOL="${RECHECK_TOOL}" \
  EPB_LEAN4="${LEAN4_VERSION_PIN}" \
  EPB_COQ="${COQ_VERSION_PIN}" \
  python3 <<'PY'
import glob
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone

proof_source = os.environ["EPB_PROOF_SOURCE"]
out_dir = os.environ["EPB_OUT_DIR"]
bundle_schema = os.environ["EPB_BUNDLE_SCHEMA"]
proof_schema = os.environ["EPB_PROOF_SCHEMA"]
recheck_tool = os.environ["EPB_RECHECK_TOOL"]

if not os.path.isdir(proof_source):
    print(f"[export_proof_bundle] proof source dir not found: {proof_source}", file=sys.stderr)
    sys.exit(1)

proof_files = sorted(glob.glob(os.path.join(proof_source, "*.proof.json")))
if not proof_files:
    print(f"[export_proof_bundle] no *.proof.json under {proof_source}", file=sys.stderr)
    sys.exit(1)


def canonical_body_hash(proof: dict) -> str:
    body = {k: v for k, v in proof.items() if k != "content_hash"}
    enc = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(enc).hexdigest()


proofs = []
for path in proof_files:
    with open(path, "r", encoding="utf-8") as fh:
        proof = json.load(fh)
    claim_id = proof.get("claim_id", os.path.basename(path))
    stated = proof.get("verdict")
    declared_hash = proof.get("content_hash")
    recomputed = canonical_body_hash(proof)
    integrity = "intact" if declared_hash == recomputed else "tampered"
    schema_ok = proof.get("schema_version") == proof_schema
    proofs.append({
        "claim_id": claim_id,
        "file": os.path.basename(path),
        "content_hash": declared_hash,
        "recomputed_hash": recomputed,
        "stated_verdict": stated,
        "schema_ok": schema_ok,
        "integrity": integrity,
    })

# Deterministic recheck digest: a pure function of the proof source content
# (claim_id + recomputed content hash + stated verdict), sorted by claim_id.
# Independent of wall-clock / freshness so a third party reproduces it exactly.
recheck_rows = sorted(
    (p["claim_id"], p["recomputed_hash"], p["stated_verdict"]) for p in proofs
)
recheck_payload = json.dumps(recheck_rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
recheck_digest = hashlib.sha256(recheck_payload).hexdigest()

all_intact = all(p["integrity"] == "intact" for p in proofs)
all_proven = all(p["stated_verdict"] == "proven" for p in proofs)
all_schema = all(p["schema_ok"] for p in proofs)
bundle_status = "complete" if (all_intact and all_proven and all_schema) else "incomplete"

# --- assemble bundle staging dir ---
staging = os.path.join(out_dir, "bundle")
src_dir = os.path.join(staging, "proof_source")
os.makedirs(src_dir, exist_ok=True)
for path in proof_files:
    shutil.copy2(path, os.path.join(src_dir, os.path.basename(path)))
# Copy any Lean/Coq proof sources if present alongside the proofs.
for ext in ("*.lean", "*.v"):
    for path in sorted(glob.glob(os.path.join(proof_source, ext))):
        shutil.copy2(path, os.path.join(src_dir, os.path.basename(path)))

versions = {
    "schema_version": "franken-engine.proof-assistant-versions.v1",
    "lean4": os.environ["EPB_LEAN4"],
    "coq": os.environ["EPB_COQ"],
    "recheck_tool": recheck_tool,
    "recheck_tool_digest_kind": "sha256",
}
with open(os.path.join(staging, "proof_assistant_versions.json"), "w", encoding="utf-8") as fh:
    json.dump(versions, fh, indent=2, sort_keys=True)
    fh.write("\n")

with open(os.path.join(staging, "recheck_expected.sha256"), "w", encoding="utf-8") as fh:
    fh.write(recheck_digest + "\n")

now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
manifest = {
    "schema_version": bundle_schema,
    "bead_id": "bd-cixqu.25.1",
    "generated_utc": now,
    "bundle_status": bundle_status,
    "proof_assistant_versions": "proof_assistant_versions.json",
    "recheck_tool": recheck_tool,
    "recheck_digest_sha256": recheck_digest,
    "recheck_expected_file": "recheck_expected.sha256",
    "recheck_instructions": (
        "Recompute sha256 over the sorted JSON array of "
        "[claim_id, sha256(canonical proof body), stated_verdict] for every "
        "proof_source/*.proof.json; it must equal recheck_expected.sha256."
    ),
    "claim_count": len(proofs),
    "claims": proofs,
}
with open(os.path.join(staging, "bundle_manifest.json"), "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2, sort_keys=True)
    fh.write("\n")

# Emit the inventory next to the tar (not inside it) for the gate surface.
with open(os.path.join(out_dir, "bundle_manifest.json"), "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2, sort_keys=True)
    fh.write("\n")

print(f"[export_proof_bundle] staged {len(proofs)} proofs, status={bundle_status}, "
      f"recheck_digest=sha256:{recheck_digest}")
print(f"STAGING={staging}")
sys.exit(0 if bundle_status == "complete" else 1)
PY
}

# Deterministically tar the staged bundle. Args: <staging_dir> <tar_path>.
pack_bundle() {
  local staging="$1"
  local tar_path="$2"
  # Deterministic tar: sorted entries, zeroed mtime/owner.
  tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -czf "${tar_path}" -C "$(dirname "${staging}")" "$(basename "${staging}")"
}

# Verify a bundle's recheck digest is reproducible from its proof source.
# Args: <staging_dir>. Returns 0 iff recomputed digest matches the pinned one.
verify_recheck_digest() {
  local staging="$1"
  EPB_V_STAGING="${staging}" EPB_PROOF_SCHEMA="${PROOF_SCHEMA}" python3 <<'PY'
import glob, hashlib, json, os, sys
staging = os.environ["EPB_V_STAGING"]
src = os.path.join(staging, "proof_source")
expected_file = os.path.join(staging, "recheck_expected.sha256")
with open(expected_file) as fh:
    expected = fh.read().strip()

def body_hash(proof):
    body = {k: v for k, v in proof.items() if k != "content_hash"}
    enc = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(enc).hexdigest()

rows = []
for path in sorted(glob.glob(os.path.join(src, "*.proof.json"))):
    with open(path) as fh:
        proof = json.load(fh)
    rows.append((proof.get("claim_id"), body_hash(proof), proof.get("verdict")))
rows.sort()
payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
recomputed = hashlib.sha256(payload).hexdigest()
if recomputed == expected:
    print(f"[verify] recheck digest matches: sha256:{recomputed}")
    sys.exit(0)
print(f"[verify] MISMATCH: expected {expected}, recomputed {recomputed}", file=sys.stderr)
sys.exit(1)
PY
}

write_fixture_proof_source() {
  local dir="$1"
  mkdir -p "${dir}"
  local claims=(
    "FE-CLAIM-016|G.2,G.3|formal-spec-isomorphism"
    "FE-CLAIM-017|G.6|translation-validation"
    "FE-CLAIM-018|G.6,G.7|policy-semantics"
    "FE-CLAIM-019|G.8|optimization-isomorphism"
    "FE-CLAIM-020|G.7,G.8|theorem-backed-compiler"
    "FE-CLAIM-021|G.7|policy-theorem-engine"
  )
  local entry claim tracks kind
  for entry in "${claims[@]}"; do
    IFS='|' read -r claim tracks kind <<<"${entry}"
    EPB_FX_DIR="${dir}" EPB_FX_CLAIM="${claim}" EPB_FX_TRACKS="${tracks}" \
    EPB_FX_KIND="${kind}" EPB_FX_SCHEMA="${PROOF_SCHEMA}" python3 <<'PY'
import hashlib, json, os
from datetime import datetime, timezone
d = os.environ["EPB_FX_DIR"]
proof = {
    "schema_version": os.environ["EPB_FX_SCHEMA"],
    "claim_id": os.environ["EPB_FX_CLAIM"],
    "track": os.environ["EPB_FX_TRACKS"],
    "proof_kind": os.environ["EPB_FX_KIND"],
    "verdict": "proven",
    "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_module": "selftest-fixture",
}
enc = json.dumps(proof, sort_keys=True, separators=(",", ":")).encode("utf-8")
proof["content_hash"] = "sha256:" + hashlib.sha256(enc).hexdigest()
with open(os.path.join(d, proof["claim_id"] + ".proof.json"), "w") as fh:
    json.dump(proof, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
  done
}

run_selftest() {
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local run_dir="${ARTIFACT_ROOT}/${ts}-selftest"
  local fx="${run_dir}/fixture_proof_source"
  mkdir -p "${run_dir}"

  echo "[${TOOL_NAME}] selftest: building fixture proof source"
  write_fixture_proof_source "${fx}"

  # 1. Export must succeed (complete bundle).
  local rc=0
  build_bundle "${fx}" "${run_dir}" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    echo "[${TOOL_NAME}] SELFTEST FAIL: export of intact fixture did not complete" >&2
    return 1
  fi
  local staging="${run_dir}/bundle"

  # 2. Tar must pack + contain the expected entries.
  pack_bundle "${staging}" "${run_dir}/proof_bundle.tar.gz"
  local listing
  listing="$(tar -tzf "${run_dir}/proof_bundle.tar.gz")"
  for want in "bundle/bundle_manifest.json" "bundle/recheck_expected.sha256" \
              "bundle/proof_assistant_versions.json" "bundle/proof_source/FE-CLAIM-016.proof.json"; do
    if ! grep -qx "${want}" <<<"${listing}"; then
      echo "[${TOOL_NAME}] SELFTEST FAIL: tar missing ${want}" >&2
      return 1
    fi
  done

  # 3. Recheck digest must verify from the bundled proof source.
  if ! verify_recheck_digest "${staging}"; then
    echo "[${TOOL_NAME}] SELFTEST FAIL: recheck digest did not verify" >&2
    return 1
  fi

  # 4. Reproducibility: a second export yields the identical recheck digest.
  local run2="${run_dir}/reexport"
  build_bundle "${fx}" "${run2}" >/dev/null || true
  local d1 d2
  d1="$(cat "${staging}/recheck_expected.sha256")"
  d2="$(cat "${run2}/bundle/recheck_expected.sha256")"
  if [[ "${d1}" != "${d2}" ]]; then
    echo "[${TOOL_NAME}] SELFTEST FAIL: recheck digest not reproducible (${d1} != ${d2})" >&2
    return 1
  fi

  # 5. Tamper: mutate a bundled proof body without fixing content_hash ->
  #    the recheck digest must NO LONGER match the pinned expected value.
  EPB_T="${staging}/proof_source/FE-CLAIM-019.proof.json" python3 -c '
import json, os
p = os.environ["EPB_T"]
with open(p) as fh: proof = json.load(fh)
proof["source_module"] = "tampered-after-export"
with open(p, "w") as fh: json.dump(proof, fh, indent=2, sort_keys=True); fh.write("\n")
'
  if verify_recheck_digest "${staging}" >/dev/null 2>&1; then
    echo "[${TOOL_NAME}] SELFTEST FAIL: tampered proof source still verified (not tamper-evident)" >&2
    return 1
  fi

  echo "[${TOOL_NAME}] SELFTEST PASS: export->complete, tar entries present, digest reproducible + tamper-evident"
  echo "[${TOOL_NAME}] artifacts: ${run_dir}"
  return 0
}

main() {
  local mode="${1:-}"
  case "${mode}" in
    -h|--help|"")
      usage
      [[ "${mode}" == "" ]] && exit 2 || exit 0
      ;;
    selftest)
      run_selftest
      exit $?
      ;;
    export)
      local proof_source="${2:-}"
      if [[ -z "${proof_source}" ]]; then
        echo "[${TOOL_NAME}] export requires <proof_source_dir>" >&2
        usage
        exit 2
      fi
      local ts out_dir
      ts="$(date -u +%Y%m%dT%H%M%SZ)"
      out_dir="${3:-${ARTIFACT_ROOT}/${ts}}"
      mkdir -p "${out_dir}"
      local rc=0
      build_bundle "${proof_source}" "${out_dir}" || rc=$?
      if [[ -d "${out_dir}/bundle" ]]; then
        pack_bundle "${out_dir}/bundle" "${out_dir}/proof_bundle.tar.gz"
        echo "[${TOOL_NAME}] bundle tar: ${out_dir}/proof_bundle.tar.gz"
      fi
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
