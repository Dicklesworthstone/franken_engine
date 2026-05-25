#!/usr/bin/env bash
# walk_lineage.sh (bd-cixqu.22.6, V.6)
#
# Operator query script for the self-replacement lineage surface. Given a slot
# id and a serialized lineage chain, it walks every ReplacementReceipt in the
# chain IN ORDER and, for each step, prints:
#   - the receipt identity (receipt_id + old_slot -> new_slot),
#   - the translation-validation-proof reference bound to that promotion,
#   - the signing key that authorized the promotion,
#   - the validation-artifact verdicts,
#   - the lineage-linkage check (each step's old_cell_digest must equal the
#     previous step's new_cell_digest; a mismatch breaks the chain).
#
# Modes:
#   walk_lineage.sh <slot_id> <lineage.json>          plain-English walk + a
#                                                     written JSON artifact under
#                                                     artifacts/self_replacement_lineage/<ts>/.
#   walk_lineage.sh --json <slot_id> <lineage.json>   emit ONLY the JSON report
#                                                     on stdout (pipe-friendly).
#   walk_lineage.sh selftest                          run against an in-tree
#                                                     synthetic 3-step chain and
#                                                     assert the walk verdicts.
#                                                     No engine build required.
#
# Lineage JSON shape: franken-engine.self-replacement-lineage.v1
#   { "slot_id": "<terminal slot>",
#     "entries": [ { "receipt": <ReplacementReceipt> }, ... ] }
# where <ReplacementReceipt> mirrors
# crates/franken-engine/src/self_replacement.rs::ReplacementReceipt
# (the Rust type is the source of truth for the shape + validation). This is
# the same `LineageChain` the `self_replacement_lineage_replay` example builds.
#
# Per bd-cixqu.45 logging discipline.

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

readonly SCHEMA_VERSION="franken-engine.self-replacement-lineage.v1"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly GENERATED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Core: read a lineage chain file, order its receipts, verify linkage, and emit
# the JSON walk report. Args: <slot_id> <lineage.json>
emit_report() {
  local slot="$1" file="$2"
  python3 - "$slot" "$file" "$SCHEMA_VERSION" "$GENERATED_UTC" <<'PY'
import json, sys
from pathlib import Path

slot, file, schema_version, generated_utc = sys.argv[1:5]

chain = json.loads(Path(file).read_text())
entries = chain.get("entries", [])

# Walk in promotion order (monotonic timestamp_ns; ties broken by receipt_id so
# the order is deterministic regardless of how the chain was assembled).
def key(e):
    r = e.get("receipt", {})
    return (r.get("timestamp_ns", 0), r.get("receipt_id", ""))
ordered = sorted(entries, key=key)

steps = []
prev_new = None
broken = 0
for i, e in enumerate(ordered):
    r = e.get("receipt", {})
    old_d = r.get("old_cell_digest")
    new_d = r.get("new_cell_digest")
    # Linkage: step i's old digest must equal step i-1's new digest.
    if i == 0:
        linkage = "chain-root"
    elif prev_new is not None and old_d == prev_new:
        linkage = "linked"
    else:
        linkage = "broken"
        broken += 1
    artifacts = r.get("validation_artifacts", []) or []
    unapproved = [a.get("artifact_id") for a in artifacts
                  if str(a.get("status", "")).lower() not in ("approved", "approve")]
    sig = r.get("signature_bundle", {}) or {}
    signing_key = sig.get("signing_key") or sig.get("verification_key") \
        or (sig.get("signatures", [{}])[0].get("signing_key") if sig.get("signatures") else None)
    steps.append({
        "step": i + 1,
        "receipt_id": r.get("receipt_id"),
        "old_slot_id": r.get("old_slot_id"),
        "new_slot_id": r.get("new_slot_id"),
        "old_cell_digest": old_d,
        "new_cell_digest": new_d,
        "translation_validation_proof_ref": r.get("translation_validation_proof_ref"),
        "signing_key": signing_key,
        "promotion_rationale": r.get("promotion_rationale"),
        "timestamp_ns": r.get("timestamp_ns"),
        "linkage": linkage,
        "validation_artifacts_total": len(artifacts),
        "validation_artifacts_unapproved": unapproved,
    })
    prev_new = new_d

# Does the requested slot terminate this chain? (Operators query by slot id.)
terminal_slot = ordered[-1]["receipt"].get("new_slot_id") if ordered else None
declared_slot = chain.get("slot_id")
slot_match = slot in (terminal_slot, declared_slot)

verdict = "ok"
if not ordered:
    verdict = "empty"
elif broken:
    verdict = "broken-linkage"
elif not slot_match:
    verdict = "slot-mismatch"
elif any(s["validation_artifacts_unapproved"] for s in steps):
    verdict = "unapproved-artifacts"

report = {
    "schema_version": schema_version,
    "generated_utc": generated_utc,
    "queried_slot_id": slot,
    "terminal_slot_id": terminal_slot,
    "slot_match": slot_match,
    "total_steps": len(steps),
    "broken_links": broken,
    "verdict": verdict,
    "steps": steps,
}
print(json.dumps(report, indent=2, sort_keys=True))
PY
}

render_summary() {
  # Report is passed as argv[1]; the heredoc is python's program (stdin), so we
  # cannot also pipe the data through stdin — read it from the argument.
  python3 - "$1" <<'PY'
import json, sys
r = json.loads(sys.argv[1])
ok = r["verdict"] == "ok"
print(f"Self-replacement lineage for slot '{r['queried_slot_id']}' "
      f"({r['generated_utc']}) — {'INTACT' if ok else 'ATTENTION: ' + r['verdict'].upper()}")
print(f"  steps={r['total_steps']} broken_links={r['broken_links']} "
      f"terminal_slot={r['terminal_slot_id']} slot_match={r['slot_match']}")
for s in r["steps"]:
    unappr = ",".join(s["validation_artifacts_unapproved"]) or "-"
    print(f"  - step {s['step']}: {s['old_slot_id']} -> {s['new_slot_id']}  [{s['linkage']}]")
    print(f"      receipt={s['receipt_id']}")
    print(f"      proof={s['translation_validation_proof_ref']}  signing_key={s['signing_key']}")
    print(f"      artifacts={s['validation_artifacts_total']} unapproved={unappr}  "
          f"rationale={s['promotion_rationale']}")
PY
}

run_selftest() {
  local tmp; tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' RETURN
  # Synthetic 3-step chain: delegate -> native_v1 -> native_v2 -> native_v3.
  # Digests link head-to-tail; out-of-order entry array exercises the sort.
  cat > "${tmp}/lineage.json" <<'EOF'
{
  "slot_id": "test_slot_native",
  "entries": [
    { "receipt": {
        "receipt_id": "rcpt-2", "old_slot_id": "test_slot_native_v1",
        "new_slot_id": "test_slot_native_v2", "old_cell_digest": "d1",
        "new_cell_digest": "d2", "translation_validation_proof_ref": "tv-proof-2",
        "content_hash_chain_into_lineage": "chain-2", "promotion_rationale": "tier-up v2",
        "timestamp_ns": 2000, "signature_bundle": { "signing_key": "key-B" },
        "validation_artifacts": [ { "artifact_id": "a2", "status": "approved" } ] } },
    { "receipt": {
        "receipt_id": "rcpt-1", "old_slot_id": "test_slot_delegate",
        "new_slot_id": "test_slot_native_v1", "old_cell_digest": "d0",
        "new_cell_digest": "d1", "translation_validation_proof_ref": "tv-proof-1",
        "content_hash_chain_into_lineage": "chain-1", "promotion_rationale": "tier-up v1",
        "timestamp_ns": 1000, "signature_bundle": { "signing_key": "key-A" },
        "validation_artifacts": [ { "artifact_id": "a1", "status": "approved" } ] } },
    { "receipt": {
        "receipt_id": "rcpt-3", "old_slot_id": "test_slot_native_v2",
        "new_slot_id": "test_slot_native", "old_cell_digest": "d2",
        "new_cell_digest": "d3", "translation_validation_proof_ref": "tv-proof-3",
        "content_hash_chain_into_lineage": "chain-3", "promotion_rationale": "tier-up v3",
        "timestamp_ns": 3000, "signature_bundle": { "signing_key": "key-C" },
        "validation_artifacts": [ { "artifact_id": "a3", "status": "approved" } ] } }
  ]
}
EOF
  local report; report="$(emit_report "test_slot_native" "${tmp}/lineage.json")"
  render_summary "${report}"
  python3 - <<PY
import json
r = json.loads('''${report}''')
assert r["total_steps"] == 3, r["total_steps"]
assert r["broken_links"] == 0, r["broken_links"]
assert r["verdict"] == "ok", r["verdict"]
assert r["slot_match"] is True, r
assert r["terminal_slot_id"] == "test_slot_native", r["terminal_slot_id"]
# Sorted by timestamp regardless of array order.
assert [s["receipt_id"] for s in r["steps"]] == ["rcpt-1", "rcpt-2", "rcpt-3"], r
assert r["steps"][0]["linkage"] == "chain-root", r["steps"][0]
assert all(s["linkage"] in ("chain-root", "linked") for s in r["steps"]), r
assert r["steps"][1]["signing_key"] == "key-B", r["steps"][1]
print("SELFTEST 1 OK: 3-step chain walks in order, all links intact, slot matches")
PY
  # Negative: break the middle link (step 2 old != step 1 new) -> broken-linkage.
  cat > "${tmp}/broken.json" <<'EOF'
{
  "slot_id": "test_slot_native",
  "entries": [
    { "receipt": { "receipt_id": "r1", "old_slot_id": "s0", "new_slot_id": "s1",
        "old_cell_digest": "d0", "new_cell_digest": "d1",
        "translation_validation_proof_ref": "p1", "content_hash_chain_into_lineage": "c1",
        "promotion_rationale": "v1", "timestamp_ns": 1, "signature_bundle": {"signing_key":"k1"},
        "validation_artifacts": [] } },
    { "receipt": { "receipt_id": "r2", "old_slot_id": "s1", "new_slot_id": "test_slot_native",
        "old_cell_digest": "TAMPERED", "new_cell_digest": "d2",
        "translation_validation_proof_ref": "p2", "content_hash_chain_into_lineage": "c2",
        "promotion_rationale": "v2", "timestamp_ns": 2, "signature_bundle": {"signing_key":"k2"},
        "validation_artifacts": [] } }
  ]
}
EOF
  local breport; breport="$(emit_report "test_slot_native" "${tmp}/broken.json")"
  python3 - <<PY
import json
r = json.loads('''${breport}''')
assert r["broken_links"] == 1, r["broken_links"]
assert r["verdict"] == "broken-linkage", r["verdict"]
assert r["steps"][1]["linkage"] == "broken", r["steps"][1]
print("SELFTEST 2 OK: tampered digest detected as broken-linkage")
PY
  echo "SELFTEST OK: lineage walk verified (intact chain + broken-link detection)"
}

MODE="${1:-}"
case "${MODE}" in
  selftest)
    run_selftest
    ;;
  --json)
    if [[ $# -lt 3 ]]; then echo "Usage: $0 --json <slot_id> <lineage.json>" >&2; exit 2; fi
    emit_report "$2" "$3"
    ;;
  "" | -h | --help)
    cat >&2 <<EOF
Usage:
  $0 <slot_id> <lineage.json>          walk + write artifact
  $0 --json <slot_id> <lineage.json>   JSON only (pipe-friendly)
  $0 selftest                          deterministic in-tree self-test
EOF
    exit 2
    ;;
  *)
    # MODE is the slot id; $2 is the lineage file.
    if [[ $# -lt 2 ]]; then echo "Usage: $0 <slot_id> <lineage.json>" >&2; exit 2; fi
    SLOT="$1"; FILE="$2"
    OUT_DIR="artifacts/self_replacement_lineage/${TIMESTAMP}"
    mkdir -p "${OUT_DIR}"
    {
      echo "command: $0 ${SLOT} ${FILE}"
      echo "generated_utc: ${GENERATED_UTC}"
      echo "lineage_file: ${FILE}"
    } > "${OUT_DIR}/commands.txt"
    report="$(emit_report "${SLOT}" "${FILE}")"
    echo "${report}" > "${OUT_DIR}/report.json"
    render_summary "${report}" | tee "${OUT_DIR}/summary.txt"
    echo "[walk_lineage] report written to ${OUT_DIR}/report.json" >&2
    ;;
esac
