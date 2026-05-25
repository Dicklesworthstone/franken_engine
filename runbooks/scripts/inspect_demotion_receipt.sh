#!/usr/bin/env bash
# inspect_demotion_receipt.sh (bd-cixqu.22.6, V.6)
#
# Operator query script for a triggered self-replacement demotion. Given a
# serialized demotion-fallback bundle, it surfaces the four things an operator
# needs when a promotion is rolled back:
#   1. the original PROMOTION receipt (what was promoted, by which key),
#   2. the PRE-SIGNED demotion fallback (sealed digest + permitted triggers),
#   3. the TRIGGER reason that fired the demotion (and whether it was a
#      permitted trigger — an unpermitted trigger is a fail-closed alarm),
#   4. the post-demotion SAFE-MODE fallback state the slot landed in.
#
# Modes:
#   inspect_demotion_receipt.sh <fallback.json>          plain-English report +
#                                                        a written JSON artifact
#                                                        under artifacts/demotion_inspect/<ts>/.
#   inspect_demotion_receipt.sh --json <fallback.json>   emit ONLY the JSON
#                                                        report (pipe-friendly).
#   inspect_demotion_receipt.sh selftest                 run against in-tree
#                                                        fixtures (activated +
#                                                        illegal-trigger) and
#                                                        assert verdicts. No
#                                                        engine build required.
#
# Bundle JSON shape: franken-engine.demotion-fallback.v1
#   { "promotion_receipt": <ReplacementReceipt>,
#     "fallback": <PreSignedDemotionFallback>,
#     "safe_mode_state": "<string>" }
# mirroring crates/franken-engine/src/self_replacement.rs::ReplacementReceipt
# and crates/franken-engine/src/pre_signed_demotion_fallback.rs
# (PreSignedDemotionFallback + FallbackStatus). The Rust types are the source
# of truth for the shapes + the permitted-trigger invariant.
#
# Per bd-cixqu.45 logging discipline.

set -euo pipefail

export TZ=UTC
export LC_ALL=C
export LANG=C

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_DIR}"

readonly SCHEMA_VERSION="franken-engine.demotion-fallback.v1"
readonly TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly GENERATED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Core: read a demotion-fallback bundle and emit the JSON inspection report.
# Args: <fallback.json>
emit_report() {
  local file="$1"
  python3 - "$file" "$SCHEMA_VERSION" "$GENERATED_UTC" <<'PY'
import json, sys
from pathlib import Path

file, schema_version, generated_utc = sys.argv[1:4]

bundle = json.loads(Path(file).read_text())
receipt = bundle.get("promotion_receipt", {}) or {}
fb = bundle.get("fallback", {}) or {}
safe_mode_state = bundle.get("safe_mode_state")

# FallbackStatus is an internally-tagged enum: { "kind": "...", ... }.
status = fb.get("status", {}) or {}
status_kind = status.get("kind")
fired_trigger = status.get("trigger")          # present only when activated
activated_at_ns = status.get("activated_at_ns")
voided_reason = status.get("reason")

permitted = fb.get("permitted_triggers", []) or []
trigger_permitted = (fired_trigger in permitted) if fired_trigger is not None else None

sig = receipt.get("signature_bundle", {}) or {}
promotion_signing_key = sig.get("signing_key") or sig.get("verification_key") \
    or (sig.get("signatures", [{}])[0].get("signing_key") if sig.get("signatures") else None)

# Verdict:
#   sealed    — fallback armed, demotion not fired (informational).
#   active    — promotion live, fallback armed.
#   demoted   — trigger fired and was permitted (expected rollback path).
#   voided    — promotion succeeded; fallback retired.
#   ILLEGAL-TRIGGER — a demotion fired on a trigger the fallback was NOT
#                     sealed to honor. Fail-closed alarm; never expected.
if status_kind in ("activated", "Activated"):
    verdict = "demoted" if trigger_permitted else "ILLEGAL-TRIGGER"
elif status_kind in ("voided", "Voided"):
    verdict = "voided"
elif status_kind in ("active", "Active"):
    verdict = "active"
elif status_kind in ("sealed", "Sealed"):
    verdict = "sealed"
else:
    verdict = "unknown-status"

report = {
    "schema_version": schema_version,
    "generated_utc": generated_utc,
    "verdict": verdict,
    "promotion": {
        "receipt_id": receipt.get("receipt_id"),
        "old_slot_id": receipt.get("old_slot_id"),
        "new_slot_id": receipt.get("new_slot_id"),
        "new_cell_digest": receipt.get("new_cell_digest"),
        "promotion_rationale": receipt.get("promotion_rationale"),
        "signing_key": promotion_signing_key,
        "rollback_token": receipt.get("rollback_token"),
    },
    "fallback": {
        "promotion_id": fb.get("promotion_id"),
        "receipt_digest": fb.get("receipt_digest"),
        "sealed_at_ns": fb.get("sealed_at_ns"),
        "permitted_triggers": permitted,
        "status_kind": status_kind,
    },
    "trigger": {
        "fired": fired_trigger,
        "permitted": trigger_permitted,
        "activated_at_ns": activated_at_ns,
        "voided_reason": voided_reason,
    },
    "safe_mode_state": safe_mode_state,
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
alarm = r["verdict"] == "ILLEGAL-TRIGGER"
print(f"Demotion-fallback inspection ({r['generated_utc']}) — "
      f"{'!! ALARM: ILLEGAL TRIGGER !!' if alarm else r['verdict'].upper()}")
p = r["promotion"]
print(f"  promotion: {p['old_slot_id']} -> {p['new_slot_id']}")
print(f"    receipt={p['receipt_id']}  signing_key={p['signing_key']}")
print(f"    rationale={p['promotion_rationale']}  rollback_token={p['rollback_token']}")
fb = r["fallback"]
print(f"  fallback: promotion_id={fb['promotion_id']}  status={fb['status_kind']}")
print(f"    sealed_at_ns={fb['sealed_at_ns']}  receipt_digest={fb['receipt_digest']}")
print(f"    permitted_triggers={','.join(fb['permitted_triggers']) or '-'}")
t = r["trigger"]
if t["fired"] is not None:
    print(f"  trigger: {t['fired']}  permitted={t['permitted']}  at_ns={t['activated_at_ns']}")
if t["voided_reason"]:
    print(f"  voided_reason: {t['voided_reason']}")
print(f"  safe_mode_state: {r['safe_mode_state']}")
PY
}

run_selftest() {
  local tmp; tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' RETURN
  # Fixture 1: a legitimately-activated demotion (permitted trigger).
  cat > "${tmp}/activated.json" <<'EOF'
{
  "promotion_receipt": {
    "receipt_id": "rcpt-9", "old_slot_id": "slot_delegate", "new_slot_id": "slot_native",
    "new_cell_digest": "nd9", "promotion_rationale": "tier-up to native",
    "rollback_token": "rbk-9", "signature_bundle": { "signing_key": "promo-key" }
  },
  "fallback": {
    "promotion_id": "promotion_9", "receipt_digest": "digest-9", "sealed_at_ns": 500,
    "permitted_triggers": ["digest_drift", "severity_threshold_crossed", "gatekeeper_rejection"],
    "status": { "kind": "activated", "activated_at_ns": 900, "trigger": "digest_drift" }
  },
  "safe_mode_state": "delegate_fallback_active"
}
EOF
  local r1; r1="$(emit_report "${tmp}/activated.json")"
  render_summary "${r1}"
  python3 - <<PY
import json
r = json.loads('''${r1}''')
assert r["verdict"] == "demoted", r["verdict"]
assert r["trigger"]["fired"] == "digest_drift", r["trigger"]
assert r["trigger"]["permitted"] is True, r["trigger"]
assert r["promotion"]["signing_key"] == "promo-key", r["promotion"]
assert r["safe_mode_state"] == "delegate_fallback_active", r
print("SELFTEST 1 OK: permitted-trigger demotion -> verdict=demoted")
PY
  # Fixture 2: an UNPERMITTED trigger fired -> fail-closed ILLEGAL-TRIGGER alarm.
  cat > "${tmp}/illegal.json" <<'EOF'
{
  "promotion_receipt": {
    "receipt_id": "rcpt-x", "old_slot_id": "slot_delegate", "new_slot_id": "slot_native",
    "new_cell_digest": "ndx", "promotion_rationale": "tier-up", "rollback_token": "rbk-x",
    "signature_bundle": { "signing_key": "promo-key" }
  },
  "fallback": {
    "promotion_id": "promotion_x", "receipt_digest": "digest-x", "sealed_at_ns": 10,
    "permitted_triggers": ["digest_drift"],
    "status": { "kind": "activated", "activated_at_ns": 20, "trigger": "manual_operator" }
  },
  "safe_mode_state": "delegate_fallback_active"
}
EOF
  local r2; r2="$(emit_report "${tmp}/illegal.json")"
  python3 - <<PY
import json
r = json.loads('''${r2}''')
assert r["verdict"] == "ILLEGAL-TRIGGER", r["verdict"]
assert r["trigger"]["permitted"] is False, r["trigger"]
print("SELFTEST 2 OK: unpermitted trigger -> verdict=ILLEGAL-TRIGGER (fail-closed alarm)")
PY
  # Fixture 3: a still-sealed fallback (no demotion fired).
  cat > "${tmp}/sealed.json" <<'EOF'
{
  "promotion_receipt": { "receipt_id": "rcpt-s", "old_slot_id": "a", "new_slot_id": "b",
    "new_cell_digest": "nds", "promotion_rationale": "p", "rollback_token": "rbk-s",
    "signature_bundle": { "signing_key": "k" } },
  "fallback": { "promotion_id": "promotion_s", "receipt_digest": "d", "sealed_at_ns": 1,
    "permitted_triggers": ["digest_drift"], "status": { "kind": "sealed" } },
  "safe_mode_state": "promotion_pending"
}
EOF
  local r3; r3="$(emit_report "${tmp}/sealed.json")"
  python3 - <<PY
import json
r = json.loads('''${r3}''')
assert r["verdict"] == "sealed", r["verdict"]
assert r["trigger"]["fired"] is None, r["trigger"]
print("SELFTEST 3 OK: sealed-but-unfired fallback -> verdict=sealed")
PY
  echo "SELFTEST OK: demotion inspection verified (demoted + illegal-trigger + sealed)"
}

MODE="${1:-}"
case "${MODE}" in
  selftest)
    run_selftest
    ;;
  --json)
    if [[ $# -lt 2 ]]; then echo "Usage: $0 --json <fallback.json>" >&2; exit 2; fi
    emit_report "$2"
    ;;
  "" | -h | --help)
    cat >&2 <<EOF
Usage:
  $0 <fallback.json>          inspect + write artifact
  $0 --json <fallback.json>   JSON only (pipe-friendly)
  $0 selftest                 deterministic in-tree self-test
EOF
    exit 2
    ;;
  *)
    FILE="$1"
    OUT_DIR="artifacts/demotion_inspect/${TIMESTAMP}"
    mkdir -p "${OUT_DIR}"
    {
      echo "command: $0 ${FILE}"
      echo "generated_utc: ${GENERATED_UTC}"
      echo "fallback_file: ${FILE}"
    } > "${OUT_DIR}/commands.txt"
    report="$(emit_report "${FILE}")"
    echo "${report}" > "${OUT_DIR}/report.json"
    render_summary "${report}" | tee "${OUT_DIR}/summary.txt"
    echo "[inspect_demotion_receipt] report written to ${OUT_DIR}/report.json" >&2
    ;;
esac
