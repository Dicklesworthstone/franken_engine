#!/usr/bin/env bash
set -euo pipefail

ledger_path="${1:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/verify_rch_validation_evidence_ledger.sh LEDGER_JSON

Verifies the source-only RCH validation evidence ledger contract. The verifier
does not run Cargo or RCH.
EOF
}

if [[ -z "$ledger_path" || "$ledger_path" == "-h" || "$ledger_path" == "--help" ]]; then
  usage
  exit 64
fi
if [[ ! -r "$ledger_path" ]]; then
  printf 'ledger is missing or unreadable: %s\n' "$ledger_path" >&2
  exit 64
fi

jq -e '
  .schema_version == "franken-engine.rch-validation-evidence-ledger.v1"
  and .component == "rch_validation_evidence_ledger"
  and (.entries | type == "array" and length > 0)
  and all(.entries[]; (.bead_id // "") != "")
  and all(.entries[]; (.commit // "") != "")
  and all(.entries[]; (.command // "") != "")
  and all(.entries[]; (.command_class // "") != "")
  and all(.entries[]; (.result.status // "") != "")
  and all(.entries[]; ((.command | test("(^|[[:space:]])cargo[[:space:]]")) | not) or (.command | startswith("rch exec -- env ")))
  and all(.entries[] | select(.result.status == "infrastructure_timeout"); (.result.compile_stage_reached // "") as $stage | ["syncing_project","resolving_dependencies","compiling_dependencies","compiling_target_crate","test_harness","completed","unknown"] | index($stage) != null)
  and all(.entries[] | select(.result.status == "infrastructure_timeout"); (.result.compiler_diagnostic_surfaced | type) == "boolean")
  and (.aggregates.by_bead | type == "array")
  and (.aggregates.by_commit | type == "array")
' "$ledger_path" >/dev/null

printf 'PASS rch-validation-evidence-ledger %s\n' "$ledger_path"
