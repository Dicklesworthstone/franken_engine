#!/usr/bin/env bash
# dw_non_use_certificate_replay.sh - replay verifier for the E8 Non-Use
# Certificate capstone bundle (bd-fqlfw.8.7).
#
#   bundle [<dir>] : verify a preserved bundle's content hashes + pass outcome
#                    (picks latest complete bundle under artifacts/dw_non_use_certificate
#                    or honours DW_NON_USE_CERTIFICATE_REPLAY_RUN_DIR when <dir> is omitted)
#   rerun          : re-run the gate into artifacts/dw_non_use_certificate/replay
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

CAP="dw_non_use_certificate"
mode="${1:-bundle}"; shift || true

verify_bundle() {
  local dir="$1"
  [[ -d "$dir" ]] || { echo "replay: bundle dir not found: $dir" >&2; exit 2; }
  local manifest="$dir/run_manifest.json"
  [[ -f "$manifest" ]] || { echo "replay: missing run_manifest.json in $dir" >&2; exit 2; }
  local claim_cmds claim_events have_cmds have_events
  claim_cmds=$(jq -r '.content_hashes.commands_txt' "$manifest")
  claim_events=$(jq -r '.content_hashes.events_jsonl' "$manifest")
  have_cmds=$(sha256sum "$dir/commands.txt" | awk '{print $1}')
  have_events=$(sha256sum "$dir/events.jsonl" | awk '{print $1}')
  if [[ "$claim_cmds" != "$have_cmds" || "$claim_events" != "$have_events" ]]; then
    echo "replay: CONTENT-HASH MISMATCH - bundle tampered or corrupt" >&2
    echo "  commands.txt: manifest=$claim_cmds actual=$have_cmds" >&2
    echo "  events.jsonl: manifest=$claim_events actual=$have_events" >&2
    exit 1
  fi

  local cert="$dir/non_use_certificate_e2e/certified_bundle/non_use_certificate.json"
  if [[ -f "$cert" ]]; then
    local scope_model
    scope_model=$(jq -r '.scope.threat_model_scope' "$cert")
    if [[ "$scope_model" != "explicit_flow_ifc_v1" ]]; then
      echo "replay: preserved non_use_certificate.json threat_model_scope drifted: $scope_model" >&2
      exit 1
    fi
  fi

  local outcome
  outcome=$(jq -r '.outcome' "$manifest")
  echo "replay: $CAP bundle $dir verified (outcome=$outcome, source_revision=$(jq -r '.source_revision' "$manifest"))"
  [[ "$outcome" == "pass" ]] || { echo "replay: non-pass outcome ($outcome) - not a certifying bundle" >&2; exit 1; }
}

case "$mode" in
  bundle)
    if [[ $# -ge 1 ]]; then
      verify_bundle "$1"
    elif [[ -n "${DW_NON_USE_CERTIFICATE_REPLAY_RUN_DIR:-}" ]]; then
      verify_bundle "${DW_NON_USE_CERTIFICATE_REPLAY_RUN_DIR}"
    else
      latest=""
      if [[ -d "artifacts/$CAP" ]]; then
        while IFS= read -r dir; do
          if [[ -f "$dir/run_manifest.json" ]]; then
            latest="$dir"
            break
          fi
          echo "replay: skipping incomplete bundle $dir (no run_manifest.json)" >&2
        done < <(find "artifacts/$CAP" -mindepth 1 -maxdepth 1 -type d -print | LC_ALL=C sort -r)
      fi
      [[ -n "$latest" ]] || { echo "replay: no complete $CAP bundle found" >&2; exit 2; }
      verify_bundle "$latest"
    fi
    ;;
  rerun)
    DW_ARTIFACT_ROOT="artifacts/$CAP/replay" "./scripts/run_dw_non_use_certificate.sh" ci "$@"
    ;;
  *) echo "usage: $0 [bundle [<dir>]|rerun]" >&2; exit 2 ;;
esac
