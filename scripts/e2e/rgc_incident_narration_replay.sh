#!/usr/bin/env bash
# rgc_incident_narration_replay.sh - replay verifier for the Track X.3
# incident-narration gate bundle (bd-cixqu.24.3).
#
#   bundle [dir] : verify a preserved bundle's content hashes + the
#                  certifying narration verdict (byte-identical replay AND
#                  detected perturbation); picks the latest complete bundle
#                  when no dir is given; honours
#                  RGC_INCIDENT_NARRATION_REPLAY_RUN_DIR.
#   rerun        : re-run the gate (ci mode) to produce a fresh bundle.
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

CAP="rgc_incident_narration"
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
  # The certifying claim of this gate is the narration replay verdict: the
  # replayed narration was byte-identical AND an intentional perturbation
  # was detected. A bundle without the report is not a certifying bundle.
  local report="$dir/incident_narration_report.json"
  if [[ ! -f "$report" ]]; then
    echo "replay: missing incident_narration_report.json - not a certifying bundle" >&2
    exit 1
  fi
  if ! jq -e '.identical_replay == true and .perturbation_detected == true and .gate_verdict == "pass"' \
    "$report" >/dev/null 2>&1; then
    echo "replay: NARRATION VERDICT NOT CERTIFYING:" >&2
    jq -c '{identical_replay, perturbation_detected, gate_verdict}' "$report" >&2 || cat "$report" >&2
    exit 1
  fi
  # bd-cixqu.45 logging discipline: surface the original vs replayed hashes.
  echo "replay: narration hashes: original=$(jq -r '.original_narrative_hash' "$report") replayed=$(jq -r '.replayed_narrative_hash' "$report")"
  local outcome
  outcome=$(jq -r '.outcome' "$manifest")
  echo "replay: $CAP bundle $dir verified (outcome=$outcome, source_revision=$(jq -r '.source_revision' "$manifest"))"
  [[ "$outcome" == "pass" ]] || { echo "replay: non-pass outcome ($outcome) - not a certifying bundle" >&2; exit 1; }
}

case "$mode" in
  bundle)
    if [[ $# -ge 1 ]]; then
      verify_bundle "$1"
    elif [[ -n "${RGC_INCIDENT_NARRATION_REPLAY_RUN_DIR:-}" ]]; then
      verify_bundle "$RGC_INCIDENT_NARRATION_REPLAY_RUN_DIR"
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
    DW_ARTIFACT_ROOT="artifacts/${CAP}_replay" ./scripts/run_rgc_incident_narration.sh ci
    ;;
  *) echo "usage: $0 [bundle [dir] | rerun]" >&2; exit 2 ;;
esac
