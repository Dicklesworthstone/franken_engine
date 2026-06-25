#!/usr/bin/env bash
# dw_differential_oracle_replay.sh - replay verifier for the E2.TEST
# differential-oracle capstone bundle (bd-fqlfw.2.8).
#
#   bundle [<dir>] : verify a preserved bundle's content hashes + pass outcome.
#                    With no <dir>, picks the latest complete bundle.
#   rerun          : re-run the gate into a replay artifact root.
#
# The bundle re-verification is byte-identical: the recorded run_manifest.json
# content hashes for commands.txt and events.jsonl must match a fresh sha256 of the
# preserved files, and the recorded outcome must be `pass`. Any live oracle bundle
# persisted under oracle_corpus/<case>/ is additionally re-checked through
# `frankenctl oracle report`, which recomputes the bundle's own manifest sha256.
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

CAP="dw_differential_oracle"
mode="${1:-bundle}"; shift || true

# Re-verify any persisted live oracle bundles through `frankenctl oracle report`,
# which independently recomputes each bundle's content-addressed manifest sha256.
verify_oracle_corpus() {
  local dir="$1"
  local corpus="$dir/oracle_corpus"
  [[ -d "$corpus" ]] || return 0
  local bin=""
  if [[ -n "${DW_FRANKENCTL_BIN:-}" && -x "${DW_FRANKENCTL_BIN}" ]]; then
    bin="${DW_FRANKENCTL_BIN}"
  elif [[ -x target/release/frankenctl ]]; then
    bin="target/release/frankenctl"
  elif [[ -x target/debug/frankenctl ]]; then
    bin="target/debug/frankenctl"
  fi
  local case_dir
  while IFS= read -r case_dir; do
    [[ -f "$case_dir/manifest.json" ]] || continue
    if [[ -n "$bin" ]]; then
      if "$bin" oracle report "$case_dir" --json >/dev/null 2>&1; then
        echo "replay: oracle bundle $(basename "$case_dir") re-verified (integrity ok)"
      else
        echo "replay: oracle bundle $(basename "$case_dir") FAILED re-verification" >&2
        exit 1
      fi
    else
      echo "replay: no frankenctl binary; skipping deep re-verify of $(basename "$case_dir")" >&2
    fi
  done < <(find "$corpus" -mindepth 1 -maxdepth 1 -type d -print | LC_ALL=C sort)
}

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
  local outcome
  outcome=$(jq -r '.outcome' "$manifest")
  echo "replay: $CAP bundle $dir verified (outcome=$outcome, source_revision=$(jq -r '.source_revision' "$manifest"))"
  verify_oracle_corpus "$dir"
  [[ "$outcome" == "pass" ]] || { echo "replay: non-pass outcome ($outcome) - not a certifying bundle" >&2; exit 1; }
}

case "$mode" in
  bundle)
    if [[ $# -ge 1 ]]; then
      verify_bundle "$1"
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
    DW_ARTIFACT_ROOT="artifacts/$CAP/replay" "./scripts/run_dw_differential_oracle.sh" ci "$@"
    ;;
  *) echo "usage: $0 [bundle [<dir>]|rerun]" >&2; exit 2 ;;
esac
