#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${ALL_TARGET_CARGO_PROOF_SHARD_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-all-target-cargo-proof-shards}"
run_id="${ALL_TARGET_CARGO_PROOF_SHARD_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${ALL_TARGET_CARGO_PROOF_SHARD_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${ALL_TARGET_CARGO_PROOF_SHARD_SOURCE_REVISION:-}"
target_dir_prefix="${ALL_TARGET_CARGO_PROOF_SHARD_TARGET_DIR_PREFIX:-/tmp/rch_target_franken_engine_all_target_shards}"
case_id="manual"
package_filter=""
metadata_json=""
prior_rch_failures_json=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/all_target_cargo_proof_shard_planner.sh --cargo-metadata-json FILE [OPTIONS]

Plans all-target Cargo proof shards from preserved cargo metadata and optional
prior RCH failure evidence. It never executes Cargo, never invokes rch, and
never mutates br, Agent Mail, workers, queues, or target directories.

Required:
  --cargo-metadata-json FILE        Preserved cargo metadata JSON.

Optional:
  --prior-rch-failures-json FILE    Prior RCH failure/stale target evidence.
  --package NAME                    Restrict planning to one package.
  --case-id ID
  --source-revision REV
  --target-dir-prefix PREFIX        Defaults to /tmp/rch_target_franken_engine_all_target_shards.
  --output-dir DIR

Artifacts:
  shard_manifest.json
  commands.txt
  commands.jsonl
  stale_target_diagnostics.jsonl
  events.jsonl
  report.md

Exit codes:
  0   pass or degraded shard manifest emitted
  42  fail-closed manifest emitted
  64  invalid input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --cargo-metadata-json)
      metadata_json="${2:-}"
      shift 2
      ;;
    --prior-rch-failures-json)
      prior_rch_failures_json="${2:-}"
      shift 2
      ;;
    --package)
      package_filter="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --target-dir-prefix)
      target_dir_prefix="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for all-target cargo proof shard planning\n' >&2
  exit 2
fi
if [[ -z "$metadata_json" ]]; then
  printf 'planner requires --cargo-metadata-json\n' >&2
  usage
  exit 64
fi
if [[ ! -f "$metadata_json" ]]; then
  printf 'cargo metadata JSON not found: %s\n' "$metadata_json" >&2
  exit 64
fi
if ! jq empty "$metadata_json" >/dev/null 2>&1; then
  printf 'invalid cargo metadata JSON: %s\n' "$metadata_json" >&2
  exit 64
fi
if [[ -n "$prior_rch_failures_json" ]]; then
  if [[ ! -f "$prior_rch_failures_json" ]]; then
    printf 'prior RCH failures JSON not found: %s\n' "$prior_rch_failures_json" >&2
    exit 64
  fi
  if ! jq empty "$prior_rch_failures_json" >/dev/null 2>&1; then
    printf 'invalid prior RCH failures JSON: %s\n' "$prior_rch_failures_json" >&2
    exit 64
  fi
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
metadata_normalized="${run_dir}/cargo_metadata.normalized.json"
prior_failures_normalized="${run_dir}/prior_rch_failures.normalized.json"
manifest_path="${run_dir}/shard_manifest.json"
manifest_tmp="${manifest_path}.tmp"
commands_path="${run_dir}/commands.txt"
commands_jsonl="${run_dir}/commands.jsonl"
stale_diagnostics_path="${run_dir}/stale_target_diagnostics.jsonl"
events_path="${run_dir}/events.jsonl"
report_path="${run_dir}/report.md"

for artifact_path in "$metadata_normalized" "$prior_failures_normalized" "$manifest_path" "$manifest_tmp" "$commands_path" "$commands_jsonl" "$stale_diagnostics_path" "$events_path" "$report_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

jq -cS . "$metadata_json" >"$metadata_normalized"
if [[ -n "$prior_rch_failures_json" ]]; then
  jq -cS . "$prior_rch_failures_json" >"$prior_failures_normalized"
else
  printf '{"failures":[]}\n' >"$prior_failures_normalized"
fi

: >"$events_path"
printf './scripts/all_target_cargo_proof_shard_planner.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -n \
  --slurpfile metadata "$metadata_normalized" \
  --slurpfile prior "$prior_failures_normalized" \
  --arg schema_version "franken-engine.all-target-cargo-proof-shard-manifest.v1" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg package_filter "$package_filter" \
  --arg target_dir_prefix "$target_dir_prefix" \
  --arg metadata_normalized "$metadata_normalized" \
  --arg prior_failures_normalized "$prior_failures_normalized" \
  --arg manifest_path "$manifest_path" \
  --arg commands_path "$commands_path" \
  --arg commands_jsonl "$commands_jsonl" \
  --arg stale_diagnostics_path "$stale_diagnostics_path" \
  --arg events_path "$events_path" \
  --arg report_path "$report_path" '
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def token($v): ($v | tostring | ascii_downcase | gsub("[^a-z0-9_]+"; "_") | gsub("^_+|_+$"; ""));
  def pkg_arg($pkg): "-p " + $pkg;
  def target_dir($lane; $pkg; $target):
    $target_dir_prefix + "_" + token($lane + "_" + $pkg + "_" + ($target // "all"));
  def rch_cmd($lane; $pkg; $target; $cargo_args):
    "rch exec -- env CARGO_TARGET_DIR=" + target_dir($lane; $pkg; $target)
    + " CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo " + $cargo_args;
  def metadata_ok:
    (($metadata[0].packages // null) | type) == "array";
  def package_rows:
    if metadata_ok then
      arr($metadata[0].packages)
      | map(select(($package_filter == "") or (.name == $package_filter)))
    else [] end;
  def target_rows:
    [
      package_rows[] as $pkg
      | arr($pkg.targets)[]?
      | {
          package_name:$pkg.name,
          target_name:(.name // ""),
          kind:arr(.kind),
          crate_types:arr(.crate_types)
        }
    ];
  def has_kind($row; $kind): (arr($row.kind) | index($kind)) != null;
  def package_has_kind($pkg; $kind):
    any(target_rows[]; .package_name == $pkg and has_kind(.; $kind));
  def shard($lane; $pkg; $target; $kind; $cargo_args; $expected):
    {
      shard_id: ("cargo-proof-" + token($lane + "_" + $pkg + "_" + ($target // "all"))),
      lane:$lane,
      package:$pkg,
      target_name:$target,
      target_kind:$kind,
      command:rch_cmd($lane; $pkg; $target; $cargo_args),
      target_dir:target_dir($lane; $pkg; $target),
      expected_artifacts:$expected,
      rch_policy:{
        direct_rch_exec:true,
        requires_cargo_target_dir:true,
        rejects_local_fallback:true,
        executes_now:false
      }
    };
  def package_shards($pkg):
    [
      shard("check"; $pkg.name; null; "all-targets"; "check " + pkg_arg($pkg.name) + " --all-targets"; ["cargo-check.log"]),
      shard("clippy"; $pkg.name; null; "all-targets"; "clippy " + pkg_arg($pkg.name) + " --all-targets -- -D warnings"; ["cargo-clippy.log"]),
      if package_has_kind($pkg.name; "lib") then
        shard("lib_test"; $pkg.name; null; "lib"; "test " + pkg_arg($pkg.name) + " --lib -- --nocapture"; ["lib-test.log"])
      else empty end,
      if package_has_kind($pkg.name; "lib") then
        shard("doctest"; $pkg.name; null; "doc"; "test " + pkg_arg($pkg.name) + " --doc"; ["doctest.log"])
      else empty end,
      (target_rows[]
        | select(.package_name == $pkg.name and has_kind(.; "bin"))
        | shard("bin_test"; .package_name; .target_name; "bin"; "test " + pkg_arg(.package_name) + " --bin " + .target_name + " -- --nocapture"; ["bin-test-" + .target_name + ".log"])),
      (target_rows[]
        | select(.package_name == $pkg.name and has_kind(.; "test"))
        | shard("integration_test"; .package_name; .target_name; "test"; "test " + pkg_arg(.package_name) + " --test " + .target_name + " -- --nocapture"; ["integration-test-" + .target_name + ".log"]))
    ];
  def prior_rows:
    if (($prior[0] | type) == "array") then $prior[0]
    else arr($prior[0].failures) end;
  def target_exists($failure):
    if (($failure.target_name // "") == "") then
      any(package_rows[]; .name == ($failure.package // ""))
    else
      any(target_rows[]; .package_name == ($failure.package // "") and .target_name == ($failure.target_name // ""))
    end;
  def stale_diagnostics:
    [
      prior_rows[]?
      | select((.target_name // "") != "")
      | select(target_exists(.) | not)
      | {
          code:"FE-IW3-SHARD-STALE-TARGET",
          package:(.package // ""),
          target_name:(.target_name // ""),
          target_kind:(.target_kind // .kind // "unknown"),
          prior_command:(.command // ""),
          detail:"prior RCH failure references a target not present in current cargo metadata",
          remediation:"Drop or refresh the stale target before scheduling proof shards."
        }
    ];
  def matched_failure_count($shard):
    [
      prior_rows[]?
      | select((.package // "") == $shard.package)
      | select(((.target_name // "") == ($shard.target_name // "")) or ((.lane // "") == $shard.lane))
    ] | length;
  def reason($code; $detail; $remediation):
    {code:$code, detail:$detail, remediation:$remediation};

  if (metadata_ok | not) then
    {
      schema_version:$schema_version,
      case_id:$case_id,
      source_revision:$source_revision,
      decision:"fail_closed",
      fail_closed_reasons:[
        reason("FE-IW3-SHARD-MALFORMED-METADATA"; "cargo metadata JSON lacks a packages array"; "Regenerate cargo metadata before planning proof shards.")
      ],
      degraded_reasons:[],
      package_filter:(if $package_filter == "" then null else $package_filter end),
      package_count:0,
      target_count:0,
      shard_count:0,
      shards:[],
      stale_target_diagnostics:[],
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        runs_cargo:false,
        runs_rch:false,
        mutates_br:false,
        sends_agent_mail:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false,
        creates_deletes_target_dirs:false
      },
      artifact_paths:{
        cargo_metadata_normalized:$metadata_normalized,
        prior_rch_failures_normalized:$prior_failures_normalized,
        shard_manifest_json:$manifest_path,
        commands_txt:$commands_path,
        commands_jsonl:$commands_jsonl,
        stale_target_diagnostics_jsonl:$stale_diagnostics_path,
        events_jsonl:$events_path,
        report_md:$report_path
      }
    }
  else
    (package_rows | map(package_shards(.)) | add // []) as $shards
    | (stale_diagnostics) as $stale
    | ($shards | map(. + {prior_failure_matches: matched_failure_count(.)})) as $annotated_shards
    | {
        schema_version:$schema_version,
        case_id:$case_id,
        source_revision:$source_revision,
        decision:(if ($stale | length) > 0 then "degraded" else "pass" end),
        fail_closed_reasons:[],
        degraded_reasons:(if ($stale | length) > 0 then [
          reason("FE-IW3-SHARD-STALE-TARGET"; "prior RCH evidence references stale targets"; "Refresh stale target evidence before relying on historical failures.")
        ] else [] end),
        package_filter:(if $package_filter == "" then null else $package_filter end),
        package_count:(package_rows | length),
        target_count:(target_rows | length),
        shard_count:($annotated_shards | length),
        shards:$annotated_shards,
        stale_target_diagnostics:$stale,
        lanes:($annotated_shards | map(.lane) | unique | sort),
        command_policy:{
          heavy_commands_are_templates:true,
          required_prefix:"rch exec -- env CARGO_TARGET_DIR=",
          bare_cargo_is_fail_closed:true,
          local_fallback_is_rejected_fail_closed:true
        },
        mutation_policy:{
          advisory_only:true,
          proof_only:true,
          runs_cargo:false,
          runs_rch:false,
          mutates_br:false,
          sends_agent_mail:false,
          mutates_remote_workers:false,
          changes_live_queue_policy:false,
          creates_deletes_target_dirs:false
        },
        artifact_paths:{
          cargo_metadata_normalized:$metadata_normalized,
          prior_rch_failures_normalized:$prior_failures_normalized,
          shard_manifest_json:$manifest_path,
          commands_txt:$commands_path,
          commands_jsonl:$commands_jsonl,
          stale_target_diagnostics_jsonl:$stale_diagnostics_path,
          events_jsonl:$events_path,
          report_md:$report_path
        }
      }
  end
  ' >"$manifest_tmp"

mv "$manifest_tmp" "$manifest_path"
jq -r '.shards[].command?' "$manifest_path" >>"$commands_path"
jq -c '.shards[]?' "$manifest_path" >"$commands_jsonl"
jq -c '.stale_target_diagnostics[]?' "$manifest_path" >"$stale_diagnostics_path"
jq -c '
  {
    schema_version:"franken-engine.all-target-cargo-proof-shard.event.v1",
    event:"shard_manifest_emitted",
    decision:.decision,
    shard_count:.shard_count,
    package_count:.package_count,
    target_count:.target_count,
    source_revision:.source_revision
  },
  (.degraded_reasons[]? | {
    schema_version:"franken-engine.all-target-cargo-proof-shard.event.v1",
    event:"degraded_reason",
    code:.code,
    detail:.detail
  }),
  (.fail_closed_reasons[]? | {
    schema_version:"franken-engine.all-target-cargo-proof-shard.event.v1",
    event:"fail_closed_reason",
    code:.code,
    detail:.detail
  })
' "$manifest_path" >"$events_path"
jq -r '
  "# All-Target Cargo Proof Shard Planner\n\n"
  + "- decision: `" + .decision + "`\n"
  + "- packages: `" + (.package_count | tostring) + "`\n"
  + "- targets: `" + (.target_count | tostring) + "`\n"
  + "- shards: `" + (.shard_count | tostring) + "`\n\n"
  + "## Lanes\n\n"
  + (if ((.lanes // []) | length) == 0 then "No lanes emitted.\n" else (.lanes | map("- `" + . + "`") | join("\n")) + "\n" end)
  + "\n## Diagnostics\n\n"
  + (if ((.degraded_reasons + .fail_closed_reasons) | length) == 0 then "No degraded or fail-closed reasons.\n"
     else ((.degraded_reasons + .fail_closed_reasons) | map("- `" + .code + "`: " + .detail) | join("\n")) + "\n" end)
' "$manifest_path" >"$report_path"

decision="$(jq -r '.decision' "$manifest_path")"
printf 'all_target_cargo_proof_shard_manifest=%s\n' "$manifest_path"
printf 'all_target_cargo_proof_shard_decision=%s\n' "$decision"
if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
