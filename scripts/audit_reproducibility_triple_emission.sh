#!/usr/bin/env bash
# bd-cixqu.14.1 — Audit which RGC gate scripts emit the reproducibility
# triple (env.json + manifest.json + repro.lock) defined in
# docs/REPRODUCIBILITY_CONTRACT.md.
#
# Usage:
#   scripts/audit_reproducibility_triple_emission.sh [--json] [--summary] [--fail-on-gap]
#
# Default mode prints a markdown table. `--json` emits a JSONL stream
# (one object per gate). `--summary` prints only counts. `--fail-on-gap`
# returns exit 1 if any gate is missing at least one of the three.
#
# Detection rule: a script "emits" `<artifact>` if a literal reference to
# `<artifact>` appears in the script body (excluding comments). This is
# a structural-not-runtime check — a script that names the file in a
# variable or a help string counts; the audit pairs naturally with a
# follow-on runtime probe under bd-cixqu.14.3.

set -euo pipefail

repo_root() {
    git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/.." && pwd; }
}

emits_artifact() {
    # $1 = script path, $2 = artifact filename
    # Strip line comments before searching so a "see env.json" doc line
    # in a script header does not count as emission.
    local script="$1"
    local artifact="$2"
    if sed -E 's/#.*$//' "$script" | grep -F -q "$artifact"; then
        echo "yes"
    else
        echo "no"
    fi
}

main() {
    local format="markdown"
    local fail_on_gap=0
    local summary_only=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json) format="json"; shift;;
            --summary) summary_only=1; shift;;
            --fail-on-gap) fail_on_gap=1; shift;;
            -h|--help)
                sed -n '1,12p' "$0" | sed 's/^# \?//'
                exit 0;;
            *)
                echo "unknown arg: $1" >&2; exit 2;;
        esac
    done

    cd "$(repo_root)"
    local scripts=(scripts/run_rgc_*.sh)
    local total=${#scripts[@]}
    local env_yes=0 manifest_yes=0 repro_yes=0 all_three=0 none=0
    local rows=()

    for s in "${scripts[@]}"; do
        local name; name="$(basename "$s")"
        local e; e=$(emits_artifact "$s" "env.json")
        local m; m=$(emits_artifact "$s" "manifest.json")
        local r; r=$(emits_artifact "$s" "repro.lock")
        [[ "$e" == "yes" ]] && env_yes=$((env_yes+1))
        [[ "$m" == "yes" ]] && manifest_yes=$((manifest_yes+1))
        [[ "$r" == "yes" ]] && repro_yes=$((repro_yes+1))
        if [[ "$e" == "yes" && "$m" == "yes" && "$r" == "yes" ]]; then
            all_three=$((all_three+1))
        elif [[ "$e" == "no" && "$m" == "no" && "$r" == "no" ]]; then
            none=$((none+1))
        fi
        rows+=("${name}|${e}|${m}|${r}")
    done

    if [[ $summary_only -eq 1 ]]; then
        printf 'total_gates: %d\nenv_json_emitters: %d\nmanifest_json_emitters: %d\nrepro_lock_emitters: %d\nfull_triple_emitters: %d\nno_emission: %d\n' \
            "$total" "$env_yes" "$manifest_yes" "$repro_yes" "$all_three" "$none"
    elif [[ "$format" == "json" ]]; then
        for row in "${rows[@]}"; do
            IFS='|' read -r name e m r <<<"$row"
            jq -n \
                --arg script "$name" \
                --arg env "$e" \
                --arg manifest "$m" \
                --arg repro "$r" \
                '{script: $script, env_json: ($env == "yes"), manifest_json: ($manifest == "yes"), repro_lock: ($repro == "yes")}'
        done
    else
        echo "| Gate Script | env.json | manifest.json | repro.lock |"
        echo "|---|---|---|---|"
        for row in "${rows[@]}"; do
            IFS='|' read -r name e m r <<<"$row"
            echo "| ${name} | ${e} | ${m} | ${r} |"
        done
        echo ""
        echo "Summary: ${total} gates total — ${env_yes} emit env.json, ${manifest_yes} emit manifest.json, ${repro_yes} emit repro.lock, ${all_three} emit all three, ${none} emit none."
    fi

    if [[ $fail_on_gap -eq 1 ]]; then
        local gaps=$((total - all_three))
        if [[ $gaps -gt 0 ]]; then
            echo "FAIL: ${gaps} gate(s) missing at least one artifact" >&2
            exit 1
        fi
    fi
}

main "$@"
