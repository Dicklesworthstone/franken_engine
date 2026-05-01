#!/usr/bin/env bash
set -euo pipefail

# Proof artifact bundle doctor for bd-mtpwv.
#
# Validates a proof artifact bundle conforms to the bd-1k59y contract.
# Catches missing manifest fields, malformed events.jsonl, broken hash chains, etc.

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

bundle_dir="${1:-}"
mode="${2:-check}"

usage() {
    cat <<EOF
Usage: $0 <bundle_directory> [mode]

Validates a proof artifact bundle against the cd3d2b4d contract.

Arguments:
  bundle_directory  Path to proof artifact bundle to validate
  mode             Validation mode: 'check' (default) or 'repair'

The bundle directory must contain:
  - manifest.json (required)
  - report.json (required)
  - events.jsonl (required)
  - commands.txt (required)
  - report.md (optional but recommended)

Example:
  $0 artifacts/proof_suite/20260501T123456Z check
EOF
}

if [[ -z "$bundle_dir" ]]; then
    echo "Error: bundle directory required" >&2
    usage >&2
    exit 1
fi

if [[ ! -d "$bundle_dir" ]]; then
    echo "Error: bundle directory does not exist: $bundle_dir" >&2
    exit 1
fi

echo "🩺 Proof Artifact Bundle Doctor"
echo "   Bundle: $bundle_dir"
echo "   Mode: $mode"
echo ""

# Track validation results
errors=0
warnings=0
checks=0

check_result() {
    local check_name="$1"
    local status="$2"
    local message="${3:-}"

    checks=$((checks + 1))

    case "$status" in
        "pass")
            echo "✅ $check_name"
            ;;
        "warn")
            warnings=$((warnings + 1))
            echo "⚠️  $check_name: $message"
            ;;
        "fail")
            errors=$((errors + 1))
            echo "❌ $check_name: $message"
            ;;
    esac
}

# Check required files exist
manifest_path="$bundle_dir/manifest.json"
report_path="$bundle_dir/report.json"
events_path="$bundle_dir/events.jsonl"
commands_path="$bundle_dir/commands.txt"
markdown_path="$bundle_dir/report.md"

check_result "Manifest file exists" \
    "$(if [[ -f "$manifest_path" ]]; then echo "pass"; else echo "fail"; fi)" \
    "manifest.json is required"

check_result "Report file exists" \
    "$(if [[ -f "$report_path" ]]; then echo "pass"; else echo "fail"; fi)" \
    "report.json is required"

check_result "Events file exists" \
    "$(if [[ -f "$events_path" ]]; then echo "pass"; else echo "fail"; fi)" \
    "events.jsonl is required"

check_result "Commands file exists" \
    "$(if [[ -f "$commands_path" ]]; then echo "pass"; else echo "fail"; fi)" \
    "commands.txt is required"

check_result "Markdown report exists" \
    "$(if [[ -f "$markdown_path" ]]; then echo "pass"; else echo "warn"; fi)" \
    "report.md is recommended for human readability"

# Validate JSON files if they exist
if [[ -f "$manifest_path" ]]; then
    if jq empty < "$manifest_path" >/dev/null 2>&1; then
        check_result "Manifest JSON validity" "pass"

        # Check required manifest fields
        schema_version=$(jq -r '.schema_version // ""' "$manifest_path")
        if [[ "$schema_version" == "franken-engine.proof-artifact-manifest.v1" ]]; then
            check_result "Manifest schema version" "pass"
        else
            check_result "Manifest schema version" "fail" "expected franken-engine.proof-artifact-manifest.v1, got: $schema_version"
        fi

        # Check other required fields
        bundle_id=$(jq -r '.bundle_id // ""' "$manifest_path")
        if [[ -n "$bundle_id" ]]; then
            check_result "Manifest bundle_id field" "pass"
        else
            check_result "Manifest bundle_id field" "fail" "bundle_id is required"
        fi

        generated_utc=$(jq -r '.generated_utc // ""' "$manifest_path")
        if [[ -n "$generated_utc" && "$generated_utc" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
            check_result "Manifest timestamp format" "pass"
        else
            check_result "Manifest timestamp format" "fail" "generated_utc must be ISO 8601 format"
        fi

        status=$(jq -r '.status // ""' "$manifest_path")
        if [[ "$status" == "pass" || "$status" == "fail" || "$status" == "skip" ]]; then
            check_result "Manifest status field" "pass"
        else
            check_result "Manifest status field" "fail" "status must be pass/fail/skip, got: $status"
        fi

    else
        check_result "Manifest JSON validity" "fail" "manifest.json contains invalid JSON"
    fi
fi

if [[ -f "$report_path" ]]; then
    if jq empty < "$report_path" >/dev/null 2>&1; then
        check_result "Report JSON validity" "pass"

        # Check if report has a schema_version
        report_schema=$(jq -r '.schema_version // ""' "$report_path")
        if [[ -n "$report_schema" ]]; then
            check_result "Report schema version" "pass"
        else
            check_result "Report schema version" "warn" "schema_version field is recommended"
        fi

    else
        check_result "Report JSON validity" "fail" "report.json contains invalid JSON"
    fi
fi

# Validate events.jsonl if it exists
if [[ -f "$events_path" ]]; then
    event_line_count=0
    invalid_events=0

    while IFS= read -r line; do
        if [[ -z "$line" ]]; then
            continue
        fi

        event_line_count=$((event_line_count + 1))

        if ! jq empty <<< "$line" >/dev/null 2>&1; then
            invalid_events=$((invalid_events + 1))
            continue
        fi

        # Check required event fields
        schema_version=$(jq -r '.schema_version // ""' <<< "$line")
        if [[ "$schema_version" != "franken-engine.proof-artifact-event.v1" ]]; then
            invalid_events=$((invalid_events + 1))
        fi

    done < "$events_path"

    if [[ $event_line_count -gt 0 ]]; then
        check_result "Events file format" "pass" "found $event_line_count events"
    else
        check_result "Events file format" "warn" "events.jsonl is empty"
    fi

    if [[ $invalid_events -eq 0 ]]; then
        check_result "Event JSON validity" "pass"
    else
        check_result "Event JSON validity" "fail" "$invalid_events/$event_line_count events have invalid JSON or schema"
    fi
fi

# Validate file size constraints
if [[ -f "$events_path" ]]; then
    events_size=$(stat -f%z "$events_path" 2>/dev/null || stat -c%s "$events_path" 2>/dev/null || echo 0)
    if [[ $events_size -gt 10485760 ]]; then # 10MB
        check_result "Events file size" "warn" "events.jsonl is large (${events_size} bytes), consider splitting"
    else
        check_result "Events file size" "pass"
    fi
fi

# Check hash consistency if manifest contains file hashes
if [[ -f "$manifest_path" ]] && jq -e '.artifact_hashes' "$manifest_path" >/dev/null 2>&1; then
    events_hash_expected=$(jq -r '.artifact_hashes.events_sha256 // ""' "$manifest_path")
    commands_hash_expected=$(jq -r '.artifact_hashes.commands_sha256 // ""' "$manifest_path")

    if [[ -n "$events_hash_expected" && -f "$events_path" ]]; then
        events_hash_actual=$(proof_contract_sha256_file "$events_path")
        if [[ "$events_hash_expected" == "$events_hash_actual" ]]; then
            check_result "Events hash integrity" "pass"
        else
            check_result "Events hash integrity" "fail" "hash mismatch (expected: $events_hash_expected, actual: $events_hash_actual)"
        fi
    fi

    if [[ -n "$commands_hash_expected" && -f "$commands_path" ]]; then
        commands_hash_actual=$(proof_contract_sha256_file "$commands_path")
        if [[ "$commands_hash_expected" == "$commands_hash_actual" ]]; then
            check_result "Commands hash integrity" "pass"
        else
            check_result "Commands hash integrity" "fail" "hash mismatch (expected: $commands_hash_expected, actual: $commands_hash_actual)"
        fi
    fi
fi

# Check bundle completeness
total_files=$(find "$bundle_dir" -type f | wc -l)
if [[ $total_files -ge 4 ]]; then
    check_result "Bundle completeness" "pass" "$total_files files in bundle"
else
    check_result "Bundle completeness" "warn" "only $total_files files in bundle (minimum 4 recommended)"
fi

# Generate doctor report
echo ""
echo "📋 Validation Summary:"
echo "   Checks performed: $checks"
echo "   Errors: $errors"
echo "   Warnings: $warnings"

if [[ $errors -eq 0 && $warnings -eq 0 ]]; then
    verdict="healthy"
    echo "   Verdict: ✅ Bundle is healthy"
elif [[ $errors -eq 0 ]]; then
    verdict="healthy-with-warnings"
    echo "   Verdict: ⚠️  Bundle is healthy with warnings"
else
    verdict="unhealthy"
    echo "   Verdict: ❌ Bundle has errors"
fi

# Generate doctor report JSON
doctor_report_path="$bundle_dir/doctor_report.json"
jq -n \
  --arg schema_version "franken-engine.proof-artifact-doctor-report.v1" \
  --arg bundle_dir "$bundle_dir" \
  --arg mode "$mode" \
  --arg verdict "$verdict" \
  --argjson checks_performed "$checks" \
  --argjson errors_found "$errors" \
  --argjson warnings_found "$warnings" \
  '{
    schema_version: $schema_version,
    bundle_dir: $bundle_dir,
    mode: $mode,
    verdict: $verdict,
    summary: {
      checks_performed: $checks_performed,
      errors_found: $errors_found,
      warnings_found: $warnings_found
    },
    generated_at_utc: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
  }' > "$doctor_report_path"

echo ""
echo "📄 Doctor report: $doctor_report_path"

# Exit based on validation result
if [[ "$verdict" == "unhealthy" ]]; then
    echo ""
    echo "❌ Bundle validation failed - $errors errors found"
    exit 1
elif [[ "$verdict" == "healthy-with-warnings" ]]; then
    echo ""
    echo "⚠️  Bundle validation passed with warnings - $warnings warnings found"
    exit 0
else
    echo ""
    echo "✅ Bundle validation passed - no issues found"
    exit 0
fi