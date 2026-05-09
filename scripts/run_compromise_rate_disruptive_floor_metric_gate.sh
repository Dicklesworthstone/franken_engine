#!/usr/bin/env bash
set -euo pipefail

# Compromise rate disruptive-floor metric gate with Node and Bun denominators
#
# This script generates the red_team_compromise_rate_reduction metric artifact
# consumed by disruptive_floor_metric_gate.

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

mode="${1:-ci}"
input_path="${2:-crates/franken-engine/tests/fixtures/compromise_rate_disruptive_floor_metric_input_v1.json}"
output_dir="${3:-artifacts/compromise_rate_disruptive_floor_metric}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_dir="${output_dir}/${timestamp}"
report_path="${artifact_dir}/compromise_rate_metric_report.json"
manifest_path="${artifact_dir}/compromise_rate_metric_manifest.json"

bead_id="bd-1vwza"
component="compromise_rate_disruptive_floor_metric_gate"
schema_version="franken-engine.compromise-rate-disruptive-floor-metric-gate.v1"

mkdir -p "$artifact_dir"

if [[ "$mode" == "verify" ]]; then
  # Verification mode: validate existing artifact
  verify_path="${input_path}"
  if [[ ! -f "$verify_path" ]]; then
    echo "Error: Verification artifact not found: $verify_path" >&2
    exit 1
  fi

  echo "Verifying compromise rate metric artifact: $verify_path"

  # Basic JSON validation
  if ! jq empty < "$verify_path" 2>/dev/null; then
    echo "Error: Invalid JSON in artifact: $verify_path" >&2
    exit 1
  fi

  # Schema validation
  schema_version_actual="$(jq -r '.schema_version // empty' < "$verify_path")"
  if [[ "$schema_version_actual" != "$schema_version" ]]; then
    echo "Error: Schema version mismatch. Expected: $schema_version, Got: $schema_version_actual" >&2
    exit 1
  fi

  # Bead ID validation
  bead_id_actual="$(jq -r '.bead_id // empty' < "$verify_path")"
  if [[ "$bead_id_actual" != "$bead_id" ]]; then
    echo "Error: Bead ID mismatch. Expected: $bead_id, Got: $bead_id_actual" >&2
    exit 1
  fi

  echo "✓ Compromise rate metric artifact verified: $verify_path"
  exit 0
fi

if [[ ! -f "$input_path" ]]; then
  echo "Error: Input file not found: $input_path" >&2
  exit 1
fi

echo "Processing compromise rate metric input: $input_path"
echo "Output directory: $artifact_dir"

# Validate input JSON
if ! jq empty < "$input_path" 2>/dev/null; then
  echo "Error: Invalid JSON in input file: $input_path" >&2
  exit 1
fi

# Extract key values from input
scenario_set="$(jq -r '.scenario_set' < "$input_path")"
reduction_threshold_factor="$(jq -r '.reduction_threshold_factor' < "$input_path")"
evidence_count="$(jq -r '.evidence | length' < "$input_path")"
code_revision="$(jq -r '.code_revision' < "$input_path")"

echo "Scenario set: $scenario_set"
echo "Reduction threshold: ${reduction_threshold_factor}x"
echo "Evidence count: $evidence_count"

has_fictional_data="$(
  jq -r '
    any(.evidence[];
      ((.scenario_path // "") | startswith("/test/scenarios/")) or
      ((.output_path // "") | startswith("/test/output/")) or
      ((.verification_command // "") | test("verify_(compromise|malware|prototype|supply_chain)_results\\.sh")) or
      ((.reproducibility_command // "") | test("(run_phishing_campaign|inject_malware|pollute_prototypes|deploy_malicious_packages)\\.sh"))
    )
  ' < "$input_path"
)"

if [[ "$has_fictional_data" == "true" ]]; then
  data_quality="targeted"
  confidence_millionths=0
  coverage_millionths=0
  outcome_reason="placeholder_or_fictional_evidence_detected"
else
  data_quality="observed"
  confidence_millionths=950000
  coverage_millionths=900000
  outcome_reason="threshold_evaluated_from_live_evidence"
fi

# Compute report metrics from the supplied evidence rows. Fictional rows are
# still summarized for diagnostics, but they cannot produce a passing proof.

node_evidence_count="$(jq -r '[.evidence[] | select(.runtime_denominator == "node")] | length' < "$input_path")"
bun_evidence_count="$(jq -r '[.evidence[] | select(.runtime_denominator == "bun")] | length' < "$input_path")"

# Compute geometric mean for each denominator
if [[ "$node_evidence_count" -gt 0 ]]; then
  # Extract reduction ratios, take log, average, then exp to get geometric mean
  node_geometric_mean="$(jq -r '
    [.evidence[] | select(.runtime_denominator == "node") | .reduction_ratio_millionths] as $ratios |
    if ($ratios | length) > 0 then
      ($ratios | map(log) | add / length | exp | floor)
    else
      1000000
    end
  ' < "$input_path")"
else
  node_geometric_mean="1000000"  # 1x if no evidence
fi

if [[ "$bun_evidence_count" -gt 0 ]]; then
  bun_geometric_mean="$(jq -r '
    [.evidence[] | select(.runtime_denominator == "bun") | .reduction_ratio_millionths] as $ratios |
    if ($ratios | length) > 0 then
      ($ratios | map(log) | add / length | exp | floor)
    else
      1000000
    end
  ' < "$input_path")"
else
  bun_geometric_mean="1000000"  # 1x if no evidence
fi

# Weighted geometric mean (geometric mean of Node and Bun geometric means)
if [[ "$node_evidence_count" -gt 0 && "$bun_evidence_count" -gt 0 ]]; then
  weighted_reduction_ratio_millionths="$(echo "import math; print(int(math.sqrt($node_geometric_mean * $bun_geometric_mean)))" | python3)"
elif [[ "$node_evidence_count" -gt 0 ]]; then
  weighted_reduction_ratio_millionths="$node_geometric_mean"
elif [[ "$bun_evidence_count" -gt 0 ]]; then
  weighted_reduction_ratio_millionths="$bun_geometric_mean"
else
  weighted_reduction_ratio_millionths="1000000"  # 1x if no evidence
fi

# Determine outcome. Placeholder or fictional evidence is fail-closed even when
# its caller-supplied reduction ratios would otherwise meet the threshold.
threshold_millionths="$(( reduction_threshold_factor * 1000000 ))"
if [[ "$has_fictional_data" == "true" ]]; then
  overall_outcome="inconclusive"
elif [[ "$weighted_reduction_ratio_millionths" -ge "$threshold_millionths" ]]; then
  overall_outcome="pass"
else
  overall_outcome="fail"
fi

# Count passing evidence
passing_evidence_count="$(jq -r --argjson threshold "$threshold_millionths" '[.evidence[] | select(.reduction_ratio_millionths >= $threshold)] | length' < "$input_path")"

echo "Node evidence count: $node_evidence_count (geometric mean: $node_geometric_mean)"
echo "Bun evidence count: $bun_evidence_count (geometric mean: $bun_geometric_mean)"
echo "Weighted reduction ratio: $weighted_reduction_ratio_millionths millionths"
echo "Passing evidence: $passing_evidence_count / $evidence_count"
echo "Data quality: $data_quality"
echo "Overall outcome: $overall_outcome"

# Generate verification commands array
verification_commands="$(jq -r '[.evidence[].verification_command] | unique' < "$input_path")"

json_string() {
  jq -Rn --arg value "$1" '$value'
}

if [[ "$has_fictional_data" == "true" ]]; then
  uncertainty_notes="Contains placeholder or fictional red-team scenarios with non-existent paths. Baseline measurements require live integration. Geometric mean across $evidence_count scenarios. Status: TARGETED until real red-team scenarios are supplied."
else
  uncertainty_notes="Baseline measurements from live red-team integration. Geometric mean across $evidence_count scenarios."
fi
coverage_notes="Coverage: $node_evidence_count Node, $bun_evidence_count Bun scenarios. Threshold: ${reduction_threshold_factor}x reduction. Data quality: $data_quality."
uncertainty_notes_json="$(json_string "$uncertainty_notes")"
coverage_notes_json="$(json_string "$coverage_notes")"
outcome_reason_json="$(json_string "$outcome_reason")"

# Create report JSON
cat > "$report_path" <<EOF
{
  "schema_version": "$schema_version",
  "bead_id": "$bead_id",
  "overall_outcome": "$overall_outcome",
  "weighted_reduction_ratio_millionths": $weighted_reduction_ratio_millionths,
  "evidence_count": $evidence_count,
  "passing_evidence_count": $passing_evidence_count,
  "node_evidence_count": $node_evidence_count,
  "bun_evidence_count": $bun_evidence_count,
  "node_reduction_ratio_millionths": $node_geometric_mean,
  "bun_reduction_ratio_millionths": $bun_geometric_mean,
  "threshold_factor": $reduction_threshold_factor,
  "data_quality": "$data_quality",
  "fictional_evidence_detected": $has_fictional_data,
  "outcome_reason": $outcome_reason_json,
  "uncertainty_notes": $uncertainty_notes_json,
  "coverage_notes": $coverage_notes_json,
  "scenario_set": "$scenario_set",
  "code_revision": "$code_revision",
  "verification_commands": $verification_commands,
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# Compute report hash
report_hash="$(sha256sum "$report_path" | cut -d' ' -f1)"

# Create manifest for parent integrator consumption
cat > "$manifest_path" <<EOF
{
  "schema_version": "franken-engine.proof-artifact-manifest.v1",
  "bead_id": "$bead_id",
  "component": "$component",
  "artifact_type": "metric",
  "metric_id": "red_team_compromise_rate_reduction",
  "threshold": $threshold_millionths,
  "observed_value": $weighted_reduction_ratio_millionths,
  "unit": "x_rate_reduction",
  "baseline": "node_bun_red_team_baselines",
  "candidate": "frankenengine",
  "denominator_id": "node_and_bun",
  "scenario_set": "$scenario_set",
  "artifact_path": "$report_path",
  "artifact_hash": "$report_hash",
  "code_revision": "$code_revision",
  "freshness_days": $(jq -r '.max_freshness_days' < "$input_path"),
  "confidence_millionths": $confidence_millionths,
  "coverage_millionths": $coverage_millionths,
  "verification_command": "./scripts/run_compromise_rate_disruptive_floor_metric_gate.sh verify $report_path",
  "redaction_status": "none",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo "✓ Generated compromise rate metric report: $report_path"
echo "✓ Generated manifest: $manifest_path"
echo "✓ Report hash: $report_hash"

if [[ "$overall_outcome" != "pass" ]]; then
  echo "❌ Compromise rate metric gate FAILED: $outcome_reason (weighted reduction $weighted_reduction_ratio_millionths, threshold $threshold_millionths)"
  exit 1
else
  echo "✅ Compromise rate metric gate PASSED: weighted reduction $weighted_reduction_ratio_millionths >= threshold $threshold_millionths"
  exit 0
fi
