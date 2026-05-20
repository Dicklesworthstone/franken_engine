#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
report_path="${script_dir}/sample_reconciliation_report.json"
repair_path="${script_dir}/repair_artifact.json"

jq -e --slurpfile repair "${repair_path}" '
  def hex64: type == "string" and test("^[0-9a-f]{64}$");

  . as $report
  | $repair[0] as $repair_artifact
  | ($report.schema_id == "franken-engine.anti-entropy-trust-reconciliation.example.v1")
  and ($report.capability_number == 9)
  and ($report.strategy == "iblt_then_deterministic_fallback")
  and ($report.fallback_triggered == true)
  and ($report.repair_artifact == "repair_artifact.json")
  and ($report.object_scope == ["checkpoint_marker", "evidence_entry", "revocation_event"])
  and ($report.iblt_attempt.result == "peel_failed")
  and ($report.iblt_attempt.remaining_cells > 0)
  and (($report.local_only | sort) == $report.local_only)
  and (($report.remote_only | sort) == $report.remote_only)
  and all($report.local_only[]; hex64)
  and all($report.remote_only[]; hex64)
  and ($report.content_hash_hex | hex64)
  and any($report.events[]; .event == "reconcile_fallback" and .fallback_triggered == true)
  and any($report.events[]; .event == "fallback_executed" and .objects_transferred == (($report.local_only | length) + ($report.remote_only | length)))
  and ($repair_artifact.schema_id == "franken-engine.anti-entropy-repair-artifact.example.v1")
  and ($repair_artifact.reconciliation_id == $report.reconciliation_id)
  and ($repair_artifact.trace_id == $report.trace_id)
  and ($repair_artifact.machine_verifiable == true)
  and ($repair_artifact.mutation_policy == "fixture_only_no_live_state_mutation")
  and ($repair_artifact.inputs.sorted_hash_lists == true)
  and ($repair_artifact.inputs.epoch_id == $report.epoch_id)
  and (($repair_artifact.repair_actions | length) == (($report.local_only | length) + ($report.remote_only | length)))
  and ($repair_artifact.determinism_checks.object_hashes_sorted == true)
  and ($repair_artifact.determinism_checks.duration_ms == 0)
  and ($repair_artifact.signature_hex | hex64)
' "${report_path}" > /dev/null

echo "verified anti-entropy trust reconciliation fixture: deterministic fallback repair artifact is linked and machine-verifiable"
