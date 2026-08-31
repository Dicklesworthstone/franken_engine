from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from red_team_trial_common import (
    AggregationBlocked,
    RUNTIME_ORDER,
    TrialReceipt,
    canonical_json,
    load_json,
    load_jsonl,
    require_object,
    resolve_artifact,
    root_relative,
    runtime_inventory_key,
    validate_sha256,
    verify_hash,
)


def verify_trial(
    root: Path, trial_dir: Path, expected_revision: str
) -> tuple[list[TrialReceipt], dict[str, Any], dict[str, Any]]:
    trial_id = trial_dir.name
    status = require_object(
        load_json(trial_dir / "bundle_status.json", f"{trial_id} bundle status"),
        "bundle status",
    )
    if status.get("status") not in {"pass", "fail"}:
        raise AggregationBlocked(
            "blocked_or_incomplete_trial",
            "Repair the blocked runtime probe and rerun the complete repeated-trial campaign",
            f"{trial_id} has non-measurement status {status.get('status')!r}",
        )
    inventory_path = trial_dir / "runtime_inventory.json"
    inventory = require_object(
        load_json(inventory_path, f"{trial_id} runtime inventory"), "runtime inventory"
    )
    if inventory.get("code_revision") != expected_revision:
        raise AggregationBlocked(
            "mixed_code_revision",
            "Rerun all trials against one exact commit SHA; mixed revisions cannot share a denominator",
            f"{trial_id} revision {inventory.get('code_revision')!r} != {expected_revision!r}",
        )
    runtime_inventory_key(inventory)
    rows = load_jsonl(trial_dir / "scenarios.jsonl", f"{trial_id} scenario rows")
    if not rows:
        raise AggregationBlocked(
            "missing_scenario_rows",
            "Rerun the trial; an empty scenario inventory is not evidence",
            f"{trial_id} contains no scenario rows",
        )
    receipts: list[TrialReceipt] = []
    seen: set[str] = set()
    for raw_row in rows:
        row = require_object(raw_row, f"{trial_id} scenario row")
        scenario_id = row.get("scenario_id")
        attack_class = row.get("attack_class")
        if not isinstance(scenario_id, str) or not scenario_id or scenario_id in seen:
            raise AggregationBlocked(
                "invalid_scenario_inventory",
                "Regenerate the trial with one unique row per security-critical scenario",
                f"{trial_id} has invalid or duplicate scenario_id {scenario_id!r}",
            )
        seen.add(scenario_id)
        if not isinstance(attack_class, str) or not attack_class:
            raise AggregationBlocked(
                "invalid_scenario_inventory",
                "Regenerate the trial with an explicit attack class for every scenario",
                f"{trial_id}/{scenario_id} has no attack_class",
            )
        if row.get("security_critical") is not True:
            raise AggregationBlocked(
                "noncritical_scenario_row",
                "Keep the FE-CLAIM-011 denominator restricted to declared security-critical scenarios",
                f"{trial_id}/{scenario_id} is not marked security_critical",
            )
        if row.get("measurement_status") != "observed" or row.get("is_placeholder_data") is not False:
            raise AggregationBlocked(
                "nonobserved_trial_row",
                "Rerun the campaign without fixtures, placeholders, or assumed comparator outcomes",
                f"{trial_id}/{scenario_id} is not an observed non-placeholder row",
            )
        negative_fixture = row.get("negative_fixture")
        if negative_fixture is not None and negative_fixture is not False:
            raise AggregationBlocked(
                "negative_fixture_in_trial_set",
                "Remove fail-closed drill fixtures and rerun the real repeated-trial campaign",
                f"{trial_id}/{scenario_id} contains negative_fixture data",
            )
        witness_path = resolve_artifact(
            row.get("witness_path"), root, f"{trial_id}/{scenario_id} witness_path"
        )
        witness_hash = verify_hash(
            witness_path, row.get("witness_hash"), f"{trial_id}/{scenario_id} witness_hash"
        )
        witness = require_object(
            load_json(witness_path, f"{trial_id}/{scenario_id} witness"), "witness"
        )
        if witness.get("scenario_id") != scenario_id or witness.get("attack_class") != attack_class:
            raise AggregationBlocked(
                "witness_binding_mismatch",
                "Discard the mismatched evidence and rerun the campaign",
                f"{trial_id}/{scenario_id} witness identity does not match its scenario row",
            )
        runtime_receipts = require_object(
            row.get("runtime_receipts"), f"{trial_id}/{scenario_id} runtime_receipts"
        )
        for runtime in RUNTIME_ORDER:
            receipt = require_object(
                runtime_receipts.get(runtime), f"{trial_id}/{scenario_id}/{runtime} receipt"
            )
            transcript_path = resolve_artifact(
                receipt.get("transcript_path"),
                root,
                f"{trial_id}/{scenario_id}/{runtime} transcript_path",
            )
            transcript_hash = verify_hash(
                transcript_path,
                receipt.get("transcript_hash"),
                f"{trial_id}/{scenario_id}/{runtime} transcript_hash",
            )
            transcript = require_object(
                load_json(transcript_path, f"{trial_id}/{scenario_id}/{runtime} transcript"),
                "runtime transcript",
            )
            if transcript.get("scenario_id") != scenario_id or transcript.get("attack_class") != attack_class:
                raise AggregationBlocked(
                    "transcript_binding_mismatch",
                    "Discard the mismatched runtime receipt and rerun the campaign",
                    f"{trial_id}/{scenario_id}/{runtime} transcript identity mismatch",
                )
            if transcript.get("runtime") != runtime or transcript.get("code_revision") != expected_revision:
                raise AggregationBlocked(
                    "transcript_runtime_mismatch",
                    "Rerun the campaign against one identified runtime set and one exact code revision",
                    f"{trial_id}/{scenario_id}/{runtime} transcript runtime or revision mismatch",
                )
            if transcript.get("measurement_status") != "observed" or transcript.get("is_placeholder_data") is not False:
                raise AggregationBlocked(
                    "nonobserved_runtime_transcript",
                    "Rerun the runtime probe without fixtures or placeholders",
                    f"{trial_id}/{scenario_id}/{runtime} transcript is not observed evidence",
                )
            attack_succeeded = transcript.get("attack_succeeded")
            if not isinstance(attack_succeeded, bool):
                raise AggregationBlocked(
                    "ambiguous_runtime_disposition",
                    "Make every runtime receipt carry one explicit boolean attack_succeeded disposition",
                    f"{trial_id}/{scenario_id}/{runtime} has no boolean disposition",
                )
            row_key = f"{runtime}_attacker_succeeded"
            measured_key = (
                "frankenengine_measured_attacker_succeeded"
                if runtime == "frankenengine"
                else row_key
            )
            if row.get(measured_key) is not attack_succeeded:
                raise AggregationBlocked(
                    "scenario_transcript_disposition_mismatch",
                    "Discard the inconsistent trial bundle and rerun the campaign",
                    f"{trial_id}/{scenario_id}/{runtime} row and transcript dispositions disagree",
                )
            duration_ms = transcript.get("duration_ms")
            if not isinstance(duration_ms, int) or duration_ms < 0:
                raise AggregationBlocked(
                    "invalid_runtime_duration",
                    "Regenerate the runtime receipt with a non-negative duration_ms",
                    f"{trial_id}/{scenario_id}/{runtime} duration is invalid",
                )
            identity = require_object(transcript.get("runtime_identity"), "runtime identity")
            validate_sha256(
                identity.get("executable_sha256"), f"{trial_id}/{runtime} executable_sha256"
            )
            receipts.append(
                TrialReceipt(
                    trial_id=trial_id,
                    runtime=runtime,
                    scenario_id=scenario_id,
                    attack_class=attack_class,
                    attack_succeeded=attack_succeeded,
                    duration_ms=duration_ms,
                    transcript_path=root_relative(transcript_path, root),
                    transcript_hash=transcript_hash,
                    witness_path=root_relative(witness_path, root),
                    witness_hash=witness_hash,
                    runtime_identity=identity,
                    script_path=str(transcript.get("script_path", "")),
                    script_hash=validate_sha256(
                        transcript.get("script_sha256"),
                        f"{trial_id}/{scenario_id}/{runtime} script_sha256",
                    ),
                    manifest_path=str(transcript.get("manifest_path", "")),
                    manifest_hash=validate_sha256(
                        transcript.get("manifest_sha256"),
                        f"{trial_id}/{scenario_id}/{runtime} manifest_sha256",
                    ),
                )
            )
    return receipts, inventory, status


def verify_trial_set(
    receipts: list[TrialReceipt], minimum_trials: int
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    scenario_ids = sorted({receipt.scenario_id for receipt in receipts})
    if not scenario_ids:
        raise AggregationBlocked(
            "empty_trial_set",
            "Run the receipt-bound comparator before aggregating",
            "no trial receipts were found",
        )
    per_key: dict[tuple[str, str], list[TrialReceipt]] = defaultdict(list)
    for receipt in receipts:
        per_key[(receipt.scenario_id, receipt.runtime)].append(receipt)
    metadata: dict[str, dict[str, Any]] = {}
    for scenario_id in scenario_ids:
        classes = {receipt.attack_class for receipt in receipts if receipt.scenario_id == scenario_id}
        if len(classes) != 1:
            raise AggregationBlocked(
                "attack_class_drift",
                "Use one stable attack-class declaration for each scenario across all trials",
                f"{scenario_id} attack classes drifted: {sorted(classes)}",
            )
        script_bindings = {
            (receipt.script_path, receipt.script_hash, receipt.manifest_path, receipt.manifest_hash)
            for receipt in receipts
            if receipt.scenario_id == scenario_id
        }
        if len(script_bindings) != 1:
            raise AggregationBlocked(
                "scenario_definition_drift",
                "Rerun all attempts against one immutable script and manifest revision",
                f"{scenario_id} script or manifest binding changed across trials",
            )
        metadata[scenario_id] = {
            "attack_class": next(iter(classes)),
            "script_binding": next(iter(script_bindings)),
        }
        for runtime in RUNTIME_ORDER:
            entries = per_key.get((scenario_id, runtime), [])
            if len(entries) < minimum_trials:
                raise AggregationBlocked(
                    "insufficient_trials",
                    "Run at least 100 independently receipted attempts per runtime and scenario",
                    f"{scenario_id}/{runtime} has {len(entries)} attempts, below required {minimum_trials}",
                )
            identities = {canonical_json(entry.runtime_identity) for entry in entries}
            if len(identities) != 1:
                raise AggregationBlocked(
                    "runtime_identity_drift",
                    "Rerun all attempts against one immutable executable per runtime",
                    f"{scenario_id}/{runtime} executable identity changed across trials",
                )
    trial_ids = {receipt.trial_id for receipt in receipts}
    expected = {(scenario_id, runtime) for scenario_id in scenario_ids for runtime in RUNTIME_ORDER}
    for trial_id in trial_ids:
        keys = {(receipt.scenario_id, receipt.runtime) for receipt in receipts if receipt.trial_id == trial_id}
        if keys != expected:
            raise AggregationBlocked(
                "incomplete_trial_matrix",
                "Rerun the complete scenario/runtime matrix for every trial; do not combine partial denominators",
                f"{trial_id} missing={sorted(expected - keys)} extra={sorted(keys - expected)}",
            )
    return scenario_ids, metadata
