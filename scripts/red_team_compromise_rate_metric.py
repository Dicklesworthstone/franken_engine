#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

SCHEMA_PREFIX = "franken-engine.red-team-compromise-rate"
MAX_CAPTURE_BYTES = 131_072
INFINITE_REDUCTION_SENTINEL = 18_446_744_073_709_551_615
DEFAULT_TIMEOUT_SECONDS = 20.0
CANARY = "canary-token-for-local-test-only"


@dataclass(frozen=True)
class ScenarioSpec:
    scenario_id: str
    attack_class: str


SCENARIOS = (
    ScenarioSpec("environment_variable_exfiltration", "ambient_authority_escape"),
    ScenarioSpec("process_privilege_surface_probe", "ambient_authority_escape"),
    ScenarioSpec("prototype_pollution_capability_escape", "prototype_pollution"),
    ScenarioSpec("shell_command_injection_package_script", "ambient_authority_escape"),
    ScenarioSpec("supply_chain_backdoor_execution", "supply_chain_execution"),
)


class ComparatorBlocked(RuntimeError):
    def __init__(self, reason: str, remediation: str, detail: str | None = None) -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.remediation = remediation
        self.detail = detail or reason


@dataclass(frozen=True)
class RuntimeIdentity:
    runtime: str
    executable: Path
    executable_sha256: str
    version_command: tuple[str, ...]
    version_exit_code: int | None
    version_stdout: str
    version_stderr: str

    def to_json(self, root: Path) -> dict[str, Any]:
        return {
            "runtime": self.runtime,
            "executable_path": repo_relative(self.executable, root),
            "executable_sha256": f"sha256:{self.executable_sha256}",
            "version_command": list(self.version_command),
            "version_exit_code": self.version_exit_code,
            "version_stdout": self.version_stdout,
            "version_stderr": self.version_stderr,
        }


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    stdout_truncated: bool
    stderr_truncated: bool


@dataclass(frozen=True)
class Disposition:
    attack_succeeded: bool
    source: str


@dataclass(frozen=True)
class RuntimeReceipt:
    runtime: str
    disposition: Disposition
    transcript_path: Path
    transcript_sha256: str
    duration_ms: int
    command: tuple[str, ...]


class Comparator:
    def __init__(self, args: argparse.Namespace) -> None:
        self.root = args.root.resolve()
        self.bundle_dir = args.bundle_dir.resolve()
        self.scenario_dir = args.scenario_dir.resolve()
        self.variant = args.variant
        self.code_revision = args.code_revision
        self.verification_command = args.verification_command
        self.force_franken_compromise = args.force_franken_compromise
        self.timeout_seconds = args.timeout_seconds
        self.commands: list[tuple[str, ...]] = []
        self.runtime_identities: dict[str, RuntimeIdentity] = {}
        self.rows: list[dict[str, Any]] = []
        self.bundle_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> int:
        try:
            self._validate_scenarios()
            self._resolve_runtimes()
            self._write_runtime_inventory()
            self._execute_scenarios()
            return self._write_observed_bundle()
        except ComparatorBlocked as blocked:
            self._write_blocker_bundle(blocked)
            return 1
        except Exception as error:
            blocked = ComparatorBlocked(
                "comparator_internal_error",
                "Inspect the blocker detail, repair the comparator, and rerun without converting the failure into a containment result",
                f"{type(error).__name__}: {error}",
            )
            self._write_blocker_bundle(blocked)
            return 1

    def _validate_scenarios(self) -> None:
        if not self.scenario_dir.is_dir():
            raise ComparatorBlocked(
                "missing_real_red_team_scenarios",
                "Restore crates/franken-engine/tests/red_team_scenarios and the five required scripts/manifests before measuring compromise rate",
                f"scenario directory does not exist: {self.scenario_dir}",
            )
        for spec in SCENARIOS:
            script_path = self.scenario_dir / f"{spec.scenario_id}.js"
            manifest_path = self.scenario_dir / f"{spec.scenario_id}.manifest.json"
            if not script_path.is_file() or not manifest_path.is_file():
                raise ComparatorBlocked(
                    "missing_real_red_team_scenarios",
                    "Restore all five required scripts and matching manifests before measuring compromise rate",
                    f"missing script or manifest for {spec.scenario_id}",
                )
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise ComparatorBlocked(
                    "invalid_red_team_scenario_manifest",
                    "Repair the malformed scenario manifest before measuring compromise rate",
                    f"{manifest_path}: {error}",
                ) from error
            if manifest.get("name") != spec.scenario_id:
                raise ComparatorBlocked(
                    "invalid_red_team_scenario_manifest",
                    "Make each scenario manifest name match its script basename",
                    f"{manifest_path}: expected name {spec.scenario_id!r}",
                )
            payload = manifest.get("payload")
            if not isinstance(payload, dict) or payload.get("program") != script_path.name:
                raise ComparatorBlocked(
                    "invalid_red_team_scenario_manifest",
                    "Bind each scenario manifest payload.program to the exact measured script",
                    f"{manifest_path}: payload.program must equal {script_path.name!r}",
                )

    def _resolve_runtimes(self) -> None:
        franken = resolve_frankenengine(self.root)
        if franken is None:
            raise ComparatorBlocked(
                "frankenctl_unavailable",
                "Set FRANKENENGINE_BIN to a runnable frankenctl binary or build frankenctl before measuring compromise rate",
            )
        node = resolve_runtime("NODE_BIN", "node")
        if node is None:
            raise ComparatorBlocked(
                "node_unavailable",
                "Set NODE_BIN to a runnable Node.js binary or install Node.js before measuring the comparator baseline",
            )
        bun = resolve_runtime("BUN_BIN", "bun")
        if bun is None:
            raise ComparatorBlocked(
                "bun_unavailable",
                "Set BUN_BIN to a runnable Bun binary or install Bun before measuring the comparator baseline",
            )
        for runtime, executable in (("frankenengine", franken), ("node", node), ("bun", bun)):
            identity = identify_runtime(runtime, executable, self.timeout_seconds, self.root)
            self.runtime_identities[runtime] = identity
            self.commands.append(identity.version_command)

    def _write_runtime_inventory(self) -> None:
        write_json(
            self.bundle_dir / "runtime_inventory.json",
            {
                "schema_version": f"{SCHEMA_PREFIX}-runtime-inventory.v1",
                "code_revision": self.code_revision,
                "runtimes": [
                    self.runtime_identities[name].to_json(self.root)
                    for name in ("frankenengine", "node", "bun")
                ],
            },
        )

    def _execute_scenarios(self) -> None:
        pending_rows: list[dict[str, Any]] = []
        for index, spec in enumerate(SCENARIOS):
            script_path = self.scenario_dir / f"{spec.scenario_id}.js"
            manifest_path = self.scenario_dir / f"{spec.scenario_id}.manifest.json"
            receipts = {
                "node": self._run_reference_runtime(spec, "node", script_path, manifest_path),
                "bun": self._run_reference_runtime(spec, "bun", script_path, manifest_path),
                "frankenengine": self._run_frankenengine(spec, script_path, manifest_path),
            }
            witness_path = self.bundle_dir / "witnesses" / f"{spec.scenario_id}.json"
            witness = {
                "schema_version": f"{SCHEMA_PREFIX}-witness.v2",
                "scenario_id": spec.scenario_id,
                "attack_class": spec.attack_class,
                "security_critical": True,
                "measurement_status": "observed",
                "is_placeholder_data": False,
                "code_revision": self.code_revision,
                "script_path": repo_relative(script_path, self.root),
                "script_sha256": f"sha256:{sha256_file(script_path)}",
                "manifest_path": repo_relative(manifest_path, self.root),
                "manifest_sha256": f"sha256:{sha256_file(manifest_path)}",
                "runtime_receipts": {
                    name: {
                        "path": repo_relative(receipt.transcript_path, self.root),
                        "sha256": f"sha256:{receipt.transcript_sha256}",
                        "attack_succeeded": receipt.disposition.attack_succeeded,
                        "disposition_source": receipt.disposition.source,
                    }
                    for name, receipt in receipts.items()
                },
            }
            write_json(witness_path, witness)
            witness_hash = sha256_file(witness_path)
            measured_franken = receipts["frankenengine"].disposition.attack_succeeded
            effective_franken = measured_franken
            measurement_status = "observed"
            fixture: dict[str, Any] | None = None
            if self.force_franken_compromise and index == 0:
                effective_franken = True
                measurement_status = "negative_fixture"
                fixture = {
                    "kind": "forced_frankenengine_compromise",
                    "measured_attack_succeeded": measured_franken,
                    "effective_attack_succeeded": True,
                    "purpose": "prove the metric gate fails closed when the candidate is compromised",
                }
            row = {
                "schema_version": f"{SCHEMA_PREFIX}-scenario-row.v2",
                "scenario_id": spec.scenario_id,
                "attack_class": spec.attack_class,
                "security_critical": True,
                "measurement_status": measurement_status,
                "is_placeholder_data": False,
                "frankenengine_attacker_succeeded": effective_franken,
                "frankenengine_measured_attacker_succeeded": measured_franken,
                "node_attacker_succeeded": receipts["node"].disposition.attack_succeeded,
                "bun_attacker_succeeded": receipts["bun"].disposition.attack_succeeded,
                "runtime_receipts": {
                    name: {
                        "transcript_path": repo_relative(receipt.transcript_path, self.root),
                        "transcript_hash": f"sha256:{receipt.transcript_sha256}",
                        "disposition_source": receipt.disposition.source,
                    }
                    for name, receipt in receipts.items()
                },
                "witness_path": repo_relative(witness_path, self.root),
                "witness_hash": f"sha256:{witness_hash}",
                "replay_command": self.verification_command,
                "replay_exit_code": 0,
                "duration_ms": sum(receipt.duration_ms for receipt in receipts.values()),
                "negative_fixture": fixture,
            }
            pending_rows.append(row)
        self.rows = pending_rows

    def _run_reference_runtime(
        self,
        spec: ScenarioSpec,
        runtime: str,
        script_path: Path,
        manifest_path: Path,
    ) -> RuntimeReceipt:
        identity = self.runtime_identities[runtime]
        command = (
            (str(identity.executable), "run", str(script_path))
            if runtime == "bun"
            else (str(identity.executable), str(script_path))
        )
        result = execute_command(command, self.timeout_seconds, self.root)
        self.commands.append(result.command)
        disposition = explicit_disposition(
            result.stdout,
            scenario_id=spec.scenario_id,
            source_prefix=f"{runtime}.stdout",
            require_scenario=True,
        )
        if disposition is None:
            disposition = explicit_disposition(
                result.stderr,
                scenario_id=spec.scenario_id,
                source_prefix=f"{runtime}.stderr",
                require_scenario=True,
            )
        if disposition is None:
            raise ComparatorBlocked(
                f"{runtime}_probe_invalid",
                f"Make the {runtime} scenario emit a JSON object with matching scenario and boolean attack_succeeded",
                f"{spec.scenario_id}: no explicit disposition in {runtime} output (exit {result.exit_code})",
            )
        expected_exit = 0 if disposition.attack_succeeded else 1
        if result.exit_code != expected_exit:
            raise ComparatorBlocked(
                f"{runtime}_probe_invalid",
                f"Make the {runtime} scenario exit 0 on attack success and 1 on containment so transcript and process status agree",
                f"{spec.scenario_id}: attack_succeeded={disposition.attack_succeeded} but exit={result.exit_code}",
            )
        return self._write_runtime_transcript(
            spec, runtime, script_path, manifest_path, identity, result, disposition, None
        )

    def _run_frankenengine(
        self,
        spec: ScenarioSpec,
        script_path: Path,
        manifest_path: Path,
    ) -> RuntimeReceipt:
        identity = self.runtime_identities["frankenengine"]
        report_path = self.bundle_dir / "frankenengine_reports" / f"{spec.scenario_id}.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        command = (
            str(identity.executable),
            "run",
            "--input",
            str(script_path),
            "--extension-id",
            f"red-team-{spec.scenario_id}",
            "--goal",
            "script",
            "--out",
            str(report_path),
        )
        result = execute_command(command, self.timeout_seconds, self.root)
        self.commands.append(result.command)
        disposition = explicit_disposition(
            result.stdout,
            scenario_id=spec.scenario_id,
            source_prefix="frankenengine.stdout",
            require_scenario=False,
        )
        if disposition is None:
            disposition = explicit_disposition(
                result.stderr,
                scenario_id=spec.scenario_id,
                source_prefix="frankenengine.stderr",
                require_scenario=False,
            )
        report_payload: Any | None = None
        report_error: str | None = None
        if report_path.is_file():
            try:
                report_payload = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                report_error = str(error)
            if report_payload is not None:
                report_disposition = disposition_from_payloads(
                    ((report_payload, "frankenengine.report"),),
                    spec.scenario_id,
                    require_scenario=False,
                )
                if disposition is not None and report_disposition is not None:
                    if disposition.attack_succeeded != report_disposition.attack_succeeded:
                        raise ComparatorBlocked(
                            "frankenengine_probe_conflict",
                            "Make frankenctl stdout and its structured report agree on attack_succeeded",
                            f"{spec.scenario_id}: stdout/report dispositions conflict",
                        )
                elif report_disposition is not None:
                    disposition = report_disposition
        if disposition is None:
            combined = f"{result.stdout}\n{result.stderr}".lower()
            denial_markers = (
                "unauthorized flow detected",
                "capability denied:",
                "ambient authority denied",
            )
            if result.exit_code != 0 and any(marker in combined for marker in denial_markers):
                disposition = Disposition(False, "frankenengine.explicit_policy_denial")
        if disposition is None:
            detail = (
                f"{spec.scenario_id}: no explicit disposition (exit {result.exit_code})"
                if report_error is None
                else f"{spec.scenario_id}: malformed report ({report_error}) and no explicit disposition"
            )
            raise ComparatorBlocked(
                "frankenengine_probe_invalid",
                "Emit an explicit boolean attack_succeeded in the frankenctl report/output or a recognized policy-denial refusal; crashes, parser gaps, and malformed reports are not containment evidence",
                detail,
            )
        report_metadata = None
        if report_path.is_file():
            report_metadata = {
                "path": repo_relative(report_path, self.root),
                "sha256": f"sha256:{sha256_file(report_path)}",
                "parse_error": report_error,
            }
        return self._write_runtime_transcript(
            spec,
            "frankenengine",
            script_path,
            manifest_path,
            identity,
            result,
            disposition,
            report_metadata,
        )

    def _write_runtime_transcript(
        self,
        spec: ScenarioSpec,
        runtime: str,
        script_path: Path,
        manifest_path: Path,
        identity: RuntimeIdentity,
        result: CommandResult,
        disposition: Disposition,
        report_metadata: dict[str, Any] | None,
    ) -> RuntimeReceipt:
        transcript_path = self.bundle_dir / "transcripts" / f"{spec.scenario_id}.{runtime}.json"
        transcript = {
            "schema_version": f"{SCHEMA_PREFIX}-runtime-transcript.v2",
            "scenario_id": spec.scenario_id,
            "attack_class": spec.attack_class,
            "runtime": runtime,
            "code_revision": self.code_revision,
            "script_path": repo_relative(script_path, self.root),
            "script_sha256": f"sha256:{sha256_file(script_path)}",
            "manifest_path": repo_relative(manifest_path, self.root),
            "manifest_sha256": f"sha256:{sha256_file(manifest_path)}",
            "runtime_identity": identity.to_json(self.root),
            "command": list(result.command),
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "stdout_truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
            "duration_ms": result.duration_ms,
            "attack_succeeded": disposition.attack_succeeded,
            "disposition_source": disposition.source,
            "measurement_status": "observed",
            "is_placeholder_data": False,
            "frankenengine_report": report_metadata,
        }
        write_json(transcript_path, transcript)
        return RuntimeReceipt(
            runtime=runtime,
            disposition=disposition,
            transcript_path=transcript_path,
            transcript_sha256=sha256_file(transcript_path),
            duration_ms=result.duration_ms,
            command=result.command,
        )

    def _write_observed_bundle(self) -> int:
        scenarios_path = self.bundle_dir / "scenarios.jsonl"
        write_jsonl(scenarios_path, self.rows)
        scenarios_total = len(self.rows)
        engine_successes = sum(bool(row["frankenengine_attacker_succeeded"]) for row in self.rows)
        node_successes = sum(bool(row["node_attacker_succeeded"]) for row in self.rows)
        bun_successes = sum(bool(row["bun_attacker_succeeded"]) for row in self.rows)
        engine_rate = rate_millionths(engine_successes, scenarios_total)
        node_rate = rate_millionths(node_successes, scenarios_total)
        bun_rate = rate_millionths(bun_successes, scenarios_total)
        baseline_rate = min(node_rate, bun_rate)
        reduction = reduction_factor(baseline_rate, engine_rate)
        threshold_met = baseline_rate > 0 and (
            engine_rate == 0 or reduction >= 10
        )
        fixture_applied = any(row["measurement_status"] == "negative_fixture" for row in self.rows)
        decision = "pass" if threshold_met and not fixture_applied else "fail"
        reason = (
            "red_team_compromise_rate_reduction_verified"
            if decision == "pass"
            else "negative_fixture_candidate_compromise"
            if fixture_applied
            else "compromise_rate_reduction_below_baseline"
        )
        failure_count = 0 if decision == "pass" else 1
        details_path = self.bundle_dir / "compromise_details.json"
        details = {
            "schema_version": f"{SCHEMA_PREFIX}-metric-gate.details.v2",
            "component": "red_team_compromise_rate_metric_gate",
            "bead_id": "bd-0lim8",
            "legacy_bead_id": "bd-1vwza",
            "claim_id": "FE-CLAIM-011",
            "code_revision": self.code_revision,
            "scenario_set": "red_team_security_critical_compromise_v1",
            "scenarios_total": scenarios_total,
            "attacks_successful": engine_successes,
            "compromise_millionths": engine_rate,
            "baseline_compromise_millionths_node": node_rate,
            "baseline_compromise_millionths_bun": bun_rate,
            "baseline_reference_millionths": baseline_rate,
            "baseline_reference_policy": "minimum_of_executed_node_and_bun_rates",
            "reduction_factor_x": reduction,
            "unbounded_reduction": baseline_rate > 0 and engine_rate == 0,
            "runtime_inventory_path": repo_relative(self.bundle_dir / "runtime_inventory.json", self.root),
            "runtime_inventory_hash": f"sha256:{sha256_file(self.bundle_dir / 'runtime_inventory.json')}",
            "scenarios": self.rows,
        }
        write_json(details_path, details)
        details_hash = sha256_file(details_path)
        measurement_status = "negative_fixture" if fixture_applied else "observed"
        metric_path = self.bundle_dir / "metric_artifact.json"
        write_json(
            metric_path,
            {
                "metric_id": "red_team_compromise_rate_reduction",
                "threshold": 10,
                "observed_value": reduction,
                "measurement_status": measurement_status,
                "has_placeholder_data": False,
                "placeholder_scenario_count": 0,
                "unit": "x_rate_reduction",
                "baseline": "executed_node_and_bun",
                "candidate": "franken_engine",
                "denominator_id": f"node_and_bun:red_team_scenarios:{scenarios_total}",
                "scenario_set": "red_team_security_critical_compromise_v1",
                "artifact_path": repo_relative(details_path, self.root),
                "artifact_hash": f"sha256:{details_hash}",
                "code_revision": self.code_revision,
                "freshness_days": 0,
                "confidence_millionths": 1_000_000,
                "coverage_millionths": 1_000_000,
                "verification_command": self.verification_command,
                "redaction_status": "redacted",
                "remediation_note": None,
            },
        )
        events = [
            {
                "schema_version": "franken-engine.proof-artifact-event.v1",
                "event_name": "red_team_compromise_rate_metric.scenario_checked",
                "severity": "error" if row["frankenengine_attacker_succeeded"] else "info",
                "step_id": row["scenario_id"],
                "command_id": f"red-team:{row['scenario_id']}",
                "metric_id": "red_team_compromise_rate_reduction",
                "proof_manifest_id": f"red_team_compromise_rate_metric_gate:{self.variant}",
                "scenario_id": row["scenario_id"],
                "attack_class": row["attack_class"],
                "attack_class_label": row["attack_class"],
                "engine_compromised": row["frankenengine_attacker_succeeded"],
                "node_compromised": row["node_attacker_succeeded"],
                "bun_compromised": row["bun_attacker_succeeded"],
                "replayable_witness": True,
                "scenarios_total": scenarios_total,
                "attacks_successful": engine_successes,
                "compromise_millionths": engine_rate,
                "baseline_compromise_millionths_node": node_rate,
                "baseline_compromise_millionths_bun": bun_rate,
                "baseline_reference_millionths": baseline_rate,
                "reduction_factor_x": reduction,
                "threshold_factor_x": 10,
                "command": row["replay_command"],
                "exit_code": row["replay_exit_code"],
                "decision": "compromised" if row["frankenengine_attacker_succeeded"] else "contained",
                "reason": "attacker_succeeded_against_franken_engine"
                if row["frankenengine_attacker_succeeded"]
                else "attacker_contained_by_franken_engine",
                "artifact_path": repo_relative(details_path, self.root),
                "artifact_hash": f"sha256:{details_hash}",
                "code_revision": self.code_revision,
                "duration_ms": row["duration_ms"],
                "freshness_days": 0,
                "redaction_status": "redacted",
                "remediation": "none",
                "runtime_receipts": row["runtime_receipts"],
            }
            for row in self.rows
        ]
        events_path = self.bundle_dir / "events.jsonl"
        write_jsonl(events_path, events)
        commands_path = self.bundle_dir / "commands.txt"
        commands = [self.verification_command, *(shlex.join(command) for command in self.commands)]
        commands_path.write_text("\n".join(commands) + "\n", encoding="utf-8")
        report_path = self.bundle_dir / "metric_report.json"
        write_json(
            report_path,
            {
                "schema_version": f"{SCHEMA_PREFIX}-metric-gate.v2",
                "component": "red_team_compromise_rate_metric_gate",
                "bead_id": "bd-0lim8",
                "legacy_bead_id": "bd-1vwza",
                "claim_id": "FE-CLAIM-011",
                "metric_artifact": json.loads(metric_path.read_text(encoding="utf-8")),
                "scenarios_total": scenarios_total,
                "attacks_successful": engine_successes,
                "compromise_millionths": engine_rate,
                "baseline_compromise_millionths_node": node_rate,
                "baseline_compromise_millionths_bun": bun_rate,
                "baseline_reference_millionths": baseline_rate,
                "reduction_factor_x": reduction,
                "replayable_witness_scenarios": scenarios_total,
                "replay_coverage_millionths": 1_000_000,
                "decision": "pass" if decision == "pass" else "fail_closed",
                "reason": reason,
                "compromised_scenario_ids": [
                    row["scenario_id"] for row in self.rows if row["frankenengine_attacker_succeeded"]
                ],
                "unreplayable_scenario_ids": [],
                "events": events,
            },
        )
        summary_path = self.bundle_dir / "summary.md"
        summary_path.write_text(
            "\n".join(
                (
                    "# Red-Team Compromise-Rate Metric Gate",
                    "",
                    f"- Variant: `{self.variant}`",
                    f"- Decision: `{decision}`",
                    f"- Measurement status: `{measurement_status}`",
                    f"- FrankenEngine compromise rate: `{engine_successes}` / `{scenarios_total}` (`{engine_rate}` millionths)",
                    f"- Node compromise rate: `{node_rate}` millionths (executed)",
                    f"- Bun compromise rate: `{bun_rate}` millionths (executed)",
                    f"- Conservative reference baseline: `{baseline_rate}` millionths",
                    f"- Reduction: `{reduction}`x",
                    "- Confidence: `100%` only because all three runtime lanes emitted explicit, hashed execution receipts",
                    f"- Metric artifact: `{repo_relative(metric_path, self.root)}`",
                    f"- Runtime inventory: `{repo_relative(self.bundle_dir / 'runtime_inventory.json', self.root)}`",
                    "",
                )
            ),
            encoding="utf-8",
        )
        write_json(
            self.bundle_dir / "bundle_status.json",
            {
                "status": decision,
                "failure_count": failure_count,
                "exit_code": 0 if decision == "pass" else 1,
                "reason": reason,
            },
        )
        return 0 if decision == "pass" else 1

    def _write_blocker_bundle(self, blocked: ComparatorBlocked) -> None:
        self.bundle_dir.mkdir(parents=True, exist_ok=True)
        scenarios_path = self.bundle_dir / "scenarios.jsonl"
        scenarios_path.write_text("", encoding="utf-8")
        commands_path = self.bundle_dir / "commands.txt"
        commands = [self.verification_command, *(shlex.join(command) for command in self.commands)]
        commands_path.write_text("\n".join(commands) + "\n", encoding="utf-8")
        details_path = self.bundle_dir / "compromise_details.json"
        details = {
            "schema_version": f"{SCHEMA_PREFIX}-metric-gate.details.v2",
            "component": "red_team_compromise_rate_metric_gate",
            "bead_id": "bd-0lim8",
            "legacy_bead_id": "bd-1vwza",
            "claim_id": "FE-CLAIM-011",
            "code_revision": self.code_revision,
            "scenario_set": "red_team_security_critical_compromise_v1",
            "scenarios_total": 0,
            "attacks_successful": 0,
            "compromise_millionths": 0,
            "baseline_compromise_millionths_node": 0,
            "baseline_compromise_millionths_bun": 0,
            "baseline_reference_millionths": 0,
            "reduction_factor_x": 0,
            "blocker": {
                "reason": blocked.reason,
                "detail": redact_text(blocked.detail),
                "remediation": blocked.remediation,
                "placeholder_rows_emitted": False,
            },
            "scenarios": [],
        }
        write_json(details_path, details)
        details_hash = sha256_file(details_path)
        metric_path = self.bundle_dir / "metric_artifact.json"
        write_json(
            metric_path,
            {
                "metric_id": "red_team_compromise_rate_reduction",
                "threshold": 10,
                "observed_value": 0,
                "measurement_status": "blocked",
                "has_placeholder_data": False,
                "placeholder_scenario_count": 0,
                "unit": "x_rate_reduction",
                "baseline": "executed_node_and_bun",
                "candidate": "franken_engine",
                "denominator_id": "node_and_bun:red_team_scenarios:0",
                "scenario_set": "red_team_security_critical_compromise_v1",
                "artifact_path": repo_relative(details_path, self.root),
                "artifact_hash": f"sha256:{details_hash}",
                "code_revision": self.code_revision,
                "freshness_days": 0,
                "confidence_millionths": 0,
                "coverage_millionths": 0,
                "verification_command": self.verification_command,
                "redaction_status": "redacted",
                "blocker_reason": blocked.reason,
                "remediation_note": blocked.remediation,
            },
        )
        event = {
            "schema_version": "franken-engine.proof-artifact-event.v1",
            "event_name": "red_team_compromise_rate_metric.blocked",
            "severity": "error",
            "step_id": "red_team_metric_prerequisite_check",
            "command_id": "red-team:metric-prerequisite-check",
            "metric_id": "red_team_compromise_rate_reduction",
            "proof_manifest_id": f"red_team_compromise_rate_metric_gate:{self.variant}",
            "scenario_id": None,
            "attack_class": None,
            "attack_class_label": None,
            "engine_compromised": None,
            "node_compromised": None,
            "bun_compromised": None,
            "replayable_witness": False,
            "scenarios_total": 0,
            "attacks_successful": 0,
            "compromise_millionths": 0,
            "baseline_compromise_millionths_node": 0,
            "baseline_compromise_millionths_bun": 0,
            "baseline_reference_millionths": 0,
            "reduction_factor_x": 0,
            "threshold_factor_x": 10,
            "command": "prerequisite check",
            "exit_code": 1,
            "decision": "blocked",
            "reason": blocked.reason,
            "detail": redact_text(blocked.detail),
            "artifact_path": repo_relative(details_path, self.root),
            "artifact_hash": f"sha256:{details_hash}",
            "code_revision": self.code_revision,
            "duration_ms": 0,
            "freshness_days": 0,
            "redaction_status": "redacted",
            "remediation": blocked.remediation,
        }
        events_path = self.bundle_dir / "events.jsonl"
        write_jsonl(events_path, (event,))
        report_path = self.bundle_dir / "metric_report.json"
        write_json(
            report_path,
            {
                "schema_version": f"{SCHEMA_PREFIX}-metric-gate.v2",
                "component": "red_team_compromise_rate_metric_gate",
                "bead_id": "bd-0lim8",
                "legacy_bead_id": "bd-1vwza",
                "claim_id": "FE-CLAIM-011",
                "metric_artifact": json.loads(metric_path.read_text(encoding="utf-8")),
                "scenarios_total": 0,
                "attacks_successful": 0,
                "compromise_millionths": 0,
                "baseline_compromise_millionths_node": 0,
                "baseline_compromise_millionths_bun": 0,
                "baseline_reference_millionths": 0,
                "reduction_factor_x": 0,
                "replayable_witness_scenarios": 0,
                "replay_coverage_millionths": 0,
                "decision": "fail_closed",
                "reason": blocked.reason,
                "blocker": {
                    "reason": blocked.reason,
                    "detail": redact_text(blocked.detail),
                    "remediation": blocked.remediation,
                    "placeholder_rows_emitted": False,
                },
                "compromised_scenario_ids": [],
                "unreplayable_scenario_ids": [],
                "events": [event],
            },
        )
        (self.bundle_dir / "summary.md").write_text(
            "\n".join(
                (
                    "# Red-Team Compromise-Rate Metric Gate",
                    "",
                    f"- Variant: `{self.variant}`",
                    "- Decision: `fail_closed`",
                    "- Status: `blocked`",
                    f"- Blocker: `{blocked.reason}`",
                    f"- Detail: `{redact_text(blocked.detail)}`",
                    f"- Remediation: `{blocked.remediation}`",
                    "- Placeholder rows emitted: `false`",
                    f"- Metric artifact: `{repo_relative(metric_path, self.root)}`",
                    "",
                )
            ),
            encoding="utf-8",
        )
        write_json(
            self.bundle_dir / "bundle_status.json",
            {
                "status": "blocked",
                "failure_count": 1,
                "exit_code": 1,
                "reason": blocked.reason,
            },
        )


def resolve_runtime(env_name: str, fallback: str) -> Path | None:
    explicit = os.environ.get(env_name)
    if explicit:
        return resolve_executable(explicit)
    discovered = shutil.which(fallback)
    return Path(discovered).resolve() if discovered else None


def resolve_frankenengine(root: Path) -> Path | None:
    explicit = os.environ.get("FRANKENENGINE_BIN")
    if explicit:
        return resolve_executable(explicit)
    if os.environ.get("RED_TEAM_COMPROMISE_RATE_DISABLE_FRANKENCTL_AUTO_DISCOVERY", "false").lower() == "true":
        return None
    target_dir = os.environ.get("CARGO_TARGET_DIR")
    candidates = []
    if target_dir:
        candidates.append(Path(target_dir) / "debug" / "frankenctl")
    candidates.append(root / "target" / "debug" / "frankenctl")
    discovered = shutil.which("frankenctl")
    if discovered:
        candidates.append(Path(discovered))
    for candidate in candidates:
        resolved = resolve_executable(str(candidate))
        if resolved is not None:
            return resolved
    return None


def resolve_executable(candidate: str) -> Path | None:
    path = Path(candidate).expanduser()
    if not path.is_absolute() and len(path.parts) == 1:
        discovered = shutil.which(candidate)
        if discovered:
            path = Path(discovered)
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        return None
    return resolved


def identify_runtime(runtime: str, executable: Path, timeout_seconds: float, root: Path) -> RuntimeIdentity:
    command = (str(executable), "--version")
    try:
        result = execute_command(command, min(timeout_seconds, 5.0), root)
        return RuntimeIdentity(
            runtime=runtime,
            executable=executable,
            executable_sha256=sha256_file(executable),
            version_command=command,
            version_exit_code=result.exit_code,
            version_stdout=result.stdout,
            version_stderr=result.stderr,
        )
    except ComparatorBlocked as blocked:
        return RuntimeIdentity(
            runtime=runtime,
            executable=executable,
            executable_sha256=sha256_file(executable),
            version_command=command,
            version_exit_code=None,
            version_stdout="",
            version_stderr=redact_text(blocked.detail),
        )


def execute_command(command: Iterable[str], timeout_seconds: float, cwd: Path) -> CommandResult:
    command_tuple = tuple(str(part) for part in command)
    env = os.environ.copy()
    env["FRANKENENGINE_REDTEAM_CANARY"] = CANARY
    started = time.monotonic_ns()
    try:
        completed = subprocess.run(
            command_tuple,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=False,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise ComparatorBlocked(
            "runtime_probe_timeout",
            "Increase RED_TEAM_COMPROMISE_RATE_TIMEOUT_SECONDS only after diagnosing the hung runtime; a timeout is not containment",
            f"command timed out after {timeout_seconds}s: {shlex.join(command_tuple)}",
        ) from error
    except OSError as error:
        raise ComparatorBlocked(
            "runtime_probe_execution_failed",
            "Repair the runtime executable or its host dependencies; an execution failure is not containment",
            f"unable to execute {shlex.join(command_tuple)}: {error}",
        ) from error
    duration_ms = max(0, (time.monotonic_ns() - started) // 1_000_000)
    stdout, stdout_truncated = sanitize_capture(completed.stdout)
    stderr, stderr_truncated = sanitize_capture(completed.stderr)
    return CommandResult(
        command=command_tuple,
        exit_code=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
    )


def sanitize_capture(payload: bytes) -> tuple[str, bool]:
    truncated = len(payload) > MAX_CAPTURE_BYTES
    text = payload[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
    return redact_text(text), truncated


def redact_text(text: str) -> str:
    redacted = text.replace(CANARY, "<redacted-canary>")
    redacted = re.sub(
        r"(?i)([A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|KEY)[A-Za-z0-9_]*=)[^\s]+",
        r"\1<redacted>",
        redacted,
    )
    redacted = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1<redacted>", redacted)
    return redacted


def explicit_disposition(
    text: str,
    scenario_id: str,
    source_prefix: str,
    require_scenario: bool,
) -> Disposition | None:
    payloads = tuple((payload, source) for payload, source in json_payloads(text, source_prefix))
    return disposition_from_payloads(payloads, scenario_id, require_scenario)


def json_payloads(text: str, source_prefix: str) -> Iterable[tuple[Any, str]]:
    stripped = text.strip()
    if not stripped:
        return ()
    payloads: list[tuple[Any, str]] = []
    try:
        payloads.append((json.loads(stripped), f"{source_prefix}.document"))
    except json.JSONDecodeError:
        pass
    for index, line in enumerate(text.splitlines(), start=1):
        candidate = line.strip()
        if not candidate:
            continue
        try:
            payloads.append((json.loads(candidate), f"{source_prefix}.line[{index}]"))
        except json.JSONDecodeError:
            continue
    unique: list[tuple[Any, str]] = []
    seen: set[str] = set()
    for payload, source in payloads:
        key = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            unique.append((payload, source))
    return tuple(unique)


def disposition_from_payloads(
    payloads: Iterable[tuple[Any, str]],
    scenario_id: str,
    require_scenario: bool,
) -> Disposition | None:
    found: list[Disposition] = []
    for payload, source in payloads:
        for value, value_source, payload_scenario in find_attack_values(payload, source):
            if require_scenario and payload_scenario != scenario_id:
                continue
            if payload_scenario is not None and payload_scenario != scenario_id:
                continue
            found.append(Disposition(value, value_source))
    if not found:
        return None
    values = {item.attack_succeeded for item in found}
    if len(values) != 1:
        raise ComparatorBlocked(
            "runtime_probe_conflict",
            "Emit exactly one consistent attack_succeeded disposition per runtime/scenario transcript",
            f"{scenario_id}: conflicting dispositions at {', '.join(item.source for item in found)}",
        )
    return Disposition(found[0].attack_succeeded, ",".join(item.source for item in found))


def find_attack_values(payload: Any, source: str, inherited_scenario: str | None = None) -> Iterable[tuple[bool, str, str | None]]:
    if isinstance(payload, dict):
        scenario = payload.get("scenario") if isinstance(payload.get("scenario"), str) else inherited_scenario
        if isinstance(payload.get("scenario_id"), str):
            scenario = payload["scenario_id"]
        value = payload.get("attack_succeeded")
        if isinstance(value, bool):
            yield value, f"{source}.attack_succeeded", scenario
        console_output = payload.get("console_output")
        if isinstance(console_output, list):
            for index, item in enumerate(console_output):
                if isinstance(item, str):
                    try:
                        nested = json.loads(item)
                    except json.JSONDecodeError:
                        continue
                    yield from find_attack_values(nested, f"{source}.console_output[{index}]", scenario)
        for key, value in payload.items():
            if key in {"attack_succeeded", "console_output", "stdout", "stderr"}:
                continue
            if isinstance(value, (dict, list)):
                yield from find_attack_values(value, f"{source}.{key}", scenario)
    elif isinstance(payload, list):
        for index, item in enumerate(payload):
            yield from find_attack_values(item, f"{source}[{index}]", inherited_scenario)


def rate_millionths(successes: int, total: int) -> int:
    return 0 if total == 0 else successes * 1_000_000 // total


def reduction_factor(baseline: int, candidate: int) -> int:
    if baseline == 0 and candidate == 0:
        return 1
    if baseline == 0:
        return 0
    if candidate == 0:
        return INFINITE_REDUCTION_SENTINEL
    return baseline // candidate


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repo_relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def write_jsonl(path: Path, values: Iterable[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        for value in values:
            handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    os.replace(temporary, path)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute receipt-bound Node/Bun/FrankenEngine red-team comparisons")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--scenario-dir", type=Path, required=True)
    parser.add_argument("--variant", required=True)
    parser.add_argument("--code-revision", required=True)
    parser.add_argument("--verification-command", required=True)
    parser.add_argument("--force-franken-compromise", action="store_true")
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=float(os.environ.get("RED_TEAM_COMPROMISE_RATE_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)),
    )
    args = parser.parse_args(argv)
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    return Comparator(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
