from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

HARNESS_SCHEMA = "franken-engine.red-team-harness-output.v1"
DETAILS_SCHEMA = "franken-engine.red-team-repeated-trial-details.v1"
TRANSCRIPT_SCHEMA = "franken-engine.red-team-repeated-trial-transcript.v1"
WITNESS_SCHEMA = "franken-engine.red-team-repeated-trial-witness.v1"
BLOCKER_SCHEMA = "franken-engine.red-team-repeated-trial-blocker.v1"
SCENARIO_SET = "red_team_security_critical_compromise_v1"
RUNTIME_ORDER = ("node", "bun", "frankenengine")
RUST_RUNTIME_NAMES = {"node": "node", "bun": "bun", "frankenengine": "franken_engine"}
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class AggregationBlocked(RuntimeError):
    def __init__(self, reason: str, remediation: str, detail: str | None = None) -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.remediation = remediation
        self.detail = detail or reason


@dataclass(frozen=True)
class TrialReceipt:
    trial_id: str
    runtime: str
    scenario_id: str
    attack_class: str
    attack_succeeded: bool
    duration_ms: int
    transcript_path: str
    transcript_hash: str
    witness_path: str
    witness_hash: str
    runtime_identity: dict[str, Any]
    script_path: str
    script_hash: str
    manifest_path: str
    manifest_hash: str


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


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
            handle.write(canonical_json(value) + "\n")
    os.replace(temporary, path)


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AggregationBlocked(
            "missing_trial_artifact",
            "Restore the missing receipt-bound trial artifact and rerun the full trial set",
            f"{label} does not exist: {path}",
        ) from exc
    except json.JSONDecodeError as exc:
        raise AggregationBlocked(
            "malformed_trial_artifact",
            "Repair or regenerate the malformed trial artifact; malformed JSON is not measurement evidence",
            f"{label} is invalid JSON: {path}: {exc}",
        ) from exc


def load_jsonl(path: Path, label: str) -> list[Any]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise AggregationBlocked(
            "missing_trial_artifact",
            "Restore the missing receipt-bound trial artifact and rerun the full trial set",
            f"{label} does not exist: {path}",
        ) from exc
    values: list[Any] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            values.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise AggregationBlocked(
                "malformed_trial_artifact",
                "Repair or regenerate the malformed trial artifact; malformed JSONL is not measurement evidence",
                f"{label} line {number} is invalid JSON: {path}: {exc}",
            ) from exc
    return values


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except FileNotFoundError as exc:
        raise AggregationBlocked(
            "missing_receipt_file",
            "Restore the referenced receipt file and rerun the full trial set",
            f"referenced file does not exist: {path}",
        ) from exc
    return digest.hexdigest()


def sha256_ref(path: Path) -> str:
    return f"sha256:{sha256_file(path)}"


def validate_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise AggregationBlocked(
            "invalid_receipt_hash",
            "Regenerate the trial bundle so every receipt uses a lowercase sha256:<64-hex> content hash",
            f"{label} is not a valid SHA-256 reference: {value!r}",
        )
    return value


def resolve_artifact(path_value: Any, root: Path, label: str) -> Path:
    if not isinstance(path_value, str) or not path_value.strip():
        raise AggregationBlocked(
            "missing_receipt_path",
            "Regenerate the trial bundle with explicit witness and transcript paths",
            f"{label} is empty",
        )
    path = Path(path_value)
    return path if path.is_absolute() else root / path


def root_relative(path: Path, root: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise AggregationBlocked(
            "artifact_outside_repository",
            "Place repeated-trial evidence under the repository artifact root so replay paths remain portable",
            f"artifact is outside repository root: {resolved}",
        ) from exc


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AggregationBlocked(
            "malformed_trial_artifact",
            "Regenerate the malformed receipt-bound trial artifact",
            f"{label} must be a JSON object",
        )
    return value


def verify_hash(path: Path, expected: Any, label: str) -> str:
    expected_hash = validate_sha256(expected, label)
    actual = sha256_ref(path)
    if actual != expected_hash:
        raise AggregationBlocked(
            "receipt_hash_mismatch",
            "Discard the mutated trial set and rerun every trial from clean runtime binaries",
            f"{label} hash mismatch for {path}: expected {expected_hash}, got {actual}",
        )
    return actual


def runtime_inventory_key(inventory: dict[str, Any]) -> str:
    runtimes = inventory.get("runtimes")
    if not isinstance(runtimes, list) or len(runtimes) != 3:
        raise AggregationBlocked(
            "invalid_runtime_inventory",
            "Regenerate each trial with exactly one identified Node, Bun, and FrankenEngine executable",
            "runtime inventory must contain exactly three runtimes",
        )
    by_name: dict[str, dict[str, Any]] = {}
    for raw in runtimes:
        runtime = require_object(raw, "runtime inventory entry")
        name = runtime.get("runtime")
        if name not in RUNTIME_ORDER or name in by_name:
            raise AggregationBlocked(
                "invalid_runtime_inventory",
                "Regenerate the trial set with unique Node, Bun, and FrankenEngine identities",
                f"invalid or duplicate runtime identity: {name!r}",
            )
        validate_sha256(runtime.get("executable_sha256"), f"{name} executable_sha256")
        by_name[name] = runtime
    missing = sorted(set(RUNTIME_ORDER) - set(by_name))
    if missing:
        raise AggregationBlocked(
            "invalid_runtime_inventory",
            "Regenerate the trial set with all required runtime identities",
            f"runtime inventory is missing: {', '.join(missing)}",
        )
    return canonical_json([by_name[name] for name in RUNTIME_ORDER])
