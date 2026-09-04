#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REQUEST_SCHEMA = "franken-engine.agent-bead-ops-request.v1"
RESULT_SCHEMA = "franken-engine.agent-bead-ops-result.v2"
BEAD_ID_RE = re.compile(r"^bd-[a-z0-9]+(?:\.[a-z0-9]+)*$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ALLOWED_KEYS = {
    "schema_version",
    "request_id",
    "operation",
    "bead_id",
    "assignee",
    "reason",
    "expected_before_status",
}


class BeadOpsError(RuntimeError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BeadOpsError(f"request file does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BeadOpsError(f"request file is not valid JSON: {exc}") from exc


def validate_request(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise BeadOpsError("request must be a JSON object")
    unknown = sorted(set(raw) - ALLOWED_KEYS)
    if unknown:
        raise BeadOpsError(f"request contains unknown keys: {', '.join(unknown)}")
    if raw.get("schema_version") != REQUEST_SCHEMA:
        raise BeadOpsError(f"schema_version must be {REQUEST_SCHEMA!r}")
    request_id = raw.get("request_id")
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise BeadOpsError("request_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
    operation = raw.get("operation")
    if not isinstance(operation, str) or operation not in {"show", "claim", "close"}:
        raise BeadOpsError("operation must be one of: show, claim, close")
    bead_id = raw.get("bead_id")
    if not isinstance(bead_id, str) or not BEAD_ID_RE.fullmatch(bead_id):
        raise BeadOpsError("bead_id is not a valid bd-* identifier")
    assignee = raw.get("assignee")
    if assignee is not None and (not isinstance(assignee, str) or not assignee.strip()):
        raise BeadOpsError("assignee must be a non-empty string when present")
    reason = raw.get("reason")
    if reason is not None and (not isinstance(reason, str) or not reason.strip()):
        raise BeadOpsError("reason must be a non-empty string when present")
    expected = raw.get("expected_before_status")
    if expected is not None and (
        not isinstance(expected, str) or expected not in {"open", "in_progress", "blocked", "closed"}
    ):
        raise BeadOpsError("expected_before_status is not recognized")
    if operation == "claim" and (assignee is None or assignee.strip() == "unassigned"):
        raise BeadOpsError("claim requires a named assignee, not the unassigned sentinel")
    if operation == "close" and reason is None:
        raise BeadOpsError("close requires reason")
    return dict(raw)


def redact(text: str, limit: int = 32_768) -> str:
    text = re.sub(r"(?i)(token|secret|password|credential|authorization)=\S+", r"\1=<redacted>", text)
    text = re.sub(r"(?i)Bearer\s+\S+", "Bearer <redacted>", text)
    if len(text) > limit:
        return text[:limit] + f"\n<truncated {len(text) - limit} bytes>"
    return text


def command_record(argv: list[str], completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return {
        "argv": argv,
        "exit_code": completed.returncode,
        "stdout": redact(completed.stdout),
        "stderr": redact(completed.stderr),
    }


def run(argv: list[str], *, cwd: Path, commands: list[dict[str, Any]], check: bool = True) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("NO_COLOR", "1")
    completed = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, check=False)
    commands.append(command_record(argv, completed))
    if check and completed.returncode != 0:
        raise BeadOpsError(
            f"command failed ({completed.returncode}): {' '.join(argv)}\n{redact(completed.stderr or completed.stdout)}"
        )
    return completed


def parse_json_stdout(completed: subprocess.CompletedProcess[str], label: str) -> Any:
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise BeadOpsError(f"{label} did not emit valid JSON: {exc}") from exc


def issue_from_payload(payload: Any, expected_id: str | None = None) -> dict[str, Any]:
    candidate = payload
    if isinstance(candidate, dict) and "issue" in candidate:
        candidate = candidate["issue"]
    elif isinstance(candidate, dict) and "issues" in candidate:
        candidate = candidate["issues"]
    if isinstance(candidate, list):
        if len(candidate) != 1 or not isinstance(candidate[0], dict):
            raise BeadOpsError("br show returned an unexpected issue list")
        candidate = candidate[0]
    if not isinstance(candidate, dict):
        raise BeadOpsError("br show returned an unexpected JSON shape")
    if expected_id is not None and candidate.get("id") != expected_id:
        raise BeadOpsError(f"br show did not return requested bead {expected_id}")
    if not isinstance(candidate.get("status"), str) or not candidate["status"].strip():
        raise BeadOpsError("br show returned a missing or invalid status")
    return candidate


def issue_status(issue: dict[str, Any]) -> str | None:
    value = issue.get("status")
    return value if isinstance(value, str) else None


def issue_assignees(issue: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for key in ("assignee", "assigned_to", "assignees"):
        value = issue.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            candidates = [value]
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            candidates = value
        else:
            raise BeadOpsError(f"br show returned invalid {key}")
        values.update(
            item.strip() for item in candidates if item.strip() and item.strip() != "unassigned"
        )
    return values


def git_revision(repo_root: Path, commands: list[dict[str, Any]]) -> str:
    completed = run(["git", "rev-parse", "HEAD"], cwd=repo_root, commands=commands)
    return completed.stdout.strip()


def br_json(br: str, args: list[str], repo_root: Path, commands: list[dict[str, Any]]) -> Any:
    completed = run([br, *args, "--json"], cwd=repo_root, commands=commands)
    return parse_json_stdout(completed, f"br {' '.join(args)}")


def new_result(request: Any, commands: list[dict[str, Any]]) -> dict[str, Any]:
    result = {
        "schema_version": RESULT_SCHEMA,
        "request_id": None,
        "request_sha256": None,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "source_revision": None,
        "operation": None,
        "bead_id": None,
        "mutation_applied": False,
        "mutation_state": "not_attempted",
        "flush_completed": False,
        "before_payload": None,
        "before": None,
        "operation_result": None,
        "after_payload": None,
        "after": None,
        "commands": commands,
        "stage": "request",
        "status": "fail_closed",
        "error": None,
    }
    if isinstance(request, dict):
        for key in ("request_id", "operation", "bead_id"):
            result[key] = request.get(key)
        result["request_sha256"] = hashlib.sha256(canonical_json_bytes(request)).hexdigest()
    return result


def execute(
    request: dict[str, Any], repo_root: Path, br: str, commands: list[dict[str, Any]],
    *, evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = new_result(request, commands) if evidence is None else evidence
    result["stage"] = "source_revision"
    result["source_revision"] = git_revision(repo_root, commands)
    result["stage"] = "version"
    run([br, "--version"], cwd=repo_root, commands=commands)
    result["stage"] = "import"
    run([br, "sync", "--import-only"], cwd=repo_root, commands=commands)

    bead_id = request["bead_id"]
    result["stage"] = "observe_before"
    result["before_payload"] = br_json(br, ["show", bead_id], repo_root, commands)
    result["stage"] = "validate_before"
    before = issue_from_payload(result["before_payload"], bead_id)
    result["before"] = before
    before_status = issue_status(before)
    expected = request.get("expected_before_status")
    if expected is not None and before_status != expected:
        raise BeadOpsError(
            f"bead {bead_id} status is {before_status!r}, expected {expected!r}; refusing stale mutation"
        )

    operation = request["operation"]
    mutation_args: list[str] | None = None
    if operation == "claim":
        assignee = request["assignee"].strip()
        owners = issue_assignees(before)
        if before_status not in {"open", "in_progress"}:
            raise BeadOpsError(f"cannot claim bead {bead_id} with status {before_status!r}")
        if owners - {assignee}:
            raise BeadOpsError(f"cannot claim bead {bead_id} owned by another agent")
        if before_status == "in_progress" and owners != {assignee}:
            raise BeadOpsError(f"cannot adopt ownerless in-progress bead {bead_id}")
        if before_status != "in_progress":
            mutation_args = ["update", bead_id, "--claim", f"--actor={assignee}"]
    elif operation == "close":
        assignee = request.get("assignee")
        if assignee is not None and issue_assignees(before) - {assignee.strip()}:
            raise BeadOpsError(f"cannot close bead {bead_id} owned by another agent")
        if before_status != "closed":
            mutation_args = ["close", bead_id, "--reason", request["reason"].strip()]
    elif operation != "show":
        raise BeadOpsError(f"unsupported operation {operation!r}")

    if mutation_args is not None:
        result["stage"] = "mutate"
        result["mutation_state"] = "attempted_unknown"
        result["mutation_applied"] = None
        completed = run([br, *mutation_args, "--json"], cwd=repo_root, commands=commands)
        result["mutation_state"] = "command_succeeded"
        result["mutation_applied"] = True
        result["stage"] = "mutation_output"
        result["operation_result"] = parse_json_stdout(completed, f"br {' '.join(mutation_args)}")
        result["stage"] = "flush"
        run([br, "sync", "--flush-only"], cwd=repo_root, commands=commands)
        result["flush_completed"] = True

    result["stage"] = "observe_after"
    result["after_payload"] = br_json(br, ["show", bead_id], repo_root, commands)
    result["stage"] = "verify_after"
    after = issue_from_payload(result["after_payload"], bead_id)
    result["after"] = after
    after_status = issue_status(after)
    if operation == "claim" and (
        after_status != "in_progress" or issue_assignees(after) != {request["assignee"].strip()}
    ):
        raise BeadOpsError(f"claim did not leave bead {bead_id} in_progress with the requested owner")
    if operation == "close" and after_status != "closed":
        raise BeadOpsError(f"close did not leave bead {bead_id} closed")
    result["stage"] = "complete"
    result["status"] = "pass"
    return result


def write_result(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(result))


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply one strictly-scoped beads operation through the real br CLI")
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--br", default="br")
    args = parser.parse_args()
    try:
        request_path = args.request.resolve()
        result_path = args.result.resolve()
        if result_path == request_path or (
            result_path.exists() and request_path.exists() and result_path.samefile(request_path)
        ):
            raise BeadOpsError("result path must not overwrite the request")
        result_path.parent.mkdir(parents=True, exist_ok=True)
        if result_path.is_dir():
            raise BeadOpsError("result path must not be a directory")
    except (OSError, RuntimeError) as exc:
        print(f"cannot prepare bead operation result: {redact(str(exc))}", file=sys.stderr)
        return 1

    commands: list[dict[str, Any]] = []
    result = new_result(None, commands)
    try:
        raw = load_json(request_path)
        result = new_result(raw, commands)
        request = validate_request(raw)
        execute(request, args.repo_root.resolve(), args.br, commands, evidence=result)
    except Exception as exc:
        result["status"] = {
            "not_attempted": "fail_closed",
            "attempted_unknown": "mutation_unconfirmed",
            "command_succeeded": "partial_failure",
        }[result["mutation_state"]]
        result["error"] = redact(str(exc))

    try:
        write_result(result_path, result)
    except Exception as exc:
        print(
            f"cannot preserve bead operation result: {redact(str(exc))}; "
            f"mutation_state={result['mutation_state']}, stage={result['stage']}, "
            f"flush_completed={result['flush_completed']}",
            file=sys.stderr,
        )
        return 1
    if result["status"] != "pass":
        print(f"agent bead operation {result['status']}: {result['error']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
