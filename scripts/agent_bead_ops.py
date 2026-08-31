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
RESULT_SCHEMA = "franken-engine.agent-bead-ops-result.v1"
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
    if operation not in {"show", "claim", "close"}:
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
    if expected is not None and expected not in {"open", "in_progress", "blocked", "closed"}:
        raise BeadOpsError("expected_before_status is not recognized")
    if operation == "claim" and assignee is None:
        raise BeadOpsError("claim requires assignee")
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


def issue_from_payload(payload: Any) -> dict[str, Any]:
    candidate = payload
    if isinstance(candidate, dict) and isinstance(candidate.get("issue"), dict):
        candidate = candidate["issue"]
    if isinstance(candidate, dict) and isinstance(candidate.get("issues"), list):
        issues = candidate["issues"]
        if len(issues) == 1 and isinstance(issues[0], dict):
            candidate = issues[0]
    if isinstance(candidate, list):
        if len(candidate) != 1 or not isinstance(candidate[0], dict):
            raise BeadOpsError("br show returned an unexpected issue list")
        candidate = candidate[0]
    if not isinstance(candidate, dict):
        raise BeadOpsError("br show returned an unexpected JSON shape")
    return candidate


def issue_status(issue: dict[str, Any]) -> str | None:
    value = issue.get("status")
    return value if isinstance(value, str) else None


def issue_assignees(issue: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for key in ("assignee", "assigned_to"):
        value = issue.get(key)
        if isinstance(value, str) and value:
            values.add(value)
        elif isinstance(value, list):
            values.update(item for item in value if isinstance(item, str) and item)
    value = issue.get("assignees")
    if isinstance(value, list):
        values.update(item for item in value if isinstance(item, str) and item)
    return values


def git_revision(repo_root: Path, commands: list[dict[str, Any]]) -> str:
    completed = run(["git", "rev-parse", "HEAD"], cwd=repo_root, commands=commands)
    return completed.stdout.strip()


def br_json(br: str, args: list[str], repo_root: Path, commands: list[dict[str, Any]]) -> Any:
    completed = run([br, *args, "--json"], cwd=repo_root, commands=commands)
    return parse_json_stdout(completed, f"br {' '.join(args)}")


def execute(
    request: dict[str, Any], repo_root: Path, br: str, commands: list[dict[str, Any]]
) -> dict[str, Any]:
    source_revision = git_revision(repo_root, commands)
    run([br, "--version"], cwd=repo_root, commands=commands)
    run([br, "sync", "--import-only"], cwd=repo_root, commands=commands)

    bead_id = request["bead_id"]
    before_payload = br_json(br, ["show", bead_id], repo_root, commands)
    before = issue_from_payload(before_payload)
    before_status = issue_status(before)
    expected = request.get("expected_before_status")
    if expected is not None and before_status != expected:
        raise BeadOpsError(
            f"bead {bead_id} status is {before_status!r}, expected {expected!r}; refusing stale mutation"
        )

    operation = request["operation"]
    operation_result: Any = None
    mutation_applied = False
    if operation == "show":
        pass
    elif operation == "claim":
        assignee = request["assignee"].strip()
        if before_status == "closed":
            raise BeadOpsError(f"cannot claim closed bead {bead_id}")
        if before_status != "in_progress" or assignee not in issue_assignees(before):
            operation_result = br_json(
                br,
                ["update", bead_id, "--status", "in_progress", "--assignee", assignee],
                repo_root,
                commands,
            )
            mutation_applied = True
    elif operation == "close":
        if before_status != "closed":
            operation_result = br_json(
                br,
                ["close", bead_id, "--reason", request["reason"].strip()],
                repo_root,
                commands,
            )
            mutation_applied = True

    if mutation_applied:
        run([br, "sync", "--flush-only"], cwd=repo_root, commands=commands)

    after_payload = br_json(br, ["show", bead_id], repo_root, commands)
    after = issue_from_payload(after_payload)
    after_status = issue_status(after)
    if operation == "claim" and after_status != "in_progress":
        raise BeadOpsError(f"claim did not leave bead {bead_id} in_progress")
    if operation == "close" and after_status != "closed":
        raise BeadOpsError(f"close did not leave bead {bead_id} closed")

    return {
        "schema_version": RESULT_SCHEMA,
        "request_id": request["request_id"],
        "request_sha256": hashlib.sha256(canonical_json_bytes(request)).hexdigest(),
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "source_revision": source_revision,
        "operation": operation,
        "bead_id": bead_id,
        "mutation_applied": mutation_applied,
        "before": before,
        "operation_result": operation_result,
        "after": after,
        "commands": commands,
        "status": "pass",
        "error": None,
    }


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
    repo_root = args.repo_root.resolve()
    commands: list[dict[str, Any]] = []
    try:
        request = validate_request(load_json(args.request.resolve()))
        result = execute(request, repo_root, args.br, commands)
        write_result(args.result.resolve(), result)
        return 0
    except Exception as exc:
        failure = {
            "schema_version": RESULT_SCHEMA,
            "request_id": None,
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "source_revision": None,
            "operation": None,
            "bead_id": None,
            "mutation_applied": False,
            "before": None,
            "operation_result": None,
            "after": None,
            "commands": commands,
            "status": "fail_closed",
            "error": str(exc),
        }
        try:
            raw = load_json(args.request.resolve())
            if isinstance(raw, dict):
                failure["request_id"] = raw.get("request_id")
                failure["operation"] = raw.get("operation")
                failure["bead_id"] = raw.get("bead_id")
                failure["request_sha256"] = hashlib.sha256(canonical_json_bytes(raw)).hexdigest()
        except Exception:
            pass
        write_result(args.result.resolve(), failure)
        print(f"agent bead operation failed closed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
