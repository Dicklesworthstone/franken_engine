from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(os.environ.get("AGENT_BEAD_OPS_UNDER_TEST", Path(__file__).resolve().parents[1] / "agent_bead_ops.py"))
SPEC = importlib.util.spec_from_file_location("agent_bead_ops_under_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
OPS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OPS)

PROTOCOL_FIXTURE = r'''
import json
import sys
from pathlib import Path
root = Path(__file__).parent
args = sys.argv[1:]
with (root / "calls.jsonl").open("a") as out:
    out.write(json.dumps(args) + "\n")
config = json.loads((root / "fixture.json").read_text())
state = json.loads((root / "state.json").read_text())
if args == ["--version"]:
    print("br-protocol-fixture (not real br)")
elif args[:2] == ["sync", "--import-only"]:
    print("import fixture")
elif args[:2] == ["sync", "--flush-only"]:
    if config.get("fail_flush"):
        print("injected flush failure", file=sys.stderr)
        sys.exit(7)
    print("flush fixture")
elif args[0] == "show":
    counter = root / "shows.txt"
    count = int(counter.read_text()) if counter.exists() else 0
    counter.write_text(str(count + 1))
    if count and config.get("fail_after_read"):
        print("injected observation failure", file=sys.stderr)
        sys.exit(8)
    key = "before_payload" if count == 0 else "after_payload"
    print(json.dumps(config.get(key, state)))
elif args[0] in {"update", "close"}:
    if args[0] == "update":
        actor = next((arg.split("=", 1)[1] for arg in args if arg.startswith("--actor=")), None)
        if config.get("assign_before_update"):
            state.update(status="in_progress", assignee=config["assign_before_update"])
            (root / "state.json").write_text(json.dumps(state))
        if "--claim" in args:
            if config.get("claim_option_unavailable"):
                print("fixture: --claim unavailable", file=sys.stderr)
                sys.exit(2)
            if state.get("assignee") not in {None, "", actor}:
                print("fixture: conditional claim refused", file=sys.stderr)
                sys.exit(5)
        state["status"] = "in_progress"
        if not config.get("omit_owner_update"):
            state["assignee"] = actor if "--claim" in args else args[args.index("--assignee") + 1]
    else:
        state["status"] = "closed"
    (root / "state.json").write_text(json.dumps(state))
    if config.get("mutation_nonzero"):
        print("injected error after state change", file=sys.stderr)
        sys.exit(9)
    if config.get("invalid_mutation_json"):
        print("not JSON after state change")
    else:
        print(json.dumps(state))
else:
    print("unexpected fixture invocation", file=sys.stderr)
    sys.exit(99)
'''


def request(operation: str = "claim", **overrides: object) -> dict:
    result = {
        "schema_version": OPS.REQUEST_SCHEMA,
        "request_id": "unit-request-1",
        "operation": operation,
        "bead_id": "bd-unit1",
        "expected_before_status": "open",
    }
    if operation == "claim":
        result["assignee"] = "RepairAgent"
    if operation == "close":
        result["reason"] = "unit fixture only"
    result.update(overrides)
    return result


class FixtureCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="agent-bead-ops-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "--quiet", str(self.repo)], check=True, capture_output=True)
        subprocess.run([
            "git", "-C", str(self.repo), "-c", "user.name=Protocol Test",
            "-c", "user.email=protocol-test@example.invalid", "commit", "--allow-empty", "--quiet", "-m", "fixture",
        ], check=True, capture_output=True)
        self.br = self.root / "br-protocol-fixture"
        self.br.write_text(f"#!{sys.executable}\n" + PROTOCOL_FIXTURE)
        self.br.chmod(0o755)
        self.request_path = self.root / "request.json"
        self.result_path = self.root / "result.json"

    def invoke(self, req: dict | None = None, state: dict | None = None, config: dict | None = None) -> tuple:
        state = {"id": "bd-unit1", "status": "open", "assignee": None} if state is None else state
        self.request_path.write_text(json.dumps(request() if req is None else req))
        (self.root / "state.json").write_text(json.dumps(state))
        (self.root / "fixture.json").write_text(json.dumps(config or {}))
        completed = subprocess.run([
            sys.executable, str(SCRIPT), "--request", str(self.request_path),
            "--result", str(self.result_path), "--repo-root", str(self.repo), "--br", str(self.br),
        ], text=True, capture_output=True, timeout=20)
        result = json.loads(self.result_path.read_text()) if self.result_path.is_file() else None
        final_state = json.loads((self.root / "state.json").read_text())
        calls_path = self.root / "calls.jsonl"
        calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
        return completed, result, final_state, calls

    def assert_no_mutation(self, calls: list) -> None:
        self.assertFalse([args for args in calls if args[0] in {"update", "close"}], calls)


class PreflightTests(FixtureCase):
    def test_normal_claim(self) -> None:
        completed, result, state, _ = self.invoke()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(state["assignee"], "RepairAgent")
        self.assertEqual(state["status"], "in_progress")

    def test_open_foreign_owner_is_not_stolen(self) -> None:
        state = {"id": "bd-unit1", "status": "open", "assignee": "OtherAgent"}
        completed, _, after, calls = self.invoke(state=state)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(after, state)
        self.assert_no_mutation(calls)

    def test_in_progress_foreign_owner_is_not_stolen(self) -> None:
        state = {"id": "bd-unit1", "status": "in_progress", "assignee": "OtherAgent"}
        completed, _, after, calls = self.invoke(request(expected_before_status="in_progress"), state)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(after, state)
        self.assert_no_mutation(calls)

    def test_ownerless_in_progress_requires_explicit_recovery(self) -> None:
        state = {"id": "bd-unit1", "status": "in_progress", "assignee": "unassigned"}
        completed, _, after, calls = self.invoke(request(expected_before_status="in_progress"), state)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(after, state)
        self.assert_no_mutation(calls)

    def test_blocked_claim_is_refused(self) -> None:
        state = {"id": "bd-unit1", "status": "blocked", "assignee": None}
        completed, _, after, calls = self.invoke(request(expected_before_status="blocked"), state)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(after, state)
        self.assert_no_mutation(calls)

    def test_same_owner_replay_is_noop(self) -> None:
        state = {"id": "bd-unit1", "status": "in_progress", "assignee": "RepairAgent"}
        completed, result, after, calls = self.invoke(request(expected_before_status="in_progress"), state)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(result["mutation_applied"])
        self.assertEqual(after, state)
        self.assert_no_mutation(calls)

    def test_unassigned_sentinel_is_not_forcibly_cleared(self) -> None:
        state = {"id": "bd-unit1", "status": "open", "assignee": "unassigned"}
        completed, result, after, calls = self.invoke(state=state)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(after, state)
        self.assertEqual(result["mutation_state"], "attempted_unknown")
        updates = [args for args in calls if args[0] == "update"]
        self.assertEqual(len(updates), 1)
        self.assertIn("--claim", updates[0])
        self.assertNotIn("--assignee", updates[0])

    def test_wrong_bead_before_is_refused(self) -> None:
        completed, _, _, calls = self.invoke(config={"before_payload": {"id": "bd-other", "status": "open"}})
        self.assertEqual(completed.returncode, 1)
        self.assert_no_mutation(calls)

    def test_empty_issue_payload_is_refused_without_expected_status(self) -> None:
        req = request()
        req.pop("expected_before_status")
        completed, _, _, calls = self.invoke(req, config={"before_payload": {}})
        self.assertEqual(completed.returncode, 1)
        self.assert_no_mutation(calls)

    def test_ambiguous_issue_list_is_refused(self) -> None:
        req = request()
        req.pop("expected_before_status")
        completed, _, _, calls = self.invoke(req, config={"before_payload": {"issues": [{"id": "bd-unit1", "status": "open"}, {"id": "bd-other", "status": "open"}]}})
        self.assertEqual(completed.returncode, 1)
        self.assert_no_mutation(calls)

    def test_malformed_owner_is_refused(self) -> None:
        completed, _, _, calls = self.invoke(state={"id": "bd-unit1", "status": "open", "assignee": {"name": "OtherAgent"}})
        self.assertEqual(completed.returncode, 1)
        self.assert_no_mutation(calls)

    def test_claim_owner_postcondition_is_checked(self) -> None:
        completed, _, _, _ = self.invoke(config={"omit_owner_update": True})
        self.assertEqual(completed.returncode, 1)

    def test_returned_bead_identity_postcondition_is_checked(self) -> None:
        completed, _, _, _ = self.invoke(config={"after_payload": {"id": "bd-other", "status": "in_progress", "assignee": "RepairAgent"}})
        self.assertEqual(completed.returncode, 1)

    def test_owner_constraint_is_honored_on_close(self) -> None:
        completed, _, _, calls = self.invoke(request("close", assignee="RepairAgent"), {"id": "bd-unit1", "status": "open", "assignee": "OtherAgent"})
        self.assertEqual(completed.returncode, 1)
        self.assert_no_mutation(calls)

    def test_close_success(self) -> None:
        completed, _, after, _ = self.invoke(request("close"))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(after["status"], "closed")

    def test_closed_replay_is_noop(self) -> None:
        state = {"id": "bd-unit1", "status": "closed", "assignee": "RepairAgent"}
        completed, result, after, calls = self.invoke(request("close", expected_before_status="closed"), state)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(result["mutation_applied"])
        self.assertEqual(after, state)
        self.assert_no_mutation(calls)


class NativeClaimTests(FixtureCase):
    def test_claim_delegates_to_native_guard_with_explicit_actor(self) -> None:
        completed, _, _, calls = self.invoke()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        updates = [args for args in calls if args[0] == "update"]
        self.assertEqual(updates, [["update", "bd-unit1", "--claim", "--actor=RepairAgent", "--json"]])

    def test_competing_claim_is_not_overwritten(self) -> None:
        completed, result, state, calls = self.invoke(config={"assign_before_update": "OtherAgent"})
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(state["assignee"], "OtherAgent")
        self.assertEqual(result["before"]["status"], "open")
        self.assertEqual(result["status"], "mutation_unconfirmed")
        self.assertEqual(len([args for args in calls if args[0] == "update"]), 1)

    def test_missing_native_claim_support_never_falls_back_to_forced_update(self) -> None:
        completed, result, state, calls = self.invoke(config={"claim_option_unavailable": True})
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(state["status"], "open")
        self.assertEqual(result["status"], "mutation_unconfirmed")
        self.assertEqual(len([args for args in calls if args[0] == "update"]), 1)


class ValidationTests(unittest.TestCase):
    def test_unhashable_operation_is_a_typed_validation_error(self) -> None:
        for value in ([], {}):
            with self.subTest(value=value), self.assertRaises(OPS.BeadOpsError):
                OPS.validate_request(request(operation=value))

    def test_unhashable_expected_status_is_a_typed_validation_error(self) -> None:
        for value in ([], {}):
            with self.subTest(value=value), self.assertRaises(OPS.BeadOpsError):
                OPS.validate_request(request(expected_before_status=value))

    def test_claim_must_name_real_assignee(self) -> None:
        with self.assertRaises(OPS.BeadOpsError):
            OPS.validate_request(request(assignee="unassigned"))

    def test_owner_aliases_are_all_checked(self) -> None:
        self.assertEqual(OPS.issue_assignees({"assignee": "unassigned", "assigned_to": " RepairAgent ", "assignees": ["OtherAgent"]}), {"RepairAgent", "OtherAgent"})

    def test_supported_issue_envelopes(self) -> None:
        issue = {"id": "bd-unit1", "status": "open"}
        for value in (issue, [issue], {"issue": issue}, {"issues": [issue]}):
            with self.subTest(value=value):
                self.assertEqual(OPS.issue_from_payload(value), issue)


class ReceiptTests(FixtureCase):
    def test_success_has_confirmed_mutation_and_flush(self) -> None:
        completed, result, _, _ = self.invoke()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(result["mutation_state"], "command_succeeded")
        self.assertTrue(result["mutation_applied"])
        self.assertTrue(result["flush_completed"])

    def test_flush_failure_keeps_successful_mutation(self) -> None:
        completed, result, state, _ = self.invoke(config={"fail_flush": True})
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(state["status"], "in_progress")
        self.assertTrue(result["mutation_applied"])
        self.assertEqual(result["status"], "partial_failure")
        self.assertEqual(result["stage"], "flush")
        self.assertFalse(result["flush_completed"])
        self.assertEqual(result["before"]["status"], "open")
        self.assertEqual(len(result["source_revision"]), 40)

    def test_invalid_json_after_success_keeps_mutation_evidence(self) -> None:
        completed, result, state, _ = self.invoke(config={"invalid_mutation_json": True})
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(state["status"], "in_progress")
        self.assertTrue(result["mutation_applied"])
        self.assertEqual(result["status"], "partial_failure")
        self.assertEqual(result["stage"], "mutation_output")

    def test_nonzero_mutation_is_unknown_not_false(self) -> None:
        completed, result, state, _ = self.invoke(config={"mutation_nonzero": True})
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(state["status"], "in_progress")
        self.assertIsNone(result["mutation_applied"])
        self.assertEqual(result["mutation_state"], "attempted_unknown")
        self.assertEqual(result["status"], "mutation_unconfirmed")

    def test_after_read_failure_preserves_success_and_flush(self) -> None:
        completed, result, _, _ = self.invoke(config={"fail_after_read": True})
        self.assertEqual(completed.returncode, 1)
        self.assertTrue(result["mutation_applied"])
        self.assertTrue(result["flush_completed"])
        self.assertEqual(result["stage"], "observe_after")
        self.assertEqual(result["status"], "partial_failure")

    def test_stale_precondition_retains_observed_evidence(self) -> None:
        completed, result, _, calls = self.invoke(request(expected_before_status="in_progress"))
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(result["mutation_applied"])
        self.assertEqual(result["before"]["status"], "open")
        self.assertEqual(result["mutation_state"], "not_attempted")
        self.assertEqual(result["status"], "fail_closed")
        self.assert_no_mutation(calls)

    def test_show_stays_read_only_at_operation_boundary(self) -> None:
        completed, result, _, calls = self.invoke(request("show"))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(result["mutation_applied"])
        self.assertEqual(result["mutation_state"], "not_attempted")
        self.assertFalse(result["flush_completed"])
        self.assert_no_mutation(calls)

    def test_after_mismatch_retains_observed_identity(self) -> None:
        observed = {"id": "bd-other", "status": "in_progress", "assignee": "RepairAgent"}
        completed, result, _, _ = self.invoke(config={"after_payload": observed})
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(result["after_payload"], observed)
        self.assertTrue(result["mutation_applied"])
        self.assertEqual(result["stage"], "verify_after")

    def test_result_path_cannot_overwrite_request(self) -> None:
        self.result_path = self.request_path
        original = request()
        completed, _, _, calls = self.invoke(original)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(json.loads(self.request_path.read_text()), original)
        self.assert_no_mutation(calls)

    def test_unwritable_result_parent_blocks_before_mutation(self) -> None:
        blocked_parent = self.root / "not-a-directory"
        blocked_parent.write_text("retained")
        self.result_path = blocked_parent / "result.json"
        completed, _, _, calls = self.invoke()
        self.assertEqual(completed.returncode, 1)
        self.assert_no_mutation(calls)


if __name__ == "__main__":
    unittest.main()
