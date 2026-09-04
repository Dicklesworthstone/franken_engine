# Agent bead operations: ownership and failure evidence

`scripts/agent_bead_ops.py` applies one reviewed request through the installed
`br` CLI. Request schema remains `franken-engine.agent-bead-ops-request.v1`;
result schema is `franken-engine.agent-bead-ops-result.v2`.

The GitHub workflow pins `br` v0.5.7. Its claim path uses the existing native
`update --claim --actor=<assignee>` guard, not an unconditional
`update --status in_progress --assignee ...` fallback. Older executables that do
not support this operation must fail, not silently fall back to reassignment.
The workflow consumes the process exit status and preserves the result artifact;
it does not decode a result-schema version. Existing v1 receipts are historical
records and must not be rewritten to look like newly executed v2 operations.

## Preconditions and identity

A request has a bounded request ID, a valid bead ID, a supported operation, and
operation-specific arguments. A claim requires a named assignee; close requires
a reason. `expected_before_status`, when supplied, must match the observed
status. Request and result must not resolve to the same file, including aliases
or hard links. Obvious invalid output destinations fail before invoking `br`.
This preflight is not a guarantee against later filesystem failure.

Both observations must identify the requested bead. Missing/ambiguous issue
objects and malformed owner fields are errors. Claims reject observed foreign
ownership, blocked/closed/unsupported status, and ownerless in-progress work.
An already in-progress claim by the same owner is a no-op only when any supplied
status precondition also agrees. After a claim, the observed status **and** owner
must match the request. An optional close assignee is an observed ownership
constraint; close without it retains the existing API's semantics.

The string `unassigned` is **not** a null assignee in the pinned native claim
guard. Such legacy records may be refused. The adapter never clears an assignee
or retries with an unconditional update to get around that refusal. Any legacy
normalization or reassignment needs a separate, explicitly authorized tracker
operation and a fresh observation.

The native guard addresses conflicting assignments at its own storage boundary.
It does not provide a distributed lock across independent Git clones. The
adapter's status precheck is not a general compare-and-swap over every issue
field, and its optional close-owner check is not a transactional close-owner
predicate. Keep existing shared-worktree, Agent Mail, and tracker coordination
requirements; do not infer stronger concurrency guarantees from these checks.

## Result v2

| Field/state | Meaning |
|---|---|
| `mutation_state = not_attempted`, `mutation_applied = false` | No claim/close mutating command was issued. Import may still have run. |
| `mutation_state = attempted_unknown`, `mutation_applied = null` | A mutating command was attempted, but no successful completion was established. A nonzero exit does **not** prove rollback. |
| `mutation_state = command_succeeded`, `mutation_applied = true` | The mutating command returned zero, recorded before parsing its output. This alone does not prove a durable export or verified postcondition. |
| `flush_completed` | The explicit `br sync --flush-only` completed successfully. This is not an independent disk-durability proof. |
| `stage` | The last entered phase, including `validate_before`, `mutate`, `mutation_output`, `flush`, `observe_after`, or `verify_after`; `complete` means the operation checks finished. |
| `before_payload` / `after_payload` | Parsed observation payloads retained even when subsequent identity or shape validation fails. |
| `before` / `after` | Successfully validated issue objects, when available. |
| `source_revision`, `request_sha256`, `commands` | Source identity, canonical hash of the single loaded request, and captured command outcomes. |

`status = pass` requires the operation's full checks to succeed. Failures are
`fail_closed` only before a claim/close command was attempted;
`mutation_unconfirmed` after an unconfirmed attempt; and `partial_failure` after
a mutating command returned zero but later processing failed. `show` still runs
import and observation commands; calling it globally side-effect-free would be
incorrect. `request_id` is correlation data, not a durable exactly-once ledger.

Result-write failure returns nonzero and reports the known mutation state,
stage, and export status on stderr. It cannot promise a receipt at an unwritable
path. Process termination before receipt emission can also leave the outcome
unknown; missing evidence is never a successful or rolled-back operation.

## Recovery and validation

Preserve a failed receipt and inspect the actual bead and export before
retrying. A flush failure after an acknowledged update must not be reported as
"nothing changed." A malformed update response or failed post-read likewise
must not erase the successful command acknowledgement. Repair the actual
export/observation problem, coordinate with the current owner, and submit a new
reviewed request with a current precondition. Do not force a stale request,
automatically undo somebody else's work, or close a bead from this receipt alone.

A v1 failure receipt with `mutation_applied = false` is not reliable evidence
that no update occurred. Preserve its original command transcript and resolve
uncertainty from actual state; do not automatically relabel it `not_attempted`.

Run the adapter regression suite from the repository root:

```bash
python3 -m unittest discover -s scripts/tests -p test_agent_bead_ops.py -v
```

The suite uses real subprocesses and temporary Git repositories with an
explicitly named **protocol fixture**, not a real `br` implementation. It verifies
request/response handling, guard selection, conservative failure receipts, and
simulated interleavings. It does not establish real database locking, dependency
admission, export durability, Rust compilation, or engine conformance. Before
operational adoption, separately verify the installed pinned `br` executable
against a disposable tracker and the required repository acceptance gates.
