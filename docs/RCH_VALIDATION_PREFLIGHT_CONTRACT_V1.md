# RCH Validation Preflight Contract V1

`bd-xxi8i` defines the artifact contract agents must use before treating an
`rch`-backed Cargo validation attempt as source evidence. The contract is
advisory and diagnostic: it records whether the selected remote worker appears
capable of running the requested validation lane, and it fails closed when the
proof is missing or ambiguous. It never installs tools, restarts workers, or
mutates `/dp/remote_compilation_helper`.

The machine-readable fixture is
[`docs/rch_validation_preflight_contract_v1.json`](./rch_validation_preflight_contract_v1.json).
It captures representative validation cases for:

- a `cargo clippy` lane whose selected worker lacks `cargo-clippy`
- a successful `cargo check` lane with the required Rust toolchain available
- a stale worker capability snapshot
- an unsupported bare Cargo command

## Required Fields

Each validation case records:

- `case_id`: stable fixture id.
- `command_kind`: one of `cargo_check`, `cargo_test`, `cargo_clippy`,
  `cargo_fmt`, `rustfmt`, or `rustdoc`.
- `validation_command`: the exact operator command. Heavy Cargo commands must
  start with `rch exec --`.
- `worker`: selected worker id, host, toolchain, and component inventory.
- `required_components`: the Rust components needed for this validation lane.
- `target_dir_policy`: whether the command uses an isolated target directory.
- `local_fallback_policy`: whether local fallback is refused, allowed, or not
  applicable.
- `capability_snapshot`: timestamp and freshness verdict for the worker
  capability data.
- `verdict`: `pass`, `fail_closed`, `degraded`, or `skipped`.
- `reason_code`: stable reason for the verdict.
- `operator_guidance`: short remediation text for Agent Mail and bead closeout.

## Reason Codes

- `component_available`: worker has the required component set.
- `missing_required_component`: selected worker cannot run the requested lane.
- `stale_capability_snapshot`: capability data is too old to trust.
- `bare_cargo_not_allowed`: command bypasses the repository `rch` policy.

## Agent Workflow

1. Record the exact validation command before running it.
2. Capture the selected worker and toolchain from `rch` output or status.
3. Evaluate the required component set for the command kind.
4. Fail closed if the command is bare Cargo, the worker evidence is missing, or
   the capability snapshot is stale.
5. Paste the verdict, reason code, command, worker id, and next action into the
   bead closeout or Agent Mail update.

This contract is deliberately narrower than the SWARM-CTRL IX operator SLO
dashboard: it only classifies whether a validation attempt is meaningful
source evidence or an infrastructure/toolchain blocker.
