# Doctor Input Example

This example documents the JSON schema that `frankenctl doctor --input <path>` currently deserializes at the CLI boundary: [`RuntimeDiagnosticsCliInput`](../../crates/franken-engine/src/runtime_diagnostics_cli.rs).

## Files

- `sample.json`: minimal valid doctor input.
- `expected_output.json`: stdout from a successful `frankenctl doctor` run against `sample.json`.

## Run

From the repository root:

```bash
cargo run --bin frankenctl -- doctor --input examples/03_doctor_input/sample.json
```

To diff the live stdout against the checked-in expectation:

```bash
cargo run --bin frankenctl -- doctor --input examples/03_doctor_input/sample.json > /tmp/frankenctl_doctor_output.json
diff -u examples/03_doctor_input/expected_output.json /tmp/frankenctl_doctor_output.json
```

## Notes

- `containment_state` uses the enum's Rust serde spellings such as `"Running"`, not lowercase.
- The example keeps `evidence_entries`, `hostcall_records`, `containment_receipts`, and `replay_artifacts` empty because they are optional collections, not required for a successful doctor run.
