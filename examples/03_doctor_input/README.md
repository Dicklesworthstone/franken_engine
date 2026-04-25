# Doctor Input Example

This example documents the JSON schema that `frankenctl doctor --input <path>` currently deserializes at the CLI boundary: [`RuntimeDiagnosticsCliInput`](../../crates/franken-engine/src/runtime_diagnostics_cli.rs).

## Schema Sources

- `crates/franken-engine/src/workload_preflight_doctor.rs` exposes the derived helper input [`WorkloadPreflightDoctorInput`](../../crates/franken-engine/src/workload_preflight_doctor.rs), which contains `workload_id`, `package_name`, `target_platforms`, and `signals`.
- `frankenctl doctor` does not deserialize that helper struct directly. The live CLI entrypoint loads [`RuntimeDiagnosticsCliInput`](../../crates/franken-engine/src/runtime_diagnostics_cli.rs), then derives the preflight/doctor report from the runtime snapshot.
- Fields such as `node_version`, `target_arch`, and `capability_manifest_hash` are not required top-level keys in the current `doctor --input` JSON schema.

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
- Verified with `cargo run --bin frankenctl -- doctor --input examples/03_doctor_input/sample.json`; the checked-in `expected_output.json` matches the live stdout exactly.
