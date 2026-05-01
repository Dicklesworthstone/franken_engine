/*!
 * Conformance Test Fixtures with Provenance
 *
 * Manages test fixtures for proof-artifact contract conformance testing.
 * All fixtures documented with generation provenance per conformance-harnesses skill.
 */

use super::*;
use serde_json::json;
use std::fs;
use tempfile::TempDir;

pub struct FixtureManager {
    fixtures_dir: PathBuf,
}

impl FixtureManager {
    pub fn new(fixtures_dir: impl AsRef<Path>) -> Self {
        Self {
            fixtures_dir: fixtures_dir.as_ref().to_path_buf(),
        }
    }

    /// Creates a temporary test bundle with valid structure
    pub fn create_valid_bundle(&self) -> Result<TempDir, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let bundle_path = temp_dir.path();
        let run_dir = "test-bundle-20260501T123456Z";
        let run_path = bundle_path.join(run_dir);
        fs::create_dir_all(&run_path)?;

        // Create manifest.json
        let mut manifest = json!({
            "schema_version": PROOF_MANIFEST_SCHEMA_VERSION,
            "bundle_id": run_dir,
            "gate_name": "test_conformance_gate",
            "status": "pass",
            "generated_utc": "2026-05-01T12:34:56Z",
            "source_revision": "abcd1234567890abcdef1234567890abcdef1234",
            "rerun_command": "cargo test --gate conformance_test",
            "artifact_paths": {
                "run_dir": "test-bundle-20260501T123456Z",
                "manifest_json": "test-bundle-20260501T123456Z/manifest.json",
                "commands_txt": "test-bundle-20260501T123456Z/commands.txt",
                "events_jsonl": "test-bundle-20260501T123456Z/events.jsonl",
                "report_json": "test-bundle-20260501T123456Z/report.json",
                "report_md": "test-bundle-20260501T123456Z/report.md",
                "redaction_policy_json": "test-bundle-20260501T123456Z/redaction_policy.json"
            },
            "claim_ids": ["test-claim-1", "test-claim-2"],
            "bead_ids": ["bd-test1", "bd-test2"],
            "environment": {
                "RUST_VERSION": "1.80.0",
                "CARGO_TARGET_DIR": "target_conformance_test"
            },
            "commands": [
                {
                    "command_id": "cmd-1",
                    "display": "cargo build",
                    "redacted_display": "cargo build",
                    "cwd": "workspace",
                    "exit_code": 0,
                    "duration_ms": 1250
                }
            ],
            "generated_artifacts": [
                {
                    "path": "test-bundle-20260501T123456Z/commands.txt",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "schema_version": null,
                    "role": "command_transcript"
                },
                {
                    "path": "test-bundle-20260501T123456Z/events.jsonl",
                    "sha256": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "schema_version": PROOF_EVENT_SCHEMA_VERSION,
                    "role": "structured_events"
                },
                {
                    "path": "test-bundle-20260501T123456Z/report.json",
                    "sha256": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                    "schema_version": PROOF_REPORT_SCHEMA_VERSION,
                    "role": "source_machine_report"
                },
                {
                    "path": "test-bundle-20260501T123456Z/redaction_policy.json",
                    "sha256": null,
                    "schema_version": REDACTION_POLICY_SCHEMA_VERSION,
                    "role": "redaction_policy"
                }
            ],
            "expected_artifacts": [],
            "verifier_outputs": [],
            "freshness": {
                "generated_utc": "2026-05-01T12:34:56Z",
                "freshness_days": 0,
                "max_freshness_days": 14
            }
        });

        fs::write(
            bundle_path.join("manifest.json"),
            serde_json::to_string_pretty(&manifest)?,
        )?;

        // Create commands.txt (empty for hash match)
        fs::write(bundle_path.join("commands.txt"), "")?;
        fs::write(run_path.join("commands.txt"), "")?;

        // Create events.jsonl with valid events
        let event1 = json!({
            "schema_version": PROOF_EVENT_SCHEMA_VERSION,
            "event_name": "gate_started",
            "severity": "info",
            "step_id": "step-1",
            "command_id": "cmd-1",
            "artifact_path": null,
            "artifact_sha256": null,
            "exit_code": null,
            "duration_ms": null,
            "decision": "proceed",
            "remediation": null
        });

        let event2 = json!({
            "schema_version": PROOF_EVENT_SCHEMA_VERSION,
            "event_name": "gate_completed",
            "severity": "info",
            "step_id": "step-2",
            "command_id": null,
            "artifact_path": null,
            "artifact_sha256": null,
            "exit_code": 0,
            "duration_ms": 1250,
            "decision": "pass",
            "remediation": null
        });

        let events_content = format!(
            "{}\n{}",
            serde_json::to_string(&event1)?,
            serde_json::to_string(&event2)?
        );
        fs::write(bundle_path.join("events.jsonl"), &events_content)?;
        fs::write(run_path.join("events.jsonl"), &events_content)?;

        // Create report.json
        let report = json!({
            "schema_version": PROOF_REPORT_SCHEMA_VERSION,
            "bundle_id": "test-bundle-20260501T123456Z",
            "gate_name": "test_conformance_gate",
            "status": "pass",
            "event_count": 2,
            "failure_count": 0,
            "rerun_command": "cargo test --gate conformance_test",
            "manifest_path": "test-bundle-20260501T123456Z/manifest.json",
            "report_json_path": "test-bundle-20260501T123456Z/report.json",
            "report_md_path": "test-bundle-20260501T123456Z/report.md",
            "findings": []
        });
        let report_json = serde_json::to_string_pretty(&report)?;

        fs::write(bundle_path.join("report.json"), &report_json)?;
        fs::write(run_path.join("report.json"), &report_json)?;

        // Create report.md
        let report_md = "# Proof Artifact Report\n\n- Bundle: `test-bundle-20260501T123456Z`\n- Gate: `test_conformance_gate`\n- Status: `Pass`\n- Events: `2`\n- Failures: `0`\n- Rerun: `cargo test --gate conformance_test`\n\nNo findings were emitted.\n";
        fs::write(bundle_path.join("report.md"), report_md)?;
        fs::write(run_path.join("report.md"), report_md)?;

        // Create redaction_policy.json
        let redaction_policy = json!({
            "schema_version": REDACTION_POLICY_SCHEMA_VERSION,
            "replacement": "<redacted>",
            "env_key_fragments": [
                "API_KEY", "ACCESS_TOKEN", "TOKEN", "_TOKEN", "SECRET",
                "PASSWORD", "CREDENTIAL", "AUTH", "KEY", "_KEY",
                "BEARER", "OAUTH"
            ],
            "literal_patterns": ["Bearer "]
        });
        let redaction_policy_json = serde_json::to_string_pretty(&redaction_policy)?;

        fs::write(
            bundle_path.join("redaction_policy.json"),
            &redaction_policy_json,
        )?;
        fs::write(
            run_path.join("redaction_policy.json"),
            &redaction_policy_json,
        )?;

        manifest["generated_artifacts"][0]["sha256"] = json!(sha256_hex(b""));
        manifest["generated_artifacts"][1]["sha256"] = json!(sha256_hex(events_content.as_bytes()));
        manifest["generated_artifacts"][2]["sha256"] = json!(sha256_hex(report_json.as_bytes()));
        manifest["generated_artifacts"][3]["sha256"] =
            json!(sha256_hex(redaction_policy_json.as_bytes()));
        let manifest_json = serde_json::to_string_pretty(&manifest)?;

        fs::write(bundle_path.join("manifest.json"), &manifest_json)?;
        fs::write(run_path.join("manifest.json"), &manifest_json)?;

        Ok(temp_dir)
    }

    /// Creates a bundle with invalid schema version for negative testing
    pub fn create_invalid_schema_bundle(&self) -> Result<TempDir, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let bundle_path = temp_dir.path();

        let invalid_manifest = json!({
            "schema_version": "invalid-schema-version",
            "bundle_id": "invalid-test-bundle",
            "gate_name": "test_gate",
            "status": "fail",
            "generated_utc": "2026-05-01T12:34:56Z",
            "source_revision": "invalid",
            "rerun_command": "echo test",
            "artifact_paths": {
                "run_dir": "invalid",
                "manifest_json": "invalid/manifest.json",
                "commands_txt": "invalid/commands.txt",
                "events_jsonl": "invalid/events.jsonl",
                "report_json": "invalid/report.json",
                "report_md": "invalid/report.md",
                "redaction_policy_json": "invalid/redaction_policy.json"
            },
            "claim_ids": [],
            "bead_ids": [],
            "environment": {},
            "commands": [],
            "generated_artifacts": [],
            "expected_artifacts": [],
            "verifier_outputs": [],
            "freshness": {
                "generated_utc": "2026-05-01T12:34:56Z",
                "freshness_days": 0,
                "max_freshness_days": 14
            }
        });

        fs::write(
            bundle_path.join("manifest.json"),
            serde_json::to_string_pretty(&invalid_manifest)?,
        )?;

        Ok(temp_dir)
    }

    /// Creates a bundle with deeply nested JSON for size limit testing
    pub fn create_large_json_bundle(&self) -> Result<TempDir, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let bundle_path = temp_dir.path();

        // Create deeply nested JSON that exceeds MAX_JSON_DEPTH
        let mut deep_json = json!("value");
        for _ in 0..20 {
            deep_json = json!({ "nested": deep_json });
        }

        let invalid_event = json!({
            "schema_version": PROOF_EVENT_SCHEMA_VERSION,
            "event_name": "deep_nesting_test",
            "severity": "info",
            "step_id": "step-1",
            "command_id": null,
            "artifact_path": null,
            "artifact_sha256": null,
            "exit_code": null,
            "duration_ms": null,
            "decision": deep_json,
            "remediation": null
        });

        fs::write(
            bundle_path.join("events.jsonl"),
            serde_json::to_string(&invalid_event)?,
        )?;

        Ok(temp_dir)
    }

    /// Creates a bundle with hash mismatches for integrity testing
    pub fn create_hash_mismatch_bundle(&self) -> Result<TempDir, Box<dyn std::error::Error>> {
        let valid_bundle = self.create_valid_bundle()?;

        // Modify the commands.txt file to create hash mismatch
        let commands_path = valid_bundle.path().join("commands.txt");
        fs::write(&commands_path, "modified content")?;

        Ok(valid_bundle)
    }

    /// Load fixture by name with error context
    pub fn load_fixture(&self, name: &str) -> Result<String, Box<dyn std::error::Error>> {
        let fixture_path = self.fixtures_dir.join(name);
        if !fixture_path.exists() {
            return Err(format!("Fixture not found: {}", fixture_path.display()).into());
        }

        Ok(fs::read_to_string(fixture_path)?)
    }

    /// Creates PROVENANCE.md documentation for fixtures
    pub fn create_provenance_doc(&self) -> Result<(), Box<dyn std::error::Error>> {
        let provenance = r#"# Fixture Provenance

All fixtures in this directory are generated for proof-artifact contract conformance testing.

## Generated Fixtures

### Valid Test Bundles
- **Generated by**: `FixtureManager::create_valid_bundle()`
- **Source**: Conformance harness synthetic generation
- **Purpose**: Positive conformance testing - validates that well-formed bundles pass all contract requirements
- **Last updated**: Auto-generated per test run
- **Schema versions**:
  - Manifest: franken-engine.proof-artifact-manifest.v1
  - Event: franken-engine.proof-artifact-event.v1
  - Report: franken-engine.proof-artifact-report.v1
  - Redaction: franken-engine.proof-artifact-redaction-policy.v1

### Invalid Test Bundles
- **Generated by**: `FixtureManager::create_invalid_*()` methods
- **Source**: Conformance harness synthetic generation
- **Purpose**: Negative conformance testing - validates that malformed bundles are correctly rejected
- **Categories**: Schema violations, hash mismatches, JSON depth/size limits, missing required fields

## Fixture Update Workflow

Fixtures are auto-generated during test runs. To update fixture behavior:

1. Modify the `FixtureManager` methods in `fixtures.rs`
2. Run conformance tests with `cargo test proof_artifact_conformance`
3. Review any changes to validation behavior
4. Commit updated fixture generation logic (never commit temp test data)

## Real Bundle Integration

To test against real proof bundles from gates:

1. Add bundle paths to `SAMPLE_BUNDLES` in the conformance test
2. Ensure bundles follow the cd3d2b4d contract structure
3. Document any expected divergences in `DISCREPANCIES.md`

## Known Limitations

- Fixtures use synthetic data optimized for test coverage
- Real bundles may have additional fields not covered by synthetic fixtures
- Large bundle testing limited by CI resource constraints
"#;

        let provenance_path = self.fixtures_dir.join("PROVENANCE.md");
        fs::create_dir_all(&self.fixtures_dir)?;
        fs::write(provenance_path, provenance)?;

        Ok(())
    }
}
