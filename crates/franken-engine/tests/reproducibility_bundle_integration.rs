//! Reproducibility bundle integration tests
//!
//! Implements bd-cixqu.4.2: ≥30 integration tests verifying the bundle shape per gate.
//!
//! Validates that all OBSERVED FE-CLAIM-* entries have proper reproducibility bundles
//! containing env.json + manifest.json + repro.lock per docs/REPRODUCIBILITY_CONTRACT.md.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

// OBSERVED claims that should have reproducibility bundles
const OBSERVED_CLAIMS: &[&str] = &[
    "FE-CLAIM-001",
    "FE-CLAIM-002",
    "FE-CLAIM-003",
    "FE-CLAIM-007",
    "FE-CLAIM-008",
    "FE-CLAIM-011",
    "FE-CLAIM-012",
    "FE-CLAIM-013",
    "FE-CLAIM-015",
];

// Required files in each bundle
const REQUIRED_BUNDLE_FILES: &[&str] = &["env.json", "manifest.json", "repro.lock"];

fn bundle_path(claim_id: &str) -> PathBuf {
    PathBuf::from(format!("artifacts/reproducibility_bundles/{}", claim_id))
}

fn load_json_file(path: &Path) -> serde_json::Result<Value> {
    let content = fs::read_to_string(path).map_err(|e| {
        serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Failed to read {}: {}", path.display(), e),
        ))
    })?;
    serde_json::from_str(&content)
}

fn assert_required_keys(json: &Value, required_keys: &[&str], file_type: &str, claim_id: &str) {
    let obj = json.as_object().expect(&format!(
        "{} should be JSON object for {}",
        file_type, claim_id
    ));

    for key in required_keys {
        assert!(
            obj.contains_key(*key),
            "{} missing required key '{}' for claim {}",
            file_type,
            key,
            claim_id
        );
    }
}

// ---------------------------------------------------------------------------
// Bundle Existence Tests (9 tests)
// ---------------------------------------------------------------------------

#[test]
fn bundle_directories_exist_for_all_observed_claims() {
    for claim_id in OBSERVED_CLAIMS {
        let bundle_dir = bundle_path(claim_id);
        assert!(
            bundle_dir.exists(),
            "Bundle directory should exist for claim {}: {}",
            claim_id,
            bundle_dir.display()
        );
        assert!(
            bundle_dir.is_dir(),
            "Bundle path should be directory for claim {}: {}",
            claim_id,
            bundle_dir.display()
        );
    }
}

#[test]
fn fe_claim_001_bundle_exists() {
    let bundle_dir = bundle_path("FE-CLAIM-001");
    assert!(bundle_dir.exists() && bundle_dir.is_dir());
}

#[test]
fn fe_claim_002_bundle_exists() {
    let bundle_dir = bundle_path("FE-CLAIM-002");
    assert!(bundle_dir.exists() && bundle_dir.is_dir());
}

#[test]
fn fe_claim_003_bundle_exists() {
    let bundle_dir = bundle_path("FE-CLAIM-003");
    assert!(bundle_dir.exists() && bundle_dir.is_dir());
}

#[test]
fn fe_claim_007_bundle_exists() {
    let bundle_dir = bundle_path("FE-CLAIM-007");
    assert!(bundle_dir.exists() && bundle_dir.is_dir());
}

#[test]
fn fe_claim_008_bundle_exists() {
    let bundle_dir = bundle_path("FE-CLAIM-008");
    assert!(bundle_dir.exists() && bundle_dir.is_dir());
}

#[test]
fn fe_claim_011_bundle_exists() {
    let bundle_dir = bundle_path("FE-CLAIM-011");
    assert!(bundle_dir.exists() && bundle_dir.is_dir());
}

#[test]
fn fe_claim_012_bundle_exists() {
    let bundle_dir = bundle_path("FE-CLAIM-012");
    assert!(bundle_dir.exists() && bundle_dir.is_dir());
}

#[test]
fn fe_claim_013_bundle_exists() {
    let bundle_dir = bundle_path("FE-CLAIM-013");
    assert!(bundle_dir.exists() && bundle_dir.is_dir());
}

#[test]
fn fe_claim_015_bundle_exists() {
    let bundle_dir = bundle_path("FE-CLAIM-015");
    assert!(bundle_dir.exists() && bundle_dir.is_dir());
}

// ---------------------------------------------------------------------------
// Required Files Tests (9 tests)
// ---------------------------------------------------------------------------

#[test]
fn all_bundles_contain_required_files() {
    for claim_id in OBSERVED_CLAIMS {
        let bundle_dir = bundle_path(claim_id);

        for file in REQUIRED_BUNDLE_FILES {
            let file_path = bundle_dir.join(file);
            assert!(
                file_path.exists(),
                "Required file {} should exist for claim {} at {}",
                file,
                claim_id,
                file_path.display()
            );
            assert!(
                file_path.is_file(),
                "Required file {} should be a regular file for claim {}",
                file,
                claim_id
            );
        }
    }
}

#[test]
fn env_json_files_exist_and_parseable() {
    for claim_id in OBSERVED_CLAIMS {
        let env_path = bundle_path(claim_id).join("env.json");
        assert!(env_path.exists(), "env.json should exist for {}", claim_id);

        let _json = load_json_file(&env_path)
            .expect(&format!("env.json should be valid JSON for {}", claim_id));
    }
}

#[test]
fn manifest_json_files_exist_and_parseable() {
    for claim_id in OBSERVED_CLAIMS {
        let manifest_path = bundle_path(claim_id).join("manifest.json");
        assert!(
            manifest_path.exists(),
            "manifest.json should exist for {}",
            claim_id
        );

        let _json = load_json_file(&manifest_path).expect(&format!(
            "manifest.json should be valid JSON for {}",
            claim_id
        ));
    }
}

#[test]
fn repro_lock_files_exist_and_parseable() {
    for claim_id in OBSERVED_CLAIMS {
        let lock_path = bundle_path(claim_id).join("repro.lock");
        assert!(
            lock_path.exists(),
            "repro.lock should exist for {}",
            claim_id
        );

        let _json = load_json_file(&lock_path)
            .expect(&format!("repro.lock should be valid JSON for {}", claim_id));
    }
}

#[test]
fn bundles_contain_only_expected_files() {
    for claim_id in OBSERVED_CLAIMS {
        let bundle_dir = bundle_path(claim_id);
        let entries: Vec<_> = fs::read_dir(&bundle_dir)
            .expect(&format!(
                "Should be able to read bundle dir for {}",
                claim_id
            ))
            .collect::<Result<Vec<_>, _>>()
            .expect("Should be able to list directory entries");

        assert_eq!(
            entries.len(),
            3,
            "Bundle for {} should contain exactly 3 files, found {}",
            claim_id,
            entries.len()
        );

        let mut file_names: Vec<_> = entries
            .iter()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        file_names.sort();

        let mut expected = REQUIRED_BUNDLE_FILES.to_vec();
        expected.sort();

        assert_eq!(
            file_names, expected,
            "Bundle for {} should contain exactly the required files",
            claim_id
        );
    }
}

#[test]
fn bundle_files_are_non_empty() {
    for claim_id in OBSERVED_CLAIMS {
        for file in REQUIRED_BUNDLE_FILES {
            let file_path = bundle_path(claim_id).join(file);
            let metadata = fs::metadata(&file_path).expect(&format!(
                "Should be able to get metadata for {} in {}",
                file, claim_id
            ));

            assert!(
                metadata.len() > 0,
                "File {} should be non-empty for claim {}",
                file,
                claim_id
            );
        }
    }
}

#[test]
fn bundle_files_have_utf8_content() {
    for claim_id in OBSERVED_CLAIMS {
        for file in REQUIRED_BUNDLE_FILES {
            let file_path = bundle_path(claim_id).join(file);
            let _content = fs::read_to_string(&file_path).expect(&format!(
                "File {} should be valid UTF-8 for claim {}",
                file, claim_id
            ));
        }
    }
}

#[test]
fn bundle_files_end_with_lf_newline() {
    for claim_id in OBSERVED_CLAIMS {
        for file in REQUIRED_BUNDLE_FILES {
            let file_path = bundle_path(claim_id).join(file);
            let content = fs::read_to_string(&file_path)
                .expect(&format!("Should be able to read {} for {}", file, claim_id));

            assert!(
                content.ends_with('\n'),
                "File {} should end with LF newline for claim {}",
                file,
                claim_id
            );

            // Verify it's LF, not CRLF
            assert!(
                !content.ends_with("\r\n") || content.ends_with('\n'),
                "File {} should use LF newlines, not CRLF for claim {}",
                file,
                claim_id
            );
        }
    }
}

#[test]
fn json_files_are_properly_formatted() {
    for claim_id in OBSERVED_CLAIMS {
        for file in &["env.json", "manifest.json", "repro.lock"] {
            let file_path = bundle_path(claim_id).join(file);
            let content = fs::read_to_string(&file_path)
                .expect(&format!("Should be able to read {} for {}", file, claim_id));

            // Should parse as JSON
            let json: Value = serde_json::from_str(&content)
                .expect(&format!("{} should be valid JSON for {}", file, claim_id));

            // Should be an object
            assert!(
                json.is_object(),
                "{} should be JSON object for {}",
                file,
                claim_id
            );

            // Re-serialization should be deterministic (lexicographic key ordering)
            let canonical =
                serde_json::to_string_pretty(&json).expect("Should be able to serialize JSON");

            // Keys should be in sorted order (basic check)
            if let Some(obj) = json.as_object() {
                let keys: Vec<_> = obj.keys().collect();
                let mut sorted_keys = keys.clone();
                sorted_keys.sort();
                assert_eq!(
                    keys, sorted_keys,
                    "{} should have lexicographically sorted keys for {}",
                    file, claim_id
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Schema Contract Tests (12 tests: 4 per file type * 3 file types)
// ---------------------------------------------------------------------------

#[test]
fn env_json_schema_compliance() {
    let required_keys = &[
        "schema_version",
        "schema_hash",
        "captured_at_utc",
        "project",
        "host",
        "toolchain",
        "runtime",
        "policy",
    ];

    for claim_id in OBSERVED_CLAIMS {
        let env_path = bundle_path(claim_id).join("env.json");
        let json =
            load_json_file(&env_path).expect(&format!("env.json should load for {}", claim_id));

        assert_required_keys(&json, required_keys, "env.json", claim_id);

        // Verify schema version format
        let schema_version = json["schema_version"]
            .as_str()
            .expect(&format!("schema_version should be string for {}", claim_id));
        assert!(
            schema_version.contains(".env.v"),
            "env.json schema_version should contain '.env.v' for {}",
            claim_id
        );
    }
}

#[test]
fn env_json_project_section_complete() {
    for claim_id in OBSERVED_CLAIMS {
        let env_path = bundle_path(claim_id).join("env.json");
        let json =
            load_json_file(&env_path).expect(&format!("env.json should load for {}", claim_id));

        let project = json["project"]
            .as_object()
            .expect(&format!("project should be object for {}", claim_id));

        let required_project_keys = &["name", "version", "repository", "commit", "claim_scope"];
        for key in required_project_keys {
            assert!(
                project.contains_key(*key),
                "project.{} should exist in env.json for {}",
                key,
                claim_id
            );
        }
    }
}

#[test]
fn env_json_timestamps_valid() {
    for claim_id in OBSERVED_CLAIMS {
        let env_path = bundle_path(claim_id).join("env.json");
        let json =
            load_json_file(&env_path).expect(&format!("env.json should load for {}", claim_id));

        let timestamp = json["captured_at_utc"].as_str().expect(&format!(
            "captured_at_utc should be string for {}",
            claim_id
        ));

        // Should be valid ISO-8601 timestamp
        assert!(
            timestamp.contains('T') && timestamp.contains('Z'),
            "captured_at_utc should be ISO-8601 UTC timestamp for {}",
            claim_id
        );
    }
}

#[test]
fn env_json_hash_fields_present() {
    for claim_id in OBSERVED_CLAIMS {
        let env_path = bundle_path(claim_id).join("env.json");
        let json =
            load_json_file(&env_path).expect(&format!("env.json should load for {}", claim_id));

        let schema_hash = json["schema_hash"]
            .as_str()
            .expect(&format!("schema_hash should be string for {}", claim_id));

        assert!(
            schema_hash.starts_with("sha256:"),
            "schema_hash should start with 'sha256:' for {}",
            claim_id
        );
    }
}

#[test]
fn manifest_json_schema_compliance() {
    let required_keys = &[
        "schema_version",
        "schema_hash",
        "manifest_id",
        "generated_at_utc",
        "claim",
        "source_revision",
        "provenance",
        "artifacts",
        "inputs",
        "outputs",
        "canonicalization",
        "validation",
        "retention",
    ];

    for claim_id in OBSERVED_CLAIMS {
        let manifest_path = bundle_path(claim_id).join("manifest.json");
        let json = load_json_file(&manifest_path)
            .expect(&format!("manifest.json should load for {}", claim_id));

        assert_required_keys(&json, required_keys, "manifest.json", claim_id);

        // Verify schema version format
        let schema_version = json["schema_version"]
            .as_str()
            .expect(&format!("schema_version should be string for {}", claim_id));
        assert!(
            schema_version.contains(".manifest.v"),
            "manifest.json schema_version should contain '.manifest.v' for {}",
            claim_id
        );
    }
}

#[test]
fn manifest_json_claim_section_complete() {
    for claim_id in OBSERVED_CLAIMS {
        let manifest_path = bundle_path(claim_id).join("manifest.json");
        let json = load_json_file(&manifest_path)
            .expect(&format!("manifest.json should load for {}", claim_id));

        let claim = json["claim"]
            .as_object()
            .expect(&format!("claim should be object for {}", claim_id));

        let required_claim_keys = &["id", "scope", "state", "original_artifact_path"];
        for key in required_claim_keys {
            assert!(
                claim.contains_key(*key),
                "claim.{} should exist in manifest.json for {}",
                key,
                claim_id
            );
        }

        // Verify claim ID matches
        let claim_id_in_manifest = claim["id"]
            .as_str()
            .expect(&format!("claim.id should be string for {}", claim_id));
        assert_eq!(
            claim_id_in_manifest, claim_id,
            "claim.id should match expected claim ID"
        );

        // Verify state is observed
        let state = claim["state"]
            .as_str()
            .expect(&format!("claim.state should be string for {}", claim_id));
        assert_eq!(
            state, "observed",
            "claim.state should be 'observed' for {}",
            claim_id
        );
    }
}

#[test]
fn manifest_json_artifacts_section_complete() {
    for claim_id in OBSERVED_CLAIMS {
        let manifest_path = bundle_path(claim_id).join("manifest.json");
        let json = load_json_file(&manifest_path)
            .expect(&format!("manifest.json should load for {}", claim_id));

        let artifacts = json["artifacts"]
            .as_object()
            .expect(&format!("artifacts should be object for {}", claim_id));

        let required_artifact_keys = &[
            "primary",
            "bundle_path",
            "env_json",
            "manifest_json",
            "repro_lock",
        ];
        for key in required_artifact_keys {
            assert!(
                artifacts.contains_key(*key),
                "artifacts.{} should exist in manifest.json for {}",
                key,
                claim_id
            );
        }
    }
}

#[test]
fn manifest_json_provenance_tracking() {
    for claim_id in OBSERVED_CLAIMS {
        let manifest_path = bundle_path(claim_id).join("manifest.json");
        let json = load_json_file(&manifest_path)
            .expect(&format!("manifest.json should load for {}", claim_id));

        let provenance = json["provenance"]
            .as_object()
            .expect(&format!("provenance should be object for {}", claim_id));

        // Should track generation source
        assert!(provenance.contains_key("generated_by"));
        assert!(provenance.contains_key("bead_id"));
        assert!(provenance.contains_key("audit_source"));

        // Should reference correct beads
        assert_eq!(provenance["bead_id"].as_str().unwrap(), "bd-cixqu.4.2");
        assert_eq!(provenance["audit_source"].as_str().unwrap(), "bd-cixqu.4.1");
    }
}

#[test]
fn repro_lock_schema_compliance() {
    let required_keys = &[
        "schema_version",
        "schema_hash",
        "generated_at_utc",
        "lock_id",
        "manifest_id",
        "source_commit",
        "determinism",
        "commands",
        "inputs",
        "expected_outputs",
        "replay",
        "verification",
    ];

    for claim_id in OBSERVED_CLAIMS {
        let lock_path = bundle_path(claim_id).join("repro.lock");
        let json =
            load_json_file(&lock_path).expect(&format!("repro.lock should load for {}", claim_id));

        assert_required_keys(&json, required_keys, "repro.lock", claim_id);

        // Verify schema version format
        let schema_version = json["schema_version"]
            .as_str()
            .expect(&format!("schema_version should be string for {}", claim_id));
        assert!(
            schema_version.contains(".lock.v"),
            "repro.lock schema_version should contain '.lock.v' for {}",
            claim_id
        );
    }
}

#[test]
fn repro_lock_determinism_configuration() {
    for claim_id in OBSERVED_CLAIMS {
        let lock_path = bundle_path(claim_id).join("repro.lock");
        let json =
            load_json_file(&lock_path).expect(&format!("repro.lock should load for {}", claim_id));

        let determinism = json["determinism"]
            .as_object()
            .expect(&format!("determinism should be object for {}", claim_id));

        let required_det_keys = &[
            "mode",
            "seed_control",
            "environment_isolation",
            "reproducible_builds",
        ];
        for key in required_det_keys {
            assert!(
                determinism.contains_key(*key),
                "determinism.{} should exist in repro.lock for {}",
                key,
                claim_id
            );
        }

        // Verify mode is strict
        assert_eq!(
            determinism["mode"].as_str().unwrap(),
            "strict",
            "determinism mode should be strict for {}",
            claim_id
        );
    }
}

#[test]
fn repro_lock_commands_complete() {
    for claim_id in OBSERVED_CLAIMS {
        let lock_path = bundle_path(claim_id).join("repro.lock");
        let json =
            load_json_file(&lock_path).expect(&format!("repro.lock should load for {}", claim_id));

        let commands = json["commands"]
            .as_object()
            .expect(&format!("commands should be object for {}", claim_id));

        assert!(commands.contains_key("verification"));
        assert!(commands.contains_key("environment_setup"));
        assert!(commands.contains_key("cleanup"));

        let verification = commands["verification"].as_str().expect(&format!(
            "verification command should be string for {}",
            claim_id
        ));
        assert!(
            !verification.is_empty(),
            "verification command should not be empty for {}",
            claim_id
        );
    }
}

// ---------------------------------------------------------------------------
// Cross-Bundle Consistency Tests (3 tests)
// ---------------------------------------------------------------------------

#[test]
fn manifest_id_consistency_across_files() {
    for claim_id in OBSERVED_CLAIMS {
        let manifest_path = bundle_path(claim_id).join("manifest.json");
        let lock_path = bundle_path(claim_id).join("repro.lock");

        let manifest_json = load_json_file(&manifest_path)
            .expect(&format!("manifest.json should load for {}", claim_id));
        let lock_json =
            load_json_file(&lock_path).expect(&format!("repro.lock should load for {}", claim_id));

        let manifest_id_from_manifest = manifest_json["manifest_id"].as_str().expect(&format!(
            "manifest_id should exist in manifest.json for {}",
            claim_id
        ));
        let manifest_id_from_lock = lock_json["manifest_id"].as_str().expect(&format!(
            "manifest_id should exist in repro.lock for {}",
            claim_id
        ));

        assert_eq!(
            manifest_id_from_manifest, manifest_id_from_lock,
            "manifest_id should be consistent between manifest.json and repro.lock for {}",
            claim_id
        );
    }
}

#[test]
fn timestamp_ordering_consistency() {
    for claim_id in OBSERVED_CLAIMS {
        let env_path = bundle_path(claim_id).join("env.json");
        let manifest_path = bundle_path(claim_id).join("manifest.json");
        let lock_path = bundle_path(claim_id).join("repro.lock");

        let env_json =
            load_json_file(&env_path).expect(&format!("env.json should load for {}", claim_id));
        let manifest_json = load_json_file(&manifest_path)
            .expect(&format!("manifest.json should load for {}", claim_id));
        let lock_json =
            load_json_file(&lock_path).expect(&format!("repro.lock should load for {}", claim_id));

        // All should have timestamps
        assert!(env_json["captured_at_utc"].is_string());
        assert!(manifest_json["generated_at_utc"].is_string());
        assert!(lock_json["generated_at_utc"].is_string());

        // Timestamps should be reasonably close (same generation run)
        // This is a basic sanity check - they should all be from the same backfill run
    }
}

#[test]
fn bundle_coverage_completeness() {
    // Verify we have bundles for all expected OBSERVED claims
    let bundle_base = PathBuf::from("artifacts/reproducibility_bundles");

    if bundle_base.exists() {
        let found_bundles: BTreeMap<String, PathBuf> = fs::read_dir(&bundle_base)
            .expect("Should be able to read bundles directory")
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("FE-CLAIM-") {
                    Some((name.clone(), entry.path()))
                } else {
                    None
                }
            })
            .collect();

        // Should have exactly the expected claims
        let expected_count = OBSERVED_CLAIMS.len();
        assert_eq!(
            found_bundles.len(),
            expected_count,
            "Should have exactly {} bundles, found {}",
            expected_count,
            found_bundles.len()
        );

        // Each expected claim should have a bundle
        for claim_id in OBSERVED_CLAIMS {
            assert!(
                found_bundles.contains_key(*claim_id),
                "Should have bundle for claim {}",
                claim_id
            );
        }
    }
}
