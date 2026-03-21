//! Integration tests for shipped_path_parity_verifier module.
//!
//! Covers: command family enumeration, entrypoint surfaces, input languages,
//! execution outcomes, parity classification, matrix construction, verifier
//! configuration, serde roundtrips, and content-hash determinism.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::shipped_path_parity_verifier::{
    BEAD_ID, COMPONENT, CommandFamily, EntrypointSurface, ExecutionOutcome, MAX_CASES_PER_FAMILY,
    MAX_MATRIX_SIZE, ParityInputLanguage, ParityMatrix, ParityStatus, SCHEMA_VERSION,
    ShippedPathParityVerifier, VerifierConfig, VerifierVerdict, build_seed_matrix, classify_parity,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::assertions_on_constants)]
fn constants_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(MAX_CASES_PER_FAMILY > 0);
    assert!(MAX_MATRIX_SIZE > 0);
}

// ---------------------------------------------------------------------------
// CommandFamily
// ---------------------------------------------------------------------------

#[test]
fn command_family_all_count() {
    assert_eq!(CommandFamily::ALL.len(), 6);
}

#[test]
fn command_family_display_all() {
    let expected = [
        (CommandFamily::Compile, "compile"),
        (CommandFamily::Run, "run"),
        (CommandFamily::Verify, "verify"),
        (CommandFamily::Benchmark, "benchmark"),
        (CommandFamily::Replay, "replay"),
        (CommandFamily::Doctor, "doctor"),
    ];
    for (fam, name) in expected {
        assert_eq!(format!("{fam}"), name);
        assert_eq!(fam.as_str(), name);
    }
}

#[test]
fn command_family_serde_roundtrip() {
    for fam in CommandFamily::ALL {
        let json = serde_json::to_string(fam).unwrap();
        let decoded: CommandFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*fam, decoded);
    }
}

#[test]
fn command_family_description_nonempty() {
    for fam in CommandFamily::ALL {
        assert!(!fam.description().is_empty(), "{fam} has empty description");
    }
}

// ---------------------------------------------------------------------------
// EntrypointSurface
// ---------------------------------------------------------------------------

#[test]
fn entrypoint_surface_display() {
    assert_eq!(EntrypointSurface::LibraryApi.as_str(), "library_api");
    assert_eq!(EntrypointSurface::FrankenctlCli.as_str(), "frankenctl_cli");
}

#[test]
fn entrypoint_surface_serde_roundtrip() {
    for surface in [
        EntrypointSurface::LibraryApi,
        EntrypointSurface::FrankenctlCli,
    ] {
        let json = serde_json::to_string(&surface).unwrap();
        let decoded: EntrypointSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(surface, decoded);
    }
}

// ---------------------------------------------------------------------------
// ParityInputLanguage
// ---------------------------------------------------------------------------

#[test]
fn input_language_all_count() {
    assert_eq!(ParityInputLanguage::ALL.len(), 4);
}

#[test]
fn input_language_display_unique() {
    let mut names = BTreeSet::new();
    for lang in ParityInputLanguage::ALL {
        assert!(names.insert(lang.as_str().to_string()), "Duplicate: {lang}");
    }
}

#[test]
fn input_language_serde_roundtrip() {
    for lang in ParityInputLanguage::ALL {
        let json = serde_json::to_string(lang).unwrap();
        let decoded: ParityInputLanguage = serde_json::from_str(&json).unwrap();
        assert_eq!(*lang, decoded);
    }
}

// ---------------------------------------------------------------------------
// ExecutionOutcome
// ---------------------------------------------------------------------------

#[test]
fn execution_outcome_success_is_success() {
    let o = ExecutionOutcome::Success {
        output_hash: ContentHash::compute(b"test"),
        artifact_hash: None,
    };
    assert!(o.is_success());
    assert!(!o.is_error());
}

#[test]
fn execution_outcome_error_is_error() {
    let o = ExecutionOutcome::Error {
        error_code: "E001".to_string(),
        error_message: "test error".to_string(),
    };
    assert!(!o.is_success());
    assert!(o.is_error());
}

#[test]
fn execution_outcome_timeout_is_neither() {
    let o = ExecutionOutcome::Timeout {
        elapsed_millis: 1000,
    };
    assert!(!o.is_success());
    assert!(!o.is_error());
}

#[test]
fn execution_outcome_serde_roundtrip() {
    let outcomes = [
        ExecutionOutcome::Success {
            output_hash: ContentHash::compute(b"out"),
            artifact_hash: Some(ContentHash::compute(b"art")),
        },
        ExecutionOutcome::Error {
            error_code: "E123".to_string(),
            error_message: "fail".to_string(),
        },
        ExecutionOutcome::Timeout {
            elapsed_millis: 5000,
        },
        ExecutionOutcome::Crash { signal: Some(11) },
        ExecutionOutcome::Unsupported {
            reason: "not available".to_string(),
        },
    ];
    for outcome in &outcomes {
        let json = serde_json::to_string(outcome).unwrap();
        let decoded: ExecutionOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*outcome, decoded);
    }
}

// ---------------------------------------------------------------------------
// ParityStatus
// ---------------------------------------------------------------------------

#[test]
fn parity_status_acceptable_variants() {
    assert!(ParityStatus::Identical.is_acceptable());
    assert!(ParityStatus::SemanticEquivalent.is_acceptable());
    assert!(ParityStatus::CliExtraMetadata.is_acceptable());
    assert!(!ParityStatus::ArtifactSchemaDrift.is_acceptable());
    assert!(!ParityStatus::SuccessFailureSplit.is_acceptable());
    assert!(!ParityStatus::CrashDivergence.is_acceptable());
}

#[test]
fn parity_status_severity_ordering() {
    assert_eq!(ParityStatus::Identical.severity_millionths(), 0);
    assert!(
        ParityStatus::SemanticEquivalent.severity_millionths()
            < ParityStatus::ErrorMessageDivergence.severity_millionths()
    );
    assert!(
        ParityStatus::ErrorMessageDivergence.severity_millionths()
            < ParityStatus::SuccessFailureSplit.severity_millionths()
    );
    assert_eq!(
        ParityStatus::SuccessFailureSplit.severity_millionths(),
        1_000_000
    );
}

#[test]
fn parity_status_serde_roundtrip() {
    let statuses = [
        ParityStatus::Identical,
        ParityStatus::SemanticEquivalent,
        ParityStatus::CliExtraMetadata,
        ParityStatus::ArtifactSchemaDrift,
        ParityStatus::SuccessFailureSplit,
        ParityStatus::ErrorCodeDivergence,
        ParityStatus::ErrorMessageDivergence,
        ParityStatus::TimeoutDivergence,
        ParityStatus::CrashDivergence,
        ParityStatus::UnsupportedOnSurface,
    ];
    for status in statuses {
        let json = serde_json::to_string(&status).unwrap();
        let decoded: ParityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, decoded);
    }
}

#[test]
fn parity_status_display_unique() {
    let mut names = BTreeSet::new();
    let all = [
        ParityStatus::Identical,
        ParityStatus::SemanticEquivalent,
        ParityStatus::CliExtraMetadata,
        ParityStatus::ArtifactSchemaDrift,
        ParityStatus::SuccessFailureSplit,
        ParityStatus::ErrorCodeDivergence,
        ParityStatus::ErrorMessageDivergence,
        ParityStatus::TimeoutDivergence,
        ParityStatus::CrashDivergence,
        ParityStatus::UnsupportedOnSurface,
    ];
    for s in all {
        assert!(names.insert(format!("{s}")), "Duplicate display: {s}");
    }
}

// ---------------------------------------------------------------------------
// classify_parity function
// ---------------------------------------------------------------------------

#[test]
fn classify_identical_success() {
    let hash = ContentHash::compute(b"same");
    let lib = ExecutionOutcome::Success {
        output_hash: hash,
        artifact_hash: None,
    };
    let cli = ExecutionOutcome::Success {
        output_hash: hash,
        artifact_hash: None,
    };
    assert_eq!(classify_parity(&lib, &cli), ParityStatus::Identical);
}

#[test]
fn classify_schema_drift_on_different_hashes() {
    let lib = ExecutionOutcome::Success {
        output_hash: ContentHash::compute(b"lib_out"),
        artifact_hash: None,
    };
    let cli = ExecutionOutcome::Success {
        output_hash: ContentHash::compute(b"cli_out"),
        artifact_hash: None,
    };
    assert_eq!(
        classify_parity(&lib, &cli),
        ParityStatus::ArtifactSchemaDrift
    );
}

#[test]
fn classify_cli_extra_metadata_when_only_cli_has_artifact_hash() {
    let output_hash = ContentHash::compute(b"same_out");
    let lib = ExecutionOutcome::Success {
        output_hash,
        artifact_hash: None,
    };
    let cli = ExecutionOutcome::Success {
        output_hash,
        artifact_hash: Some(ContentHash::compute(b"cli_artifact")),
    };
    assert_eq!(classify_parity(&lib, &cli), ParityStatus::CliExtraMetadata);
}

#[test]
fn classify_schema_drift_when_artifact_hashes_differ() {
    let output_hash = ContentHash::compute(b"same_out");
    let lib = ExecutionOutcome::Success {
        output_hash,
        artifact_hash: Some(ContentHash::compute(b"lib_artifact")),
    };
    let cli = ExecutionOutcome::Success {
        output_hash,
        artifact_hash: Some(ContentHash::compute(b"cli_artifact")),
    };
    assert_eq!(
        classify_parity(&lib, &cli),
        ParityStatus::ArtifactSchemaDrift
    );
}

#[test]
fn classify_success_failure_split() {
    let lib = ExecutionOutcome::Success {
        output_hash: ContentHash::compute(b"ok"),
        artifact_hash: None,
    };
    let cli = ExecutionOutcome::Error {
        error_code: "E001".to_string(),
        error_message: "failed".to_string(),
    };
    assert_eq!(
        classify_parity(&lib, &cli),
        ParityStatus::SuccessFailureSplit
    );
}

#[test]
fn classify_identical_errors() {
    let lib = ExecutionOutcome::Error {
        error_code: "E001".to_string(),
        error_message: "msg".to_string(),
    };
    let cli = ExecutionOutcome::Error {
        error_code: "E001".to_string(),
        error_message: "msg".to_string(),
    };
    assert_eq!(classify_parity(&lib, &cli), ParityStatus::Identical);
}

#[test]
fn classify_error_code_divergence() {
    let lib = ExecutionOutcome::Error {
        error_code: "E001".to_string(),
        error_message: "msg".to_string(),
    };
    let cli = ExecutionOutcome::Error {
        error_code: "E002".to_string(),
        error_message: "msg".to_string(),
    };
    assert_eq!(
        classify_parity(&lib, &cli),
        ParityStatus::ErrorCodeDivergence
    );
}

#[test]
fn classify_error_message_divergence() {
    let lib = ExecutionOutcome::Error {
        error_code: "E001".to_string(),
        error_message: "lib msg".to_string(),
    };
    let cli = ExecutionOutcome::Error {
        error_code: "E001".to_string(),
        error_message: "cli msg".to_string(),
    };
    assert_eq!(
        classify_parity(&lib, &cli),
        ParityStatus::ErrorMessageDivergence
    );
}

#[test]
fn classify_timeout_divergence() {
    let lib = ExecutionOutcome::Success {
        output_hash: ContentHash::compute(b"ok"),
        artifact_hash: None,
    };
    let cli = ExecutionOutcome::Timeout {
        elapsed_millis: 5000,
    };
    assert_eq!(classify_parity(&lib, &cli), ParityStatus::TimeoutDivergence);
}

#[test]
fn classify_crash_divergence() {
    let lib = ExecutionOutcome::Success {
        output_hash: ContentHash::compute(b"ok"),
        artifact_hash: None,
    };
    let cli = ExecutionOutcome::Crash { signal: Some(11) };
    assert_eq!(classify_parity(&lib, &cli), ParityStatus::CrashDivergence);
}

#[test]
fn classify_unsupported() {
    let lib = ExecutionOutcome::Success {
        output_hash: ContentHash::compute(b"ok"),
        artifact_hash: None,
    };
    let cli = ExecutionOutcome::Unsupported {
        reason: "not available".to_string(),
    };
    assert_eq!(
        classify_parity(&lib, &cli),
        ParityStatus::UnsupportedOnSurface
    );
}

// ---------------------------------------------------------------------------
// ParityMatrix and build_seed_matrix
// ---------------------------------------------------------------------------

#[test]
fn seed_matrix_is_nonempty() {
    let matrix = build_seed_matrix();
    assert!(!matrix.test_cases.is_empty());
}

#[test]
fn seed_matrix_covers_all_command_families() {
    let matrix = build_seed_matrix();
    let families: BTreeSet<CommandFamily> =
        matrix.test_cases.iter().map(|c| c.command_family).collect();
    for fam in CommandFamily::ALL {
        assert!(families.contains(fam), "Missing family: {fam}");
    }
}

#[test]
fn seed_matrix_serde_roundtrip() {
    let m1 = build_seed_matrix();
    let json = serde_json::to_string(&m1).unwrap();
    let decoded: ParityMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m1.test_cases.len(), decoded.test_cases.len());
}

#[test]
fn parity_matrix_new_is_empty() {
    let matrix = ParityMatrix::new();
    assert!(matrix.test_cases.is_empty());
}

// ---------------------------------------------------------------------------
// VerifierConfig
// ---------------------------------------------------------------------------

#[test]
fn verifier_config_default_sane() {
    let cfg = VerifierConfig::default();
    assert!(cfg.min_coverage_ratio_millionths > 0);
    assert!(cfg.min_parity_rate_millionths > 0);
    assert!(cfg.max_avg_severity_millionths > 0);
    assert!(!cfg.required_families.is_empty());
}

#[test]
fn verifier_config_serde_roundtrip() {
    let cfg = VerifierConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let decoded: VerifierConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, decoded);
}

// ---------------------------------------------------------------------------
// VerifierVerdict
// ---------------------------------------------------------------------------

#[test]
fn verifier_verdict_pass_serde_roundtrip() {
    let v = VerifierVerdict::Pass;
    let json = serde_json::to_string(&v).unwrap();
    let decoded: VerifierVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
    assert!(v.is_pass());
}

#[test]
fn verifier_verdict_fail_is_not_pass() {
    let v = VerifierVerdict::Fail {
        reasons: Vec::new(),
    };
    assert!(!v.is_pass());
}

// ---------------------------------------------------------------------------
// ShippedPathParityVerifier
// ---------------------------------------------------------------------------

#[test]
fn verifier_with_seed_matrix_produces_report() {
    let verifier = ShippedPathParityVerifier::new(VerifierConfig::default());
    let matrix = build_seed_matrix();
    let report = verifier.verify(&matrix);
    assert!(!report.matrix_hash.as_bytes().is_empty());
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}
