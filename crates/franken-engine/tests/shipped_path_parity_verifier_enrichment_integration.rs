//! Enrichment integration tests for shipped_path_parity_verifier.
//!
//! Covers command families, entrypoint surfaces, parity matrix
//! operations, verifier configuration, rejection reasons, verdict
//! rendering, content hash stability, and full verification scenarios.
//!
//! Plan reference: bd-1lsy.9.6 (RGC-806).

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::shipped_path_parity_verifier::{
    BEAD_ID, COMPONENT, CommandFamily, EntrypointSurface, ExecutionOutcome, MAX_CASES_PER_FAMILY,
    MAX_MATRIX_SIZE, MatrixCellKey, ParityInputLanguage, ParityMatrix, ParityStatus,
    ParityTestCase, RejectionReason, SCHEMA_VERSION, ShippedPathParityVerifier, VerificationReport,
    VerifierConfig, VerifierVerdict,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn identical_case(id: &str, family: CommandFamily, lang: ParityInputLanguage) -> ParityTestCase {
    let hash = ContentHash::compute(id.as_bytes());
    ParityTestCase {
        id: id.to_string(),
        command_family: family,
        language: lang,
        input_description: format!("Test case {id}"),
        input_hash: hash,
        library_outcome: ExecutionOutcome::Success {
            output_hash: hash,
            artifact_hash: Some(hash),
        },
        cli_outcome: ExecutionOutcome::Success {
            output_hash: hash,
            artifact_hash: Some(hash),
        },
        parity_status: ParityStatus::Identical,
        divergence_details: String::new(),
        evidence_path: None,
    }
}

fn divergent_case(
    id: &str,
    family: CommandFamily,
    lang: ParityInputLanguage,
    status: ParityStatus,
) -> ParityTestCase {
    let hash = ContentHash::compute(id.as_bytes());
    ParityTestCase {
        id: id.to_string(),
        command_family: family,
        language: lang,
        input_description: format!("Divergent case {id}"),
        input_hash: hash,
        library_outcome: ExecutionOutcome::Success {
            output_hash: hash,
            artifact_hash: None,
        },
        cli_outcome: ExecutionOutcome::Error {
            error_code: "E001".to_string(),
            error_message: "Mismatch".to_string(),
        },
        parity_status: status,
        divergence_details: format!("Divergence in {id}"),
        evidence_path: Some(format!("artifacts/{id}.json")),
    }
}

/// Build a matrix with one identical case per (family, language) pair.
fn full_coverage_matrix() -> ParityMatrix {
    let mut matrix = ParityMatrix::new();
    let mut idx = 0;
    for family in CommandFamily::ALL {
        for lang in ParityInputLanguage::ALL {
            matrix
                .add_case(identical_case(&format!("case_{idx}"), *family, *lang))
                .unwrap();
            idx += 1;
        }
    }
    matrix
}

// ---------------------------------------------------------------------------
// CommandFamily
// ---------------------------------------------------------------------------

#[test]
fn command_family_all_count() {
    assert_eq!(CommandFamily::ALL.len(), 6);
}

#[test]
fn command_family_distinct_labels() {
    let strs: Vec<&str> = CommandFamily::ALL.iter().map(|f| f.as_str()).collect();
    for (i, a) in strs.iter().enumerate() {
        for (j, b) in strs.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "families {i} and {j} share label");
            }
        }
    }
}

#[test]
fn command_family_descriptions_non_empty() {
    for family in CommandFamily::ALL {
        assert!(!family.description().is_empty());
    }
}

#[test]
fn command_family_display_matches_as_str() {
    for family in CommandFamily::ALL {
        assert_eq!(format!("{family}"), family.as_str());
    }
}

#[test]
fn command_family_serde_roundtrip() {
    for family in CommandFamily::ALL {
        let json = serde_json::to_string(family).unwrap();
        let back: CommandFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*family, back);
    }
}

// ---------------------------------------------------------------------------
// EntrypointSurface
// ---------------------------------------------------------------------------

#[test]
fn entrypoint_surface_serde() {
    for surface in [
        EntrypointSurface::LibraryApi,
        EntrypointSurface::FrankenctlCli,
    ] {
        let json = serde_json::to_string(&surface).unwrap();
        let back: EntrypointSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(surface, back);
    }
}

#[test]
fn entrypoint_surface_display() {
    assert_eq!(format!("{}", EntrypointSurface::LibraryApi), "library_api");
    assert_eq!(
        format!("{}", EntrypointSurface::FrankenctlCli),
        "frankenctl_cli"
    );
}

// ---------------------------------------------------------------------------
// ParityInputLanguage
// ---------------------------------------------------------------------------

#[test]
fn parity_input_language_all_count() {
    assert_eq!(ParityInputLanguage::ALL.len(), 4);
}

#[test]
fn parity_input_language_serde_roundtrip() {
    for lang in ParityInputLanguage::ALL {
        let json = serde_json::to_string(lang).unwrap();
        let back: ParityInputLanguage = serde_json::from_str(&json).unwrap();
        assert_eq!(*lang, back);
    }
}

// ---------------------------------------------------------------------------
// ExecutionOutcome
// ---------------------------------------------------------------------------

#[test]
fn outcome_success_is_success() {
    let o = ExecutionOutcome::Success {
        output_hash: ContentHash::compute(b"out"),
        artifact_hash: None,
    };
    assert!(o.is_success());
    assert!(!o.is_error());
}

#[test]
fn outcome_error_is_error() {
    let o = ExecutionOutcome::Error {
        error_code: "E001".to_string(),
        error_message: "fail".to_string(),
    };
    assert!(o.is_error());
    assert!(!o.is_success());
}

#[test]
fn outcome_timeout_neither() {
    let o = ExecutionOutcome::Timeout {
        elapsed_millis: 5000,
    };
    assert!(!o.is_success());
    assert!(!o.is_error());
}

#[test]
fn outcome_serde_all_variants() {
    let outcomes = vec![
        ExecutionOutcome::Success {
            output_hash: ContentHash::compute(b"out"),
            artifact_hash: Some(ContentHash::compute(b"art")),
        },
        ExecutionOutcome::Error {
            error_code: "E001".to_string(),
            error_message: "msg".to_string(),
        },
        ExecutionOutcome::Timeout {
            elapsed_millis: 1000,
        },
        ExecutionOutcome::Crash { signal: Some(9) },
        ExecutionOutcome::Crash { signal: None },
        ExecutionOutcome::Unsupported {
            reason: "not available".to_string(),
        },
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).unwrap();
        let back: ExecutionOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

// ---------------------------------------------------------------------------
// ParityStatus
// ---------------------------------------------------------------------------

#[test]
fn parity_status_acceptable_partition() {
    let acceptable = [
        ParityStatus::Identical,
        ParityStatus::SemanticEquivalent,
        ParityStatus::CliExtraMetadata,
    ];
    let unacceptable = [
        ParityStatus::ArtifactSchemaDrift,
        ParityStatus::SuccessFailureSplit,
        ParityStatus::ErrorCodeDivergence,
        ParityStatus::ErrorMessageDivergence,
        ParityStatus::TimeoutDivergence,
        ParityStatus::CrashDivergence,
    ];
    for s in acceptable {
        assert!(s.is_acceptable(), "{s} should be acceptable");
    }
    for s in unacceptable {
        assert!(!s.is_acceptable(), "{s} should not be acceptable");
    }
    // UnsupportedOnSurface is a special case — severity 0 but not acceptable
    assert!(!ParityStatus::UnsupportedOnSurface.is_acceptable());
}

#[test]
fn parity_status_severity_ordering() {
    // Identical should have lowest severity
    assert_eq!(ParityStatus::Identical.severity_millionths(), 0);
    // SuccessFailureSplit should have highest
    assert_eq!(
        ParityStatus::SuccessFailureSplit.severity_millionths(),
        1_000_000
    );
    // CrashDivergence should be very high
    assert!(ParityStatus::CrashDivergence.severity_millionths() > 800_000);
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
    for s in statuses {
        let json = serde_json::to_string(&s).unwrap();
        let back: ParityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ---------------------------------------------------------------------------
// ParityMatrix
// ---------------------------------------------------------------------------

#[test]
fn matrix_empty_by_default() {
    let m = ParityMatrix::new();
    assert_eq!(m.case_count(), 0);
    assert_eq!(m.covered_cell_count(), 0);
    assert_eq!(m.version, SCHEMA_VERSION);
}

#[test]
fn matrix_total_possible_cells() {
    let total = ParityMatrix::total_possible_cells();
    assert_eq!(
        total,
        CommandFamily::ALL.len() * ParityInputLanguage::ALL.len()
    );
    assert_eq!(total, 24); // 6 * 4
}

#[test]
fn matrix_add_case_updates_summaries() {
    let mut m = ParityMatrix::new();
    m.add_case(identical_case(
        "c1",
        CommandFamily::Compile,
        ParityInputLanguage::JavaScript,
    ))
    .unwrap();
    assert_eq!(m.case_count(), 1);
    assert_eq!(m.covered_cell_count(), 1);
    assert_eq!(m.cell_summaries[0].acceptable_count, 1);
}

#[test]
fn matrix_duplicate_rejected() {
    let mut m = ParityMatrix::new();
    m.add_case(identical_case(
        "c1",
        CommandFamily::Compile,
        ParityInputLanguage::JavaScript,
    ))
    .unwrap();
    let err = m
        .add_case(identical_case(
            "c1",
            CommandFamily::Run,
            ParityInputLanguage::TypeScript,
        ))
        .unwrap_err();
    assert!(format!("{err}").contains("c1"));
}

#[test]
fn matrix_uncovered_cells_empty_matrix() {
    let m = ParityMatrix::new();
    let uncovered = m.uncovered_cells();
    assert_eq!(uncovered.len(), ParityMatrix::total_possible_cells());
}

#[test]
fn matrix_full_coverage_no_uncovered() {
    let m = full_coverage_matrix();
    assert_eq!(m.case_count(), 24);
    assert_eq!(m.covered_cell_count(), 24);
    assert!(m.uncovered_cells().is_empty());
}

#[test]
fn matrix_unacceptable_cases_filter() {
    let mut m = ParityMatrix::new();
    m.add_case(identical_case(
        "ok",
        CommandFamily::Compile,
        ParityInputLanguage::JavaScript,
    ))
    .unwrap();
    m.add_case(divergent_case(
        "bad",
        CommandFamily::Compile,
        ParityInputLanguage::TypeScript,
        ParityStatus::SuccessFailureSplit,
    ))
    .unwrap();
    let bad = m.unacceptable_cases();
    assert_eq!(bad.len(), 1);
    assert_eq!(bad[0].id, "bad");
}

#[test]
fn matrix_content_hash_deterministic() {
    let m1 = full_coverage_matrix();
    let m2 = full_coverage_matrix();
    assert_eq!(m1.content_hash(), m2.content_hash());
}

#[test]
fn matrix_content_hash_changes_with_case() {
    let m1 = full_coverage_matrix();
    let mut m2 = full_coverage_matrix();
    // Add an extra case with a unique ID — same cell but different content
    m2.add_case(divergent_case(
        "extra_99",
        CommandFamily::Compile,
        ParityInputLanguage::JavaScript,
        ParityStatus::ErrorCodeDivergence,
    ))
    .unwrap();
    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn matrix_cell_summary_parity_rate() {
    let mut m = ParityMatrix::new();
    // 3 identical + 1 divergent in same cell = 75% parity
    for i in 0..3 {
        m.add_case(identical_case(
            &format!("ok_{i}"),
            CommandFamily::Compile,
            ParityInputLanguage::JavaScript,
        ))
        .unwrap();
    }
    m.add_case(divergent_case(
        "bad_0",
        CommandFamily::Compile,
        ParityInputLanguage::JavaScript,
        ParityStatus::SuccessFailureSplit,
    ))
    .unwrap();
    let summary = &m.cell_summaries[0];
    assert_eq!(summary.total_cases, 4);
    assert_eq!(summary.acceptable_count, 3);
    assert_eq!(summary.unacceptable_count, 1);
    assert_eq!(summary.parity_rate_millionths, 750_000);
}

#[test]
fn matrix_serde_roundtrip() {
    let m = full_coverage_matrix();
    let json = serde_json::to_string_pretty(&m).unwrap();
    let back: ParityMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m.case_count(), back.case_count());
    assert_eq!(m.content_hash(), back.content_hash());
}

// ---------------------------------------------------------------------------
// VerifierConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let config = VerifierConfig::default();
    assert_eq!(config.min_coverage_ratio_millionths, 800_000);
    assert_eq!(config.min_parity_rate_millionths, 950_000);
    assert_eq!(config.max_avg_severity_millionths, 100_000);
    assert_eq!(config.required_families.len(), CommandFamily::ALL.len());
    assert_eq!(config.required_languages.len(), 2); // JS and TS
}

#[test]
fn config_serde_roundtrip() {
    let config = VerifierConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: VerifierConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// ShippedPathParityVerifier
// ---------------------------------------------------------------------------

#[test]
fn verifier_empty_matrix_fails() {
    let verifier = ShippedPathParityVerifier::with_defaults();
    let matrix = ParityMatrix::new();
    let report = verifier.verify(&matrix);
    assert!(!report.verdict.is_pass());
}

#[test]
fn verifier_full_coverage_passes() {
    let config = VerifierConfig {
        min_coverage_ratio_millionths: 800_000,
        min_parity_rate_millionths: 900_000,
        max_avg_severity_millionths: 100_000,
        required_families: BTreeSet::new(), // No required families
        required_languages: BTreeSet::new(), // No required languages
    };
    let verifier = ShippedPathParityVerifier::new(config);
    let matrix = full_coverage_matrix();
    let report = verifier.verify(&matrix);
    assert!(
        report.verdict.is_pass(),
        "full coverage should pass: {:?}",
        report.verdict
    );
}

#[test]
fn verifier_missing_family_fails() {
    let mut config = VerifierConfig {
        min_coverage_ratio_millionths: 0, // Don't fail on coverage
        ..Default::default()
    };
    config.required_languages.clear();
    let verifier = ShippedPathParityVerifier::new(config);

    // Only add Compile family
    let mut matrix = ParityMatrix::new();
    matrix
        .add_case(identical_case(
            "c1",
            CommandFamily::Compile,
            ParityInputLanguage::JavaScript,
        ))
        .unwrap();

    let report = verifier.verify(&matrix);
    assert!(!report.verdict.is_pass());
    if let VerifierVerdict::Fail { reasons } = &report.verdict {
        let has_missing = reasons
            .iter()
            .any(|r| matches!(r, RejectionReason::MissingFamily { .. }));
        assert!(has_missing, "should have missing family reason");
    }
}

#[test]
fn verifier_report_has_correct_counts() {
    let verifier = ShippedPathParityVerifier::with_defaults();
    let matrix = full_coverage_matrix();
    let report = verifier.verify(&matrix);
    assert_eq!(report.total_cases, 24);
    assert_eq!(report.covered_cells, 24);
    assert_eq!(report.total_possible_cells, 24);
    assert_eq!(report.coverage_ratio_millionths, 1_000_000);
    assert_eq!(report.unacceptable_case_count, 0);
}

#[test]
fn verifier_report_serde_roundtrip() {
    let verifier = ShippedPathParityVerifier::with_defaults();
    let matrix = full_coverage_matrix();
    let report = verifier.verify(&matrix);
    let json = serde_json::to_string_pretty(&report).unwrap();
    let back: VerificationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.total_cases, back.total_cases);
    assert_eq!(report.matrix_hash, back.matrix_hash);
}

// ---------------------------------------------------------------------------
// VerifierVerdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_pass_display() {
    let v = VerifierVerdict::Pass;
    assert!(v.is_pass());
    assert_eq!(format!("{v}"), "PASS");
}

#[test]
fn verdict_fail_display() {
    let v = VerifierVerdict::Fail {
        reasons: vec![RejectionReason::EmptyMatrix],
    };
    assert!(!v.is_pass());
    assert!(format!("{v}").contains("FAIL"));
}

#[test]
fn verdict_insufficient_data_display() {
    let v = VerifierVerdict::InsufficientData {
        reason: "no data".to_string(),
    };
    assert!(!v.is_pass());
    assert!(format!("{v}").contains("INSUFFICIENT_DATA"));
}

// ---------------------------------------------------------------------------
// RejectionReason
// ---------------------------------------------------------------------------

#[test]
fn rejection_reason_display_all_variants() {
    let reasons = vec![
        RejectionReason::EmptyMatrix,
        RejectionReason::InsufficientCoverage {
            required_ratio_millionths: 800_000,
            actual_ratio_millionths: 500_000,
        },
        RejectionReason::MissingFamily {
            family: CommandFamily::Compile,
        },
        RejectionReason::MissingLanguage {
            language: ParityInputLanguage::TypeScript,
        },
        RejectionReason::CellParityBelowThreshold {
            key: MatrixCellKey {
                command_family: CommandFamily::Run,
                language: ParityInputLanguage::Jsx,
            },
            rate_millionths: 500_000,
            threshold: 950_000,
        },
        RejectionReason::ExcessiveSeverity {
            avg_severity_millionths: 300_000,
            threshold: 100_000,
        },
    ];
    for r in &reasons {
        let msg = format!("{r}");
        assert!(
            !msg.is_empty(),
            "rejection reason display should not be empty"
        );
    }
}

#[test]
fn rejection_reason_serde_roundtrip() {
    let reasons = vec![
        RejectionReason::EmptyMatrix,
        RejectionReason::InsufficientCoverage {
            required_ratio_millionths: 800_000,
            actual_ratio_millionths: 500_000,
        },
        RejectionReason::MissingFamily {
            family: CommandFamily::Doctor,
        },
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::assertions_on_constants)]
fn constants_valid() {
    assert!(!COMPONENT.is_empty());
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(MAX_CASES_PER_FAMILY > 0);
    assert!(MAX_MATRIX_SIZE > 0);
}

#[test]
fn schema_version_contains_component() {
    assert!(SCHEMA_VERSION.contains("shipped-path-parity-verifier"));
}
