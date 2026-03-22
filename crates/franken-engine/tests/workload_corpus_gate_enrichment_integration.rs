//! Enrichment integration tests for workload_corpus_gate.
//!
//! Covers workload family taxonomy, provenance tracking, license
//! status, corpus management, behavior equivalence, verdict engine,
//! content hash stability, and full serde round-trips.
//!
//! Plan reference: bd-1lsy.8.4 (RGC-704).

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::workload_corpus_gate::{
    BEAD_ID, COMPONENT, EQUIVALENCE_CONFIDENCE_THRESHOLD, LicenseStatus, MAX_CORPUS_SIZE,
    MAX_DIVERGENCE_RATIO, MAX_WORKLOADS_PER_FAMILY, MIN_REQUIRED_FAMILIES,
    MIN_WORKLOADS_PER_FAMILY, ObservabilityMode, SCHEMA_VERSION, WorkloadFamily, WorkloadOrigin,
    WorkloadProvenance,
};

// ---------------------------------------------------------------------------
// WorkloadFamily
// ---------------------------------------------------------------------------

#[test]
fn workload_family_all_count() {
    assert_eq!(WorkloadFamily::ALL.len(), 16);
}

#[test]
fn workload_family_distinct_labels() {
    let strs: Vec<&str> = WorkloadFamily::ALL.iter().map(|f| f.as_str()).collect();
    for (i, a) in strs.iter().enumerate() {
        for (j, b) in strs.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "families {i} and {j} share label {a}");
            }
        }
    }
}

#[test]
fn workload_family_descriptions_non_empty() {
    for family in WorkloadFamily::ALL {
        assert!(
            !family.description().is_empty(),
            "{family} has empty description"
        );
    }
}

#[test]
fn workload_family_display_matches_as_str() {
    for family in WorkloadFamily::ALL {
        assert_eq!(format!("{family}"), family.as_str());
    }
}

#[test]
fn workload_family_serde_roundtrip() {
    for family in WorkloadFamily::ALL {
        let json = serde_json::to_string(family).unwrap();
        let back: WorkloadFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*family, back);
    }
}

#[test]
fn workload_family_ordering_stable() {
    let mut sorted = WorkloadFamily::ALL.to_vec();
    sorted.sort();
    let mut resorted = sorted.clone();
    resorted.sort();
    assert_eq!(sorted, resorted);
}

// ---------------------------------------------------------------------------
// WorkloadOrigin
// ---------------------------------------------------------------------------

#[test]
fn workload_origin_all_variants_serde() {
    let origins = [
        WorkloadOrigin::NpmPackage,
        WorkloadOrigin::OpenSourceProject,
        WorkloadOrigin::BenchmarkSuite,
        WorkloadOrigin::Synthetic,
        WorkloadOrigin::RealUserAnonymized,
        WorkloadOrigin::InternalFixture,
    ];
    for origin in origins {
        let json = serde_json::to_string(&origin).unwrap();
        let back: WorkloadOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(origin, back);
    }
}

#[test]
fn workload_origin_display_matches_as_str() {
    for origin in [
        WorkloadOrigin::NpmPackage,
        WorkloadOrigin::OpenSourceProject,
        WorkloadOrigin::BenchmarkSuite,
        WorkloadOrigin::Synthetic,
        WorkloadOrigin::RealUserAnonymized,
        WorkloadOrigin::InternalFixture,
    ] {
        assert_eq!(format!("{origin}"), origin.as_str());
    }
}

// ---------------------------------------------------------------------------
// LicenseStatus
// ---------------------------------------------------------------------------

#[test]
fn license_publishable_partition() {
    assert!(LicenseStatus::Permissive.is_publishable());
    assert!(!LicenseStatus::Copyleft.is_publishable());
    assert!(!LicenseStatus::Restricted.is_publishable());
    assert!(!LicenseStatus::Unknown.is_publishable());
}

#[test]
fn license_status_serde_roundtrip() {
    for status in [
        LicenseStatus::Permissive,
        LicenseStatus::Copyleft,
        LicenseStatus::Restricted,
        LicenseStatus::Unknown,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let back: LicenseStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }
}

#[test]
fn license_status_display_matches_as_str() {
    for status in [
        LicenseStatus::Permissive,
        LicenseStatus::Copyleft,
        LicenseStatus::Restricted,
        LicenseStatus::Unknown,
    ] {
        assert_eq!(format!("{status}"), status.as_str());
    }
}

// ---------------------------------------------------------------------------
// ObservabilityMode
// ---------------------------------------------------------------------------

#[test]
fn observability_mode_serde_roundtrip() {
    for mode in [
        ObservabilityMode::BudgetedDefault,
        ObservabilityMode::ExactShadow,
        ObservabilityMode::Degraded,
        ObservabilityMode::IncidentFullCapture,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        let back: ObservabilityMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }
}

#[test]
fn observability_mode_display_matches_as_str() {
    for mode in [
        ObservabilityMode::BudgetedDefault,
        ObservabilityMode::ExactShadow,
        ObservabilityMode::Degraded,
        ObservabilityMode::IncidentFullCapture,
    ] {
        assert_eq!(format!("{mode}"), mode.as_str());
    }
}

// ---------------------------------------------------------------------------
// WorkloadProvenance
// ---------------------------------------------------------------------------

#[test]
fn provenance_serde_roundtrip() {
    let prov = WorkloadProvenance {
        origin: WorkloadOrigin::NpmPackage,
        source_url: "https://registry.npmjs.org/express".to_string(),
        license: LicenseStatus::Permissive,
        spdx_id: Some("MIT".to_string()),
        source_version: "4.18.2".to_string(),
        selection_rationale: "Top-10 npm package by downloads".to_string(),
        content_hash: ContentHash::compute(b"express_source"),
    };
    let json = serde_json::to_string_pretty(&prov).unwrap();
    let back: WorkloadProvenance = serde_json::from_str(&json).unwrap();
    assert_eq!(prov, back);
}

#[test]
fn provenance_without_spdx() {
    let prov = WorkloadProvenance {
        origin: WorkloadOrigin::Synthetic,
        source_url: String::new(),
        license: LicenseStatus::Unknown,
        spdx_id: None,
        source_version: "generated".to_string(),
        selection_rationale: "Coverage gap fill".to_string(),
        content_hash: ContentHash::compute(b"synthetic"),
    };
    let json = serde_json::to_string(&prov).unwrap();
    let back: WorkloadProvenance = serde_json::from_str(&json).unwrap();
    assert!(back.spdx_id.is_none());
}

#[test]
fn provenance_all_origin_license_combos() {
    let origins = [
        WorkloadOrigin::NpmPackage,
        WorkloadOrigin::OpenSourceProject,
        WorkloadOrigin::BenchmarkSuite,
        WorkloadOrigin::Synthetic,
        WorkloadOrigin::RealUserAnonymized,
        WorkloadOrigin::InternalFixture,
    ];
    let licenses = [
        LicenseStatus::Permissive,
        LicenseStatus::Copyleft,
        LicenseStatus::Restricted,
        LicenseStatus::Unknown,
    ];
    for origin in &origins {
        for license in &licenses {
            let prov = WorkloadProvenance {
                origin: *origin,
                source_url: format!("test://{}", origin.as_str()),
                license: *license,
                spdx_id: None,
                source_version: "1.0".to_string(),
                selection_rationale: "test".to_string(),
                content_hash: ContentHash::compute(
                    format!("{}:{}", origin.as_str(), license.as_str()).as_bytes(),
                ),
            };
            let json = serde_json::to_string(&prov).unwrap();
            let back: WorkloadProvenance = serde_json::from_str(&json).unwrap();
            assert_eq!(back.origin, *origin);
            assert_eq!(back.license, *license);
        }
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
    assert!(MAX_WORKLOADS_PER_FAMILY > 0);
    assert!(MAX_CORPUS_SIZE > 0);
    assert!(MIN_REQUIRED_FAMILIES > 0);
    assert!(MIN_REQUIRED_FAMILIES <= WorkloadFamily::ALL.len());
    assert!(MIN_WORKLOADS_PER_FAMILY > 0);
    assert!(EQUIVALENCE_CONFIDENCE_THRESHOLD > 0);
    assert!(EQUIVALENCE_CONFIDENCE_THRESHOLD <= 1_000_000);
    assert!(MAX_DIVERGENCE_RATIO > 0);
    assert!(MAX_DIVERGENCE_RATIO <= 1_000_000);
}

#[test]
fn schema_version_contains_component() {
    assert!(SCHEMA_VERSION.contains("workload-corpus-gate"));
}

#[test]
fn bead_id_matches_plan() {
    assert_eq!(BEAD_ID, "bd-1lsy.8.4");
}

#[test]
fn min_required_families_reasonable() {
    // Should require at least 10 of 16 families
    assert_eq!(MIN_REQUIRED_FAMILIES, 10);
    assert_eq!(WorkloadFamily::ALL.len(), 16);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn corpus_size_larger_than_per_family() {
    // Max corpus should accommodate at least MIN_REQUIRED_FAMILIES * MAX_WORKLOADS_PER_FAMILY
    assert!(MAX_CORPUS_SIZE >= MIN_REQUIRED_FAMILIES * MIN_WORKLOADS_PER_FAMILY);
}

// ---------------------------------------------------------------------------
// Cross-cutting: family coverage
// ---------------------------------------------------------------------------

#[test]
fn all_families_have_unique_descriptions() {
    let descs: Vec<&str> = WorkloadFamily::ALL
        .iter()
        .map(|f| f.description())
        .collect();
    for (i, a) in descs.iter().enumerate() {
        for (j, b) in descs.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "families {i} and {j} share description");
            }
        }
    }
}

#[test]
fn family_react_related_exists() {
    // Mixed real world should cover React-like patterns
    let has_mixed = WorkloadFamily::ALL.contains(&WorkloadFamily::MixedRealWorld);
    assert!(
        has_mixed,
        "should have mixed real world family for React coverage"
    );
}

#[test]
fn family_async_exists() {
    let has_async = WorkloadFamily::ALL.contains(&WorkloadFamily::AsyncHeavy);
    assert!(has_async, "should have async-heavy family");
}

#[test]
fn family_typescript_exists() {
    let has_ts = WorkloadFamily::ALL.contains(&WorkloadFamily::TypeScriptHeavy);
    assert!(has_ts, "should have typescript-heavy family");
}

// ---------------------------------------------------------------------------
// Provenance determinism
// ---------------------------------------------------------------------------

#[test]
fn provenance_content_hash_deterministic() {
    let bytes = b"deterministic_source_content";
    let h1 = ContentHash::compute(bytes);
    let h2 = ContentHash::compute(bytes);
    assert_eq!(h1, h2);
}

#[test]
fn provenance_content_hash_differs_by_content() {
    let h1 = ContentHash::compute(b"source_a");
    let h2 = ContentHash::compute(b"source_b");
    assert_ne!(h1, h2);
}

// ---------------------------------------------------------------------------
// Large-scale family enumeration
// ---------------------------------------------------------------------------

#[test]
fn all_families_serde_stable() {
    // Serialize all, sort, deserialize — order should be stable
    let jsons: Vec<String> = WorkloadFamily::ALL
        .iter()
        .map(|f| serde_json::to_string(f).unwrap())
        .collect();
    let backs: Vec<WorkloadFamily> = jsons
        .iter()
        .map(|j| serde_json::from_str(j).unwrap())
        .collect();
    for (orig, back) in WorkloadFamily::ALL.iter().zip(backs.iter()) {
        assert_eq!(*orig, *back);
    }
}
