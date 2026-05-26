//! FRX-20.1 unit-test taxonomy and fixture registry contract.
//!
//! This module defines a deterministic, versioned taxonomy for unit-test
//! classes and binds fixture registries to lane ownership and replay controls.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const UNIT_TEST_TAXONOMY_SCHEMA_VERSION: &str = "frx.unit-test-taxonomy.v1";
pub const FIXTURE_REGISTRY_SCHEMA_VERSION: &str = "frx.fixture-registry.v1";
pub const DETERMINISM_CONTRACT_SCHEMA_VERSION: &str = "frx.test-determinism-contract.v1";

pub const REQUIRED_STRUCTURED_LOG_FIELDS: &[&str] = &[
    "schema_version",
    "scenario_id",
    "trace_id",
    "decision_id",
    "policy_id",
    "component",
    "event",
    "decision_path",
    "seed",
    "timing_us",
    "outcome",
    "error_code",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitTestClass {
    Core,
    Edge,
    Adversarial,
    Regression,
    FaultInjection,
}

impl UnitTestClass {
    pub const ALL: [Self; 5] = [
        Self::Core,
        Self::Edge,
        Self::Adversarial,
        Self::Regression,
        Self::FaultInjection,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Edge => "edge",
            Self::Adversarial => "adversarial",
            Self::Regression => "regression",
            Self::FaultInjection => "fault_injection",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneId {
    Compiler,
    JsRuntime,
    WasmRuntime,
    HybridRouter,
    Verification,
    Toolchain,
    GovernanceEvidence,
    AdoptionRelease,
}

impl LaneId {
    pub const ALL: [Self; 8] = [
        Self::Compiler,
        Self::JsRuntime,
        Self::WasmRuntime,
        Self::HybridRouter,
        Self::Verification,
        Self::Toolchain,
        Self::GovernanceEvidence,
        Self::AdoptionRelease,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compiler => "compiler",
            Self::JsRuntime => "js_runtime",
            Self::WasmRuntime => "wasm_runtime",
            Self::HybridRouter => "hybrid_router",
            Self::Verification => "verification",
            Self::Toolchain => "toolchain",
            Self::GovernanceEvidence => "governance_evidence",
            Self::AdoptionRelease => "adoption_release",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterminismContract {
    pub schema_version: String,
    pub require_seed: bool,
    pub require_seed_transcript_checksum: bool,
    pub require_fixed_timezone: bool,
    pub timezone: String,
    pub require_fixed_locale: bool,
    pub lang: String,
    pub lc_all: String,
    pub require_toolchain_fingerprint: bool,
    pub require_replay_command: bool,
}

impl DeterminismContract {
    pub fn default_frx20() -> Self {
        Self {
            schema_version: DETERMINISM_CONTRACT_SCHEMA_VERSION.to_string(),
            require_seed: true,
            require_seed_transcript_checksum: true,
            require_fixed_timezone: true,
            timezone: "UTC".to_string(),
            require_fixed_locale: true,
            lang: "C.UTF-8".to_string(),
            lc_all: "C.UTF-8".to_string(),
            require_toolchain_fingerprint: true,
            require_replay_command: true,
        }
    }

    fn validate(&self) -> Result<(), TaxonomyValidationError> {
        if self.schema_version != DETERMINISM_CONTRACT_SCHEMA_VERSION {
            return Err(TaxonomyValidationError::InvalidSchemaVersion {
                field: "determinism_contract.schema_version".to_string(),
                expected: DETERMINISM_CONTRACT_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.require_fixed_timezone && self.timezone.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: "determinism_contract.timezone".to_string(),
            });
        }
        if self.require_fixed_locale
            && (self.lang.trim().is_empty() || self.lc_all.trim().is_empty())
        {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: "determinism_contract.locale".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureRegistryEntry {
    pub fixture_id: String,
    pub fixture_path: String,
    pub trace_path: Option<String>,
    pub provenance: String,
    pub owner_lane: LaneId,
    pub required_classes: Vec<UnitTestClass>,
    pub e2e_family: String,
    pub seed_strategy: String,
    pub structured_log_fields: Vec<String>,
    pub artifact_retention: String,
}

impl FixtureRegistryEntry {
    fn validate(&self, seen_ids: &mut BTreeSet<String>) -> Result<(), TaxonomyValidationError> {
        if self.fixture_id.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: "fixture_registry.fixture_id".to_string(),
            });
        }
        if !seen_ids.insert(self.fixture_id.clone()) {
            return Err(TaxonomyValidationError::DuplicateFixtureId {
                fixture_id: self.fixture_id.clone(),
            });
        }
        if self.fixture_path.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("fixture_registry.{}.fixture_path", self.fixture_id),
            });
        }
        if self.provenance.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("fixture_registry.{}.provenance", self.fixture_id),
            });
        }
        if self.required_classes.is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("fixture_registry.{}.required_classes", self.fixture_id),
            });
        }
        if self.e2e_family.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("fixture_registry.{}.e2e_family", self.fixture_id),
            });
        }
        if self.seed_strategy.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("fixture_registry.{}.seed_strategy", self.fixture_id),
            });
        }
        if self.artifact_retention.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("fixture_registry.{}.artifact_retention", self.fixture_id),
            });
        }

        let field_set: BTreeSet<&str> = self
            .structured_log_fields
            .iter()
            .map(String::as_str)
            .collect();
        for required in REQUIRED_STRUCTURED_LOG_FIELDS {
            if !field_set.contains(required) {
                return Err(TaxonomyValidationError::MissingStructuredLogField {
                    fixture_id: self.fixture_id.clone(),
                    field: (*required).to_string(),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneCoverageContract {
    pub lane: LaneId,
    pub owner: String,
    pub required_unit_classes: Vec<UnitTestClass>,
    pub mapped_e2e_families: Vec<String>,
    pub coverage_rationale: String,
}

impl LaneCoverageContract {
    fn validate(&self) -> Result<(), TaxonomyValidationError> {
        if self.owner.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("lane_coverage.{}.owner", self.lane.as_str()),
            });
        }
        if self.required_unit_classes.is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("lane_coverage.{}.required_unit_classes", self.lane.as_str()),
            });
        }
        if self.mapped_e2e_families.is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("lane_coverage.{}.mapped_e2e_families", self.lane.as_str()),
            });
        }
        if self.coverage_rationale.trim().is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: format!("lane_coverage.{}.coverage_rationale", self.lane.as_str()),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitTestTaxonomyBundle {
    pub schema_version: String,
    pub fixture_registry_schema_version: String,
    pub determinism_contract: DeterminismContract,
    pub lane_coverage: Vec<LaneCoverageContract>,
    pub fixture_registry: Vec<FixtureRegistryEntry>,
}

impl UnitTestTaxonomyBundle {
    pub fn validate_for_gate(&self) -> Result<(), TaxonomyValidationError> {
        if self.schema_version != UNIT_TEST_TAXONOMY_SCHEMA_VERSION {
            return Err(TaxonomyValidationError::InvalidSchemaVersion {
                field: "schema_version".to_string(),
                expected: UNIT_TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.fixture_registry_schema_version != FIXTURE_REGISTRY_SCHEMA_VERSION {
            return Err(TaxonomyValidationError::InvalidSchemaVersion {
                field: "fixture_registry_schema_version".to_string(),
                expected: FIXTURE_REGISTRY_SCHEMA_VERSION.to_string(),
                actual: self.fixture_registry_schema_version.clone(),
            });
        }

        self.determinism_contract.validate()?;

        if self.lane_coverage.is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: "lane_coverage".to_string(),
            });
        }

        let mut seen_lanes = BTreeSet::new();
        for coverage in &self.lane_coverage {
            coverage.validate()?;
            if !seen_lanes.insert(coverage.lane) {
                return Err(TaxonomyValidationError::DuplicateLaneCoverage {
                    lane: coverage.lane.as_str().to_string(),
                });
            }
        }

        for lane in LaneId::ALL {
            if !seen_lanes.contains(&lane) {
                return Err(TaxonomyValidationError::MissingLaneCoverage {
                    lane: lane.as_str().to_string(),
                });
            }
        }

        if self.fixture_registry.is_empty() {
            return Err(TaxonomyValidationError::MissingRequiredField {
                field: "fixture_registry".to_string(),
            });
        }

        let mut seen_fixture_ids = BTreeSet::new();
        for fixture in &self.fixture_registry {
            fixture.validate(&mut seen_fixture_ids)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaxonomyValidationError {
    MissingRequiredField {
        field: String,
    },
    InvalidSchemaVersion {
        field: String,
        expected: String,
        actual: String,
    },
    MissingStructuredLogField {
        fixture_id: String,
        field: String,
    },
    DuplicateFixtureId {
        fixture_id: String,
    },
    DuplicateLaneCoverage {
        lane: String,
    },
    MissingLaneCoverage {
        lane: String,
    },
}

impl TaxonomyValidationError {
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::MissingRequiredField { .. } => "FE-FRX-20-1-REGISTRY-0001",
            Self::InvalidSchemaVersion { .. } => "FE-FRX-20-1-SCHEMA-0001",
            Self::MissingStructuredLogField { .. } => "FE-FRX-20-1-LOGGING-0001",
            Self::DuplicateFixtureId { .. } => "FE-FRX-20-1-REGISTRY-0002",
            Self::DuplicateLaneCoverage { .. } => "FE-FRX-20-1-COVERAGE-0001",
            Self::MissingLaneCoverage { .. } => "FE-FRX-20-1-COVERAGE-0002",
        }
    }
}

pub fn default_frx20_bundle() -> UnitTestTaxonomyBundle {
    UnitTestTaxonomyBundle {
        schema_version: UNIT_TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
        fixture_registry_schema_version: FIXTURE_REGISTRY_SCHEMA_VERSION.to_string(),
        determinism_contract: DeterminismContract::default_frx20(),
        lane_coverage: vec![
            LaneCoverageContract {
                lane: LaneId::Compiler,
                owner: "frx-compiler-lane".to_string(),
                required_unit_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Regression,
                    UnitTestClass::Edge,
                ],
                mapped_e2e_families: vec!["frx_track_b_compiler".to_string()],
                coverage_rationale:
                    "Compiler lane requires deterministic semantic and lowering parity.".to_string(),
            },
            LaneCoverageContract {
                lane: LaneId::JsRuntime,
                owner: "frx-js-runtime-lane".to_string(),
                required_unit_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Edge,
                    UnitTestClass::Adversarial,
                ],
                mapped_e2e_families: vec!["frx_track_c_js_runtime".to_string()],
                coverage_rationale:
                    "JS runtime lane validates hook/effect ordering and replay stability.".to_string(),
            },
            LaneCoverageContract {
                lane: LaneId::WasmRuntime,
                owner: "frx-wasm-lane".to_string(),
                required_unit_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Edge,
                    UnitTestClass::FaultInjection,
                ],
                mapped_e2e_families: vec!["frx_track_d_wasm_lane".to_string()],
                coverage_rationale:
                    "WASM lane enforces fallback and scheduler integrity under degraded conditions."
                        .to_string(),
            },
            LaneCoverageContract {
                lane: LaneId::HybridRouter,
                owner: "frx-hybrid-router".to_string(),
                required_unit_classes: vec![UnitTestClass::Core, UnitTestClass::Regression],
                mapped_e2e_families: vec!["frx_track_d_hybrid_router".to_string()],
                coverage_rationale:
                    "Router lane must preserve deterministic routing decisions across seeds."
                        .to_string(),
            },
            LaneCoverageContract {
                lane: LaneId::Verification,
                owner: "frx-verification-lane".to_string(),
                required_unit_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Adversarial,
                    UnitTestClass::FaultInjection,
                ],
                mapped_e2e_families: vec!["frx_track_e_verification".to_string()],
                coverage_rationale:
                    "Verification lane requires adversarial and fault-driven evidence closure.".to_string(),
            },
            LaneCoverageContract {
                lane: LaneId::Toolchain,
                owner: "frx-toolchain-lane".to_string(),
                required_unit_classes: vec![UnitTestClass::Core, UnitTestClass::Regression],
                mapped_e2e_families: vec!["frx_track_f_toolchain".to_string()],
                coverage_rationale:
                    "Toolchain lane validates compatibility and reproducible integration hooks."
                        .to_string(),
            },
            LaneCoverageContract {
                lane: LaneId::GovernanceEvidence,
                owner: "frx-governance-evidence-lane".to_string(),
                required_unit_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Regression,
                    UnitTestClass::FaultInjection,
                ],
                mapped_e2e_families: vec!["frx_governance_evidence".to_string()],
                coverage_rationale:
                    "Governance lane enforces evidence integrity and replay linkage contracts."
                        .to_string(),
            },
            LaneCoverageContract {
                lane: LaneId::AdoptionRelease,
                owner: "frx-adoption-release-lane".to_string(),
                required_unit_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Regression,
                    UnitTestClass::Adversarial,
                ],
                mapped_e2e_families: vec!["frx_adoption_release".to_string()],
                coverage_rationale:
                    "Adoption/release lane validates fail-closed readiness with deterministic replay."
                        .to_string(),
            },
        ],
        fixture_registry: vec![
            FixtureRegistryEntry {
                fixture_id: "frx.react.corpus.v1".to_string(),
                fixture_path:
                    "crates/franken-engine/tests/conformance/frx_react_corpus/fixtures".to_string(),
                trace_path: Some(
                    "crates/franken-engine/tests/conformance/frx_react_corpus/traces".to_string(),
                ),
                provenance: "docs/frx_canonical_react_behavior_corpus_v1.json".to_string(),
                owner_lane: LaneId::JsRuntime,
                required_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Edge,
                    UnitTestClass::Regression,
                ],
                e2e_family: "frx_react_behavior_replay".to_string(),
                seed_strategy: "fixture_seed_stable_by_scenario".to_string(),
                structured_log_fields: REQUIRED_STRUCTURED_LOG_FIELDS
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                artifact_retention: "manifest+events+commands".to_string(),
            },
            FixtureRegistryEntry {
                fixture_id: "ifc.corpus.v1".to_string(),
                fixture_path: "crates/franken-engine/tests/conformance/ifc_corpus/fixtures"
                    .to_string(),
                trace_path: Some(
                    "crates/franken-engine/tests/conformance/ifc_corpus/expected".to_string(),
                ),
                provenance: "crates/franken-engine/tests/conformance/ifc_corpus/ifc_conformance_assets.json"
                    .to_string(),
                owner_lane: LaneId::Verification,
                required_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Adversarial,
                    UnitTestClass::FaultInjection,
                ],
                e2e_family: "ifc_conformance_gate".to_string(),
                seed_strategy: "seed_fixed_by_asset_id".to_string(),
                structured_log_fields: REQUIRED_STRUCTURED_LOG_FIELDS
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                artifact_retention: "manifest+evidence+ifc_summary".to_string(),
            },
            FixtureRegistryEntry {
                fixture_id: "transplanted.conformance.v1".to_string(),
                fixture_path:
                    "crates/franken-engine/tests/conformance/transplanted/fixtures".to_string(),
                trace_path: Some(
                    "crates/franken-engine/tests/conformance/transplanted/expected".to_string(),
                ),
                provenance:
                    "crates/franken-engine/tests/conformance/transplanted/conformance_assets.json"
                        .to_string(),
                owner_lane: LaneId::Compiler,
                required_classes: vec![
                    UnitTestClass::Core,
                    UnitTestClass::Regression,
                    UnitTestClass::Edge,
                ],
                e2e_family: "parser_conformance_replay".to_string(),
                seed_strategy: "seed_fixed_by_fixture_ref".to_string(),
                structured_log_fields: REQUIRED_STRUCTURED_LOG_FIELDS
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                artifact_retention: "manifest+evidence+counterexample".to_string(),
            },
            FixtureRegistryEntry {
                fixture_id: "parser.phase0.semantic.fixtures.v1".to_string(),
                fixture_path:
                    "crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json"
                        .to_string(),
                trace_path: None,
                provenance: "docs/PARSER_GRAMMAR_CLOSURE_BACKLOG.md".to_string(),
                owner_lane: LaneId::Compiler,
                required_classes: vec![UnitTestClass::Core, UnitTestClass::Regression],
                e2e_family: "parser_phase0_gate".to_string(),
                seed_strategy: "seed_derived_from_fixture_hash".to_string(),
                structured_log_fields: REQUIRED_STRUCTURED_LOG_FIELDS
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                artifact_retention: "manifest+events+commands".to_string(),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bundle_validates() {
        let bundle = default_frx20_bundle();
        assert_eq!(bundle.validate_for_gate(), Ok(()));
    }

    #[test]
    fn fails_on_missing_structured_log_field() {
        let mut bundle = default_frx20_bundle();
        bundle.fixture_registry[0]
            .structured_log_fields
            .retain(|field| field != "trace_id");

        let error = bundle
            .validate_for_gate()
            .expect_err("expected missing log field");
        assert_eq!(error.error_code(), "FE-FRX-20-1-LOGGING-0001");
    }

    #[test]
    fn fails_on_duplicate_fixture_ids() {
        let mut bundle = default_frx20_bundle();
        let duplicate = bundle.fixture_registry[0].clone();
        bundle.fixture_registry.push(duplicate);

        let error = bundle
            .validate_for_gate()
            .expect_err("expected duplicate fixture id");
        assert_eq!(error.error_code(), "FE-FRX-20-1-REGISTRY-0002");
    }

    #[test]
    fn fails_when_lane_coverage_missing() {
        let mut bundle = default_frx20_bundle();
        bundle
            .lane_coverage
            .retain(|coverage| coverage.lane != LaneId::HybridRouter);

        let error = bundle
            .validate_for_gate()
            .expect_err("expected missing lane coverage");
        assert_eq!(error.error_code(), "FE-FRX-20-1-COVERAGE-0002");
    }

    #[test]
    fn fails_when_schema_version_mismatches() {
        let mut bundle = default_frx20_bundle();
        bundle.schema_version = "frx.unit-test-taxonomy.v0".to_string();

        let error = bundle
            .validate_for_gate()
            .expect_err("expected schema mismatch");
        assert_eq!(error.error_code(), "FE-FRX-20-1-SCHEMA-0001");
    }

    #[test]
    fn serde_roundtrip_preserves_bundle() {
        let bundle = default_frx20_bundle();
        // SAFETY: UnitTestTaxonomyBundle derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let encoded = serde_json::to_string(&bundle).expect("serialize derived Serialize");
        // SAFETY: JSON was just produced by to_string of a valid UnitTestTaxonomyBundle,
        // so from_str back to UnitTestTaxonomyBundle cannot fail (valid format + matching schema).
        let decoded: UnitTestTaxonomyBundle =
            serde_json::from_str(&encoded).expect("deserialize known-valid JSON");
        assert_eq!(decoded, bundle);
    }

    // ── UnitTestClass enum coverage ──────────────────────────────

    #[test]
    fn unit_test_class_all_has_five_variants() {
        assert_eq!(UnitTestClass::ALL.len(), 5);
    }

    #[test]
    fn unit_test_class_as_str_core() {
        assert_eq!(UnitTestClass::Core.as_str(), "core");
    }

    #[test]
    fn unit_test_class_as_str_edge() {
        assert_eq!(UnitTestClass::Edge.as_str(), "edge");
    }

    #[test]
    fn unit_test_class_as_str_adversarial() {
        assert_eq!(UnitTestClass::Adversarial.as_str(), "adversarial");
    }

    #[test]
    fn unit_test_class_as_str_regression() {
        assert_eq!(UnitTestClass::Regression.as_str(), "regression");
    }

    #[test]
    fn unit_test_class_as_str_fault_injection() {
        assert_eq!(UnitTestClass::FaultInjection.as_str(), "fault_injection");
    }

    #[test]
    fn unit_test_class_serde_roundtrip_all_variants() {
        for variant in UnitTestClass::ALL {
            // SAFETY: UnitTestClass derives Serialize and has no non-serializable fields.
            // to_string on derived Serialize types only fails on writer errors (impossible with String).
            let json = serde_json::to_string(&variant).expect("serialize derived Serialize");
            // SAFETY: JSON was just produced by to_string of a valid UnitTestClass,
            // so from_str back to UnitTestClass cannot fail (valid format + matching schema).
            let back: UnitTestClass =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn unit_test_class_serde_snake_case() {
        // SAFETY: UnitTestClass derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&UnitTestClass::FaultInjection)
            .expect("serialization should succeed");
        assert_eq!(json, "\"fault_injection\"");
    }

    #[test]
    fn unit_test_class_ordering_is_declaration_order() {
        assert!(UnitTestClass::Core < UnitTestClass::Edge);
        assert!(UnitTestClass::Edge < UnitTestClass::Adversarial);
        assert!(UnitTestClass::Adversarial < UnitTestClass::Regression);
        assert!(UnitTestClass::Regression < UnitTestClass::FaultInjection);
    }

    // ── LaneId enum coverage ─────────────────────────────────────

    #[test]
    fn lane_id_all_has_eight_variants() {
        assert_eq!(LaneId::ALL.len(), 8);
    }

    #[test]
    fn lane_id_as_str_all_variants() {
        let expected = [
            (LaneId::Compiler, "compiler"),
            (LaneId::JsRuntime, "js_runtime"),
            (LaneId::WasmRuntime, "wasm_runtime"),
            (LaneId::HybridRouter, "hybrid_router"),
            (LaneId::Verification, "verification"),
            (LaneId::Toolchain, "toolchain"),
            (LaneId::GovernanceEvidence, "governance_evidence"),
            (LaneId::AdoptionRelease, "adoption_release"),
        ];
        for (lane, name) in expected {
            assert_eq!(lane.as_str(), name);
        }
    }

    #[test]
    fn lane_id_serde_roundtrip_all_variants() {
        for lane in LaneId::ALL {
            // SAFETY: LaneId derives Serialize and has no non-serializable fields.
            // to_string on derived Serialize types only fails on writer errors (impossible with String).
            let json = serde_json::to_string(&lane).expect("serialize derived Serialize");
            // SAFETY: JSON was just produced by to_string of a valid LaneId,
            // so from_str back to LaneId cannot fail (valid format + matching schema).
            let back: LaneId = serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(back, lane);
        }
    }

    #[test]
    fn lane_id_ordering_is_declaration_order() {
        assert!(LaneId::Compiler < LaneId::JsRuntime);
        assert!(LaneId::JsRuntime < LaneId::WasmRuntime);
        assert!(LaneId::WasmRuntime < LaneId::HybridRouter);
        assert!(LaneId::Toolchain < LaneId::GovernanceEvidence);
        assert!(LaneId::GovernanceEvidence < LaneId::AdoptionRelease);
    }

    // ── DeterminismContract validation ───────────────────────────

    #[test]
    fn determinism_contract_default_validates() {
        let contract = DeterminismContract::default_frx20();
        assert_eq!(contract.validate(), Ok(()));
    }

    #[test]
    fn determinism_contract_default_schema_version() {
        let contract = DeterminismContract::default_frx20();
        assert_eq!(contract.schema_version, DETERMINISM_CONTRACT_SCHEMA_VERSION);
    }

    #[test]
    fn determinism_contract_bad_schema_version() {
        let mut contract = DeterminismContract::default_frx20();
        contract.schema_version = "wrong.version".to_string();
        let err = contract.validate().unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-SCHEMA-0001");
    }

    #[test]
    fn determinism_contract_empty_timezone_when_required() {
        let mut contract = DeterminismContract::default_frx20();
        contract.timezone = "  ".to_string();
        let err = contract.validate().unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
        if let TaxonomyValidationError::MissingRequiredField { field } = &err {
            assert!(field.contains("timezone"));
        } else {
            // SAFETY: Test-only panic to validate that TaxonomyValidationError matches expected MissingRequiredField variant
            panic!("expected MissingRequiredField");
        }
    }

    #[test]
    fn determinism_contract_empty_timezone_ok_when_not_required() {
        let mut contract = DeterminismContract::default_frx20();
        contract.require_fixed_timezone = false;
        contract.timezone = String::new();
        assert_eq!(contract.validate(), Ok(()));
    }

    #[test]
    fn determinism_contract_empty_lang_when_locale_required() {
        let mut contract = DeterminismContract::default_frx20();
        contract.lang = " ".to_string();
        let err = contract.validate().unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
        if let TaxonomyValidationError::MissingRequiredField { field } = &err {
            assert!(field.contains("locale"));
        } else {
            // SAFETY: Test validates taxonomy error type matches expected MissingRequiredField variant
            panic!("expected MissingRequiredField");
        }
    }

    #[test]
    fn determinism_contract_empty_lc_all_when_locale_required() {
        let mut contract = DeterminismContract::default_frx20();
        contract.lc_all = String::new();
        let err = contract.validate().unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
    }

    #[test]
    fn determinism_contract_empty_locale_ok_when_not_required() {
        let mut contract = DeterminismContract::default_frx20();
        contract.require_fixed_locale = false;
        contract.lang = String::new();
        contract.lc_all = String::new();
        assert_eq!(contract.validate(), Ok(()));
    }

    #[test]
    fn determinism_contract_serde_roundtrip() {
        let contract = DeterminismContract::default_frx20();
        // SAFETY: DeterminismContract derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&contract).expect("serialize derived Serialize");
        // SAFETY: JSON was just produced by to_string of a valid DeterminismContract,
        // so from_str back to DeterminismContract cannot fail (valid format + matching schema).
        let back: DeterminismContract =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, contract);
    }

    // ── FixtureRegistryEntry validation ──────────────────────────

    fn valid_fixture_entry() -> FixtureRegistryEntry {
        FixtureRegistryEntry {
            fixture_id: "test.fixture.v1".to_string(),
            fixture_path: "path/to/fixtures".to_string(),
            trace_path: Some("path/to/traces".to_string()),
            provenance: "docs/provenance.json".to_string(),
            owner_lane: LaneId::Compiler,
            required_classes: vec![UnitTestClass::Core],
            e2e_family: "test_family".to_string(),
            seed_strategy: "seed_fixed".to_string(),
            structured_log_fields: REQUIRED_STRUCTURED_LOG_FIELDS
                .iter()
                .map(|v| (*v).to_string())
                .collect(),
            artifact_retention: "manifest+events".to_string(),
        }
    }

    #[test]
    fn fixture_entry_valid_passes() {
        let entry = valid_fixture_entry();
        let mut seen = BTreeSet::new();
        assert_eq!(entry.validate(&mut seen), Ok(()));
    }

    #[test]
    fn fixture_entry_empty_id_fails() {
        let mut entry = valid_fixture_entry();
        entry.fixture_id = "  ".to_string();
        let mut seen = BTreeSet::new();
        let err = entry.validate(&mut seen).unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
    }

    #[test]
    fn fixture_entry_duplicate_id_fails() {
        let entry = valid_fixture_entry();
        let mut seen = BTreeSet::new();
        seen.insert("test.fixture.v1".to_string());
        let err = entry.validate(&mut seen).unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0002");
        if let TaxonomyValidationError::DuplicateFixtureId { fixture_id } = &err {
            assert_eq!(fixture_id, "test.fixture.v1");
        } else {
            // SAFETY: Test validates taxonomy error type matches expected DuplicateFixtureId variant
            panic!("expected DuplicateFixtureId");
        }
    }

    #[test]
    fn fixture_entry_empty_path_fails() {
        let mut entry = valid_fixture_entry();
        entry.fixture_path = String::new();
        let mut seen = BTreeSet::new();
        let err = entry.validate(&mut seen).unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
        if let TaxonomyValidationError::MissingRequiredField { field } = &err {
            assert!(field.contains("fixture_path"));
        } else {
            // SAFETY: Test validates taxonomy error for fixture_path field validation
            panic!("expected MissingRequiredField");
        }
    }

    #[test]
    fn fixture_entry_empty_provenance_fails() {
        let mut entry = valid_fixture_entry();
        entry.provenance = " ".to_string();
        let mut seen = BTreeSet::new();
        let err = entry.validate(&mut seen).unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
    }

    #[test]
    fn fixture_entry_empty_required_classes_fails() {
        let mut entry = valid_fixture_entry();
        entry.required_classes.clear();
        let mut seen = BTreeSet::new();
        let err = entry.validate(&mut seen).unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
    }

    #[test]
    fn fixture_entry_empty_e2e_family_fails() {
        let mut entry = valid_fixture_entry();
        entry.e2e_family = String::new();
        let mut seen = BTreeSet::new();
        let err = entry.validate(&mut seen).unwrap_err();
        if let TaxonomyValidationError::MissingRequiredField { field } = &err {
            assert!(field.contains("e2e_family"));
        } else {
            // SAFETY: Test validates taxonomy error for e2e_family field validation
            panic!("expected MissingRequiredField");
        }
    }

    #[test]
    fn fixture_entry_empty_seed_strategy_fails() {
        let mut entry = valid_fixture_entry();
        entry.seed_strategy = "  ".to_string();
        let mut seen = BTreeSet::new();
        let err = entry.validate(&mut seen).unwrap_err();
        if let TaxonomyValidationError::MissingRequiredField { field } = &err {
            assert!(field.contains("seed_strategy"));
        } else {
            panic!("expected MissingRequiredField");
        }
    }

    #[test]
    fn fixture_entry_empty_artifact_retention_fails() {
        let mut entry = valid_fixture_entry();
        entry.artifact_retention = String::new();
        let mut seen = BTreeSet::new();
        let err = entry.validate(&mut seen).unwrap_err();
        if let TaxonomyValidationError::MissingRequiredField { field } = &err {
            assert!(field.contains("artifact_retention"));
        } else {
            panic!("expected MissingRequiredField");
        }
    }

    #[test]
    fn fixture_entry_missing_one_log_field_fails() {
        let mut entry = valid_fixture_entry();
        entry.structured_log_fields.retain(|f| f != "decision_path");
        let mut seen = BTreeSet::new();
        let err = entry.validate(&mut seen).unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-LOGGING-0001");
        if let TaxonomyValidationError::MissingStructuredLogField { fixture_id, field } = &err {
            assert_eq!(fixture_id, "test.fixture.v1");
            assert_eq!(field, "decision_path");
        } else {
            panic!("expected MissingStructuredLogField");
        }
    }

    #[test]
    fn fixture_entry_serde_roundtrip() {
        let entry = valid_fixture_entry();
        // SAFETY: FixtureRegistryEntry derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&entry).expect("serialize derived Serialize");
        // SAFETY: JSON was just produced by to_string of a valid FixtureRegistryEntry,
        // so from_str back to FixtureRegistryEntry cannot fail (valid format + matching schema).
        let back: FixtureRegistryEntry =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, entry);
    }

    #[test]
    fn fixture_entry_none_trace_path_serde() {
        let mut entry = valid_fixture_entry();
        entry.trace_path = None;
        // SAFETY: FixtureRegistryEntry derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&entry).expect("serialize derived Serialize");
        // SAFETY: JSON was just produced by to_string of a valid FixtureRegistryEntry,
        // so from_str back to FixtureRegistryEntry cannot fail (valid format + matching schema).
        let back: FixtureRegistryEntry =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back.trace_path, None);
    }

    // ── LaneCoverageContract validation ──────────────────────────

    fn valid_lane_coverage() -> LaneCoverageContract {
        LaneCoverageContract {
            lane: LaneId::Compiler,
            owner: "test-owner".to_string(),
            required_unit_classes: vec![UnitTestClass::Core],
            mapped_e2e_families: vec!["family_a".to_string()],
            coverage_rationale: "Compiler tests are required.".to_string(),
        }
    }

    #[test]
    fn lane_coverage_valid_passes() {
        assert_eq!(valid_lane_coverage().validate(), Ok(()));
    }

    #[test]
    fn lane_coverage_empty_owner_fails() {
        let mut lc = valid_lane_coverage();
        lc.owner = "  ".to_string();
        let err = lc.validate().unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
    }

    #[test]
    fn lane_coverage_empty_classes_fails() {
        let mut lc = valid_lane_coverage();
        lc.required_unit_classes.clear();
        let err = lc.validate().unwrap_err();
        if let TaxonomyValidationError::MissingRequiredField { field } = &err {
            assert!(field.contains("required_unit_classes"));
        } else {
            panic!("expected MissingRequiredField");
        }
    }

    #[test]
    fn lane_coverage_empty_families_fails() {
        let mut lc = valid_lane_coverage();
        lc.mapped_e2e_families.clear();
        let err = lc.validate().unwrap_err();
        if let TaxonomyValidationError::MissingRequiredField { field } = &err {
            assert!(field.contains("mapped_e2e_families"));
        } else {
            panic!("expected MissingRequiredField");
        }
    }

    #[test]
    fn lane_coverage_empty_rationale_fails() {
        let mut lc = valid_lane_coverage();
        lc.coverage_rationale = String::new();
        let err = lc.validate().unwrap_err();
        if let TaxonomyValidationError::MissingRequiredField { field } = &err {
            assert!(field.contains("coverage_rationale"));
        } else {
            panic!("expected MissingRequiredField");
        }
    }

    #[test]
    fn lane_coverage_serde_roundtrip() {
        let lc = valid_lane_coverage();
        // SAFETY: LaneCoverageContract derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&lc).expect("serialize derived Serialize");
        // SAFETY: JSON was just produced by to_string of a valid LaneCoverageContract,
        // so from_str back to LaneCoverageContract cannot fail (valid format + matching schema).
        let back: LaneCoverageContract =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, lc);
    }

    // ── UnitTestTaxonomyBundle validation ────────────────────────

    #[test]
    fn bundle_fixture_registry_schema_mismatch() {
        let mut bundle = default_frx20_bundle();
        bundle.fixture_registry_schema_version = "wrong".to_string();
        let err = bundle.validate_for_gate().unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-SCHEMA-0001");
        if let TaxonomyValidationError::InvalidSchemaVersion {
            field,
            expected,
            actual,
        } = &err
        {
            assert_eq!(field, "fixture_registry_schema_version");
            assert_eq!(expected, FIXTURE_REGISTRY_SCHEMA_VERSION);
            assert_eq!(actual, "wrong");
        } else {
            panic!("expected InvalidSchemaVersion");
        }
    }

    #[test]
    fn bundle_empty_lane_coverage_fails() {
        let mut bundle = default_frx20_bundle();
        bundle.lane_coverage.clear();
        let err = bundle.validate_for_gate().unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
    }

    #[test]
    fn bundle_duplicate_lane_coverage_fails() {
        let mut bundle = default_frx20_bundle();
        let dup = bundle.lane_coverage[0].clone();
        bundle.lane_coverage.push(dup);
        let err = bundle.validate_for_gate().unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-COVERAGE-0001");
        if let TaxonomyValidationError::DuplicateLaneCoverage { lane } = &err {
            assert_eq!(lane, "compiler");
        } else {
            panic!("expected DuplicateLaneCoverage");
        }
    }

    #[test]
    fn bundle_empty_fixture_registry_fails() {
        let mut bundle = default_frx20_bundle();
        bundle.fixture_registry.clear();
        let err = bundle.validate_for_gate().unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
    }

    #[test]
    fn bundle_propagates_determinism_contract_error() {
        let mut bundle = default_frx20_bundle();
        bundle.determinism_contract.schema_version = "bad".to_string();
        let err = bundle.validate_for_gate().unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-SCHEMA-0001");
    }

    #[test]
    fn bundle_propagates_lane_coverage_error() {
        let mut bundle = default_frx20_bundle();
        bundle.lane_coverage[0].owner = String::new();
        let err = bundle.validate_for_gate().unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
    }

    #[test]
    fn bundle_propagates_fixture_entry_error() {
        let mut bundle = default_frx20_bundle();
        bundle.fixture_registry[0].fixture_id = String::new();
        let err = bundle.validate_for_gate().unwrap_err();
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
    }

    // ── TaxonomyValidationError coverage ─────────────────────────

    #[test]
    fn error_code_missing_required_field() {
        let err = TaxonomyValidationError::MissingRequiredField {
            field: "test".to_string(),
        };
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
    }

    #[test]
    fn error_code_invalid_schema_version() {
        let err = TaxonomyValidationError::InvalidSchemaVersion {
            field: "f".to_string(),
            expected: "e".to_string(),
            actual: "a".to_string(),
        };
        assert_eq!(err.error_code(), "FE-FRX-20-1-SCHEMA-0001");
    }

    #[test]
    fn error_code_missing_structured_log_field() {
        let err = TaxonomyValidationError::MissingStructuredLogField {
            fixture_id: "f".to_string(),
            field: "trace_id".to_string(),
        };
        assert_eq!(err.error_code(), "FE-FRX-20-1-LOGGING-0001");
    }

    #[test]
    fn error_code_duplicate_fixture_id() {
        let err = TaxonomyValidationError::DuplicateFixtureId {
            fixture_id: "dup".to_string(),
        };
        assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0002");
    }

    #[test]
    fn error_code_duplicate_lane_coverage() {
        let err = TaxonomyValidationError::DuplicateLaneCoverage {
            lane: "compiler".to_string(),
        };
        assert_eq!(err.error_code(), "FE-FRX-20-1-COVERAGE-0001");
    }

    #[test]
    fn error_code_missing_lane_coverage() {
        let err = TaxonomyValidationError::MissingLaneCoverage {
            lane: "wasm_runtime".to_string(),
        };
        assert_eq!(err.error_code(), "FE-FRX-20-1-COVERAGE-0002");
    }

    #[test]
    fn taxonomy_error_serde_roundtrip_all_variants() {
        let variants: Vec<TaxonomyValidationError> = vec![
            TaxonomyValidationError::MissingRequiredField {
                field: "test".to_string(),
            },
            TaxonomyValidationError::InvalidSchemaVersion {
                field: "sv".to_string(),
                expected: "v1".to_string(),
                actual: "v0".to_string(),
            },
            TaxonomyValidationError::MissingStructuredLogField {
                fixture_id: "fix1".to_string(),
                field: "trace_id".to_string(),
            },
            TaxonomyValidationError::DuplicateFixtureId {
                fixture_id: "dup".to_string(),
            },
            TaxonomyValidationError::DuplicateLaneCoverage {
                lane: "compiler".to_string(),
            },
            TaxonomyValidationError::MissingLaneCoverage {
                lane: "wasm_runtime".to_string(),
            },
        ];
        for variant in &variants {
            // SAFETY: TaxonomyValidationError derives Serialize and has no non-serializable fields.
            // to_string on derived Serialize types only fails on writer errors (impossible with String).
            let json = serde_json::to_string(variant).expect("serialize derived Serialize");
            // SAFETY: JSON was just produced by to_string of a valid TaxonomyValidationError,
            // so from_str back to TaxonomyValidationError cannot fail (valid format + matching schema).
            let back: TaxonomyValidationError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(&back, variant);
        }
    }

    // ── default_frx20_bundle structural assertions ───────────────

    #[test]
    fn default_bundle_covers_all_eight_lanes() {
        let bundle = default_frx20_bundle();
        let covered: BTreeSet<LaneId> = bundle.lane_coverage.iter().map(|lc| lc.lane).collect();
        for lane in LaneId::ALL {
            assert!(covered.contains(&lane), "lane {:?} not covered", lane);
        }
    }

    #[test]
    fn default_bundle_has_four_fixtures() {
        let bundle = default_frx20_bundle();
        assert_eq!(bundle.fixture_registry.len(), 4);
    }

    #[test]
    fn default_bundle_fixture_ids_are_unique() {
        let bundle = default_frx20_bundle();
        let ids: BTreeSet<&str> = bundle
            .fixture_registry
            .iter()
            .map(|f| f.fixture_id.as_str())
            .collect();
        assert_eq!(ids.len(), bundle.fixture_registry.len());
    }

    #[test]
    fn default_bundle_all_fixtures_have_all_required_log_fields() {
        let bundle = default_frx20_bundle();
        for fixture in &bundle.fixture_registry {
            let field_set: BTreeSet<&str> = fixture
                .structured_log_fields
                .iter()
                .map(String::as_str)
                .collect();
            for required in REQUIRED_STRUCTURED_LOG_FIELDS {
                assert!(
                    field_set.contains(required),
                    "fixture {} missing log field {}",
                    fixture.fixture_id,
                    required
                );
            }
        }
    }

    #[test]
    fn default_bundle_lane_coverage_owners_non_empty() {
        let bundle = default_frx20_bundle();
        for lc in &bundle.lane_coverage {
            assert!(
                !lc.owner.trim().is_empty(),
                "lane {:?} has empty owner",
                lc.lane
            );
        }
    }

    #[test]
    fn default_bundle_determinism_contract_requires_all() {
        let contract = &default_frx20_bundle().determinism_contract;
        assert!(contract.require_seed);
        assert!(contract.require_seed_transcript_checksum);
        assert!(contract.require_fixed_timezone);
        assert!(contract.require_fixed_locale);
        assert!(contract.require_toolchain_fingerprint);
        assert!(contract.require_replay_command);
    }

    // ── Constants verification ───────────────────────────────────

    #[test]
    fn schema_version_constants_contain_frx() {
        assert!(UNIT_TEST_TAXONOMY_SCHEMA_VERSION.contains("frx"));
        assert!(FIXTURE_REGISTRY_SCHEMA_VERSION.contains("frx"));
        assert!(DETERMINISM_CONTRACT_SCHEMA_VERSION.contains("frx"));
    }

    #[test]
    fn required_structured_log_fields_has_twelve_entries() {
        assert_eq!(REQUIRED_STRUCTURED_LOG_FIELDS.len(), 12);
    }

    #[test]
    fn required_structured_log_fields_include_critical_fields() {
        let fields: BTreeSet<&str> = REQUIRED_STRUCTURED_LOG_FIELDS.iter().copied().collect();
        assert!(fields.contains("trace_id"));
        assert!(fields.contains("decision_id"));
        assert!(fields.contains("seed"));
        assert!(fields.contains("outcome"));
    }

    // ── Edge case: removing each required log field ──────────────

    #[test]
    fn fixture_missing_each_required_log_field() {
        for required in REQUIRED_STRUCTURED_LOG_FIELDS {
            let mut entry = valid_fixture_entry();
            entry.structured_log_fields.retain(|f| f != *required);
            let mut seen = BTreeSet::new();
            let err = entry.validate(&mut seen).unwrap_err();
            if let TaxonomyValidationError::MissingStructuredLogField { field, .. } = &err {
                assert_eq!(field, *required);
            } else {
                panic!("expected MissingStructuredLogField for {}", required);
            }
        }
    }

    // ── Edge case: removing each lane from default bundle ────────

    #[test]
    fn bundle_missing_each_lane_reports_correct_lane() {
        for lane in LaneId::ALL {
            let mut bundle = default_frx20_bundle();
            bundle.lane_coverage.retain(|lc| lc.lane != lane);
            let err = bundle.validate_for_gate().unwrap_err();
            if let TaxonomyValidationError::MissingLaneCoverage { lane: name } = &err {
                assert_eq!(name, lane.as_str());
            } else {
                panic!("expected MissingLaneCoverage for {:?}", lane);
            }
        }
    }
}
