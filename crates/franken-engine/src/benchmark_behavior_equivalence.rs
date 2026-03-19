//! Deterministic benchmark behavior-equivalence classification and owner routing.
//!
//! This module provides the reusable classification primitive beneath
//! `RGC-704B`: benchmark workloads must be screened for semantic parity before
//! any performance claim can be treated as publishable. The runner-level
//! orchestration still lives elsewhere; this module keeps the core verdicts and
//! owner routing machine-readable and deterministic.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::benchmark_evidence_bundle::ParityTarget;
use crate::hash_tiers::ContentHash;

pub const SCHEMA_VERSION: &str = "franken-engine.benchmark-behavior-equivalence.v1";
pub const COMPONENT: &str = "benchmark_behavior_equivalence";
pub const BEAD_ID: &str = "bd-1lsy.8.4.2";
pub const POLICY_ID: &str = "RGC-704B";

/// Whether the evidence came from the user-visible shipped path or from an
/// internal/library-only surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSurface {
    ShippedPath,
    LibraryOnly,
}

impl EvidenceSurface {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ShippedPath => "shipped_path",
            Self::LibraryOnly => "library_only",
        }
    }
}

impl fmt::Display for EvidenceSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Deterministic benchmark parity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorEquivalenceClass {
    Equivalent,
    SemanticMismatch,
    UnsupportedFeature,
    InfraFailure,
    BenchmarkNoise,
    ShippedPathDrift,
}

impl BehaviorEquivalenceClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equivalent => "equivalent",
            Self::SemanticMismatch => "semantic_mismatch",
            Self::UnsupportedFeature => "unsupported_feature",
            Self::InfraFailure => "infra_failure",
            Self::BenchmarkNoise => "benchmark_noise",
            Self::ShippedPathDrift => "shipped_path_drift",
        }
    }

    #[must_use]
    pub const fn blocks_publication(self) -> bool {
        !matches!(self, Self::Equivalent)
    }
}

impl fmt::Display for BehaviorEquivalenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a parity record can be used by publication tooling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationDisposition {
    PublicationEligible,
    NonPublicationEvidence,
    Blocked,
}

impl PublicationDisposition {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicationEligible => "publication_eligible",
            Self::NonPublicationEvidence => "non_publication_evidence",
            Self::Blocked => "blocked",
        }
    }
}

impl fmt::Display for PublicationDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable hint used to route failing cases toward the owning bead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerRouteHint {
    RuntimeSemantics,
    ModuleInterop,
    TypeScriptNormalization,
    ShippedPathParity,
    BenchmarkHarness,
    BenchmarkCorpus,
    DocsContract,
}

impl OwnerRouteHint {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeSemantics => "runtime_semantics",
            Self::ModuleInterop => "module_interop",
            Self::TypeScriptNormalization => "typescript_normalization",
            Self::ShippedPathParity => "shipped_path_parity",
            Self::BenchmarkHarness => "benchmark_harness",
            Self::BenchmarkCorpus => "benchmark_corpus",
            Self::DocsContract => "docs_contract",
        }
    }

    #[must_use]
    pub const fn owner_bead_id(self) -> &'static str {
        match self {
            Self::RuntimeSemantics => "bd-1lsy.4",
            Self::ModuleInterop => "bd-1lsy.5",
            Self::TypeScriptNormalization => "bd-1lsy.3",
            Self::ShippedPathParity => "bd-1lsy.9.6",
            Self::BenchmarkHarness => BEAD_ID,
            Self::BenchmarkCorpus => "bd-1lsy.8.4.1",
            Self::DocsContract => "bd-1lsy.10.11",
        }
    }

    #[must_use]
    pub const fn component(self) -> &'static str {
        match self {
            Self::RuntimeSemantics => "runtime_semantics",
            Self::ModuleInterop => "module_system_interop",
            Self::TypeScriptNormalization => "ts_normalization",
            Self::ShippedPathParity => "shipped_path_parity",
            Self::BenchmarkHarness => COMPONENT,
            Self::BenchmarkCorpus => "benchmark_workload_corpus",
            Self::DocsContract => "docs_help_surface",
        }
    }
}

impl fmt::Display for OwnerRouteHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Raw observation emitted by a benchmark parity runner before classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorEquivalenceObservation {
    pub workload_id: String,
    pub baseline: ParityTarget,
    pub surface: EvidenceSurface,
    pub output_equivalent: bool,
    pub feature_supported: bool,
    pub infra_ok: bool,
    pub noise_only: bool,
    pub detail: String,
    pub owner_hint: OwnerRouteHint,
    #[serde(default)]
    pub minimized_repro_command: Option<String>,
}

impl BehaviorEquivalenceObservation {
    #[must_use]
    pub fn new(
        workload_id: impl Into<String>,
        baseline: ParityTarget,
        surface: EvidenceSurface,
        owner_hint: OwnerRouteHint,
    ) -> Self {
        Self {
            workload_id: workload_id.into(),
            baseline,
            surface,
            output_equivalent: true,
            feature_supported: true,
            infra_ok: true,
            noise_only: false,
            detail: String::new(),
            owner_hint,
            minimized_repro_command: None,
        }
    }

    #[must_use]
    pub fn with_output_equivalence(mut self, output_equivalent: bool) -> Self {
        self.output_equivalent = output_equivalent;
        self
    }

    #[must_use]
    pub fn with_feature_supported(mut self, feature_supported: bool) -> Self {
        self.feature_supported = feature_supported;
        self
    }

    #[must_use]
    pub fn with_infra_ok(mut self, infra_ok: bool) -> Self {
        self.infra_ok = infra_ok;
        self
    }

    #[must_use]
    pub fn with_noise_only(mut self, noise_only: bool) -> Self {
        self.noise_only = noise_only;
        self
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    #[must_use]
    pub fn with_minimized_repro_command(mut self, command: impl Into<String>) -> Self {
        self.minimized_repro_command = Some(command.into());
        self
    }
}

/// Deterministic owner route for a failing parity record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerRoute {
    pub owner_bead_id: String,
    pub owner_hint: OwnerRouteHint,
    pub component: String,
    pub rationale: String,
}

/// One classified parity verdict record. This is the JSONL line shape that a
/// future runner can emit as `benchmark_parity_verdict.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkParityVerdictRecord {
    pub workload_id: String,
    pub baseline: ParityTarget,
    pub surface: EvidenceSurface,
    pub classification: BehaviorEquivalenceClass,
    pub publication_disposition: PublicationDisposition,
    pub owner_route: Option<OwnerRoute>,
    pub detail: String,
    #[serde(default)]
    pub minimized_repro_command: Option<String>,
    pub record_hash: ContentHash,
}

/// Aggregated owner route index. This is the machine-readable payload a future
/// runner can emit as `divergence_owner_route.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceOwnerRoute {
    pub owner_bead_id: String,
    pub owner_hint: OwnerRouteHint,
    pub component: String,
    pub rationale: String,
    pub workload_ids: Vec<String>,
    pub classifications: Vec<BehaviorEquivalenceClass>,
}

/// Deterministic report envelope for one benchmark parity classification pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorEquivalenceReport {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub records: Vec<BenchmarkParityVerdictRecord>,
    pub owner_routes: Vec<DivergenceOwnerRoute>,
}

impl BehaviorEquivalenceReport {
    #[must_use]
    pub fn has_publication_blockers(&self) -> bool {
        self.records
            .iter()
            .any(|record| record.publication_disposition == PublicationDisposition::Blocked)
    }

    pub fn benchmark_parity_verdict_jsonl(&self) -> Result<String, serde_json::Error> {
        self.records
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .map(|lines| lines.join("\n"))
    }

    pub fn divergence_owner_route_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.owner_routes)
    }
}

#[must_use]
pub fn classify_observation(
    observation: &BehaviorEquivalenceObservation,
) -> BehaviorEquivalenceClass {
    if !observation.infra_ok {
        return BehaviorEquivalenceClass::InfraFailure;
    }
    if !observation.feature_supported {
        return BehaviorEquivalenceClass::UnsupportedFeature;
    }
    if observation.noise_only {
        return BehaviorEquivalenceClass::BenchmarkNoise;
    }
    if !observation.output_equivalent {
        return match observation.surface {
            EvidenceSurface::ShippedPath => BehaviorEquivalenceClass::ShippedPathDrift,
            EvidenceSurface::LibraryOnly => BehaviorEquivalenceClass::SemanticMismatch,
        };
    }
    BehaviorEquivalenceClass::Equivalent
}

#[must_use]
pub fn publication_disposition_for(
    classification: BehaviorEquivalenceClass,
    surface: EvidenceSurface,
) -> PublicationDisposition {
    if classification.blocks_publication() {
        return PublicationDisposition::Blocked;
    }
    match surface {
        EvidenceSurface::ShippedPath => PublicationDisposition::PublicationEligible,
        EvidenceSurface::LibraryOnly => PublicationDisposition::NonPublicationEvidence,
    }
}

#[must_use]
pub fn route_owner(
    classification: BehaviorEquivalenceClass,
    owner_hint: OwnerRouteHint,
) -> Option<OwnerRoute> {
    let (route_hint, rationale) = match classification {
        BehaviorEquivalenceClass::Equivalent => return None,
        BehaviorEquivalenceClass::SemanticMismatch => (
            owner_hint,
            "semantic mismatch should route to the owning feature lane",
        ),
        BehaviorEquivalenceClass::UnsupportedFeature => (
            owner_hint,
            "unsupported feature should route to the owning feature or support lane",
        ),
        BehaviorEquivalenceClass::InfraFailure => (
            OwnerRouteHint::BenchmarkHarness,
            "runner or baseline infra failure belongs to the benchmark harness lane",
        ),
        BehaviorEquivalenceClass::BenchmarkNoise => (
            OwnerRouteHint::BenchmarkHarness,
            "benchmark-only noise belongs to the behavior-equivalence runner lane",
        ),
        BehaviorEquivalenceClass::ShippedPathDrift => (
            OwnerRouteHint::ShippedPathParity,
            "user-visible shipped-path drift belongs to the shipped-path parity lane",
        ),
    };

    Some(OwnerRoute {
        owner_bead_id: route_hint.owner_bead_id().to_string(),
        owner_hint: route_hint,
        component: route_hint.component().to_string(),
        rationale: rationale.to_string(),
    })
}

#[must_use]
pub fn build_record(observation: &BehaviorEquivalenceObservation) -> BenchmarkParityVerdictRecord {
    let classification = classify_observation(observation);
    let publication_disposition = publication_disposition_for(classification, observation.surface);
    let owner_route = route_owner(classification, observation.owner_hint);
    let record_hash = compute_record_hash(
        observation,
        classification,
        publication_disposition,
        owner_route.as_ref(),
    );

    BenchmarkParityVerdictRecord {
        workload_id: observation.workload_id.clone(),
        baseline: observation.baseline,
        surface: observation.surface,
        classification,
        publication_disposition,
        owner_route,
        detail: observation.detail.clone(),
        minimized_repro_command: observation.minimized_repro_command.clone(),
        record_hash,
    }
}

#[must_use]
pub fn build_report(
    trace_id: impl Into<String>,
    decision_id: impl Into<String>,
    policy_id: impl Into<String>,
    observations: &[BehaviorEquivalenceObservation],
) -> BehaviorEquivalenceReport {
    let mut records = observations.iter().map(build_record).collect::<Vec<_>>();
    records.sort_by(|left, right| {
        (
            left.workload_id.as_str(),
            left.baseline.as_str(),
            left.surface.as_str(),
            left.classification.as_str(),
        )
            .cmp(&(
                right.workload_id.as_str(),
                right.baseline.as_str(),
                right.surface.as_str(),
                right.classification.as_str(),
            ))
    });

    let owner_routes = aggregate_owner_routes(&records);

    BehaviorEquivalenceReport {
        schema_version: SCHEMA_VERSION.to_string(),
        trace_id: trace_id.into(),
        decision_id: decision_id.into(),
        policy_id: policy_id.into(),
        component: COMPONENT.to_string(),
        records,
        owner_routes,
    }
}

fn aggregate_owner_routes(records: &[BenchmarkParityVerdictRecord]) -> Vec<DivergenceOwnerRoute> {
    let mut grouped: BTreeMap<
        (String, OwnerRouteHint, String, String),
        Vec<&BenchmarkParityVerdictRecord>,
    > = BTreeMap::new();

    for record in records {
        let Some(owner_route) = &record.owner_route else {
            continue;
        };
        let key = (
            owner_route.owner_bead_id.clone(),
            owner_route.owner_hint,
            owner_route.component.clone(),
            owner_route.rationale.clone(),
        );
        grouped.entry(key).or_default().push(record);
    }

    grouped
        .into_iter()
        .map(
            |((owner_bead_id, owner_hint, component, rationale), records_for_owner)| {
                let workload_ids = records_for_owner
                    .iter()
                    .map(|record| record.workload_id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let classifications = records_for_owner
                    .iter()
                    .map(|record| record.classification)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();

                DivergenceOwnerRoute {
                    owner_bead_id,
                    owner_hint,
                    component,
                    rationale,
                    workload_ids,
                    classifications,
                }
            },
        )
        .collect()
}

fn compute_record_hash(
    observation: &BehaviorEquivalenceObservation,
    classification: BehaviorEquivalenceClass,
    publication_disposition: PublicationDisposition,
    owner_route: Option<&OwnerRoute>,
) -> ContentHash {
    let mut hasher = Sha256::new();
    update_string(&mut hasher, SCHEMA_VERSION);
    update_string(&mut hasher, observation.workload_id.as_str());
    update_string(&mut hasher, observation.baseline.as_str());
    update_string(&mut hasher, observation.surface.as_str());
    hasher.update([u8::from(observation.output_equivalent)]);
    hasher.update([u8::from(observation.feature_supported)]);
    hasher.update([u8::from(observation.infra_ok)]);
    hasher.update([u8::from(observation.noise_only)]);
    update_string(&mut hasher, classification.as_str());
    update_string(&mut hasher, publication_disposition.as_str());
    update_string(&mut hasher, observation.detail.as_str());
    update_optional_string(&mut hasher, observation.minimized_repro_command.as_deref());

    if let Some(owner_route) = owner_route {
        update_string(&mut hasher, owner_route.owner_bead_id.as_str());
        update_string(&mut hasher, owner_route.owner_hint.as_str());
        update_string(&mut hasher, owner_route.component.as_str());
        update_string(&mut hasher, owner_route.rationale.as_str());
    } else {
        update_string(&mut hasher, "owner_route:none");
    }

    ContentHash::compute(&hasher.finalize())
}

fn update_string(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn update_optional_string(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            update_string(hasher, value);
        }
        None => hasher.update([0]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shipped_observation(workload_id: &str) -> BehaviorEquivalenceObservation {
        BehaviorEquivalenceObservation::new(
            workload_id,
            ParityTarget::NodeJs,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        )
    }

    fn library_observation(workload_id: &str) -> BehaviorEquivalenceObservation {
        BehaviorEquivalenceObservation::new(
            workload_id,
            ParityTarget::NodeJs,
            EvidenceSurface::LibraryOnly,
            OwnerRouteHint::ModuleInterop,
        )
    }

    // --- EvidenceSurface ---

    #[test]
    fn evidence_surface_as_str_shipped_path() {
        assert_eq!(EvidenceSurface::ShippedPath.as_str(), "shipped_path");
    }

    #[test]
    fn evidence_surface_as_str_library_only() {
        assert_eq!(EvidenceSurface::LibraryOnly.as_str(), "library_only");
    }

    #[test]
    fn evidence_surface_display_roundtrips() {
        assert_eq!(format!("{}", EvidenceSurface::ShippedPath), "shipped_path");
        assert_eq!(format!("{}", EvidenceSurface::LibraryOnly), "library_only");
    }

    // --- BehaviorEquivalenceClass ---

    #[test]
    fn equivalence_class_as_str_all_variants() {
        assert_eq!(BehaviorEquivalenceClass::Equivalent.as_str(), "equivalent");
        assert_eq!(
            BehaviorEquivalenceClass::SemanticMismatch.as_str(),
            "semantic_mismatch"
        );
        assert_eq!(
            BehaviorEquivalenceClass::UnsupportedFeature.as_str(),
            "unsupported_feature"
        );
        assert_eq!(
            BehaviorEquivalenceClass::InfraFailure.as_str(),
            "infra_failure"
        );
        assert_eq!(
            BehaviorEquivalenceClass::BenchmarkNoise.as_str(),
            "benchmark_noise"
        );
        assert_eq!(
            BehaviorEquivalenceClass::ShippedPathDrift.as_str(),
            "shipped_path_drift"
        );
    }

    #[test]
    fn only_equivalent_does_not_block_publication() {
        assert!(!BehaviorEquivalenceClass::Equivalent.blocks_publication());
        assert!(BehaviorEquivalenceClass::SemanticMismatch.blocks_publication());
        assert!(BehaviorEquivalenceClass::UnsupportedFeature.blocks_publication());
        assert!(BehaviorEquivalenceClass::InfraFailure.blocks_publication());
        assert!(BehaviorEquivalenceClass::BenchmarkNoise.blocks_publication());
        assert!(BehaviorEquivalenceClass::ShippedPathDrift.blocks_publication());
    }

    // --- PublicationDisposition ---

    #[test]
    fn publication_disposition_as_str_all_variants() {
        assert_eq!(
            PublicationDisposition::PublicationEligible.as_str(),
            "publication_eligible"
        );
        assert_eq!(
            PublicationDisposition::NonPublicationEvidence.as_str(),
            "non_publication_evidence"
        );
        assert_eq!(PublicationDisposition::Blocked.as_str(), "blocked");
    }

    // --- OwnerRouteHint ---

    #[test]
    fn owner_route_hint_as_str_all_variants() {
        assert_eq!(
            OwnerRouteHint::RuntimeSemantics.as_str(),
            "runtime_semantics"
        );
        assert_eq!(OwnerRouteHint::ModuleInterop.as_str(), "module_interop");
        assert_eq!(
            OwnerRouteHint::TypeScriptNormalization.as_str(),
            "typescript_normalization"
        );
        assert_eq!(
            OwnerRouteHint::ShippedPathParity.as_str(),
            "shipped_path_parity"
        );
        assert_eq!(
            OwnerRouteHint::BenchmarkHarness.as_str(),
            "benchmark_harness"
        );
        assert_eq!(OwnerRouteHint::BenchmarkCorpus.as_str(), "benchmark_corpus");
        assert_eq!(OwnerRouteHint::DocsContract.as_str(), "docs_contract");
    }

    #[test]
    fn owner_route_hint_bead_ids_are_stable() {
        assert_eq!(
            OwnerRouteHint::RuntimeSemantics.owner_bead_id(),
            "bd-1lsy.4"
        );
        assert_eq!(OwnerRouteHint::ModuleInterop.owner_bead_id(), "bd-1lsy.5");
        assert_eq!(
            OwnerRouteHint::TypeScriptNormalization.owner_bead_id(),
            "bd-1lsy.3"
        );
        assert_eq!(
            OwnerRouteHint::ShippedPathParity.owner_bead_id(),
            "bd-1lsy.9.6"
        );
        assert_eq!(OwnerRouteHint::BenchmarkHarness.owner_bead_id(), BEAD_ID);
        assert_eq!(
            OwnerRouteHint::BenchmarkCorpus.owner_bead_id(),
            "bd-1lsy.8.4.1"
        );
        assert_eq!(
            OwnerRouteHint::DocsContract.owner_bead_id(),
            "bd-1lsy.10.11"
        );
    }

    #[test]
    fn owner_route_hint_components_are_stable() {
        assert_eq!(
            OwnerRouteHint::RuntimeSemantics.component(),
            "runtime_semantics"
        );
        assert_eq!(
            OwnerRouteHint::ModuleInterop.component(),
            "module_system_interop"
        );
        assert_eq!(OwnerRouteHint::BenchmarkHarness.component(), COMPONENT);
    }

    // --- classify_observation ---

    #[test]
    fn classify_infra_failure_takes_priority() {
        let obs = shipped_observation("w1")
            .with_infra_ok(false)
            .with_output_equivalence(false)
            .with_feature_supported(false);
        assert_eq!(
            classify_observation(&obs),
            BehaviorEquivalenceClass::InfraFailure
        );
    }

    #[test]
    fn classify_unsupported_feature_after_infra_ok() {
        let obs = shipped_observation("w1")
            .with_infra_ok(true)
            .with_feature_supported(false);
        assert_eq!(
            classify_observation(&obs),
            BehaviorEquivalenceClass::UnsupportedFeature
        );
    }

    #[test]
    fn classify_benchmark_noise() {
        let obs = shipped_observation("w1")
            .with_noise_only(true)
            .with_output_equivalence(false);
        assert_eq!(
            classify_observation(&obs),
            BehaviorEquivalenceClass::BenchmarkNoise
        );
    }

    #[test]
    fn classify_shipped_path_drift_on_mismatch() {
        let obs = shipped_observation("w1").with_output_equivalence(false);
        assert_eq!(
            classify_observation(&obs),
            BehaviorEquivalenceClass::ShippedPathDrift
        );
    }

    #[test]
    fn classify_semantic_mismatch_for_library_only() {
        let obs = library_observation("w1").with_output_equivalence(false);
        assert_eq!(
            classify_observation(&obs),
            BehaviorEquivalenceClass::SemanticMismatch
        );
    }

    #[test]
    fn classify_equivalent_when_all_pass() {
        let obs = shipped_observation("w1");
        assert_eq!(
            classify_observation(&obs),
            BehaviorEquivalenceClass::Equivalent
        );
    }

    // --- publication_disposition_for ---

    #[test]
    fn disposition_equivalent_shipped_is_publication_eligible() {
        assert_eq!(
            publication_disposition_for(
                BehaviorEquivalenceClass::Equivalent,
                EvidenceSurface::ShippedPath,
            ),
            PublicationDisposition::PublicationEligible
        );
    }

    #[test]
    fn disposition_equivalent_library_is_non_publication() {
        assert_eq!(
            publication_disposition_for(
                BehaviorEquivalenceClass::Equivalent,
                EvidenceSurface::LibraryOnly,
            ),
            PublicationDisposition::NonPublicationEvidence
        );
    }

    #[test]
    fn disposition_any_blocker_is_blocked() {
        for class in [
            BehaviorEquivalenceClass::SemanticMismatch,
            BehaviorEquivalenceClass::UnsupportedFeature,
            BehaviorEquivalenceClass::InfraFailure,
            BehaviorEquivalenceClass::BenchmarkNoise,
            BehaviorEquivalenceClass::ShippedPathDrift,
        ] {
            assert_eq!(
                publication_disposition_for(class, EvidenceSurface::ShippedPath),
                PublicationDisposition::Blocked,
                "{class} should block publication"
            );
        }
    }

    // --- route_owner ---

    #[test]
    fn route_owner_returns_none_for_equivalent() {
        assert!(
            route_owner(
                BehaviorEquivalenceClass::Equivalent,
                OwnerRouteHint::RuntimeSemantics,
            )
            .is_none()
        );
    }

    #[test]
    fn route_owner_semantic_mismatch_preserves_hint() {
        let route = route_owner(
            BehaviorEquivalenceClass::SemanticMismatch,
            OwnerRouteHint::ModuleInterop,
        )
        .expect("should route");
        assert_eq!(route.owner_hint, OwnerRouteHint::ModuleInterop);
        assert_eq!(route.owner_bead_id, "bd-1lsy.5");
    }

    #[test]
    fn route_owner_infra_failure_always_routes_to_harness() {
        let route = route_owner(
            BehaviorEquivalenceClass::InfraFailure,
            OwnerRouteHint::TypeScriptNormalization,
        )
        .expect("should route");
        assert_eq!(route.owner_hint, OwnerRouteHint::BenchmarkHarness);
        assert_eq!(route.owner_bead_id, BEAD_ID);
    }

    #[test]
    fn route_owner_shipped_path_drift_routes_to_shipped_path() {
        let route = route_owner(
            BehaviorEquivalenceClass::ShippedPathDrift,
            OwnerRouteHint::RuntimeSemantics,
        )
        .expect("should route");
        assert_eq!(route.owner_hint, OwnerRouteHint::ShippedPathParity);
        assert_eq!(route.owner_bead_id, "bd-1lsy.9.6");
    }

    // --- build_record ---

    #[test]
    fn build_record_deterministic_hash() {
        let obs = shipped_observation("wk1").with_detail("stable");
        let r1 = build_record(&obs);
        let r2 = build_record(&obs);
        assert_eq!(r1.record_hash, r2.record_hash);
    }

    #[test]
    fn build_record_hash_changes_on_different_detail() {
        let obs_a = shipped_observation("wk1").with_detail("detail-a");
        let obs_b = shipped_observation("wk1").with_detail("detail-b");
        assert_ne!(
            build_record(&obs_a).record_hash,
            build_record(&obs_b).record_hash
        );
    }

    #[test]
    fn build_record_carries_minimized_repro_command() {
        let obs = shipped_observation("w1")
            .with_output_equivalence(false)
            .with_minimized_repro_command("frankenctl run --min");
        let record = build_record(&obs);
        assert_eq!(
            record.minimized_repro_command.as_deref(),
            Some("frankenctl run --min")
        );
    }

    // --- build_report ---

    #[test]
    fn build_report_empty_observations_produces_empty_records() {
        let report = build_report("t1", "d1", "p1", &[]);
        assert!(report.records.is_empty());
        assert!(report.owner_routes.is_empty());
        assert!(!report.has_publication_blockers());
    }

    #[test]
    fn build_report_sorts_records_deterministically() {
        let observations = vec![
            shipped_observation("zeta"),
            shipped_observation("alpha"),
            shipped_observation("mu"),
        ];
        let report = build_report("t", "d", POLICY_ID, &observations);
        let ids: Vec<&str> = report
            .records
            .iter()
            .map(|r| r.workload_id.as_str())
            .collect();
        assert_eq!(ids, vec!["alpha", "mu", "zeta"]);
    }

    #[test]
    fn build_report_has_publication_blockers_false_when_all_equivalent() {
        let observations = vec![shipped_observation("w1"), shipped_observation("w2")];
        let report = build_report("t", "d", POLICY_ID, &observations);
        assert!(!report.has_publication_blockers());
    }

    #[test]
    fn build_report_has_publication_blockers_true_when_any_blocked() {
        let observations = vec![
            shipped_observation("w1"),
            shipped_observation("w2").with_output_equivalence(false),
        ];
        let report = build_report("t", "d", POLICY_ID, &observations);
        assert!(report.has_publication_blockers());
    }

    #[test]
    fn build_report_aggregates_owner_routes_by_key() {
        let observations = vec![
            shipped_observation("w1").with_output_equivalence(false),
            shipped_observation("w2").with_output_equivalence(false),
        ];
        let report = build_report("t", "d", POLICY_ID, &observations);
        // Both are ShippedPathDrift from RuntimeSemantics → routed to ShippedPathParity
        // Should be aggregated into one owner route entry
        assert_eq!(report.owner_routes.len(), 1);
        assert_eq!(report.owner_routes[0].workload_ids.len(), 2);
    }

    // --- BehaviorEquivalenceReport methods ---

    #[test]
    fn benchmark_parity_verdict_jsonl_renders_valid_lines() {
        let report = build_report(
            "t",
            "d",
            POLICY_ID,
            &[shipped_observation("w1"), shipped_observation("w2")],
        );
        let jsonl = report
            .benchmark_parity_verdict_jsonl()
            .expect("should render");
        let lines: Vec<&str> = jsonl.split('\n').collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let _: BenchmarkParityVerdictRecord =
                serde_json::from_str(line).expect("each line should be valid JSON");
        }
    }

    #[test]
    fn divergence_owner_route_json_renders_valid_json() {
        let obs = shipped_observation("w1").with_output_equivalence(false);
        let report = build_report("t", "d", POLICY_ID, &[obs]);
        let json_str = report.divergence_owner_route_json().expect("should render");
        let routes: Vec<DivergenceOwnerRoute> =
            serde_json::from_str(&json_str).expect("should parse back");
        assert_eq!(routes.len(), 1);
    }

    // --- serde roundtrip ---

    #[test]
    fn observation_serde_roundtrip() {
        let obs = shipped_observation("serde_test")
            .with_detail("detail")
            .with_minimized_repro_command("cmd");
        let json = serde_json::to_string(&obs).expect("serialize");
        let back: BehaviorEquivalenceObservation =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(obs, back);
    }

    #[test]
    fn report_serde_roundtrip() {
        let report = build_report(
            "trace-serde",
            "dec-serde",
            POLICY_ID,
            &[shipped_observation("w1").with_output_equivalence(false)],
        );
        let json = serde_json::to_string(&report).expect("serialize");
        let back: BehaviorEquivalenceReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, back);
    }

    // --- BehaviorEquivalenceObservation builder ---

    #[test]
    fn observation_builder_defaults_to_passing() {
        let obs = shipped_observation("w1");
        assert!(obs.output_equivalent);
        assert!(obs.feature_supported);
        assert!(obs.infra_ok);
        assert!(!obs.noise_only);
        assert!(obs.detail.is_empty());
        assert!(obs.minimized_repro_command.is_none());
    }

    // --- constants ---

    #[test]
    fn schema_version_is_stable() {
        assert_eq!(
            SCHEMA_VERSION,
            "franken-engine.benchmark-behavior-equivalence.v1"
        );
    }

    #[test]
    fn component_matches_module_name() {
        assert_eq!(COMPONENT, "benchmark_behavior_equivalence");
    }

    #[test]
    fn bead_id_matches_rgc_704b() {
        assert_eq!(BEAD_ID, "bd-1lsy.8.4.2");
    }

    #[test]
    fn policy_id_is_rgc_704b() {
        assert_eq!(POLICY_ID, "RGC-704B");
    }

    // --- Additional hash determinism tests ---

    #[test]
    fn build_record_hash_differs_by_workload_id() {
        let obs_a = shipped_observation("workload_alpha");
        let obs_b = shipped_observation("workload_beta");
        assert_ne!(
            build_record(&obs_a).record_hash,
            build_record(&obs_b).record_hash
        );
    }

    #[test]
    fn build_record_hash_differs_by_surface() {
        let obs_shipped = BehaviorEquivalenceObservation::new(
            "w1",
            ParityTarget::NodeJs,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        );
        let obs_library = BehaviorEquivalenceObservation::new(
            "w1",
            ParityTarget::NodeJs,
            EvidenceSurface::LibraryOnly,
            OwnerRouteHint::RuntimeSemantics,
        );
        assert_ne!(
            build_record(&obs_shipped).record_hash,
            build_record(&obs_library).record_hash
        );
    }

    #[test]
    fn build_record_hash_differs_by_baseline() {
        let obs_node = BehaviorEquivalenceObservation::new(
            "w1",
            ParityTarget::NodeJs,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        );
        let obs_bun = BehaviorEquivalenceObservation::new(
            "w1",
            ParityTarget::Bun,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        );
        assert_ne!(
            build_record(&obs_node).record_hash,
            build_record(&obs_bun).record_hash
        );
    }

    #[test]
    fn build_record_hash_differs_with_and_without_repro_command() {
        let obs_no_cmd = shipped_observation("w1");
        let obs_with_cmd =
            shipped_observation("w1").with_minimized_repro_command("frankenctl repro");
        assert_ne!(
            build_record(&obs_no_cmd).record_hash,
            build_record(&obs_with_cmd).record_hash
        );
    }

    #[test]
    fn build_record_hash_differs_by_repro_command_content() {
        let obs_a = shipped_observation("w1").with_minimized_repro_command("cmd_a");
        let obs_b = shipped_observation("w1").with_minimized_repro_command("cmd_b");
        assert_ne!(
            build_record(&obs_a).record_hash,
            build_record(&obs_b).record_hash
        );
    }

    #[test]
    fn build_record_hash_stable_across_multiple_invocations() {
        let obs = shipped_observation("stability_test")
            .with_detail("some detail")
            .with_minimized_repro_command("frankenctl run");
        let hashes: Vec<ContentHash> = (0..5).map(|_| build_record(&obs).record_hash).collect();
        for hash in &hashes[1..] {
            assert_eq!(&hashes[0], hash);
        }
    }

    // --- classify_observation priority / edge cases ---

    #[test]
    fn classify_infra_failure_wins_over_noise() {
        let obs = shipped_observation("w1")
            .with_infra_ok(false)
            .with_noise_only(true);
        assert_eq!(
            classify_observation(&obs),
            BehaviorEquivalenceClass::InfraFailure
        );
    }

    #[test]
    fn classify_unsupported_feature_wins_over_noise() {
        let obs = shipped_observation("w1")
            .with_feature_supported(false)
            .with_noise_only(true);
        assert_eq!(
            classify_observation(&obs),
            BehaviorEquivalenceClass::UnsupportedFeature
        );
    }

    #[test]
    fn classify_noise_wins_over_output_mismatch() {
        let obs = shipped_observation("w1")
            .with_noise_only(true)
            .with_output_equivalence(false);
        assert_eq!(
            classify_observation(&obs),
            BehaviorEquivalenceClass::BenchmarkNoise
        );
    }

    #[test]
    fn classify_library_equivalent_when_all_pass() {
        let obs = library_observation("w1");
        assert_eq!(
            classify_observation(&obs),
            BehaviorEquivalenceClass::Equivalent
        );
    }

    // --- route_owner edge cases ---

    #[test]
    fn route_owner_unsupported_feature_preserves_hint() {
        let route = route_owner(
            BehaviorEquivalenceClass::UnsupportedFeature,
            OwnerRouteHint::DocsContract,
        )
        .expect("should route");
        assert_eq!(route.owner_hint, OwnerRouteHint::DocsContract);
        assert_eq!(route.owner_bead_id, "bd-1lsy.10.11");
        assert_eq!(route.component, "docs_help_surface");
    }

    #[test]
    fn route_owner_benchmark_noise_always_routes_to_harness() {
        let route = route_owner(
            BehaviorEquivalenceClass::BenchmarkNoise,
            OwnerRouteHint::BenchmarkCorpus,
        )
        .expect("should route");
        assert_eq!(route.owner_hint, OwnerRouteHint::BenchmarkHarness);
        assert_eq!(route.owner_bead_id, BEAD_ID);
        assert_eq!(route.component, COMPONENT);
    }

    #[test]
    fn route_owner_shipped_path_drift_ignores_provided_hint() {
        // ShippedPathDrift always routes to ShippedPathParity, regardless of the hint provided
        let route = route_owner(
            BehaviorEquivalenceClass::ShippedPathDrift,
            OwnerRouteHint::DocsContract,
        )
        .expect("should route");
        assert_eq!(route.owner_hint, OwnerRouteHint::ShippedPathParity);
        assert_eq!(route.owner_bead_id, "bd-1lsy.9.6");
    }

    #[test]
    fn route_owner_semantic_mismatch_with_all_hint_variants() {
        let hints = [
            OwnerRouteHint::RuntimeSemantics,
            OwnerRouteHint::ModuleInterop,
            OwnerRouteHint::TypeScriptNormalization,
            OwnerRouteHint::ShippedPathParity,
            OwnerRouteHint::BenchmarkHarness,
            OwnerRouteHint::BenchmarkCorpus,
            OwnerRouteHint::DocsContract,
        ];
        for hint in hints {
            let route = route_owner(BehaviorEquivalenceClass::SemanticMismatch, hint)
                .expect("should route");
            assert_eq!(route.owner_hint, hint);
            assert_eq!(route.owner_bead_id, hint.owner_bead_id());
            assert_eq!(route.component, hint.component());
        }
    }

    // --- publication_disposition_for edge cases ---

    #[test]
    fn disposition_blocked_for_all_non_equivalent_library_surface() {
        for class in [
            BehaviorEquivalenceClass::SemanticMismatch,
            BehaviorEquivalenceClass::UnsupportedFeature,
            BehaviorEquivalenceClass::InfraFailure,
            BehaviorEquivalenceClass::BenchmarkNoise,
            BehaviorEquivalenceClass::ShippedPathDrift,
        ] {
            assert_eq!(
                publication_disposition_for(class, EvidenceSurface::LibraryOnly),
                PublicationDisposition::Blocked,
                "{class} library-only should still block publication"
            );
        }
    }

    // --- serde roundtrip edge cases ---

    #[test]
    fn evidence_surface_serde_roundtrip() {
        for surface in [EvidenceSurface::ShippedPath, EvidenceSurface::LibraryOnly] {
            let json = serde_json::to_string(&surface).expect("serialize");
            let back: EvidenceSurface = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(surface, back);
        }
    }

    #[test]
    fn behavior_equivalence_class_serde_roundtrip() {
        let variants = [
            BehaviorEquivalenceClass::Equivalent,
            BehaviorEquivalenceClass::SemanticMismatch,
            BehaviorEquivalenceClass::UnsupportedFeature,
            BehaviorEquivalenceClass::InfraFailure,
            BehaviorEquivalenceClass::BenchmarkNoise,
            BehaviorEquivalenceClass::ShippedPathDrift,
        ];
        for variant in variants {
            let json = serde_json::to_string(&variant).expect("serialize");
            let back: BehaviorEquivalenceClass = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn publication_disposition_serde_roundtrip() {
        for disp in [
            PublicationDisposition::PublicationEligible,
            PublicationDisposition::NonPublicationEvidence,
            PublicationDisposition::Blocked,
        ] {
            let json = serde_json::to_string(&disp).expect("serialize");
            let back: PublicationDisposition = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(disp, back);
        }
    }

    #[test]
    fn owner_route_hint_serde_roundtrip() {
        let hints = [
            OwnerRouteHint::RuntimeSemantics,
            OwnerRouteHint::ModuleInterop,
            OwnerRouteHint::TypeScriptNormalization,
            OwnerRouteHint::ShippedPathParity,
            OwnerRouteHint::BenchmarkHarness,
            OwnerRouteHint::BenchmarkCorpus,
            OwnerRouteHint::DocsContract,
        ];
        for hint in hints {
            let json = serde_json::to_string(&hint).expect("serialize");
            let back: OwnerRouteHint = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(hint, back);
        }
    }

    #[test]
    fn verdict_record_serde_roundtrip_with_owner_route() {
        let obs = shipped_observation("w1").with_output_equivalence(false);
        let record = build_record(&obs);
        assert!(record.owner_route.is_some());
        let json = serde_json::to_string(&record).expect("serialize");
        let back: BenchmarkParityVerdictRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, back);
    }

    #[test]
    fn verdict_record_serde_roundtrip_without_owner_route() {
        let obs = shipped_observation("w1");
        let record = build_record(&obs);
        assert!(record.owner_route.is_none());
        let json = serde_json::to_string(&record).expect("serialize");
        let back: BenchmarkParityVerdictRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, back);
    }

    #[test]
    fn observation_serde_roundtrip_without_minimized_repro() {
        let obs = shipped_observation("w1").with_detail("no repro");
        let json = serde_json::to_string(&obs).expect("serialize");
        let back: BehaviorEquivalenceObservation =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(obs, back);
        assert!(back.minimized_repro_command.is_none());
    }

    #[test]
    fn observation_deserialize_missing_repro_field_defaults_to_none() {
        // Simulate JSON without minimized_repro_command field
        let json = r#"{
            "workload_id": "w1",
            "baseline": "node_js",
            "surface": "shipped_path",
            "output_equivalent": true,
            "feature_supported": true,
            "infra_ok": true,
            "noise_only": false,
            "detail": "",
            "owner_hint": "runtime_semantics"
        }"#;
        let obs: BehaviorEquivalenceObservation = serde_json::from_str(json).expect("deserialize");
        assert!(obs.minimized_repro_command.is_none());
    }

    // --- Display formatting ---

    #[test]
    fn behavior_equivalence_class_display_matches_as_str() {
        let variants = [
            BehaviorEquivalenceClass::Equivalent,
            BehaviorEquivalenceClass::SemanticMismatch,
            BehaviorEquivalenceClass::UnsupportedFeature,
            BehaviorEquivalenceClass::InfraFailure,
            BehaviorEquivalenceClass::BenchmarkNoise,
            BehaviorEquivalenceClass::ShippedPathDrift,
        ];
        for variant in variants {
            assert_eq!(format!("{variant}"), variant.as_str());
        }
    }

    #[test]
    fn publication_disposition_display_matches_as_str() {
        for disp in [
            PublicationDisposition::PublicationEligible,
            PublicationDisposition::NonPublicationEvidence,
            PublicationDisposition::Blocked,
        ] {
            assert_eq!(format!("{disp}"), disp.as_str());
        }
    }

    #[test]
    fn owner_route_hint_display_matches_as_str() {
        let hints = [
            OwnerRouteHint::RuntimeSemantics,
            OwnerRouteHint::ModuleInterop,
            OwnerRouteHint::TypeScriptNormalization,
            OwnerRouteHint::ShippedPathParity,
            OwnerRouteHint::BenchmarkHarness,
            OwnerRouteHint::BenchmarkCorpus,
            OwnerRouteHint::DocsContract,
        ];
        for hint in hints {
            assert_eq!(format!("{hint}"), hint.as_str());
        }
    }

    // --- build_report aggregation and structure ---

    #[test]
    fn build_report_populates_schema_and_policy_fields() {
        let report = build_report("trace-42", "dec-99", "RGC-704B", &[]);
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.trace_id, "trace-42");
        assert_eq!(report.decision_id, "dec-99");
        assert_eq!(report.policy_id, "RGC-704B");
        assert_eq!(report.component, COMPONENT);
    }

    #[test]
    fn build_report_multiple_different_owner_routes_grouped_separately() {
        // Two observations routed to different owners
        let obs_shipped_drift = shipped_observation("w1").with_output_equivalence(false);
        let obs_infra_fail = library_observation("w2").with_infra_ok(false);
        let report = build_report("t", "d", POLICY_ID, &[obs_shipped_drift, obs_infra_fail]);
        // ShippedPathDrift -> ShippedPathParity owner
        // InfraFailure -> BenchmarkHarness owner
        assert_eq!(report.owner_routes.len(), 2);
        let owner_hints: BTreeSet<OwnerRouteHint> =
            report.owner_routes.iter().map(|r| r.owner_hint).collect();
        assert!(owner_hints.contains(&OwnerRouteHint::ShippedPathParity));
        assert!(owner_hints.contains(&OwnerRouteHint::BenchmarkHarness));
    }

    #[test]
    fn build_report_no_owner_routes_when_all_equivalent() {
        let observations = vec![
            shipped_observation("w1"),
            library_observation("w2"),
            shipped_observation("w3"),
        ];
        let report = build_report("t", "d", POLICY_ID, &observations);
        assert!(report.owner_routes.is_empty());
    }

    #[test]
    fn build_report_owner_route_workload_ids_are_sorted_and_deduped() {
        // Two observations with different workload_ids hitting same owner route
        let obs1 = shipped_observation("zeta_workload").with_output_equivalence(false);
        let obs2 = shipped_observation("alpha_workload").with_output_equivalence(false);
        let report = build_report("t", "d", POLICY_ID, &[obs1, obs2]);
        assert_eq!(report.owner_routes.len(), 1);
        let wids = &report.owner_routes[0].workload_ids;
        assert_eq!(wids, &["alpha_workload", "zeta_workload"]);
    }

    #[test]
    fn build_report_owner_route_classifications_are_deduped() {
        // Both are ShippedPathDrift, so only one classification in the aggregated route
        let obs1 = shipped_observation("w1").with_output_equivalence(false);
        let obs2 = shipped_observation("w2").with_output_equivalence(false);
        let report = build_report("t", "d", POLICY_ID, &[obs1, obs2]);
        assert_eq!(report.owner_routes.len(), 1);
        assert_eq!(
            report.owner_routes[0].classifications,
            vec![BehaviorEquivalenceClass::ShippedPathDrift]
        );
    }

    // --- build_record field propagation ---

    #[test]
    fn build_record_propagates_all_observation_fields() {
        let obs = BehaviorEquivalenceObservation::new(
            "my_workload",
            ParityTarget::Deno,
            EvidenceSurface::LibraryOnly,
            OwnerRouteHint::TypeScriptNormalization,
        )
        .with_detail("some detail text")
        .with_minimized_repro_command("frankenctl --debug");
        let record = build_record(&obs);
        assert_eq!(record.workload_id, "my_workload");
        assert_eq!(record.baseline, ParityTarget::Deno);
        assert_eq!(record.surface, EvidenceSurface::LibraryOnly);
        assert_eq!(record.detail, "some detail text");
        assert_eq!(
            record.minimized_repro_command.as_deref(),
            Some("frankenctl --debug")
        );
    }

    #[test]
    fn build_record_equivalent_has_no_owner_route() {
        let obs = shipped_observation("w1");
        let record = build_record(&obs);
        assert_eq!(record.classification, BehaviorEquivalenceClass::Equivalent);
        assert_eq!(
            record.publication_disposition,
            PublicationDisposition::PublicationEligible
        );
        assert!(record.owner_route.is_none());
    }

    #[test]
    fn build_record_library_equivalent_non_publication() {
        let obs = library_observation("w1");
        let record = build_record(&obs);
        assert_eq!(record.classification, BehaviorEquivalenceClass::Equivalent);
        assert_eq!(
            record.publication_disposition,
            PublicationDisposition::NonPublicationEvidence
        );
    }

    // --- JSONL / JSON output edge cases ---

    #[test]
    fn benchmark_parity_verdict_jsonl_empty_report() {
        let report = build_report("t", "d", POLICY_ID, &[]);
        let jsonl = report
            .benchmark_parity_verdict_jsonl()
            .expect("should render");
        assert_eq!(jsonl, "");
    }

    #[test]
    fn divergence_owner_route_json_empty_report() {
        let report = build_report("t", "d", POLICY_ID, &[]);
        let json_str = report.divergence_owner_route_json().expect("should render");
        let routes: Vec<DivergenceOwnerRoute> =
            serde_json::from_str(&json_str).expect("should parse");
        assert!(routes.is_empty());
    }

    // --- Observation builder chaining ---

    #[test]
    fn observation_builder_chaining_all_flags() {
        let obs = shipped_observation("chain_test")
            .with_output_equivalence(false)
            .with_feature_supported(false)
            .with_infra_ok(false)
            .with_noise_only(true)
            .with_detail("full chain")
            .with_minimized_repro_command("cmd");
        assert!(!obs.output_equivalent);
        assert!(!obs.feature_supported);
        assert!(!obs.infra_ok);
        assert!(obs.noise_only);
        assert_eq!(obs.detail, "full chain");
        assert_eq!(obs.minimized_repro_command.as_deref(), Some("cmd"));
    }

    // --- Ord / Hash on enums ---

    #[test]
    fn behavior_equivalence_class_ord_is_consistent() {
        // Verify Ord is defined (derive-based, follows declaration order)
        let mut variants = [
            BehaviorEquivalenceClass::ShippedPathDrift,
            BehaviorEquivalenceClass::Equivalent,
            BehaviorEquivalenceClass::BenchmarkNoise,
            BehaviorEquivalenceClass::InfraFailure,
            BehaviorEquivalenceClass::UnsupportedFeature,
            BehaviorEquivalenceClass::SemanticMismatch,
        ];
        variants.sort();
        // Declaration order: Equivalent, SemanticMismatch, UnsupportedFeature,
        // InfraFailure, BenchmarkNoise, ShippedPathDrift
        assert_eq!(variants[0], BehaviorEquivalenceClass::Equivalent);
        assert_eq!(variants[1], BehaviorEquivalenceClass::SemanticMismatch);
        assert_eq!(variants[2], BehaviorEquivalenceClass::UnsupportedFeature);
        assert_eq!(variants[3], BehaviorEquivalenceClass::InfraFailure);
        assert_eq!(variants[4], BehaviorEquivalenceClass::BenchmarkNoise);
        assert_eq!(variants[5], BehaviorEquivalenceClass::ShippedPathDrift);
    }

    #[test]
    fn evidence_surface_ord_shipped_before_library() {
        assert!(EvidenceSurface::ShippedPath < EvidenceSurface::LibraryOnly);
    }

    #[test]
    fn owner_route_hint_can_be_used_as_btreeset_key() {
        let mut set = BTreeSet::new();
        set.insert(OwnerRouteHint::RuntimeSemantics);
        set.insert(OwnerRouteHint::DocsContract);
        set.insert(OwnerRouteHint::RuntimeSemantics); // duplicate
        assert_eq!(set.len(), 2);
    }

    // --- ParityTarget variants in observations ---

    #[test]
    fn classify_works_with_all_parity_targets() {
        for target in ParityTarget::ALL {
            let obs = BehaviorEquivalenceObservation::new(
                "target_test",
                *target,
                EvidenceSurface::ShippedPath,
                OwnerRouteHint::RuntimeSemantics,
            );
            assert_eq!(
                classify_observation(&obs),
                BehaviorEquivalenceClass::Equivalent
            );
        }
    }

    #[test]
    fn build_record_with_v8_isolate_baseline() {
        let obs = BehaviorEquivalenceObservation::new(
            "v8_test",
            ParityTarget::V8Isolate,
            EvidenceSurface::ShippedPath,
            OwnerRouteHint::RuntimeSemantics,
        )
        .with_output_equivalence(false);
        let record = build_record(&obs);
        assert_eq!(record.baseline, ParityTarget::V8Isolate);
        assert_eq!(
            record.classification,
            BehaviorEquivalenceClass::ShippedPathDrift
        );
    }

    // --- empty/edge string handling ---

    #[test]
    fn observation_with_empty_workload_id() {
        let obs = shipped_observation("");
        let record = build_record(&obs);
        assert_eq!(record.workload_id, "");
        assert_eq!(record.classification, BehaviorEquivalenceClass::Equivalent);
    }

    #[test]
    fn observation_with_unicode_detail() {
        let obs = shipped_observation("unicode_test").with_detail("divergence \u{1F4A5} detected");
        let record = build_record(&obs);
        let json = serde_json::to_string(&record).expect("serialize");
        let back: BenchmarkParityVerdictRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.detail, "divergence \u{1F4A5} detected");
    }

    #[test]
    fn build_report_single_observation_produces_single_record() {
        let obs = shipped_observation("singleton");
        let report = build_report("t", "d", POLICY_ID, &[obs]);
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].workload_id, "singleton");
    }
}
