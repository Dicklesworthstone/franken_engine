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
