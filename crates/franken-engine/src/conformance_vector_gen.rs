//! Conformance-vector generator and property/fuzz harness for cross-repo
//! boundary invariants, including degraded and fault-mode scenarios.
//!
//! Generates deterministic test vectors from the conformance-lab contract
//! catalog (`conformance_catalog`), covering:
//! - Positive vectors (valid interactions)
//! - Negative vectors (boundary violations, malformed payloads, version mismatches)
//! - Degraded-mode vectors (stale revocation heads, partial availability, timeouts)
//! - Fault-mode vectors (corrupted payloads, truncated messages, replay attacks)
//!
//! All generated vectors are deterministically reproducible from a seed.
//!
//! Plan reference: Section 10.15 item 2 (`bd-3rgq`).
//! Cross-refs: 9I.4 (FrankenSuite Cross-Repo Conformance Lab).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::conformance_catalog::{
    BoundarySurface, CatalogEntry, ConformanceCatalog, SemanticVersion, SiblingRepo, SurfaceKind,
};
use crate::cross_repo_contract::RegressionClass;

// ---------------------------------------------------------------------------
// Vector categories
// ---------------------------------------------------------------------------

/// Category of a generated conformance vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VectorCategory {
    /// Valid interaction that must pass.
    Positive,
    /// Boundary violation or malformed input that must fail.
    Negative,
    /// Degraded-mode scenario (partial availability, stale data, timeouts).
    Degraded,
    /// Fault-mode scenario (corruption, truncation, replay attacks).
    Fault,
}

impl VectorCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::Negative => "negative",
            Self::Degraded => "degraded",
            Self::Fault => "fault",
        }
    }
}

impl fmt::Display for VectorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Degraded-mode scenario types
// ---------------------------------------------------------------------------

/// Specific degraded-mode scenario for vector generation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DegradedScenario {
    /// Revocation head is stale (behind current epoch).
    StaleRevocationHead { epochs_behind: u64 },
    /// Sibling repo partially unavailable.
    PartialAvailability { available_fraction_millionths: u64 },
    /// Request timed out at boundary.
    Timeout { timeout_ms: u64 },
    /// Schema drift: remote uses a newer minor version.
    SchemaDrift {
        local_version: SemanticVersion,
        remote_version: SemanticVersion,
    },
    /// Empty response from sibling (valid but degenerate).
    EmptyResponse,
}

impl fmt::Display for DegradedScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleRevocationHead { epochs_behind } => {
                write!(f, "stale-revocation-head ({}ep behind)", epochs_behind)
            }
            Self::PartialAvailability {
                available_fraction_millionths,
            } => {
                write!(
                    f,
                    "partial-availability ({}/1M)",
                    available_fraction_millionths
                )
            }
            Self::Timeout { timeout_ms } => write!(f, "timeout ({}ms)", timeout_ms),
            Self::SchemaDrift {
                local_version,
                remote_version,
            } => write!(f, "schema-drift ({} vs {})", local_version, remote_version),
            Self::EmptyResponse => f.write_str("empty-response"),
        }
    }
}

// ---------------------------------------------------------------------------
// Fault-mode scenario types
// ---------------------------------------------------------------------------

/// Specific fault-mode scenario for vector generation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FaultScenario {
    /// Payload bytes corrupted at a specific offset.
    CorruptedPayload { corruption_offset: usize },
    /// Message truncated to a fraction of original length.
    TruncatedMessage { retain_fraction_millionths: u64 },
    /// Out-of-order sequence numbers.
    OutOfOrderSequence { expected_seq: u64, actual_seq: u64 },
    /// Replay attack: duplicate message with same nonce.
    ReplayAttack { original_nonce: u64 },
    /// Malformed JSON (syntax error).
    MalformedJson,
    /// Wrong content type / encoding mismatch.
    EncodingMismatch { expected: String, actual: String },
}

impl fmt::Display for FaultScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CorruptedPayload { corruption_offset } => {
                write!(f, "corrupted-payload (offset {})", corruption_offset)
            }
            Self::TruncatedMessage {
                retain_fraction_millionths,
            } => write!(
                f,
                "truncated-message (retain {}/1M)",
                retain_fraction_millionths
            ),
            Self::OutOfOrderSequence {
                expected_seq,
                actual_seq,
            } => write!(
                f,
                "out-of-order-sequence (expected {}, got {})",
                expected_seq, actual_seq
            ),
            Self::ReplayAttack { original_nonce } => {
                write!(f, "replay-attack (nonce {})", original_nonce)
            }
            Self::MalformedJson => f.write_str("malformed-json"),
            Self::EncodingMismatch { expected, actual } => {
                write!(f, "encoding-mismatch ({} vs {})", expected, actual)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Generated vector
// ---------------------------------------------------------------------------

/// A generated conformance test vector with full provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedVector {
    /// Unique vector identifier.
    pub vector_id: String,
    /// Human-readable description.
    pub description: String,
    /// Category of this vector.
    pub category: VectorCategory,
    /// Source catalog entry ID this was generated from.
    pub source_entry_id: String,
    /// Sibling repo boundary this tests.
    pub boundary: SiblingRepo,
    /// Surface kind being tested.
    pub surface_kind: SurfaceKind,
    /// Input payload (JSON string).
    pub input_json: String,
    /// Whether this vector should pass validation.
    pub expected_pass: bool,
    /// Expected regression class if failure.
    pub expected_regression_class: Option<RegressionClass>,
    /// Degraded-mode scenario if applicable.
    pub degraded_scenario: Option<DegradedScenario>,
    /// Fault-mode scenario if applicable.
    pub fault_scenario: Option<FaultScenario>,
    /// Deterministic seed used to generate this vector.
    pub seed: u64,
    /// Fields covered by this vector.
    pub covered_fields: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// Generation configuration
// ---------------------------------------------------------------------------

/// Configuration for the vector generator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorConfig {
    /// Master seed for deterministic generation.
    pub seed: u64,
    /// Maximum positive vectors per catalog entry.
    pub max_positive_per_entry: usize,
    /// Maximum negative vectors per catalog entry.
    pub max_negative_per_entry: usize,
    /// Maximum degraded vectors per catalog entry.
    pub max_degraded_per_entry: usize,
    /// Maximum fault vectors per catalog entry.
    pub max_fault_per_entry: usize,
    /// Filter to specific sibling repos (empty = all).
    pub sibling_filter: BTreeSet<SiblingRepo>,
    /// Filter to specific surface kinds (empty = all).
    pub surface_filter: BTreeSet<SurfaceKind>,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            seed: 42,
            max_positive_per_entry: 3,
            max_negative_per_entry: 3,
            max_degraded_per_entry: 5,
            max_fault_per_entry: 6,
            sibling_filter: BTreeSet::new(),
            surface_filter: BTreeSet::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Generation result
// ---------------------------------------------------------------------------

/// Result of a vector generation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationResult {
    /// Seed used for this run.
    pub seed: u64,
    /// Catalog version used.
    pub catalog_version: SemanticVersion,
    /// All generated vectors.
    pub vectors: Vec<GeneratedVector>,
    /// Per-category counts.
    pub category_counts: BTreeMap<String, usize>,
    /// Per-boundary counts.
    pub boundary_counts: BTreeMap<String, usize>,
    /// Warnings during generation.
    pub warnings: Vec<String>,
}

impl GenerationResult {
    /// Count vectors of a specific category.
    pub fn count_by_category(&self, category: VectorCategory) -> usize {
        self.vectors
            .iter()
            .filter(|v| v.category == category)
            .count()
    }

    /// Count vectors for a specific sibling.
    pub fn count_by_boundary(&self, sibling: SiblingRepo) -> usize {
        self.vectors
            .iter()
            .filter(|v| v.boundary == sibling)
            .count()
    }

    /// All unique vector IDs.
    pub fn vector_ids(&self) -> BTreeSet<String> {
        self.vectors.iter().map(|v| v.vector_id.clone()).collect()
    }
}

// ---------------------------------------------------------------------------
// Deterministic RNG (simple xorshift64 for reproducibility)
// ---------------------------------------------------------------------------

/// Simple deterministic PRNG for vector generation (xorshift64).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DetRng {
    state: u64,
}

impl DetRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_range(&mut self, max: u64) -> u64 {
        if max == 0 {
            return 0;
        }
        self.next_u64() % max
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let idx = self.next_range(items.len() as u64) as usize;
        &items[idx]
    }
}

// ---------------------------------------------------------------------------
// Property definitions
// ---------------------------------------------------------------------------

/// A property that must hold for a boundary surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryProperty {
    /// Unique property identifier.
    pub property_id: String,
    /// Human-readable description.
    pub description: String,
    /// Surface kinds this property applies to.
    pub applicable_surfaces: BTreeSet<SurfaceKind>,
    /// Whether this property requires round-trip verification.
    pub requires_roundtrip: bool,
    /// Regression class if this property is violated.
    pub violation_class: RegressionClass,
}

/// Build the canonical set of boundary properties.
pub fn canonical_boundary_properties() -> Vec<BoundaryProperty> {
    let all_surfaces: BTreeSet<SurfaceKind> = [
        SurfaceKind::IdentifierSchema,
        SurfaceKind::DecisionPayload,
        SurfaceKind::EvidencePayload,
        SurfaceKind::ApiMessage,
        SurfaceKind::PersistenceSemantics,
        SurfaceKind::ReplayFormat,
        SurfaceKind::ExportFormat,
        SurfaceKind::TuiEventContract,
        SurfaceKind::TuiStateContract,
        SurfaceKind::TelemetrySchema,
    ]
    .into_iter()
    .collect();

    let payload_surfaces: BTreeSet<SurfaceKind> = [
        SurfaceKind::DecisionPayload,
        SurfaceKind::EvidencePayload,
        SurfaceKind::ApiMessage,
        SurfaceKind::PersistenceSemantics,
        SurfaceKind::ReplayFormat,
        SurfaceKind::ExportFormat,
    ]
    .into_iter()
    .collect();

    vec![
        BoundaryProperty {
            property_id: "serde-roundtrip".to_string(),
            description: "Serialization round-trip preserves all fields".to_string(),
            applicable_surfaces: all_surfaces.clone(),
            requires_roundtrip: true,
            violation_class: RegressionClass::Breaking,
        },
        BoundaryProperty {
            property_id: "version-negotiation-convergence".to_string(),
            description: "Version negotiation converges within 3 steps".to_string(),
            applicable_surfaces: all_surfaces.clone(),
            requires_roundtrip: false,
            violation_class: RegressionClass::Breaking,
        },
        BoundaryProperty {
            property_id: "field-presence-invariant".to_string(),
            description: "Required fields are always present in valid payloads".to_string(),
            applicable_surfaces: payload_surfaces.clone(),
            requires_roundtrip: false,
            violation_class: RegressionClass::Breaking,
        },
        BoundaryProperty {
            property_id: "ordering-determinism".to_string(),
            description: "Collection fields maintain deterministic ordering across round-trips"
                .to_string(),
            applicable_surfaces: payload_surfaces.clone(),
            requires_roundtrip: true,
            violation_class: RegressionClass::Behavioral,
        },
        BoundaryProperty {
            property_id: "error-envelope-stability".to_string(),
            description: "Error responses maintain stable envelope structure".to_string(),
            applicable_surfaces: [SurfaceKind::ApiMessage].into_iter().collect(),
            requires_roundtrip: false,
            violation_class: RegressionClass::Behavioral,
        },
        BoundaryProperty {
            property_id: "telemetry-field-completeness".to_string(),
            description: "All documented telemetry fields are emitted".to_string(),
            applicable_surfaces: [SurfaceKind::TelemetrySchema].into_iter().collect(),
            requires_roundtrip: false,
            violation_class: RegressionClass::Observability,
        },
        BoundaryProperty {
            property_id: "graceful-degradation".to_string(),
            description: "Boundary handles partial availability without crash".to_string(),
            applicable_surfaces: payload_surfaces,
            requires_roundtrip: false,
            violation_class: RegressionClass::Behavioral,
        },
        BoundaryProperty {
            property_id: "replay-idempotence".to_string(),
            description: "Replaying the same input produces identical output".to_string(),
            applicable_surfaces: all_surfaces,
            requires_roundtrip: true,
            violation_class: RegressionClass::Breaking,
        },
    ]
}

/// Get applicable properties for a given surface kind.
pub fn properties_for_surface(surface_kind: SurfaceKind) -> Vec<BoundaryProperty> {
    canonical_boundary_properties()
        .into_iter()
        .filter(|p| p.applicable_surfaces.contains(&surface_kind))
        .collect()
}

// ---------------------------------------------------------------------------
// Vector generator
// ---------------------------------------------------------------------------

/// Generate conformance vectors from a catalog.
pub fn generate_vectors(
    catalog: &ConformanceCatalog,
    config: &GeneratorConfig,
) -> GenerationResult {
    let mut rng = DetRng::new(config.seed);
    let mut vectors = Vec::new();
    let mut warnings = Vec::new();

    for entry in &catalog.entries {
        if !config.sibling_filter.is_empty()
            && !config.sibling_filter.contains(&entry.boundary.sibling)
        {
            continue;
        }
        if !config.surface_filter.is_empty()
            && !config.surface_filter.contains(&entry.boundary.surface_kind)
        {
            continue;
        }

        // Positive vectors.
        let positives = generate_positive_vectors(entry, config.max_positive_per_entry, &mut rng);
        vectors.extend(positives);

        // Negative vectors.
        let negatives = generate_negative_vectors(entry, config.max_negative_per_entry, &mut rng);
        vectors.extend(negatives);

        // Degraded-mode vectors.
        let degraded = generate_degraded_vectors(entry, config.max_degraded_per_entry, &mut rng);
        vectors.extend(degraded);

        // Fault-mode vectors.
        let faults = generate_fault_vectors(entry, config.max_fault_per_entry, &mut rng);
        vectors.extend(faults);

        if entry.positive_vectors.is_empty() {
            warnings.push(format!(
                "catalog entry `{}` has no baseline positive vectors",
                entry.entry_id
            ));
        }
    }

    // Compute summary counts.
    let mut category_counts = BTreeMap::new();
    let mut boundary_counts = BTreeMap::new();
    for v in &vectors {
        *category_counts
            .entry(v.category.as_str().to_string())
            .or_insert(0) += 1;
        *boundary_counts
            .entry(v.boundary.as_str().to_string())
            .or_insert(0) += 1;
    }

    GenerationResult {
        seed: config.seed,
        catalog_version: catalog.catalog_version,
        vectors,
        category_counts,
        boundary_counts,
        warnings,
    }
}

// ---------------------------------------------------------------------------
// Positive vector generation
// ---------------------------------------------------------------------------

fn generate_positive_vectors(
    entry: &CatalogEntry,
    max_count: usize,
    rng: &mut DetRng,
) -> Vec<GeneratedVector> {
    let mut vectors = Vec::new();

    // Baseline: echo the catalog's own positive vectors.
    for (i, cv) in entry.positive_vectors.iter().enumerate() {
        if vectors.len() >= max_count {
            break;
        }
        vectors.push(GeneratedVector {
            vector_id: format!("{}/gen/positive/{}", entry.entry_id, i),
            description: format!("Baseline positive: {} (from catalog)", cv.description),
            category: VectorCategory::Positive,
            source_entry_id: entry.entry_id.clone(),
            boundary: entry.boundary.sibling,
            surface_kind: entry.boundary.surface_kind,
            input_json: cv.input_json.clone(),
            expected_pass: true,
            expected_regression_class: None,
            degraded_scenario: None,
            fault_scenario: None,
            seed: rng.next_u64(),
            covered_fields: entry.boundary.covered_fields.clone(),
        });
    }

    // Generate additional positive vectors with field permutations.
    while vectors.len() < max_count {
        let seed = rng.next_u64();
        let fields: Vec<String> = entry.boundary.covered_fields.iter().cloned().collect();
        let json = build_valid_json_for_fields(&fields, seed);
        vectors.push(GeneratedVector {
            vector_id: format!("{}/gen/positive/{}", entry.entry_id, vectors.len()),
            description: format!(
                "Generated positive with seed {} for {}",
                seed, entry.boundary.surface_id
            ),
            category: VectorCategory::Positive,
            source_entry_id: entry.entry_id.clone(),
            boundary: entry.boundary.sibling,
            surface_kind: entry.boundary.surface_kind,
            input_json: json,
            expected_pass: true,
            expected_regression_class: None,
            degraded_scenario: None,
            fault_scenario: None,
            seed,
            covered_fields: entry.boundary.covered_fields.clone(),
        });
    }

    vectors
}

// ---------------------------------------------------------------------------
// Negative vector generation
// ---------------------------------------------------------------------------

fn generate_negative_vectors(
    entry: &CatalogEntry,
    max_count: usize,
    rng: &mut DetRng,
) -> Vec<GeneratedVector> {
    let mut vectors = Vec::new();

    // Missing required field.
    if vectors.len() < max_count {
        let fields: Vec<String> = entry.boundary.covered_fields.iter().cloned().collect();
        if !fields.is_empty() {
            let missing = rng.pick(&fields).clone();
            let seed = rng.next_u64();
            vectors.push(GeneratedVector {
                vector_id: format!("{}/gen/negative/{}", entry.entry_id, vectors.len()),
                description: format!("Missing required field `{}`", missing),
                category: VectorCategory::Negative,
                source_entry_id: entry.entry_id.clone(),
                boundary: entry.boundary.sibling,
                surface_kind: entry.boundary.surface_kind,
                input_json: format!("{{\"__missing\":\"{}\"}}", missing),
                expected_pass: false,
                expected_regression_class: Some(entry.failure_class),
                degraded_scenario: None,
                fault_scenario: None,
                seed,
                covered_fields: {
                    let mut s = entry.boundary.covered_fields.clone();
                    s.remove(&missing);
                    s
                },
            });
        }
    }

    // Version mismatch.
    if vectors.len() < max_count {
        let seed = rng.next_u64();
        vectors.push(GeneratedVector {
            vector_id: format!("{}/gen/negative/{}", entry.entry_id, vectors.len()),
            description: "Major version mismatch (incompatible)".to_string(),
            category: VectorCategory::Negative,
            source_entry_id: entry.entry_id.clone(),
            boundary: entry.boundary.sibling,
            surface_kind: entry.boundary.surface_kind,
            input_json: "{\"__version_mismatch\":true,\"version\":\"99.0.0\"}".to_string(),
            expected_pass: false,
            expected_regression_class: Some(RegressionClass::Breaking),
            degraded_scenario: None,
            fault_scenario: None,
            seed,
            covered_fields: BTreeSet::new(),
        });
    }

    // Extra unknown field (should be tolerated or rejected per version class).
    if vectors.len() < max_count {
        let seed = rng.next_u64();
        let expect_pass = entry.boundary.version_class.allows_additive_fields();
        vectors.push(GeneratedVector {
            vector_id: format!("{}/gen/negative/{}", entry.entry_id, vectors.len()),
            description: format!(
                "Unknown extra field (version_class={}, expect_pass={})",
                entry.boundary.version_class, expect_pass
            ),
            category: VectorCategory::Negative,
            source_entry_id: entry.entry_id.clone(),
            boundary: entry.boundary.sibling,
            surface_kind: entry.boundary.surface_kind,
            input_json: "{\"__unknown_field_42\":\"surprise\"}".to_string(),
            expected_pass: expect_pass,
            expected_regression_class: if expect_pass {
                None
            } else {
                Some(RegressionClass::Breaking)
            },
            degraded_scenario: None,
            fault_scenario: None,
            seed,
            covered_fields: BTreeSet::new(),
        });
    }

    vectors
}

// ---------------------------------------------------------------------------
// Degraded-mode vector generation
// ---------------------------------------------------------------------------

fn generate_degraded_vectors(
    entry: &CatalogEntry,
    max_count: usize,
    rng: &mut DetRng,
) -> Vec<GeneratedVector> {
    let mut vectors = Vec::new();

    let scenarios = build_degraded_scenarios(rng);
    for (i, scenario) in scenarios.into_iter().enumerate() {
        if vectors.len() >= max_count {
            break;
        }
        let seed = rng.next_u64();
        vectors.push(GeneratedVector {
            vector_id: format!("{}/gen/degraded/{}", entry.entry_id, i),
            description: format!("Degraded: {} for {}", scenario, entry.boundary.surface_id),
            category: VectorCategory::Degraded,
            source_entry_id: entry.entry_id.clone(),
            boundary: entry.boundary.sibling,
            surface_kind: entry.boundary.surface_kind,
            input_json: build_degraded_json(&scenario, &entry.boundary),
            expected_pass: false,
            expected_regression_class: Some(RegressionClass::Behavioral),
            degraded_scenario: Some(scenario),
            fault_scenario: None,
            seed,
            covered_fields: entry.boundary.covered_fields.clone(),
        });
    }

    vectors
}

fn build_degraded_scenarios(rng: &mut DetRng) -> Vec<DegradedScenario> {
    vec![
        DegradedScenario::StaleRevocationHead {
            epochs_behind: rng.next_range(10) + 1,
        },
        DegradedScenario::PartialAvailability {
            available_fraction_millionths: rng.next_range(500_000) + 100_000, // 10%-60%
        },
        DegradedScenario::Timeout {
            timeout_ms: rng.next_range(5000) + 100,
        },
        DegradedScenario::SchemaDrift {
            local_version: SemanticVersion::new(1, 0, 0),
            remote_version: SemanticVersion::new(1, (rng.next_range(5) + 1) as u32, 0),
        },
        DegradedScenario::EmptyResponse,
    ]
}

fn build_degraded_json(scenario: &DegradedScenario, surface: &BoundarySurface) -> String {
    match scenario {
        DegradedScenario::StaleRevocationHead { epochs_behind } => {
            format!(
                "{{\"__degraded\":\"stale_revocation\",\"boundary\":\"{}\",\"epochs_behind\":{}}}",
                surface.surface_id, epochs_behind
            )
        }
        DegradedScenario::PartialAvailability {
            available_fraction_millionths,
        } => {
            format!(
                "{{\"__degraded\":\"partial_availability\",\"boundary\":\"{}\",\"available_millionths\":{}}}",
                surface.surface_id, available_fraction_millionths
            )
        }
        DegradedScenario::Timeout { timeout_ms } => {
            format!(
                "{{\"__degraded\":\"timeout\",\"boundary\":\"{}\",\"timeout_ms\":{}}}",
                surface.surface_id, timeout_ms
            )
        }
        DegradedScenario::SchemaDrift {
            local_version,
            remote_version,
        } => {
            format!(
                "{{\"__degraded\":\"schema_drift\",\"boundary\":\"{}\",\"local\":\"{}\",\"remote\":\"{}\"}}",
                surface.surface_id, local_version, remote_version
            )
        }
        DegradedScenario::EmptyResponse => {
            format!(
                "{{\"__degraded\":\"empty_response\",\"boundary\":\"{}\"}}",
                surface.surface_id
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Fault-mode vector generation
// ---------------------------------------------------------------------------

fn generate_fault_vectors(
    entry: &CatalogEntry,
    max_count: usize,
    rng: &mut DetRng,
) -> Vec<GeneratedVector> {
    let mut vectors = Vec::new();

    let scenarios = build_fault_scenarios(rng);
    for (i, scenario) in scenarios.into_iter().enumerate() {
        if vectors.len() >= max_count {
            break;
        }
        let seed = rng.next_u64();
        vectors.push(GeneratedVector {
            vector_id: format!("{}/gen/fault/{}", entry.entry_id, i),
            description: format!("Fault: {} for {}", scenario, entry.boundary.surface_id),
            category: VectorCategory::Fault,
            source_entry_id: entry.entry_id.clone(),
            boundary: entry.boundary.sibling,
            surface_kind: entry.boundary.surface_kind,
            input_json: build_fault_json(&scenario, &entry.boundary),
            expected_pass: false,
            expected_regression_class: Some(RegressionClass::Breaking),
            degraded_scenario: None,
            fault_scenario: Some(scenario),
            seed,
            covered_fields: BTreeSet::new(),
        });
    }

    vectors
}

fn build_fault_scenarios(rng: &mut DetRng) -> Vec<FaultScenario> {
    vec![
        FaultScenario::CorruptedPayload {
            corruption_offset: rng.next_range(256) as usize,
        },
        FaultScenario::TruncatedMessage {
            retain_fraction_millionths: rng.next_range(500_000) + 100_000, // 10%-60%
        },
        FaultScenario::OutOfOrderSequence {
            expected_seq: 5,
            actual_seq: rng.next_range(4) + 1,
        },
        FaultScenario::ReplayAttack {
            original_nonce: rng.next_u64(),
        },
        FaultScenario::MalformedJson,
        FaultScenario::EncodingMismatch {
            expected: "application/json".to_string(),
            actual: "application/octet-stream".to_string(),
        },
    ]
}

fn build_fault_json(scenario: &FaultScenario, surface: &BoundarySurface) -> String {
    match scenario {
        FaultScenario::CorruptedPayload { corruption_offset } => {
            format!(
                "{{\"__fault\":\"corrupted\",\"boundary\":\"{}\",\"offset\":{}}}",
                surface.surface_id, corruption_offset
            )
        }
        FaultScenario::TruncatedMessage {
            retain_fraction_millionths,
        } => {
            format!(
                "{{\"__fault\":\"truncated\",\"boundary\":\"{}\",\"retain_millionths\":{}}}",
                surface.surface_id, retain_fraction_millionths
            )
        }
        FaultScenario::OutOfOrderSequence {
            expected_seq,
            actual_seq,
        } => {
            format!(
                "{{\"__fault\":\"out_of_order\",\"boundary\":\"{}\",\"expected\":{},\"actual\":{}}}",
                surface.surface_id, expected_seq, actual_seq
            )
        }
        FaultScenario::ReplayAttack { original_nonce } => {
            format!(
                "{{\"__fault\":\"replay\",\"boundary\":\"{}\",\"nonce\":{}}}",
                surface.surface_id, original_nonce
            )
        }
        FaultScenario::MalformedJson => {
            "{\"__fault\":\"malformed\",\"boundary\":\"".to_string()
                + &surface.surface_id
                + "\",INVALID_JSON"
        }
        FaultScenario::EncodingMismatch { expected, actual } => {
            format!(
                "{{\"__fault\":\"encoding_mismatch\",\"boundary\":\"{}\",\"expected\":\"{}\",\"actual\":\"{}\"}}",
                surface.surface_id, expected, actual
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Validation: verify generated vectors against properties
// ---------------------------------------------------------------------------

/// Result of a property check against a vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyCheckResult {
    /// Property that was checked.
    pub property_id: String,
    /// Vector that was checked.
    pub vector_id: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Detail message.
    pub detail: String,
}

/// Validate that generated vectors cover all boundary properties.
pub fn validate_property_coverage(
    result: &GenerationResult,
    properties: &[BoundaryProperty],
) -> Vec<String> {
    let mut missing = Vec::new();

    // Collect which surface kinds have vectors.
    let covered_surfaces: BTreeSet<SurfaceKind> =
        result.vectors.iter().map(|v| v.surface_kind).collect();

    for prop in properties {
        let applicable_and_covered: Vec<SurfaceKind> = prop
            .applicable_surfaces
            .iter()
            .filter(|s| covered_surfaces.contains(s))
            .copied()
            .collect();

        if applicable_and_covered.is_empty() && !prop.applicable_surfaces.is_empty() {
            missing.push(format!(
                "property `{}` has no vectors for any applicable surface",
                prop.property_id
            ));
        }
    }

    missing
}

// ---------------------------------------------------------------------------
// Helper: build valid JSON from field names
// ---------------------------------------------------------------------------

fn build_valid_json_for_fields(fields: &[String], seed: u64) -> String {
    let mut parts = Vec::new();
    for (i, field) in fields.iter().enumerate() {
        let value = format!("test_value_{}_{}", seed, i);
        parts.push(format!("\"{}\":\"{}\"", field, value));
    }
    format!("{{{}}}", parts.join(","))
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance_catalog::{self, ConformanceVector, VersionClass};

    fn test_catalog() -> ConformanceCatalog {
        conformance_catalog::build_canonical_catalog()
    }

    fn default_config() -> GeneratorConfig {
        GeneratorConfig::default()
    }

    // --- Vector category ---

    #[test]
    fn vector_category_display() {
        assert_eq!(VectorCategory::Positive.to_string(), "positive");
        assert_eq!(VectorCategory::Negative.to_string(), "negative");
        assert_eq!(VectorCategory::Degraded.to_string(), "degraded");
        assert_eq!(VectorCategory::Fault.to_string(), "fault");
    }

    #[test]
    fn vector_category_ordering() {
        assert!(VectorCategory::Positive < VectorCategory::Negative);
        assert!(VectorCategory::Negative < VectorCategory::Degraded);
        assert!(VectorCategory::Degraded < VectorCategory::Fault);
    }

    #[test]
    fn vector_category_serde_roundtrip() {
        for cat in [
            VectorCategory::Positive,
            VectorCategory::Negative,
            VectorCategory::Degraded,
            VectorCategory::Fault,
        ] {
            let json = serde_json::to_string(&cat).expect("serde deserialization should succeed");
            let decoded: VectorCategory =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(cat, decoded);
        }
    }

    // --- Degraded scenario ---

    #[test]
    fn degraded_scenario_display() {
        let s = DegradedScenario::StaleRevocationHead { epochs_behind: 5 };
        assert!(s.to_string().contains("5"));
        let s = DegradedScenario::EmptyResponse;
        assert_eq!(s.to_string(), "empty-response");
    }

    #[test]
    fn degraded_scenario_serde_roundtrip() {
        let scenarios = vec![
            DegradedScenario::StaleRevocationHead { epochs_behind: 3 },
            DegradedScenario::PartialAvailability {
                available_fraction_millionths: 300_000,
            },
            DegradedScenario::Timeout { timeout_ms: 5000 },
            DegradedScenario::SchemaDrift {
                local_version: SemanticVersion::new(1, 0, 0),
                remote_version: SemanticVersion::new(1, 2, 0),
            },
            DegradedScenario::EmptyResponse,
        ];
        for s in &scenarios {
            let json = serde_json::to_string(s).expect("serde deserialization should succeed");
            let decoded: DegradedScenario =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*s, decoded);
        }
    }

    // --- Fault scenario ---

    #[test]
    fn fault_scenario_display() {
        let s = FaultScenario::MalformedJson;
        assert_eq!(s.to_string(), "malformed-json");
        let s = FaultScenario::ReplayAttack { original_nonce: 42 };
        assert!(s.to_string().contains("42"));
    }

    #[test]
    fn fault_scenario_serde_roundtrip() {
        let scenarios = vec![
            FaultScenario::CorruptedPayload {
                corruption_offset: 10,
            },
            FaultScenario::TruncatedMessage {
                retain_fraction_millionths: 250_000,
            },
            FaultScenario::OutOfOrderSequence {
                expected_seq: 5,
                actual_seq: 3,
            },
            FaultScenario::ReplayAttack { original_nonce: 99 },
            FaultScenario::MalformedJson,
            FaultScenario::EncodingMismatch {
                expected: "json".to_string(),
                actual: "binary".to_string(),
            },
        ];
        for s in &scenarios {
            let json = serde_json::to_string(s).expect("serde deserialization should succeed");
            let decoded: FaultScenario =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*s, decoded);
        }
    }

    // --- DetRng determinism ---

    #[test]
    fn det_rng_deterministic() {
        let mut rng1 = DetRng::new(42);
        let mut rng2 = DetRng::new(42);
        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn det_rng_different_seeds_different_output() {
        let mut rng1 = DetRng::new(42);
        let mut rng2 = DetRng::new(43);
        let mut same_count = 0;
        for _ in 0..100 {
            if rng1.next_u64() == rng2.next_u64() {
                same_count += 1;
            }
        }
        assert!(same_count < 5, "too many collisions: {}", same_count);
    }

    #[test]
    fn det_rng_zero_seed_is_handled() {
        let mut rng = DetRng::new(0);
        let v = rng.next_u64();
        assert_ne!(v, 0);
    }

    #[test]
    fn det_rng_range() {
        let mut rng = DetRng::new(123);
        for _ in 0..100 {
            let val = rng.next_range(10);
            assert!(val < 10);
        }
    }

    // --- Boundary properties ---

    #[test]
    fn canonical_properties_exist() {
        let props = canonical_boundary_properties();
        assert!(props.len() >= 5);
    }

    #[test]
    fn canonical_properties_have_unique_ids() {
        let props = canonical_boundary_properties();
        let mut seen = BTreeSet::new();
        for p in &props {
            assert!(seen.insert(&p.property_id), "duplicate: {}", p.property_id);
        }
    }

    #[test]
    fn properties_for_surface_filters_correctly() {
        let api_props = properties_for_surface(SurfaceKind::ApiMessage);
        assert!(!api_props.is_empty());
        for p in &api_props {
            assert!(p.applicable_surfaces.contains(&SurfaceKind::ApiMessage));
        }
    }

    #[test]
    fn all_surfaces_have_at_least_serde_roundtrip_property() {
        let props = canonical_boundary_properties();
        let serde_prop = props
            .iter()
            .find(|p| p.property_id == "serde-roundtrip")
            .expect("serde deserialization should succeed");
        // serde-roundtrip applies to all surface kinds.
        assert!(serde_prop.applicable_surfaces.len() >= 10);
    }

    // --- Vector generation ---

    #[test]
    fn generate_vectors_produces_all_categories() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());

        assert!(result.count_by_category(VectorCategory::Positive) > 0);
        assert!(result.count_by_category(VectorCategory::Negative) > 0);
        assert!(result.count_by_category(VectorCategory::Degraded) > 0);
        assert!(result.count_by_category(VectorCategory::Fault) > 0);
    }

    #[test]
    fn generate_vectors_covers_all_primary_boundaries() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());

        for repo in SiblingRepo::all() {
            if repo.is_primary() {
                assert!(
                    result.count_by_boundary(*repo) > 0,
                    "no vectors for primary boundary {}",
                    repo
                );
            }
        }
    }

    #[test]
    fn generate_vectors_deterministic() {
        let catalog = test_catalog();
        let config = default_config();
        let r1 = generate_vectors(&catalog, &config);
        let r2 = generate_vectors(&catalog, &config);
        assert_eq!(r1.vectors.len(), r2.vectors.len());
        for (a, b) in r1.vectors.iter().zip(r2.vectors.iter()) {
            assert_eq!(a.vector_id, b.vector_id);
            assert_eq!(a.input_json, b.input_json);
        }
    }

    #[test]
    fn generate_vectors_different_seeds_different_output() {
        let catalog = test_catalog();
        let mut c1 = default_config();
        c1.seed = 42;
        let mut c2 = default_config();
        c2.seed = 99;
        let r1 = generate_vectors(&catalog, &c1);
        let r2 = generate_vectors(&catalog, &c2);

        // Same number of vectors (structure is same).
        assert_eq!(r1.vectors.len(), r2.vectors.len());

        // But degraded/fault seeds differ.
        let mut diff_count = 0;
        for (a, b) in r1.vectors.iter().zip(r2.vectors.iter()) {
            if a.seed != b.seed {
                diff_count += 1;
            }
        }
        assert!(
            diff_count > 0,
            "different seeds should produce different vector seeds"
        );
    }

    #[test]
    fn generate_vectors_unique_ids() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());
        let ids = result.vector_ids();
        assert_eq!(
            ids.len(),
            result.vectors.len(),
            "duplicate vector IDs found"
        );
    }

    #[test]
    fn generate_vectors_sibling_filter() {
        let catalog = test_catalog();
        let mut config = default_config();
        config.sibling_filter.insert(SiblingRepo::Frankentui);

        let result = generate_vectors(&catalog, &config);
        for v in &result.vectors {
            assert_eq!(v.boundary, SiblingRepo::Frankentui);
        }
        assert!(!result.vectors.is_empty());
    }

    #[test]
    fn generate_vectors_surface_filter() {
        let catalog = test_catalog();
        let mut config = default_config();
        config
            .surface_filter
            .insert(SurfaceKind::PersistenceSemantics);

        let result = generate_vectors(&catalog, &config);
        for v in &result.vectors {
            assert_eq!(v.surface_kind, SurfaceKind::PersistenceSemantics);
        }
        assert!(!result.vectors.is_empty());
    }

    #[test]
    fn generate_vectors_category_counts_match() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());

        let pos_count = result.count_by_category(VectorCategory::Positive);
        let neg_count = result.count_by_category(VectorCategory::Negative);
        let deg_count = result.count_by_category(VectorCategory::Degraded);
        let flt_count = result.count_by_category(VectorCategory::Fault);

        assert_eq!(
            pos_count + neg_count + deg_count + flt_count,
            result.vectors.len()
        );

        assert_eq!(
            *result.category_counts.get("positive").unwrap_or(&0),
            pos_count
        );
    }

    #[test]
    fn generate_vectors_boundary_counts_match() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());

        let total: usize = result.boundary_counts.values().sum();
        assert_eq!(total, result.vectors.len());
    }

    // --- Positive vectors ---

    #[test]
    fn positive_vectors_expected_pass() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());

        for v in &result.vectors {
            if v.category == VectorCategory::Positive {
                assert!(
                    v.expected_pass,
                    "positive vector should expect pass: {}",
                    v.vector_id
                );
                assert!(
                    v.expected_regression_class.is_none(),
                    "positive vector should have no regression class"
                );
            }
        }
    }

    // --- Negative vectors ---

    #[test]
    fn negative_vectors_expected_fail_mostly() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());

        let negative_fail_count = result
            .vectors
            .iter()
            .filter(|v| v.category == VectorCategory::Negative && !v.expected_pass)
            .count();

        let negative_total = result.count_by_category(VectorCategory::Negative);
        // Most negative vectors should expect failure (some unknown-field tests may pass).
        assert!(
            negative_fail_count > negative_total / 2,
            "most negative vectors should expect failure"
        );
    }

    // --- Degraded vectors ---

    #[test]
    fn degraded_vectors_have_scenario() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());

        for v in &result.vectors {
            if v.category == VectorCategory::Degraded {
                assert!(
                    v.degraded_scenario.is_some(),
                    "degraded vector must have scenario: {}",
                    v.vector_id
                );
            }
        }
    }

    // --- Fault vectors ---

    #[test]
    fn fault_vectors_have_scenario() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());

        for v in &result.vectors {
            if v.category == VectorCategory::Fault {
                assert!(
                    v.fault_scenario.is_some(),
                    "fault vector must have scenario: {}",
                    v.vector_id
                );
            }
        }
    }

    #[test]
    fn fault_vectors_expect_failure() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());

        for v in &result.vectors {
            if v.category == VectorCategory::Fault {
                assert!(
                    !v.expected_pass,
                    "fault vector should expect failure: {}",
                    v.vector_id
                );
            }
        }
    }

    // --- Property coverage ---

    #[test]
    fn property_coverage_no_gaps_for_canonical_catalog() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());
        let props = canonical_boundary_properties();

        let gaps = validate_property_coverage(&result, &props);
        assert!(gaps.is_empty(), "property coverage gaps: {:?}", gaps);
    }

    // --- GenerationResult ---

    #[test]
    fn generation_result_serde_roundtrip() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());

        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let decoded: GenerationResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result.vectors.len(), decoded.vectors.len());
        assert_eq!(result.seed, decoded.seed);
        assert_eq!(result.catalog_version, decoded.catalog_version);
    }

    // --- GeneratedVector ---

    #[test]
    fn generated_vector_serde_roundtrip() {
        let v = GeneratedVector {
            vector_id: "test/gen/positive/0".to_string(),
            description: "test vector".to_string(),
            category: VectorCategory::Positive,
            source_entry_id: "test/entry".to_string(),
            boundary: SiblingRepo::Frankentui,
            surface_kind: SurfaceKind::TuiEventContract,
            input_json: "{}".to_string(),
            expected_pass: true,
            expected_regression_class: None,
            degraded_scenario: None,
            fault_scenario: None,
            seed: 42,
            covered_fields: ["field_a"].iter().map(|s| s.to_string()).collect(),
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let decoded: GeneratedVector =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(v, decoded);
    }

    // --- GeneratorConfig ---

    #[test]
    fn generator_config_default() {
        let config = GeneratorConfig::default();
        assert_eq!(config.seed, 42);
        assert_eq!(config.max_positive_per_entry, 3);
        assert_eq!(config.max_negative_per_entry, 3);
        assert_eq!(config.max_degraded_per_entry, 5);
        assert_eq!(config.max_fault_per_entry, 6);
        assert!(config.sibling_filter.is_empty());
        assert!(config.surface_filter.is_empty());
    }

    #[test]
    fn generator_config_serde_roundtrip() {
        let config = default_config();
        let json = serde_json::to_string(&config).expect("serde deserialization should succeed");
        let decoded: GeneratorConfig =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(config, decoded);
    }

    // --- Build helpers ---

    #[test]
    fn build_valid_json_for_fields_produces_valid_json() {
        let fields = vec!["alpha".to_string(), "beta".to_string()];
        let json = build_valid_json_for_fields(&fields, 42);
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert!(parsed.is_object());
        assert!(parsed.get("alpha").is_some());
        assert!(parsed.get("beta").is_some());
    }

    #[test]
    fn build_valid_json_empty_fields() {
        let json = build_valid_json_for_fields(&[], 42);
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert!(parsed.is_object());
    }

    // --- BoundaryProperty ---

    #[test]
    fn boundary_property_serde_roundtrip() {
        let props = canonical_boundary_properties();
        for p in &props {
            let json = serde_json::to_string(p).expect("serde deserialization should succeed");
            let decoded: BoundaryProperty =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*p, decoded);
        }
    }

    // --- PropertyCheckResult ---

    #[test]
    fn property_check_result_serde_roundtrip() {
        let r = PropertyCheckResult {
            property_id: "serde-roundtrip".to_string(),
            vector_id: "test/gen/positive/0".to_string(),
            passed: true,
            detail: "all fields preserved".to_string(),
        };
        let json = serde_json::to_string(&r).expect("serde deserialization should succeed");
        let decoded: PropertyCheckResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(r, decoded);
    }

    // --- Integration: full pipeline ---

    #[test]
    fn full_pipeline_catalog_to_vectors_to_validation() {
        let catalog = test_catalog();
        let config = default_config();
        let result = generate_vectors(&catalog, &config);
        let props = canonical_boundary_properties();

        // All vectors generated.
        assert!(!result.vectors.is_empty());

        // All categories present.
        assert!(result.count_by_category(VectorCategory::Positive) > 0);
        assert!(result.count_by_category(VectorCategory::Negative) > 0);
        assert!(result.count_by_category(VectorCategory::Degraded) > 0);
        assert!(result.count_by_category(VectorCategory::Fault) > 0);

        // Property coverage.
        let gaps = validate_property_coverage(&result, &props);
        assert!(gaps.is_empty());

        // Serde roundtrip of full result.
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let decoded: GenerationResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result.vectors.len(), decoded.vectors.len());

        // Unique IDs.
        let ids = result.vector_ids();
        assert_eq!(ids.len(), result.vectors.len());
    }

    #[test]
    fn full_pipeline_with_restricted_config() {
        let catalog = test_catalog();
        let mut config = default_config();
        config.max_positive_per_entry = 1;
        config.max_negative_per_entry = 1;
        config.max_degraded_per_entry = 2;
        config.max_fault_per_entry = 2;
        config.sibling_filter.insert(SiblingRepo::Asupersync);

        let result = generate_vectors(&catalog, &config);

        // All vectors should be for asupersync.
        for v in &result.vectors {
            assert_eq!(v.boundary, SiblingRepo::Asupersync);
        }

        // Smaller vector set.
        let asupersync_entries = catalog.entries_for_boundary(SiblingRepo::Asupersync);
        let expected_max = asupersync_entries.len() * (1 + 1 + 2 + 2);
        assert!(
            result.vectors.len() <= expected_max,
            "too many vectors: {} > {}",
            result.vectors.len(),
            expected_max
        );
    }

    // --- Display impls ---

    #[test]
    fn degraded_scenario_all_display_non_empty() {
        let scenarios = vec![
            DegradedScenario::StaleRevocationHead { epochs_behind: 1 },
            DegradedScenario::PartialAvailability {
                available_fraction_millionths: 500_000,
            },
            DegradedScenario::Timeout { timeout_ms: 100 },
            DegradedScenario::SchemaDrift {
                local_version: SemanticVersion::new(1, 0, 0),
                remote_version: SemanticVersion::new(1, 1, 0),
            },
            DegradedScenario::EmptyResponse,
        ];
        for s in &scenarios {
            assert!(!s.to_string().is_empty(), "empty display for {:?}", s);
        }
    }

    #[test]
    fn fault_scenario_all_display_non_empty() {
        let scenarios = vec![
            FaultScenario::CorruptedPayload {
                corruption_offset: 0,
            },
            FaultScenario::TruncatedMessage {
                retain_fraction_millionths: 100_000,
            },
            FaultScenario::OutOfOrderSequence {
                expected_seq: 1,
                actual_seq: 0,
            },
            FaultScenario::ReplayAttack { original_nonce: 1 },
            FaultScenario::MalformedJson,
            FaultScenario::EncodingMismatch {
                expected: "a".to_string(),
                actual: "b".to_string(),
            },
        ];
        for s in &scenarios {
            assert!(!s.to_string().is_empty(), "empty display for {:?}", s);
        }
    }

    // --- Warnings ---

    #[test]
    fn generate_vectors_warns_on_missing_baseline_vectors() {
        let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
        // Add an entry with no positive vectors.
        catalog.entries.push(CatalogEntry {
            entry_id: "test/no_positive".to_string(),
            boundary: BoundarySurface {
                sibling: SiblingRepo::Frankentui,
                surface_id: "test/no_positive".to_string(),
                surface_kind: SurfaceKind::TuiEventContract,
                description: "test".to_string(),
                covered_fields: ["f1"].iter().map(|s| s.to_string()).collect(),
                version_class: VersionClass::Minor,
            },
            positive_vectors: vec![],
            negative_vectors: vec![ConformanceVector {
                vector_id: "n1".to_string(),
                description: "neg".to_string(),
                input_json: "{}".to_string(),
                expected_pass: false,
                expected_regression_class: Some(RegressionClass::Behavioral),
            }],
            replay_obligation: conformance_catalog::ReplayObligation::standard(
                "test/no_positive",
                SiblingRepo::Frankentui,
            ),
            failure_class: RegressionClass::Behavioral,
            approved: false,
            approval_epoch: None,
        });

        let result = generate_vectors(&catalog, &default_config());
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("no baseline positive vectors")),
            "expected warning about missing positive vectors"
        );
    }

    // --- Enrichment tests ---

    #[test]
    fn vector_category_display_uniqueness_btreeset() {
        let cats = [
            VectorCategory::Positive,
            VectorCategory::Negative,
            VectorCategory::Degraded,
            VectorCategory::Fault,
        ];
        let displays: BTreeSet<String> = cats.iter().map(|c| c.to_string()).collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn degraded_scenario_display_uniqueness() {
        let scenarios = [
            DegradedScenario::StaleRevocationHead { epochs_behind: 1 },
            DegradedScenario::PartialAvailability {
                available_fraction_millionths: 500_000,
            },
            DegradedScenario::Timeout { timeout_ms: 100 },
            DegradedScenario::SchemaDrift {
                local_version: SemanticVersion::new(1, 0, 0),
                remote_version: SemanticVersion::new(2, 0, 0),
            },
            DegradedScenario::EmptyResponse,
        ];
        let displays: BTreeSet<String> = scenarios.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            displays.len(),
            5,
            "all 5 degraded scenarios should have unique Display"
        );
    }

    #[test]
    fn fault_scenario_display_uniqueness() {
        let scenarios = [
            FaultScenario::CorruptedPayload {
                corruption_offset: 0,
            },
            FaultScenario::TruncatedMessage {
                retain_fraction_millionths: 500_000,
            },
            FaultScenario::OutOfOrderSequence {
                expected_seq: 1,
                actual_seq: 0,
            },
            FaultScenario::ReplayAttack { original_nonce: 42 },
            FaultScenario::MalformedJson,
            FaultScenario::EncodingMismatch {
                expected: "json".into(),
                actual: "binary".into(),
            },
        ];
        let displays: BTreeSet<String> = scenarios.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            displays.len(),
            6,
            "all 6 fault scenarios should have unique Display"
        );
    }

    #[test]
    fn det_rng_next_range_single_value() {
        let mut rng = DetRng::new(7);
        for _ in 0..50 {
            assert_eq!(rng.next_range(1), 0);
        }
    }

    #[test]
    fn build_valid_json_for_fields_field_values_deterministic() {
        let fields = vec!["alpha".to_string(), "beta".to_string()];
        let json1 = build_valid_json_for_fields(&fields, 42);
        let json2 = build_valid_json_for_fields(&fields, 42);
        assert_eq!(json1, json2);
    }

    #[test]
    fn build_valid_json_for_fields_different_seeds_may_differ() {
        let fields = vec!["x".to_string(), "y".to_string(), "z".to_string()];
        let json1 = build_valid_json_for_fields(&fields, 100);
        let json2 = build_valid_json_for_fields(&fields, 200);
        // Structure is the same but values may differ (or not) depending on impl.
        // Both should parse as valid JSON.
        let _: serde_json::Value =
            serde_json::from_str(&json1).expect("serde deserialization should succeed");
        let _: serde_json::Value =
            serde_json::from_str(&json2).expect("serde deserialization should succeed");
    }

    #[test]
    fn generator_config_with_both_filters_active() {
        let catalog = test_catalog();
        let mut config = default_config();
        config.sibling_filter.insert(SiblingRepo::Frankentui);
        config.surface_filter.insert(SurfaceKind::TuiEventContract);

        let result = generate_vectors(&catalog, &config);
        for v in &result.vectors {
            assert_eq!(v.boundary, SiblingRepo::Frankentui);
            assert_eq!(v.surface_kind, SurfaceKind::TuiEventContract);
        }
    }

    #[test]
    fn positive_vectors_have_no_fault_or_degraded_scenario() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());
        for v in &result.vectors {
            if v.category == VectorCategory::Positive {
                assert!(v.degraded_scenario.is_none());
                assert!(v.fault_scenario.is_none());
            }
        }
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn generator_config_serde_stable_roundtrip() {
        let config = default_config();
        let json = serde_json::to_string(&config).expect("serde deserialization should succeed");
        let back: GeneratorConfig =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(config, back);
    }

    #[test]
    fn generation_result_full_serde_roundtrip() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let back: GenerationResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, back);
    }

    #[test]
    fn vector_category_as_str_all_distinct() {
        let variants = [
            VectorCategory::Positive,
            VectorCategory::Negative,
            VectorCategory::Degraded,
            VectorCategory::Fault,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.as_str());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn degraded_scenario_display_all_distinct() {
        let variants = vec![
            DegradedScenario::StaleRevocationHead { epochs_behind: 3 },
            DegradedScenario::PartialAvailability {
                available_fraction_millionths: 500_000,
            },
            DegradedScenario::Timeout { timeout_ms: 5000 },
            DegradedScenario::SchemaDrift {
                local_version: SemanticVersion::new(1, 0, 0),
                remote_version: SemanticVersion::new(1, 1, 0),
            },
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn fault_scenario_display_all_distinct() {
        let variants = vec![
            FaultScenario::CorruptedPayload {
                corruption_offset: 10,
            },
            FaultScenario::TruncatedMessage {
                retain_fraction_millionths: 500_000,
            },
            FaultScenario::OutOfOrderSequence {
                expected_seq: 1,
                actual_seq: 3,
            },
            FaultScenario::ReplayAttack { original_nonce: 42 },
            FaultScenario::MalformedJson,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn generated_vector_first_entry_serde_roundtrip() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());
        assert!(!result.vectors.is_empty());
        let v = &result.vectors[0];
        let json = serde_json::to_string(v).expect("serde deserialization should succeed");
        let back: GeneratedVector =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(*v, back);
    }

    #[test]
    fn generation_result_count_by_boundary_matches_map() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());
        for (key, &count) in &result.boundary_counts {
            let manual_count = result
                .vectors
                .iter()
                .filter(|v| v.boundary.as_str() == key)
                .count();
            assert_eq!(manual_count, count);
        }
    }

    #[test]
    fn generation_result_vector_ids_all_unique() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());
        let ids = result.vector_ids();
        let unique: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn enrichment_vector_category_copy_semantics() {
        let a = VectorCategory::Degraded;
        let b = a; // Copy
        let c = a; // still valid after copy
        assert_eq!(b, c);
        assert_eq!(a, VectorCategory::Degraded);
    }

    #[test]
    fn enrichment_vector_category_clone_eq_all_variants() {
        let variants = [
            VectorCategory::Positive,
            VectorCategory::Negative,
            VectorCategory::Degraded,
            VectorCategory::Fault,
        ];
        for v in &variants {
            let cloned = *v;
            assert_eq!(*v, cloned);
        }
    }

    #[test]
    fn enrichment_vector_category_json_quoted_strings() {
        // Verify serde serialises as quoted strings (not integers).
        let json = serde_json::to_string(&VectorCategory::Positive)
            .expect("serde deserialization should succeed");
        assert!(
            json.starts_with('"'),
            "expected quoted string, got: {}",
            json
        );
        let json = serde_json::to_string(&VectorCategory::Fault)
            .expect("serde deserialization should succeed");
        assert!(json.starts_with('"'));
    }

    #[test]
    fn enrichment_degraded_scenario_clone_preserves_inner() {
        let orig = DegradedScenario::SchemaDrift {
            local_version: SemanticVersion::new(2, 3, 4),
            remote_version: SemanticVersion::new(2, 5, 0),
        };
        let cloned = orig.clone();
        assert_eq!(orig, cloned);
        // Verify inner fields survived.
        if let DegradedScenario::SchemaDrift {
            local_version,
            remote_version,
        } = &cloned
        {
            assert_eq!(local_version.major, 2);
            assert_eq!(remote_version.minor, 5);
        } else {
            panic!("wrong variant after clone");
        }
    }

    #[test]
    fn enrichment_degraded_scenario_ord_consistent() {
        let a = DegradedScenario::EmptyResponse;
        let b = DegradedScenario::Timeout { timeout_ms: 100 };
        // Ord is derived, so ordering follows variant declaration order.
        // EmptyResponse is last in the enum, Timeout is third.
        assert!(
            b < a,
            "Timeout should sort before EmptyResponse by derive Ord"
        );
    }

    #[test]
    fn enrichment_degraded_scenario_json_field_stale_revocation() {
        let s = DegradedScenario::StaleRevocationHead { epochs_behind: 42 };
        let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
        let val: serde_json::Value =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        // Tagged enum: check the variant key exists.
        assert!(
            val.get("StaleRevocationHead").is_some(),
            "expected StaleRevocationHead key in: {}",
            json
        );
    }

    #[test]
    fn enrichment_fault_scenario_clone_encoding_mismatch() {
        let orig = FaultScenario::EncodingMismatch {
            expected: "utf-8".to_string(),
            actual: "latin-1".to_string(),
        };
        let cloned = orig.clone();
        assert_eq!(orig, cloned);
        if let FaultScenario::EncodingMismatch { expected, actual } = &cloned {
            assert_eq!(expected, "utf-8");
            assert_eq!(actual, "latin-1");
        } else {
            panic!("wrong variant after clone");
        }
    }

    #[test]
    fn enrichment_fault_scenario_ord_consistent() {
        let a = FaultScenario::MalformedJson;
        let b = FaultScenario::CorruptedPayload {
            corruption_offset: 0,
        };
        // CorruptedPayload declared first, MalformedJson later.
        assert!(b < a, "CorruptedPayload should sort before MalformedJson");
    }

    #[test]
    fn enrichment_fault_scenario_json_field_replay() {
        let s = FaultScenario::ReplayAttack {
            original_nonce: 9999,
        };
        let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
        let val: serde_json::Value =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert!(
            val.get("ReplayAttack").is_some(),
            "expected ReplayAttack key in: {}",
            json
        );
        let inner = val
            .get("ReplayAttack")
            .expect("serde deserialization should succeed");
        assert_eq!(
            inner
                .get("original_nonce")
                .expect("serde deserialization should succeed")
                .as_u64()
                .expect("serde deserialization should succeed"),
            9999
        );
    }

    #[test]
    fn enrichment_generated_vector_clone_deep() {
        let v = GeneratedVector {
            vector_id: "clone-test/0".to_string(),
            description: "clone deep test".to_string(),
            category: VectorCategory::Negative,
            source_entry_id: "src/entry".to_string(),
            boundary: SiblingRepo::Frankensqlite,
            surface_kind: SurfaceKind::PersistenceSemantics,
            input_json: "{\"k\":1}".to_string(),
            expected_pass: false,
            expected_regression_class: Some(RegressionClass::Breaking),
            degraded_scenario: None,
            fault_scenario: Some(FaultScenario::MalformedJson),
            seed: 777,
            covered_fields: ["a", "b"].iter().map(|s| s.to_string()).collect(),
        };
        let cloned = v.clone();
        assert_eq!(v, cloned);
        assert_eq!(cloned.covered_fields.len(), 2);
        assert!(cloned.fault_scenario.is_some());
    }

    #[test]
    fn enrichment_generated_vector_json_field_presence() {
        let v = GeneratedVector {
            vector_id: "field-check/0".to_string(),
            description: "field presence test".to_string(),
            category: VectorCategory::Degraded,
            source_entry_id: "src/e2".to_string(),
            boundary: SiblingRepo::Asupersync,
            surface_kind: SurfaceKind::ApiMessage,
            input_json: "{}".to_string(),
            expected_pass: false,
            expected_regression_class: Some(RegressionClass::Behavioral),
            degraded_scenario: Some(DegradedScenario::EmptyResponse),
            fault_scenario: None,
            seed: 0,
            covered_fields: BTreeSet::new(),
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let val: serde_json::Value =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert!(val.get("vector_id").is_some());
        assert!(val.get("category").is_some());
        assert!(val.get("seed").is_some());
        assert!(val.get("expected_pass").is_some());
        assert!(val.get("degraded_scenario").is_some());
        assert!(
            !val["expected_pass"]
                .as_bool()
                .expect("serde deserialization should succeed")
        );
    }

    #[test]
    fn enrichment_generator_config_clone_eq() {
        let a = GeneratorConfig {
            seed: 99,
            max_positive_per_entry: 10,
            max_negative_per_entry: 5,
            max_degraded_per_entry: 2,
            max_fault_per_entry: 1,
            sibling_filter: [SiblingRepo::Asupersync].into_iter().collect(),
            surface_filter: BTreeSet::new(),
        };
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(b.seed, 99);
        assert_eq!(b.sibling_filter.len(), 1);
    }

    #[test]
    fn enrichment_generator_config_json_fields() {
        let config = default_config();
        let json = serde_json::to_string(&config).expect("serde deserialization should succeed");
        let val: serde_json::Value =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(
            val["seed"]
                .as_u64()
                .expect("serde deserialization should succeed"),
            42
        );
        assert_eq!(
            val["max_positive_per_entry"]
                .as_u64()
                .expect("serde deserialization should succeed"),
            3
        );
        assert!(val["sibling_filter"].is_array());
        assert!(val["surface_filter"].is_array());
    }

    #[test]
    fn enrichment_generation_result_empty_catalog() {
        let catalog = ConformanceCatalog::new(SemanticVersion::new(0, 1, 0));
        let result = generate_vectors(&catalog, &default_config());
        assert!(result.vectors.is_empty());
        assert!(result.category_counts.is_empty());
        assert!(result.boundary_counts.is_empty());
        assert!(result.warnings.is_empty());
        assert_eq!(result.count_by_category(VectorCategory::Positive), 0);
        assert_eq!(result.count_by_category(VectorCategory::Fault), 0);
        assert!(result.vector_ids().is_empty());
    }

    #[test]
    fn enrichment_generation_result_count_by_boundary_nonexistent() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());
        // SqlmodelRust may or may not have entries; check a boundary that
        // we explicitly did not filter for — the method should return 0 or a
        // valid count without panicking.
        let count = result.count_by_boundary(SiblingRepo::SqlmodelRust);
        assert!(count <= result.vectors.len());
    }

    #[test]
    fn enrichment_boundary_property_clone_eq() {
        let props = canonical_boundary_properties();
        for p in &props {
            let cloned = p.clone();
            assert_eq!(*p, cloned);
        }
    }

    #[test]
    fn enrichment_boundary_property_json_fields() {
        let props = canonical_boundary_properties();
        let p = &props[0]; // "serde-roundtrip"
        let json = serde_json::to_string(p).expect("serde deserialization should succeed");
        let val: serde_json::Value =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert!(val.get("property_id").is_some());
        assert!(val.get("description").is_some());
        assert!(val.get("requires_roundtrip").is_some());
        assert!(val.get("violation_class").is_some());
        assert!(val.get("applicable_surfaces").is_some());
    }

    #[test]
    fn enrichment_property_check_result_clone_failed() {
        let r = PropertyCheckResult {
            property_id: "field-presence-invariant".to_string(),
            vector_id: "test/gen/negative/0".to_string(),
            passed: false,
            detail: "missing required field `foo`".to_string(),
        };
        let cloned = r.clone();
        assert_eq!(r, cloned);
        assert!(!cloned.passed);
        assert!(cloned.detail.contains("foo"));
    }

    #[test]
    fn enrichment_property_check_result_json_fields() {
        let r = PropertyCheckResult {
            property_id: "ordering-determinism".to_string(),
            vector_id: "test/gen/positive/1".to_string(),
            passed: true,
            detail: "ok".to_string(),
        };
        let json = serde_json::to_string(&r).expect("serde deserialization should succeed");
        let val: serde_json::Value =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(
            val["property_id"]
                .as_str()
                .expect("serde deserialization should succeed"),
            "ordering-determinism"
        );
        assert!(
            val["passed"]
                .as_bool()
                .expect("serde deserialization should succeed")
        );
        assert_eq!(
            val["detail"]
                .as_str()
                .expect("serde deserialization should succeed"),
            "ok"
        );
    }

    #[test]
    fn enrichment_validate_property_coverage_empty_properties() {
        let catalog = test_catalog();
        let result = generate_vectors(&catalog, &default_config());
        let gaps = validate_property_coverage(&result, &[]);
        assert!(gaps.is_empty(), "empty properties should produce no gaps");
    }

    #[test]
    fn enrichment_validate_property_coverage_empty_result() {
        let empty_result = GenerationResult {
            seed: 0,
            catalog_version: SemanticVersion::new(1, 0, 0),
            vectors: vec![],
            category_counts: BTreeMap::new(),
            boundary_counts: BTreeMap::new(),
            warnings: vec![],
        };
        let props = canonical_boundary_properties();
        let gaps = validate_property_coverage(&empty_result, &props);
        // All properties should report gaps since there are no vectors.
        assert!(
            !gaps.is_empty(),
            "empty result should have gaps against canonical properties"
        );
    }

    #[test]
    fn enrichment_det_rng_next_range_zero_returns_zero() {
        let mut rng = DetRng::new(42);
        assert_eq!(rng.next_range(0), 0);
        assert_eq!(rng.next_range(0), 0);
    }

    #[test]
    fn enrichment_det_rng_large_seed() {
        let mut rng = DetRng::new(u64::MAX);
        // Should not panic and should produce nonzero values.
        let v1 = rng.next_u64();
        let v2 = rng.next_u64();
        assert_ne!(v1, v2, "large seed should still produce distinct values");
    }

    #[test]
    fn enrichment_generate_vectors_zero_max_per_entry() {
        let catalog = test_catalog();
        let mut config = default_config();
        config.max_positive_per_entry = 0;
        config.max_negative_per_entry = 0;
        config.max_degraded_per_entry = 0;
        config.max_fault_per_entry = 0;

        let result = generate_vectors(&catalog, &config);
        assert!(
            result.vectors.is_empty(),
            "zero max should produce no vectors"
        );
    }

    #[test]
    fn enrichment_properties_for_telemetry_surface() {
        let props = properties_for_surface(SurfaceKind::TelemetrySchema);
        // Should include "telemetry-field-completeness" plus universals.
        let ids: BTreeSet<String> = props.iter().map(|p| p.property_id.clone()).collect();
        assert!(
            ids.contains("telemetry-field-completeness"),
            "TelemetrySchema should have telemetry-field-completeness property"
        );
        assert!(
            ids.contains("serde-roundtrip"),
            "TelemetrySchema should have serde-roundtrip property"
        );
    }
}
