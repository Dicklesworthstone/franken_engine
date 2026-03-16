//! Cross-Version Semantic Transport Ledger — FRX-14.4
//!
//! Tracks which semantic contracts can be transported unchanged across
//! React version boundaries and ecosystem variants, and where adapters
//! or fallback strategies are required.
//!
//! Core model:
//!
//! 1. **Semantic entry** — a named contract fragment (hook, effect, context,
//!    capability) with a source version and a target version.
//! 2. **Transport verdict** — whether the fragment transports unchanged,
//!    requires an adapter, or is incompatible.
//! 3. **Compatibility morphism** — a deterministic transformation rule that
//!    maps a contract fragment from one version to another while preserving
//!    specified invariants.
//! 4. **Regression mask detector** — flags cases where an apparent "pass"
//!    across versions actually hides a behavioral change behind an adapter
//!    rather than proving genuine compatibility.
//!
//! The ledger is a pure-data structure: all operations are deterministic
//! under identical inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use crate::hash_tiers::ContentHash;
use crate::semantic_contract_baseline::SemanticContractVersion;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

/// Schema version for transport ledger artifacts.
pub const TRANSPORT_LEDGER_SCHEMA_VERSION: &str = "franken-engine.semantic_transport_ledger.v1";

/// Bead identifier for this module.
pub const TRANSPORT_LEDGER_BEAD_ID: &str = "bd-mjh3.14.4";

/// Maximum entries in a single ledger.
const MAX_LEDGER_ENTRIES: usize = 50_000;

/// Maximum morphisms per entry.
const MAX_MORPHISMS_PER_ENTRY: usize = 100;

/// Maximum regression mask warnings per analysis.
const MAX_REGRESSION_MASKS: usize = 10_000;

// ---------------------------------------------------------------------------
// Blocking quality-debt codes (FRX-14.4)
// ---------------------------------------------------------------------------

pub const DEBT_TRANSPORT_INCOMPATIBLE: &str = "FE-FRX-14-4-TRANSPORT-0001";
pub const DEBT_ADAPTER_REQUIRED: &str = "FE-FRX-14-4-TRANSPORT-0002";
pub const DEBT_REGRESSION_MASKED: &str = "FE-FRX-14-4-TRANSPORT-0003";
pub const DEBT_MORPHISM_UNVERIFIED: &str = "FE-FRX-14-4-TRANSPORT-0004";
pub const DEBT_BUDGET_EXHAUSTED: &str = "FE-FRX-14-4-TRANSPORT-0005";

// ---------------------------------------------------------------------------
// Transport verdict
// ---------------------------------------------------------------------------

/// Whether a semantic fragment transports across a version boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TransportVerdict {
    /// Semantics identical — no adapter needed.
    Unchanged,
    /// Minor behavioral difference — adapter can bridge.
    AdapterRequired,
    /// Fundamental incompatibility — fallback strategy needed.
    Incompatible,
    /// Not yet analyzed.
    Unknown,
}

impl fmt::Display for TransportVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unchanged => write!(f, "unchanged"),
            Self::AdapterRequired => write!(f, "adapter-required"),
            Self::Incompatible => write!(f, "incompatible"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// Contract domain
// ---------------------------------------------------------------------------

/// The semantic domain of a contract fragment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ContractDomain {
    /// Hook invocation, ordering, cleanup semantics.
    Hook,
    /// Effect timing, side-effect boundary, determinism.
    Effect,
    /// Context provider/consumer resolution.
    Context,
    /// Capability requirements and grants.
    Capability,
    /// Suspense/concurrent rendering behavior.
    Suspense,
    /// Hydration and SSR contracts.
    Hydration,
    /// Error boundary behavior.
    ErrorBoundary,
    /// Ref forwarding and imperative handle contracts.
    Ref,
    /// Portal behavior.
    Portal,
}

impl fmt::Display for ContractDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hook => write!(f, "hook"),
            Self::Effect => write!(f, "effect"),
            Self::Context => write!(f, "context"),
            Self::Capability => write!(f, "capability"),
            Self::Suspense => write!(f, "suspense"),
            Self::Hydration => write!(f, "hydration"),
            Self::ErrorBoundary => write!(f, "error-boundary"),
            Self::Ref => write!(f, "ref"),
            Self::Portal => write!(f, "portal"),
        }
    }
}

// ---------------------------------------------------------------------------
// Version pair
// ---------------------------------------------------------------------------

/// An ordered pair of semantic contract versions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VersionPair {
    pub source: SemanticContractVersion,
    pub target: SemanticContractVersion,
}

impl VersionPair {
    pub fn new(source: SemanticContractVersion, target: SemanticContractVersion) -> Self {
        Self { source, target }
    }

    pub fn is_same_major(&self) -> bool {
        self.source.major == self.target.major
    }

    pub fn is_upgrade(&self) -> bool {
        self.target > self.source
    }

    pub fn is_downgrade(&self) -> bool {
        self.target < self.source
    }
}

impl fmt::Display for VersionPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} → {}", self.source, self.target)
    }
}

// ---------------------------------------------------------------------------
// Transport entry
// ---------------------------------------------------------------------------

/// A single entry in the semantic transport ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportEntry {
    /// Unique identifier for this entry.
    pub id: EngineObjectId,
    /// Human-readable name for the semantic fragment.
    pub fragment_name: String,
    /// The contract domain this fragment belongs to.
    pub domain: ContractDomain,
    /// Version pair (source → target).
    pub version_pair: VersionPair,
    /// Transport verdict.
    pub verdict: TransportVerdict,
    /// Specific behavioral differences (empty if Unchanged).
    pub behavioral_deltas: Vec<BehavioralDelta>,
    /// Invariants that must hold across the transport.
    pub required_invariants: Vec<String>,
    /// Invariants verified as holding.
    pub verified_invariants: Vec<String>,
    /// Invariants that failed verification.
    pub broken_invariants: Vec<String>,
    /// Debt code if verdict is not Unchanged.
    pub debt_code: Option<String>,
    /// Confidence score in millionths (1_000_000 = fully confident).
    pub confidence_millionths: i64,
    /// Deterministic evidence hash.
    pub entry_hash: ContentHash,
}

impl TransportEntry {
    /// Whether this entry blocks release gates.
    pub fn is_blocking(&self) -> bool {
        self.verdict == TransportVerdict::Incompatible
    }

    /// Whether all invariants pass.
    pub fn all_invariants_verified(&self) -> bool {
        self.broken_invariants.is_empty()
            && self.verified_invariants.len() == self.required_invariants.len()
    }

    /// Coverage ratio in millionths.
    pub fn invariant_coverage_millionths(&self) -> i64 {
        if self.required_invariants.is_empty() {
            return MILLION;
        }
        let verified = self.verified_invariants.len() as i64;
        let total = self.required_invariants.len() as i64;
        verified.saturating_mul(MILLION) / total
    }

    /// Summary line for operator display.
    pub fn summary_line(&self) -> String {
        format!(
            "[{}] {} ({}) {} — {} deltas, confidence={}",
            self.domain,
            self.fragment_name,
            self.version_pair,
            self.verdict,
            self.behavioral_deltas.len(),
            self.confidence_millionths,
        )
    }
}

/// A specific behavioral difference between versions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BehavioralDelta {
    /// Aspect of behavior that differs.
    pub aspect: String,
    /// Description of the source version's behavior.
    pub source_behavior: String,
    /// Description of the target version's behavior.
    pub target_behavior: String,
    /// Severity of the difference in millionths.
    pub severity_millionths: i64,
    /// Whether an adapter can bridge this difference.
    pub adapter_bridgeable: bool,
}

impl fmt::Display for BehavioralDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: '{}' → '{}' (severity={}, bridgeable={})",
            self.aspect,
            self.source_behavior,
            self.target_behavior,
            self.severity_millionths,
            self.adapter_bridgeable,
        )
    }
}

// ---------------------------------------------------------------------------
// Compatibility morphism
// ---------------------------------------------------------------------------

/// A deterministic transformation rule mapping a contract fragment from
/// one version to another while preserving specified invariants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityMorphism {
    /// Unique identifier.
    pub id: EngineObjectId,
    /// Human-readable name.
    pub name: String,
    /// Domain this morphism operates in.
    pub domain: ContractDomain,
    /// Version pair this morphism bridges.
    pub version_pair: VersionPair,
    /// Invariants preserved by this morphism.
    pub preserved_invariants: Vec<String>,
    /// Invariants NOT preserved (lossy morphism).
    pub broken_invariants: Vec<String>,
    /// Whether this morphism is verified (tests pass).
    pub verified: bool,
    /// Whether this morphism is lossy (some information lost).
    pub lossy: bool,
    /// Description of the transformation.
    pub description: String,
    /// Adapter code/strategy reference.
    pub adapter_ref: Option<String>,
    /// Evidence hash for verification status.
    pub evidence_hash: ContentHash,
}

impl CompatibilityMorphism {
    /// Whether this morphism is safe (verified and not lossy).
    pub fn is_safe(&self) -> bool {
        self.verified && !self.lossy
    }

    /// Summary line.
    pub fn summary_line(&self) -> String {
        let safety = if self.is_safe() {
            "safe"
        } else if self.verified {
            "verified-lossy"
        } else {
            "UNVERIFIED"
        };
        format!(
            "[{}] {} ({}) — {} invariants preserved, {}",
            self.domain,
            self.name,
            self.version_pair,
            self.preserved_invariants.len(),
            safety,
        )
    }
}

// ---------------------------------------------------------------------------
// Regression mask
// ---------------------------------------------------------------------------

/// A regression mask warning: cases where an adapter hides a behavioral
/// change rather than proving genuine compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionMask {
    /// Unique identifier.
    pub id: EngineObjectId,
    /// The transport entry that triggered this mask.
    pub entry_id: EngineObjectId,
    /// The morphism that may be masking the regression.
    pub morphism_id: Option<EngineObjectId>,
    /// What behavioral aspect is masked.
    pub masked_aspect: String,
    /// Why this is considered a potential mask.
    pub reason: String,
    /// Risk score in millionths.
    pub risk_millionths: i64,
    /// Debt code.
    pub debt_code: String,
    /// Evidence hash.
    pub evidence_hash: ContentHash,
}

impl RegressionMask {
    /// Whether this mask represents high risk (>= 500k).
    pub fn is_high_risk(&self) -> bool {
        self.risk_millionths >= 500_000
    }

    /// Summary line.
    pub fn summary_line(&self) -> String {
        format!(
            "MASK: {} — risk={}, reason: {}",
            self.masked_aspect, self.risk_millionths, self.reason,
        )
    }
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

/// The full semantic transport ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticTransportLedger {
    /// Schema version.
    pub schema_version: String,
    /// Bead identifier.
    pub bead_id: String,
    /// Transport entries indexed by fragment name.
    pub entries: Vec<TransportEntry>,
    /// Compatibility morphisms.
    pub morphisms: Vec<CompatibilityMorphism>,
    /// Regression mask warnings.
    pub regression_masks: Vec<RegressionMask>,
    /// Epoch at which the ledger was compiled.
    pub compiled_epoch: u64,
    /// Deterministic ledger hash.
    pub ledger_hash: ContentHash,
}

impl SemanticTransportLedger {
    pub fn new(epoch: u64) -> Self {
        let hash = ContentHash::compute(b"empty-ledger");
        Self {
            schema_version: TRANSPORT_LEDGER_SCHEMA_VERSION.to_string(),
            bead_id: TRANSPORT_LEDGER_BEAD_ID.to_string(),
            entries: Vec::new(),
            morphisms: Vec::new(),
            regression_masks: Vec::new(),
            compiled_epoch: epoch,
            ledger_hash: hash,
        }
    }

    /// Total entry count.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Entries with a specific verdict.
    pub fn entries_by_verdict(&self, verdict: &TransportVerdict) -> Vec<&TransportEntry> {
        self.entries
            .iter()
            .filter(|e| e.verdict == *verdict)
            .collect()
    }

    /// Entries in a specific domain.
    pub fn entries_by_domain(&self, domain: &ContractDomain) -> Vec<&TransportEntry> {
        self.entries
            .iter()
            .filter(|e| e.domain == *domain)
            .collect()
    }

    /// All unique version pairs in the ledger.
    pub fn version_pairs(&self) -> BTreeSet<String> {
        self.entries
            .iter()
            .map(|e| format!("{}", e.version_pair))
            .collect()
    }

    /// Count of incompatible entries.
    pub fn incompatible_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.verdict == TransportVerdict::Incompatible)
            .count()
    }

    /// Count of entries requiring adapters.
    pub fn adapter_required_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.verdict == TransportVerdict::AdapterRequired)
            .count()
    }

    /// Count of unchanged entries.
    pub fn unchanged_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.verdict == TransportVerdict::Unchanged)
            .count()
    }

    /// Transport coverage: ratio of analyzed entries with known verdicts.
    pub fn coverage_millionths(&self) -> i64 {
        if self.entries.is_empty() {
            return 0;
        }
        let known = self
            .entries
            .iter()
            .filter(|e| e.verdict != TransportVerdict::Unknown)
            .count() as i64;
        let total = self.entries.len() as i64;
        known.saturating_mul(MILLION) / total
    }

    /// High-risk regression masks.
    pub fn high_risk_masks(&self) -> Vec<&RegressionMask> {
        self.regression_masks
            .iter()
            .filter(|m| m.is_high_risk())
            .collect()
    }

    /// All debt codes across entries, morphisms, and masks.
    pub fn all_debt_codes(&self) -> BTreeSet<String> {
        let mut codes = BTreeSet::new();
        for entry in &self.entries {
            if let Some(code) = &entry.debt_code {
                codes.insert(code.clone());
            }
        }
        for mask in &self.regression_masks {
            codes.insert(mask.debt_code.clone());
        }
        codes
    }

    /// Summary line.
    pub fn summary_line(&self) -> String {
        format!(
            "transport ledger: {} entries ({} unchanged, {} adapter-required, {} incompatible), {} morphisms, {} regression masks",
            self.entries.len(),
            self.unchanged_count(),
            self.adapter_required_count(),
            self.incompatible_count(),
            self.morphisms.len(),
            self.regression_masks.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Analysis outcome
// ---------------------------------------------------------------------------

/// Outcome of the transport analysis.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TransportAnalysisOutcome {
    /// All fragments transport unchanged.
    FullyCompatible,
    /// Some fragments need adapters but all are bridgeable.
    CompatibleWithAdapters,
    /// At least one fragment is incompatible.
    HasIncompatibilities,
    /// Regression masking detected — apparent compatibility is suspect.
    RegressionMaskDetected,
    /// Budget exhausted.
    BudgetExhausted,
}

impl fmt::Display for TransportAnalysisOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FullyCompatible => write!(f, "fully-compatible"),
            Self::CompatibleWithAdapters => write!(f, "compatible-with-adapters"),
            Self::HasIncompatibilities => write!(f, "has-incompatibilities"),
            Self::RegressionMaskDetected => write!(f, "regression-mask-detected"),
            Self::BudgetExhausted => write!(f, "budget-exhausted"),
        }
    }
}

/// Full analysis result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportAnalysisResult {
    pub schema_version: String,
    pub bead_id: String,
    pub outcome: TransportAnalysisOutcome,
    pub ledger: SemanticTransportLedger,
    pub total_entries: usize,
    pub unchanged_entries: usize,
    pub adapter_entries: usize,
    pub incompatible_entries: usize,
    pub unknown_entries: usize,
    pub regression_mask_count: usize,
    pub high_risk_mask_count: usize,
    pub analysis_epoch: u64,
    pub result_hash: ContentHash,
}

impl TransportAnalysisResult {
    /// Whether the analysis allows release to proceed.
    pub fn can_release(&self) -> bool {
        matches!(
            self.outcome,
            TransportAnalysisOutcome::FullyCompatible
                | TransportAnalysisOutcome::CompatibleWithAdapters
        )
    }

    /// Summary line.
    pub fn summary_line(&self) -> String {
        format!(
            "{}: {} entries ({} unchanged, {} adapted, {} incompatible, {} unknown), {} masks ({} high-risk)",
            self.outcome,
            self.total_entries,
            self.unchanged_entries,
            self.adapter_entries,
            self.incompatible_entries,
            self.unknown_entries,
            self.regression_mask_count,
            self.high_risk_mask_count,
        )
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportError {
    BudgetExhausted { resource: String, limit: usize },
    DuplicateEntry(String),
    InvalidVersionPair(String),
    MorphismConflict(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExhausted { resource, limit } => {
                write!(f, "budget exhausted for {resource}: limit={limit}")
            }
            Self::DuplicateEntry(name) => write!(f, "duplicate entry: {name}"),
            Self::InvalidVersionPair(msg) => write!(f, "invalid version pair: {msg}"),
            Self::MorphismConflict(msg) => write!(f, "morphism conflict: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Input specification
// ---------------------------------------------------------------------------

/// Input for a single transport analysis entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportEntrySpec {
    /// Fragment name.
    pub fragment_name: String,
    /// Contract domain.
    pub domain: ContractDomain,
    /// Source version.
    pub source_version: SemanticContractVersion,
    /// Target version.
    pub target_version: SemanticContractVersion,
    /// Behavioral deltas observed.
    pub behavioral_deltas: Vec<BehavioralDelta>,
    /// Required invariants.
    pub required_invariants: Vec<String>,
    /// Verified invariants.
    pub verified_invariants: Vec<String>,
    /// Broken invariants.
    pub broken_invariants: Vec<String>,
}

/// Input for a morphism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphismSpec {
    /// Name.
    pub name: String,
    /// Domain.
    pub domain: ContractDomain,
    /// Source version.
    pub source_version: SemanticContractVersion,
    /// Target version.
    pub target_version: SemanticContractVersion,
    /// Preserved invariants.
    pub preserved_invariants: Vec<String>,
    /// Broken invariants.
    pub broken_invariants: Vec<String>,
    /// Verified.
    pub verified: bool,
    /// Description.
    pub description: String,
    /// Optional adapter reference.
    pub adapter_ref: Option<String>,
}

/// Full input for a transport analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportAnalysisInput {
    /// Entry specifications.
    pub entries: Vec<TransportEntrySpec>,
    /// Morphism specifications.
    pub morphisms: Vec<MorphismSpec>,
    /// Analysis epoch.
    pub epoch: u64,
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

/// Configuration for the transport analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportAnalyzerConfig {
    pub max_entries: usize,
    pub max_morphisms_per_entry: usize,
    pub max_regression_masks: usize,
    /// Threshold (in millionths) for adapter-required vs incompatible.
    /// If total delta severity exceeds this, verdict is Incompatible.
    pub incompatibility_threshold_millionths: i64,
    /// Whether to detect regression masks.
    pub detect_regression_masks: bool,
}

impl Default for TransportAnalyzerConfig {
    fn default() -> Self {
        Self {
            max_entries: MAX_LEDGER_ENTRIES,
            max_morphisms_per_entry: MAX_MORPHISMS_PER_ENTRY,
            max_regression_masks: MAX_REGRESSION_MASKS,
            incompatibility_threshold_millionths: 750_000,
            detect_regression_masks: true,
        }
    }
}

/// The semantic transport analyzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticTransportAnalyzer {
    config: TransportAnalyzerConfig,
}

impl SemanticTransportAnalyzer {
    pub fn new() -> Self {
        Self {
            config: TransportAnalyzerConfig::default(),
        }
    }

    pub fn with_config(config: TransportAnalyzerConfig) -> Self {
        Self { config }
    }

    /// Run the full transport analysis.
    pub fn analyze(
        &self,
        input: &TransportAnalysisInput,
    ) -> Result<TransportAnalysisResult, TransportError> {
        let mut entries = Vec::new();
        let mut seen_names: BTreeSet<String> = BTreeSet::new();
        let mut budget_exhausted = false;

        for spec in &input.entries {
            if entries.len() >= self.config.max_entries {
                budget_exhausted = true;
                break;
            }
            if seen_names.contains(&spec.fragment_name) {
                return Err(TransportError::DuplicateEntry(spec.fragment_name.clone()));
            }
            seen_names.insert(spec.fragment_name.clone());
            let entry = self.build_entry(spec)?;
            entries.push(entry);
        }

        let morphisms = self.build_morphisms(&input.morphisms)?;

        let regression_masks = if self.config.detect_regression_masks {
            self.detect_regression_masks(&entries, &morphisms)
        } else {
            Vec::new()
        };

        let ledger_hash = Self::compute_ledger_hash(&entries, &morphisms, &regression_masks);
        let ledger = SemanticTransportLedger {
            schema_version: TRANSPORT_LEDGER_SCHEMA_VERSION.to_string(),
            bead_id: TRANSPORT_LEDGER_BEAD_ID.to_string(),
            entries,
            morphisms,
            regression_masks,
            compiled_epoch: input.epoch,
            ledger_hash,
        };

        let unchanged = ledger.unchanged_count();
        let adapters = ledger.adapter_required_count();
        let incompatible = ledger.incompatible_count();
        let unknown = ledger
            .entries
            .iter()
            .filter(|e| e.verdict == TransportVerdict::Unknown)
            .count();
        let high_risk = ledger.high_risk_masks().len();

        let outcome = if budget_exhausted {
            TransportAnalysisOutcome::BudgetExhausted
        } else if high_risk > 0 {
            TransportAnalysisOutcome::RegressionMaskDetected
        } else if incompatible > 0 {
            TransportAnalysisOutcome::HasIncompatibilities
        } else if adapters > 0 {
            TransportAnalysisOutcome::CompatibleWithAdapters
        } else {
            TransportAnalysisOutcome::FullyCompatible
        };

        let result_hash = Self::compute_result_hash(&outcome, &ledger.ledger_hash);

        Ok(TransportAnalysisResult {
            schema_version: TRANSPORT_LEDGER_SCHEMA_VERSION.to_string(),
            bead_id: TRANSPORT_LEDGER_BEAD_ID.to_string(),
            outcome,
            total_entries: ledger.entries.len(),
            unchanged_entries: unchanged,
            adapter_entries: adapters,
            incompatible_entries: incompatible,
            unknown_entries: unknown,
            regression_mask_count: ledger.regression_masks.len(),
            high_risk_mask_count: high_risk,
            analysis_epoch: input.epoch,
            result_hash,
            ledger,
        })
    }

    // -----------------------------------------------------------------------
    // Entry construction
    // -----------------------------------------------------------------------

    fn build_entry(&self, spec: &TransportEntrySpec) -> Result<TransportEntry, TransportError> {
        let version_pair =
            VersionPair::new(spec.source_version.clone(), spec.target_version.clone());

        let verdict = self.determine_verdict(spec);
        let debt_code = match &verdict {
            TransportVerdict::Incompatible => Some(DEBT_TRANSPORT_INCOMPATIBLE.to_string()),
            TransportVerdict::AdapterRequired => Some(DEBT_ADAPTER_REQUIRED.to_string()),
            TransportVerdict::Unknown => None,
            TransportVerdict::Unchanged => None,
        };

        let confidence = self.compute_confidence(spec);
        let entry_hash =
            Self::compute_entry_hash(&spec.fragment_name, &spec.domain, &version_pair, &verdict);

        let schema_id = SchemaId::from_definition(b"semantic_transport_ledger.entry.v1");
        let id = derive_id(
            ObjectDomain::EvidenceRecord,
            "transport-entry",
            &schema_id,
            entry_hash.as_bytes(),
        )
        .unwrap_or_else(|_| {
            let fb = SchemaId::from_definition(b"transport.entry.fb.v1");
            derive_id(
                ObjectDomain::EvidenceRecord,
                "transport-entry-fb",
                &fb,
                spec.fragment_name.as_bytes(),
            )
            .expect("fallback id should not fail")
        });

        Ok(TransportEntry {
            id,
            fragment_name: spec.fragment_name.clone(),
            domain: spec.domain.clone(),
            version_pair,
            verdict,
            behavioral_deltas: spec.behavioral_deltas.clone(),
            required_invariants: spec.required_invariants.clone(),
            verified_invariants: spec.verified_invariants.clone(),
            broken_invariants: spec.broken_invariants.clone(),
            debt_code,
            confidence_millionths: confidence,
            entry_hash,
        })
    }

    fn determine_verdict(&self, spec: &TransportEntrySpec) -> TransportVerdict {
        // If there are broken invariants, it's incompatible.
        if !spec.broken_invariants.is_empty() {
            return TransportVerdict::Incompatible;
        }

        // If there are no behavioral deltas, it's unchanged.
        if spec.behavioral_deltas.is_empty() {
            return TransportVerdict::Unchanged;
        }

        // Compute total severity.
        let total_severity: i64 = spec
            .behavioral_deltas
            .iter()
            .map(|d| d.severity_millionths)
            .sum();

        // If total severity exceeds threshold, check if adapters can bridge.
        if total_severity >= self.config.incompatibility_threshold_millionths {
            let all_bridgeable = spec.behavioral_deltas.iter().all(|d| d.adapter_bridgeable);
            if all_bridgeable {
                return TransportVerdict::AdapterRequired;
            }
            return TransportVerdict::Incompatible;
        }

        // Below threshold with deltas: adapter required if any delta exists.
        let has_unbridgeable = spec.behavioral_deltas.iter().any(|d| !d.adapter_bridgeable);
        if has_unbridgeable {
            return TransportVerdict::Incompatible;
        }

        TransportVerdict::AdapterRequired
    }

    fn compute_confidence(&self, spec: &TransportEntrySpec) -> i64 {
        if spec.required_invariants.is_empty() {
            return 500_000; // Medium confidence with no invariants.
        }
        let verified = spec.verified_invariants.len() as i64;
        let total = spec.required_invariants.len() as i64;
        verified.saturating_mul(MILLION) / total
    }

    // -----------------------------------------------------------------------
    // Morphism construction
    // -----------------------------------------------------------------------

    fn build_morphisms(
        &self,
        specs: &[MorphismSpec],
    ) -> Result<Vec<CompatibilityMorphism>, TransportError> {
        let mut morphisms = Vec::new();
        for spec in specs {
            let version_pair =
                VersionPair::new(spec.source_version.clone(), spec.target_version.clone());
            let lossy = !spec.broken_invariants.is_empty();
            let evidence_hash =
                Self::compute_morphism_hash(&spec.name, &spec.domain, &version_pair);

            let schema_id = SchemaId::from_definition(b"semantic_transport_ledger.morphism.v1");
            let id = derive_id(
                ObjectDomain::EvidenceRecord,
                "transport-morphism",
                &schema_id,
                evidence_hash.as_bytes(),
            )
            .unwrap_or_else(|_| {
                let fb = SchemaId::from_definition(b"transport.morphism.fb.v1");
                derive_id(
                    ObjectDomain::EvidenceRecord,
                    "transport-morphism-fb",
                    &fb,
                    spec.name.as_bytes(),
                )
                .expect("fallback id should not fail")
            });

            morphisms.push(CompatibilityMorphism {
                id,
                name: spec.name.clone(),
                domain: spec.domain.clone(),
                version_pair,
                preserved_invariants: spec.preserved_invariants.clone(),
                broken_invariants: spec.broken_invariants.clone(),
                verified: spec.verified,
                lossy,
                description: spec.description.clone(),
                adapter_ref: spec.adapter_ref.clone(),
                evidence_hash,
            });
        }
        Ok(morphisms)
    }

    // -----------------------------------------------------------------------
    // Regression mask detection
    // -----------------------------------------------------------------------

    fn detect_regression_masks(
        &self,
        entries: &[TransportEntry],
        morphisms: &[CompatibilityMorphism],
    ) -> Vec<RegressionMask> {
        let mut masks = Vec::new();

        // Build a lookup of morphisms by domain and version pair.
        let morphism_lookup: BTreeMap<(String, String), Vec<&CompatibilityMorphism>> = {
            let mut map: BTreeMap<(String, String), Vec<&CompatibilityMorphism>> = BTreeMap::new();
            for m in morphisms {
                let key = (format!("{}", m.domain), format!("{}", m.version_pair));
                map.entry(key).or_default().push(m);
            }
            map
        };

        for entry in entries {
            if masks.len() >= self.config.max_regression_masks {
                break;
            }

            // Mask type 1: AdapterRequired verdict where the adapter morphism
            // is lossy — the apparent compatibility is suspect.
            if entry.verdict == TransportVerdict::AdapterRequired {
                let key = (
                    format!("{}", entry.domain),
                    format!("{}", entry.version_pair),
                );
                if let Some(applicable_morphisms) = morphism_lookup.get(&key) {
                    for morph in applicable_morphisms {
                        if morph.lossy {
                            let mask = self.build_regression_mask(
                                entry,
                                Some(&morph.id),
                                &format!(
                                    "Lossy morphism '{}' bridges '{}' but drops invariants: [{}]",
                                    morph.name,
                                    entry.fragment_name,
                                    morph.broken_invariants.join(", "),
                                ),
                                750_000, // High risk.
                            );
                            masks.push(mask);
                        }
                    }
                }
            }

            // Mask type 2: Entry has deltas but all marked adapter-bridgeable,
            // yet invariant coverage is low.
            if entry.verdict == TransportVerdict::AdapterRequired
                && entry.invariant_coverage_millionths() < 500_000
                && !entry.required_invariants.is_empty()
            {
                let mask = self.build_regression_mask(
                    entry,
                    None,
                    &format!(
                        "Low invariant coverage ({}/{}M) on '{}' with adapter verdict — \
                         untested invariants may hide regression.",
                        entry.invariant_coverage_millionths(),
                        MILLION,
                        entry.fragment_name,
                    ),
                    600_000,
                );
                masks.push(mask);
            }

            // Mask type 3: Unchanged verdict but unverified invariants.
            if entry.verdict == TransportVerdict::Unchanged
                && !entry.all_invariants_verified()
                && !entry.required_invariants.is_empty()
            {
                let mask = self.build_regression_mask(
                    entry,
                    None,
                    &format!(
                        "Unchanged verdict for '{}' but {}/{} invariants unverified.",
                        entry.fragment_name,
                        entry
                            .required_invariants
                            .len()
                            .saturating_sub(entry.verified_invariants.len()),
                        entry.required_invariants.len(),
                    ),
                    400_000, // Medium risk.
                );
                masks.push(mask);
            }
        }

        masks
    }

    fn build_regression_mask(
        &self,
        entry: &TransportEntry,
        morphism_id: Option<&EngineObjectId>,
        reason: &str,
        risk: i64,
    ) -> RegressionMask {
        let evidence_hash = Self::compute_mask_hash(&entry.id, reason);
        let schema_id = SchemaId::from_definition(b"semantic_transport_ledger.mask.v1");
        let id = derive_id(
            ObjectDomain::EvidenceRecord,
            "transport-mask",
            &schema_id,
            evidence_hash.as_bytes(),
        )
        .unwrap_or_else(|_| entry.id.clone());

        RegressionMask {
            id,
            entry_id: entry.id.clone(),
            morphism_id: morphism_id.cloned(),
            masked_aspect: entry.fragment_name.clone(),
            reason: reason.to_string(),
            risk_millionths: risk,
            debt_code: DEBT_REGRESSION_MASKED.to_string(),
            evidence_hash,
        }
    }

    // -----------------------------------------------------------------------
    // Hashing
    // -----------------------------------------------------------------------

    fn compute_entry_hash(
        name: &str,
        domain: &ContractDomain,
        version_pair: &VersionPair,
        verdict: &TransportVerdict,
    ) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(TRANSPORT_LEDGER_SCHEMA_VERSION.as_bytes());
        canonical.extend_from_slice(b"|entry|");
        canonical.extend_from_slice(name.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(format!("{domain}").as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(format!("{version_pair}").as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(format!("{verdict}").as_bytes());
        ContentHash::compute(&canonical)
    }

    fn compute_morphism_hash(
        name: &str,
        domain: &ContractDomain,
        version_pair: &VersionPair,
    ) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(TRANSPORT_LEDGER_SCHEMA_VERSION.as_bytes());
        canonical.extend_from_slice(b"|morphism|");
        canonical.extend_from_slice(name.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(format!("{domain}").as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(format!("{version_pair}").as_bytes());
        ContentHash::compute(&canonical)
    }

    fn compute_mask_hash(entry_id: &EngineObjectId, reason: &str) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(TRANSPORT_LEDGER_SCHEMA_VERSION.as_bytes());
        canonical.extend_from_slice(b"|mask|");
        canonical.extend_from_slice(format!("{entry_id}").as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(reason.as_bytes());
        ContentHash::compute(&canonical)
    }

    fn compute_ledger_hash(
        entries: &[TransportEntry],
        morphisms: &[CompatibilityMorphism],
        masks: &[RegressionMask],
    ) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(TRANSPORT_LEDGER_SCHEMA_VERSION.as_bytes());
        canonical.extend_from_slice(b"|ledger|");
        for e in entries {
            canonical.extend_from_slice(e.entry_hash.as_bytes());
            canonical.push(b';');
        }
        canonical.push(b'|');
        for m in morphisms {
            canonical.extend_from_slice(m.evidence_hash.as_bytes());
            canonical.push(b';');
        }
        canonical.push(b'|');
        for mask in masks {
            canonical.extend_from_slice(mask.evidence_hash.as_bytes());
            canonical.push(b';');
        }
        ContentHash::compute(&canonical)
    }

    fn compute_result_hash(
        outcome: &TransportAnalysisOutcome,
        ledger_hash: &ContentHash,
    ) -> ContentHash {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(TRANSPORT_LEDGER_SCHEMA_VERSION.as_bytes());
        canonical.extend_from_slice(b"|result|");
        canonical.extend_from_slice(format!("{outcome}").as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(ledger_hash.as_bytes());
        ContentHash::compute(&canonical)
    }
}

impl Default for SemanticTransportAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Gate integration helpers
// ---------------------------------------------------------------------------

/// Check whether a transport analysis blocks a gate.
pub fn should_block_gate(result: &TransportAnalysisResult) -> bool {
    matches!(
        result.outcome,
        TransportAnalysisOutcome::HasIncompatibilities
            | TransportAnalysisOutcome::RegressionMaskDetected
            | TransportAnalysisOutcome::BudgetExhausted
    )
}

/// Render a human-readable transport report.
pub fn render_transport_report(result: &TransportAnalysisResult) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "=== Semantic Transport Report (epoch {}) ===",
        result.analysis_epoch,
    ));
    lines.push(result.summary_line());
    lines.push(String::new());

    let ledger = &result.ledger;

    if ledger.entries.is_empty() {
        lines.push("No transport entries. Nothing to analyze.".to_string());
    } else {
        // Group by verdict.
        for verdict in &[
            TransportVerdict::Incompatible,
            TransportVerdict::AdapterRequired,
            TransportVerdict::Unknown,
            TransportVerdict::Unchanged,
        ] {
            let matching = ledger.entries_by_verdict(verdict);
            if !matching.is_empty() {
                lines.push(format!("--- {} ({}) ---", verdict, matching.len()));
                for entry in matching {
                    lines.push(format!("  {}", entry.summary_line()));
                    for delta in &entry.behavioral_deltas {
                        lines.push(format!("    Delta: {delta}"));
                    }
                }
                lines.push(String::new());
            }
        }
    }

    if !ledger.morphisms.is_empty() {
        lines.push(format!("--- Morphisms ({}) ---", ledger.morphisms.len()));
        for m in &ledger.morphisms {
            lines.push(format!("  {}", m.summary_line()));
        }
        lines.push(String::new());
    }

    if !ledger.regression_masks.is_empty() {
        lines.push(format!(
            "--- Regression Masks ({}) ---",
            ledger.regression_masks.len()
        ));
        for mask in &ledger.regression_masks {
            lines.push(format!("  {}", mask.summary_line()));
        }
        lines.push(String::new());
    }

    lines.push(format!("Result hash: {}", result.result_hash));
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn v(major: u32, minor: u32, patch: u32) -> SemanticContractVersion {
        SemanticContractVersion {
            major,
            minor,
            patch,
        }
    }

    fn simple_spec(name: &str, deltas: Vec<BehavioralDelta>) -> TransportEntrySpec {
        TransportEntrySpec {
            fragment_name: name.to_string(),
            domain: ContractDomain::Hook,
            source_version: v(0, 1, 0),
            target_version: v(0, 2, 0),
            behavioral_deltas: deltas,
            required_invariants: vec!["inv1".to_string(), "inv2".to_string()],
            verified_invariants: vec!["inv1".to_string(), "inv2".to_string()],
            broken_invariants: vec![],
        }
    }

    fn delta(severity: i64, bridgeable: bool) -> BehavioralDelta {
        BehavioralDelta {
            aspect: "timing".to_string(),
            source_behavior: "sync".to_string(),
            target_behavior: "async".to_string(),
            severity_millionths: severity,
            adapter_bridgeable: bridgeable,
        }
    }

    fn simple_input(specs: Vec<TransportEntrySpec>) -> TransportAnalysisInput {
        TransportAnalysisInput {
            entries: specs,
            morphisms: vec![],
            epoch: 1,
        }
    }

    // =========================================================================
    // Basic construction
    // =========================================================================

    #[test]
    fn test_analyzer_default_config() {
        let a = SemanticTransportAnalyzer::new();
        assert_eq!(a.config.max_entries, MAX_LEDGER_ENTRIES);
        assert!(a.config.detect_regression_masks);
    }

    #[test]
    fn test_analyzer_custom_config() {
        let config = TransportAnalyzerConfig {
            max_entries: 10,
            detect_regression_masks: false,
            ..TransportAnalyzerConfig::default()
        };
        let a = SemanticTransportAnalyzer::with_config(config);
        assert_eq!(a.config.max_entries, 10);
        assert!(!a.config.detect_regression_masks);
    }

    #[test]
    fn test_analyzer_default_trait() {
        let a = SemanticTransportAnalyzer::default();
        assert_eq!(a.config.max_entries, MAX_LEDGER_ENTRIES);
    }

    // =========================================================================
    // Empty input
    // =========================================================================

    #[test]
    fn test_empty_input_fully_compatible() {
        let a = SemanticTransportAnalyzer::new();
        let input = simple_input(vec![]);
        let result = a.analyze(&input).unwrap();
        assert_eq!(result.outcome, TransportAnalysisOutcome::FullyCompatible);
        assert_eq!(result.total_entries, 0);
        assert!(result.can_release());
        assert!(!should_block_gate(&result));
    }

    // =========================================================================
    // Unchanged verdict
    // =========================================================================

    #[test]
    fn test_unchanged_verdict_no_deltas() {
        let a = SemanticTransportAnalyzer::new();
        let spec = simple_spec("useEffect.cleanup", vec![]);
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();

        assert_eq!(result.outcome, TransportAnalysisOutcome::FullyCompatible);
        assert_eq!(result.unchanged_entries, 1);
        assert!(result.can_release());
    }

    // =========================================================================
    // Adapter required verdict
    // =========================================================================

    #[test]
    fn test_adapter_required_bridgeable_deltas() {
        let a = SemanticTransportAnalyzer::new();
        let spec = simple_spec("useEffect.timing", vec![delta(300_000, true)]);
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();

        assert_eq!(
            result.outcome,
            TransportAnalysisOutcome::CompatibleWithAdapters
        );
        assert_eq!(result.adapter_entries, 1);
        assert!(result.can_release());
    }

    // =========================================================================
    // Incompatible verdict
    // =========================================================================

    #[test]
    fn test_incompatible_unbridgeable_delta() {
        let a = SemanticTransportAnalyzer::new();
        let spec = simple_spec("useLayoutEffect.order", vec![delta(300_000, false)]);
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();

        assert_eq!(
            result.outcome,
            TransportAnalysisOutcome::HasIncompatibilities
        );
        assert_eq!(result.incompatible_entries, 1);
        assert!(!result.can_release());
        assert!(should_block_gate(&result));
    }

    #[test]
    fn test_incompatible_broken_invariants() {
        let a = SemanticTransportAnalyzer::new();
        let mut spec = simple_spec("useState.semantics", vec![]);
        spec.broken_invariants = vec!["ordering-guarantee".to_string()];
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();

        assert_eq!(
            result.outcome,
            TransportAnalysisOutcome::HasIncompatibilities
        );
    }

    // =========================================================================
    // Mixed verdicts
    // =========================================================================

    #[test]
    fn test_mixed_verdicts() {
        let a = SemanticTransportAnalyzer::new();
        let s1 = simple_spec("hook.cleanup", vec![]);
        let s2 = simple_spec("effect.timing", vec![delta(200_000, true)]);
        let s3 = simple_spec("context.resolution", vec![delta(100_000, false)]);
        let input = simple_input(vec![s1, s2, s3]);
        let result = a.analyze(&input).unwrap();

        assert_eq!(
            result.outcome,
            TransportAnalysisOutcome::HasIncompatibilities
        );
        assert_eq!(result.unchanged_entries, 1);
        assert_eq!(result.adapter_entries, 1);
        assert_eq!(result.incompatible_entries, 1);
    }

    // =========================================================================
    // Duplicate entry detection
    // =========================================================================

    #[test]
    fn test_duplicate_entry_error() {
        let a = SemanticTransportAnalyzer::new();
        let s1 = simple_spec("hook.cleanup", vec![]);
        let s2 = simple_spec("hook.cleanup", vec![]);
        let input = simple_input(vec![s1, s2]);
        let err = a.analyze(&input).unwrap_err();
        assert!(matches!(err, TransportError::DuplicateEntry(ref n) if n == "hook.cleanup"));
    }

    // =========================================================================
    // Budget exhaustion
    // =========================================================================

    #[test]
    fn test_budget_exhaustion() {
        let config = TransportAnalyzerConfig {
            max_entries: 2,
            ..TransportAnalyzerConfig::default()
        };
        let a = SemanticTransportAnalyzer::with_config(config);
        let specs: Vec<TransportEntrySpec> = (0..5)
            .map(|i| simple_spec(&format!("frag{i}"), vec![]))
            .collect();
        let input = simple_input(specs);
        let result = a.analyze(&input).unwrap();

        assert_eq!(result.outcome, TransportAnalysisOutcome::BudgetExhausted);
        assert_eq!(result.total_entries, 2);
        assert!(should_block_gate(&result));
    }

    // =========================================================================
    // Morphisms
    // =========================================================================

    #[test]
    fn test_morphism_construction() {
        let a = SemanticTransportAnalyzer::new();
        let input = TransportAnalysisInput {
            entries: vec![],
            morphisms: vec![MorphismSpec {
                name: "effect-timing-adapter".to_string(),
                domain: ContractDomain::Effect,
                source_version: v(0, 1, 0),
                target_version: v(0, 2, 0),
                preserved_invariants: vec!["ordering".to_string()],
                broken_invariants: vec![],
                verified: true,
                description: "Bridges timing difference.".to_string(),
                adapter_ref: Some("adapter::effect_timing".to_string()),
            }],
            epoch: 1,
        };
        let result = a.analyze(&input).unwrap();
        assert_eq!(result.ledger.morphisms.len(), 1);
        let m = &result.ledger.morphisms[0];
        assert!(m.is_safe());
        assert!(!m.lossy);
        assert!(m.verified);
    }

    #[test]
    fn test_lossy_morphism() {
        let a = SemanticTransportAnalyzer::new();
        let input = TransportAnalysisInput {
            entries: vec![],
            morphisms: vec![MorphismSpec {
                name: "lossy-adapter".to_string(),
                domain: ContractDomain::Hook,
                source_version: v(0, 1, 0),
                target_version: v(0, 2, 0),
                preserved_invariants: vec!["inv1".to_string()],
                broken_invariants: vec!["inv2".to_string()],
                verified: true,
                description: "Loses some ordering guarantees.".to_string(),
                adapter_ref: None,
            }],
            epoch: 1,
        };
        let result = a.analyze(&input).unwrap();
        let m = &result.ledger.morphisms[0];
        assert!(m.lossy);
        assert!(!m.is_safe());
    }

    // =========================================================================
    // Regression mask detection
    // =========================================================================

    #[test]
    fn test_regression_mask_lossy_morphism() {
        let a = SemanticTransportAnalyzer::new();
        let input = TransportAnalysisInput {
            entries: vec![TransportEntrySpec {
                fragment_name: "hook.cleanup".to_string(),
                domain: ContractDomain::Hook,
                source_version: v(0, 1, 0),
                target_version: v(0, 2, 0),
                behavioral_deltas: vec![delta(300_000, true)],
                required_invariants: vec!["inv1".to_string(), "inv2".to_string()],
                verified_invariants: vec!["inv1".to_string(), "inv2".to_string()],
                broken_invariants: vec![],
            }],
            morphisms: vec![MorphismSpec {
                name: "lossy-hook-adapter".to_string(),
                domain: ContractDomain::Hook,
                source_version: v(0, 1, 0),
                target_version: v(0, 2, 0),
                preserved_invariants: vec!["inv1".to_string()],
                broken_invariants: vec!["inv2".to_string()],
                verified: true,
                description: "Lossy adapter.".to_string(),
                adapter_ref: None,
            }],
            epoch: 1,
        };
        let result = a.analyze(&input).unwrap();

        assert_eq!(
            result.outcome,
            TransportAnalysisOutcome::RegressionMaskDetected
        );
        assert!(result.regression_mask_count > 0);
        assert!(result.high_risk_mask_count > 0);
        assert!(should_block_gate(&result));
    }

    #[test]
    fn test_regression_mask_low_invariant_coverage() {
        let a = SemanticTransportAnalyzer::new();
        let input = simple_input(vec![TransportEntrySpec {
            fragment_name: "effect.timing".to_string(),
            domain: ContractDomain::Effect,
            source_version: v(0, 1, 0),
            target_version: v(0, 2, 0),
            behavioral_deltas: vec![delta(200_000, true)],
            required_invariants: vec![
                "inv1".to_string(),
                "inv2".to_string(),
                "inv3".to_string(),
                "inv4".to_string(),
            ],
            verified_invariants: vec!["inv1".to_string()], // Only 1/4 verified.
            broken_invariants: vec![],
        }]);
        let result = a.analyze(&input).unwrap();

        // Should detect low-coverage mask.
        assert!(result.regression_mask_count > 0);
    }

    #[test]
    fn test_regression_mask_unchanged_unverified() {
        let a = SemanticTransportAnalyzer::new();
        let input = simple_input(vec![TransportEntrySpec {
            fragment_name: "hook.ordering".to_string(),
            domain: ContractDomain::Hook,
            source_version: v(0, 1, 0),
            target_version: v(0, 2, 0),
            behavioral_deltas: vec![],
            required_invariants: vec!["inv1".to_string(), "inv2".to_string()],
            verified_invariants: vec!["inv1".to_string()], // Only 1/2 verified.
            broken_invariants: vec![],
        }]);
        let result = a.analyze(&input).unwrap();

        // Unchanged verdict but unverified invariants → mask warning.
        assert!(result.regression_mask_count > 0);
    }

    #[test]
    fn test_no_regression_masks_when_disabled() {
        let config = TransportAnalyzerConfig {
            detect_regression_masks: false,
            ..TransportAnalyzerConfig::default()
        };
        let a = SemanticTransportAnalyzer::with_config(config);
        let input = simple_input(vec![TransportEntrySpec {
            fragment_name: "hook.ordering".to_string(),
            domain: ContractDomain::Hook,
            source_version: v(0, 1, 0),
            target_version: v(0, 2, 0),
            behavioral_deltas: vec![],
            required_invariants: vec!["inv1".to_string()],
            verified_invariants: vec![],
            broken_invariants: vec![],
        }]);
        let result = a.analyze(&input).unwrap();
        assert_eq!(result.regression_mask_count, 0);
    }

    // =========================================================================
    // Determinism
    // =========================================================================

    #[test]
    fn test_deterministic_output() {
        let a = SemanticTransportAnalyzer::new();
        let input = simple_input(vec![
            simple_spec("frag1", vec![]),
            simple_spec("frag2", vec![delta(200_000, true)]),
        ]);

        let r1 = a.analyze(&input).unwrap();
        let r2 = a.analyze(&input).unwrap();

        assert_eq!(r1.result_hash, r2.result_hash);
        assert_eq!(r1.ledger.ledger_hash, r2.ledger.ledger_hash);
    }

    // =========================================================================
    // Serde round-trip
    // =========================================================================

    #[test]
    fn test_analysis_result_serde() {
        let a = SemanticTransportAnalyzer::new();
        let input = simple_input(vec![simple_spec("frag1", vec![])]);
        let result = a.analyze(&input).unwrap();

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: TransportAnalysisResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.outcome, deserialized.outcome);
        assert_eq!(result.result_hash, deserialized.result_hash);
    }

    #[test]
    fn test_ledger_serde() {
        let ledger = SemanticTransportLedger::new(42);
        let json = serde_json::to_string(&ledger).unwrap();
        let deserialized: SemanticTransportLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger.compiled_epoch, deserialized.compiled_epoch);
    }

    #[test]
    fn test_config_serde() {
        let config = TransportAnalyzerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TransportAnalyzerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.max_entries, deserialized.max_entries);
    }

    // =========================================================================
    // VersionPair
    // =========================================================================

    #[test]
    fn test_version_pair_same_major() {
        let pair = VersionPair::new(v(1, 0, 0), v(1, 2, 0));
        assert!(pair.is_same_major());
        assert!(pair.is_upgrade());
        assert!(!pair.is_downgrade());
    }

    #[test]
    fn test_version_pair_different_major() {
        let pair = VersionPair::new(v(1, 0, 0), v(2, 0, 0));
        assert!(!pair.is_same_major());
    }

    #[test]
    fn test_version_pair_downgrade() {
        let pair = VersionPair::new(v(2, 0, 0), v(1, 0, 0));
        assert!(!pair.is_upgrade());
        assert!(pair.is_downgrade());
    }

    #[test]
    fn test_version_pair_display() {
        let pair = VersionPair::new(v(0, 1, 0), v(0, 2, 0));
        assert_eq!(format!("{pair}"), "0.1.0 → 0.2.0");
    }

    // =========================================================================
    // ContractDomain Display
    // =========================================================================

    #[test]
    fn test_contract_domain_display() {
        assert_eq!(format!("{}", ContractDomain::Hook), "hook");
        assert_eq!(format!("{}", ContractDomain::Effect), "effect");
        assert_eq!(format!("{}", ContractDomain::Context), "context");
        assert_eq!(format!("{}", ContractDomain::Capability), "capability");
        assert_eq!(format!("{}", ContractDomain::Suspense), "suspense");
        assert_eq!(format!("{}", ContractDomain::Hydration), "hydration");
        assert_eq!(
            format!("{}", ContractDomain::ErrorBoundary),
            "error-boundary"
        );
        assert_eq!(format!("{}", ContractDomain::Ref), "ref");
        assert_eq!(format!("{}", ContractDomain::Portal), "portal");
    }

    // =========================================================================
    // TransportVerdict Display
    // =========================================================================

    #[test]
    fn test_transport_verdict_display() {
        assert_eq!(format!("{}", TransportVerdict::Unchanged), "unchanged");
        assert_eq!(
            format!("{}", TransportVerdict::AdapterRequired),
            "adapter-required"
        );
        assert_eq!(
            format!("{}", TransportVerdict::Incompatible),
            "incompatible"
        );
        assert_eq!(format!("{}", TransportVerdict::Unknown), "unknown");
    }

    // =========================================================================
    // TransportAnalysisOutcome Display
    // =========================================================================

    #[test]
    fn test_analysis_outcome_display() {
        assert_eq!(
            format!("{}", TransportAnalysisOutcome::FullyCompatible),
            "fully-compatible"
        );
        assert_eq!(
            format!("{}", TransportAnalysisOutcome::CompatibleWithAdapters),
            "compatible-with-adapters"
        );
        assert_eq!(
            format!("{}", TransportAnalysisOutcome::HasIncompatibilities),
            "has-incompatibilities"
        );
        assert_eq!(
            format!("{}", TransportAnalysisOutcome::RegressionMaskDetected),
            "regression-mask-detected"
        );
        assert_eq!(
            format!("{}", TransportAnalysisOutcome::BudgetExhausted),
            "budget-exhausted"
        );
    }

    // =========================================================================
    // TransportError Display
    // =========================================================================

    #[test]
    fn test_transport_error_display() {
        let err = TransportError::BudgetExhausted {
            resource: "entries".to_string(),
            limit: 100,
        };
        assert!(format!("{err}").contains("budget exhausted"));

        let err = TransportError::DuplicateEntry("x".to_string());
        assert!(format!("{err}").contains("duplicate"));

        let err = TransportError::InvalidVersionPair("bad".to_string());
        assert!(format!("{err}").contains("invalid"));

        let err = TransportError::MorphismConflict("conflict".to_string());
        assert!(format!("{err}").contains("conflict"));
    }

    // =========================================================================
    // BehavioralDelta Display
    // =========================================================================

    #[test]
    fn test_behavioral_delta_display() {
        let d = delta(500_000, true);
        let s = format!("{d}");
        assert!(s.contains("timing"));
        assert!(s.contains("sync"));
        assert!(s.contains("async"));
    }

    // =========================================================================
    // TransportEntry helpers
    // =========================================================================

    #[test]
    fn test_entry_is_blocking() {
        let a = SemanticTransportAnalyzer::new();
        let mut spec = simple_spec("test", vec![delta(100_000, false)]);
        spec.broken_invariants = vec![];
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        assert!(result.ledger.entries[0].is_blocking());
    }

    #[test]
    fn test_entry_invariant_coverage() {
        let a = SemanticTransportAnalyzer::new();
        let spec = TransportEntrySpec {
            fragment_name: "test".to_string(),
            domain: ContractDomain::Hook,
            source_version: v(0, 1, 0),
            target_version: v(0, 2, 0),
            behavioral_deltas: vec![],
            required_invariants: vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
            ],
            verified_invariants: vec!["a".to_string(), "b".to_string()],
            broken_invariants: vec![],
        };
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        let entry = &result.ledger.entries[0];
        assert_eq!(entry.invariant_coverage_millionths(), 500_000);
        assert!(!entry.all_invariants_verified());
    }

    #[test]
    fn test_entry_full_invariant_coverage() {
        let a = SemanticTransportAnalyzer::new();
        let spec = simple_spec("test", vec![]);
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        let entry = &result.ledger.entries[0];
        assert_eq!(entry.invariant_coverage_millionths(), MILLION);
        assert!(entry.all_invariants_verified());
    }

    #[test]
    fn test_entry_no_invariants_full_coverage() {
        let a = SemanticTransportAnalyzer::new();
        let spec = TransportEntrySpec {
            fragment_name: "test".to_string(),
            domain: ContractDomain::Hook,
            source_version: v(0, 1, 0),
            target_version: v(0, 2, 0),
            behavioral_deltas: vec![],
            required_invariants: vec![],
            verified_invariants: vec![],
            broken_invariants: vec![],
        };
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        let entry = &result.ledger.entries[0];
        assert_eq!(entry.invariant_coverage_millionths(), MILLION);
    }

    // =========================================================================
    // Ledger helpers
    // =========================================================================

    #[test]
    fn test_ledger_entries_by_domain() {
        let a = SemanticTransportAnalyzer::new();
        let mut s1 = simple_spec("hook1", vec![]);
        s1.domain = ContractDomain::Hook;
        let mut s2 = simple_spec("effect1", vec![]);
        s2.domain = ContractDomain::Effect;
        let input = simple_input(vec![s1, s2]);
        let result = a.analyze(&input).unwrap();

        let hooks = result.ledger.entries_by_domain(&ContractDomain::Hook);
        assert_eq!(hooks.len(), 1);
        let effects = result.ledger.entries_by_domain(&ContractDomain::Effect);
        assert_eq!(effects.len(), 1);
    }

    #[test]
    fn test_ledger_version_pairs() {
        let a = SemanticTransportAnalyzer::new();
        let spec = simple_spec("test", vec![]);
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        let pairs = result.ledger.version_pairs();
        assert_eq!(pairs.len(), 1);
    }

    #[test]
    fn test_ledger_all_debt_codes() {
        let a = SemanticTransportAnalyzer::new();
        let s1 = simple_spec("unchanged", vec![]);
        let s2 = simple_spec("adapted", vec![delta(200_000, true)]);
        let input = simple_input(vec![s1, s2]);
        let result = a.analyze(&input).unwrap();
        let codes = result.ledger.all_debt_codes();
        assert!(codes.contains(DEBT_ADAPTER_REQUIRED));
    }

    // =========================================================================
    // Report rendering
    // =========================================================================

    #[test]
    fn test_render_report_empty() {
        let a = SemanticTransportAnalyzer::new();
        let input = simple_input(vec![]);
        let result = a.analyze(&input).unwrap();
        let report = render_transport_report(&result);
        assert!(report.contains("Nothing to analyze"));
    }

    #[test]
    fn test_render_report_with_entries() {
        let a = SemanticTransportAnalyzer::new();
        let input = simple_input(vec![
            simple_spec("frag1", vec![]),
            simple_spec("frag2", vec![delta(200_000, true)]),
        ]);
        let result = a.analyze(&input).unwrap();
        let report = render_transport_report(&result);
        assert!(report.contains("unchanged"));
        assert!(report.contains("adapter-required"));
        assert!(report.contains("Result hash"));
    }

    // =========================================================================
    // RegressionMask helpers
    // =========================================================================

    #[test]
    fn test_regression_mask_is_high_risk() {
        let mask = RegressionMask {
            id: derive_id(
                ObjectDomain::EvidenceRecord,
                "test",
                &SchemaId::from_definition(b"test"),
                b"test",
            )
            .unwrap(),
            entry_id: derive_id(
                ObjectDomain::EvidenceRecord,
                "test",
                &SchemaId::from_definition(b"test"),
                b"test2",
            )
            .unwrap(),
            morphism_id: None,
            masked_aspect: "timing".to_string(),
            reason: "test reason".to_string(),
            risk_millionths: 800_000,
            debt_code: DEBT_REGRESSION_MASKED.to_string(),
            evidence_hash: ContentHash::compute(b"test"),
        };
        assert!(mask.is_high_risk());
    }

    // =========================================================================
    // Schema/bead constants
    // =========================================================================

    #[test]
    fn test_constants() {
        assert_eq!(
            TRANSPORT_LEDGER_SCHEMA_VERSION,
            "franken-engine.semantic_transport_ledger.v1"
        );
        assert_eq!(TRANSPORT_LEDGER_BEAD_ID, "bd-mjh3.14.4");
    }

    #[test]
    fn test_debt_code_format() {
        assert!(DEBT_TRANSPORT_INCOMPATIBLE.starts_with("FE-FRX-14-4-"));
        assert!(DEBT_ADAPTER_REQUIRED.starts_with("FE-FRX-14-4-"));
        assert!(DEBT_REGRESSION_MASKED.starts_with("FE-FRX-14-4-"));
        assert!(DEBT_MORPHISM_UNVERIFIED.starts_with("FE-FRX-14-4-"));
        assert!(DEBT_BUDGET_EXHAUSTED.starts_with("FE-FRX-14-4-"));
    }

    // =========================================================================
    // CompatibilityMorphism helpers
    // =========================================================================

    #[test]
    fn test_morphism_summary_line() {
        let a = SemanticTransportAnalyzer::new();
        let input = TransportAnalysisInput {
            entries: vec![],
            morphisms: vec![MorphismSpec {
                name: "test-morph".to_string(),
                domain: ContractDomain::Effect,
                source_version: v(0, 1, 0),
                target_version: v(0, 2, 0),
                preserved_invariants: vec!["inv".to_string()],
                broken_invariants: vec![],
                verified: true,
                description: "Test.".to_string(),
                adapter_ref: None,
            }],
            epoch: 1,
        };
        let result = a.analyze(&input).unwrap();
        let summary = result.ledger.morphisms[0].summary_line();
        assert!(summary.contains("safe"));
        assert!(summary.contains("test-morph"));
    }

    // =========================================================================
    // Entry summary line
    // =========================================================================

    #[test]
    fn test_entry_summary_line() {
        let a = SemanticTransportAnalyzer::new();
        let spec = simple_spec("test-entry", vec![delta(200_000, true)]);
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        let summary = result.ledger.entries[0].summary_line();
        assert!(summary.contains("test-entry"));
        assert!(summary.contains("adapter-required"));
    }

    // =========================================================================
    // Ledger summary line
    // =========================================================================

    #[test]
    fn test_ledger_summary_line() {
        let ledger = SemanticTransportLedger::new(1);
        let s = ledger.summary_line();
        assert!(s.contains("0 entries"));
    }

    // =========================================================================
    // High threshold - entries below threshold still get adapter
    // =========================================================================

    #[test]
    fn test_high_severity_bridgeable_gets_adapter() {
        let a = SemanticTransportAnalyzer::new();
        let spec = simple_spec("test", vec![delta(800_000, true)]);
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        assert_eq!(
            result.ledger.entries[0].verdict,
            TransportVerdict::AdapterRequired
        );
    }

    #[test]
    fn test_high_severity_unbridgeable_gets_incompatible() {
        let a = SemanticTransportAnalyzer::new();
        let spec = simple_spec("test", vec![delta(400_000, true), delta(400_000, false)]);
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        assert_eq!(
            result.ledger.entries[0].verdict,
            TransportVerdict::Incompatible
        );
    }

    // =========================================================================
    // Enrichment: ledger coverage_millionths
    // =========================================================================

    #[test]
    fn test_ledger_coverage_empty() {
        let ledger = SemanticTransportLedger::new(1);
        assert_eq!(ledger.coverage_millionths(), 0);
    }

    #[test]
    fn test_ledger_coverage_all_known() {
        let a = SemanticTransportAnalyzer::new();
        let input = simple_input(vec![
            simple_spec("frag1", vec![]),
            simple_spec("frag2", vec![delta(200_000, true)]),
        ]);
        let result = a.analyze(&input).unwrap();
        assert_eq!(result.ledger.coverage_millionths(), MILLION);
    }

    // =========================================================================
    // Enrichment: ledger high_risk_masks
    // =========================================================================

    #[test]
    fn test_ledger_high_risk_masks() {
        let a = SemanticTransportAnalyzer::new();
        let input = TransportAnalysisInput {
            entries: vec![TransportEntrySpec {
                fragment_name: "hook.cleanup".to_string(),
                domain: ContractDomain::Hook,
                source_version: v(0, 1, 0),
                target_version: v(0, 2, 0),
                behavioral_deltas: vec![delta(300_000, true)],
                required_invariants: vec!["inv1".to_string(), "inv2".to_string()],
                verified_invariants: vec!["inv1".to_string(), "inv2".to_string()],
                broken_invariants: vec![],
            }],
            morphisms: vec![MorphismSpec {
                name: "lossy-adapter".to_string(),
                domain: ContractDomain::Hook,
                source_version: v(0, 1, 0),
                target_version: v(0, 2, 0),
                preserved_invariants: vec!["inv1".to_string()],
                broken_invariants: vec!["inv2".to_string()],
                verified: true,
                description: "Lossy.".to_string(),
                adapter_ref: None,
            }],
            epoch: 1,
        };
        let result = a.analyze(&input).unwrap();
        let high = result.ledger.high_risk_masks();
        assert!(!high.is_empty());
        assert!(high[0].is_high_risk());
    }

    // =========================================================================
    // Enrichment: transport entry debt codes per verdict
    // =========================================================================

    #[test]
    fn test_entry_debt_code_incompatible() {
        let a = SemanticTransportAnalyzer::new();
        let mut spec = simple_spec("test", vec![]);
        spec.broken_invariants = vec!["broken".to_string()];
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        assert_eq!(
            result.ledger.entries[0].debt_code.as_deref(),
            Some(DEBT_TRANSPORT_INCOMPATIBLE),
        );
    }

    #[test]
    fn test_entry_debt_code_adapter_required() {
        let a = SemanticTransportAnalyzer::new();
        let spec = simple_spec("test", vec![delta(300_000, true)]);
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        assert_eq!(
            result.ledger.entries[0].debt_code.as_deref(),
            Some(DEBT_ADAPTER_REQUIRED),
        );
    }

    #[test]
    fn test_entry_debt_code_unchanged_is_none() {
        let a = SemanticTransportAnalyzer::new();
        let spec = simple_spec("test", vec![]);
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        assert!(result.ledger.entries[0].debt_code.is_none());
    }

    // =========================================================================
    // Enrichment: morphism safety variants
    // =========================================================================

    #[test]
    fn test_morphism_unverified_not_lossy_is_not_safe() {
        let a = SemanticTransportAnalyzer::new();
        let input = TransportAnalysisInput {
            entries: vec![],
            morphisms: vec![MorphismSpec {
                name: "unverified-adapter".to_string(),
                domain: ContractDomain::Effect,
                source_version: v(0, 1, 0),
                target_version: v(0, 2, 0),
                preserved_invariants: vec!["inv".to_string()],
                broken_invariants: vec![],
                verified: false,
                description: "Untested.".to_string(),
                adapter_ref: None,
            }],
            epoch: 1,
        };
        let result = a.analyze(&input).unwrap();
        let m = &result.ledger.morphisms[0];
        assert!(!m.is_safe());
        assert!(!m.lossy);
        assert!(!m.verified);
    }

    #[test]
    fn test_morphism_summary_unverified_shows_label() {
        let a = SemanticTransportAnalyzer::new();
        let input = TransportAnalysisInput {
            entries: vec![],
            morphisms: vec![MorphismSpec {
                name: "unverified".to_string(),
                domain: ContractDomain::Context,
                source_version: v(1, 0, 0),
                target_version: v(2, 0, 0),
                preserved_invariants: vec![],
                broken_invariants: vec![],
                verified: false,
                description: "Not tested.".to_string(),
                adapter_ref: None,
            }],
            epoch: 1,
        };
        let result = a.analyze(&input).unwrap();
        let summary = result.ledger.morphisms[0].summary_line();
        assert!(summary.contains("UNVERIFIED"));
    }

    #[test]
    fn test_morphism_summary_verified_lossy() {
        let a = SemanticTransportAnalyzer::new();
        let input = TransportAnalysisInput {
            entries: vec![],
            morphisms: vec![MorphismSpec {
                name: "lossy-verified".to_string(),
                domain: ContractDomain::Suspense,
                source_version: v(0, 1, 0),
                target_version: v(0, 2, 0),
                preserved_invariants: vec!["a".to_string()],
                broken_invariants: vec!["b".to_string()],
                verified: true,
                description: "Lossy.".to_string(),
                adapter_ref: None,
            }],
            epoch: 1,
        };
        let result = a.analyze(&input).unwrap();
        let summary = result.ledger.morphisms[0].summary_line();
        assert!(summary.contains("verified-lossy"));
    }

    // =========================================================================
    // Enrichment: regression mask summary line
    // =========================================================================

    #[test]
    fn test_regression_mask_summary_line() {
        let mask = RegressionMask {
            id: derive_id(
                ObjectDomain::EvidenceRecord,
                "test",
                &SchemaId::from_definition(b"test"),
                b"test",
            )
            .unwrap(),
            entry_id: derive_id(
                ObjectDomain::EvidenceRecord,
                "test",
                &SchemaId::from_definition(b"test"),
                b"test2",
            )
            .unwrap(),
            morphism_id: None,
            masked_aspect: "effect.timing".to_string(),
            reason: "lossy morphism detected".to_string(),
            risk_millionths: 750_000,
            debt_code: DEBT_REGRESSION_MASKED.to_string(),
            evidence_hash: ContentHash::compute(b"mask-test"),
        };
        let s = mask.summary_line();
        assert!(s.contains("MASK:"));
        assert!(s.contains("effect.timing"));
        assert!(s.contains("750000"));
    }

    // =========================================================================
    // Enrichment: confidence computation
    // =========================================================================

    #[test]
    fn test_confidence_with_no_invariants() {
        let a = SemanticTransportAnalyzer::new();
        let spec = TransportEntrySpec {
            fragment_name: "no-inv".to_string(),
            domain: ContractDomain::Portal,
            source_version: v(0, 1, 0),
            target_version: v(0, 2, 0),
            behavioral_deltas: vec![],
            required_invariants: vec![],
            verified_invariants: vec![],
            broken_invariants: vec![],
        };
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        assert_eq!(result.ledger.entries[0].confidence_millionths, 500_000);
    }

    #[test]
    fn test_confidence_proportional_to_verified() {
        let a = SemanticTransportAnalyzer::new();
        let spec = TransportEntrySpec {
            fragment_name: "partial-inv".to_string(),
            domain: ContractDomain::Ref,
            source_version: v(0, 1, 0),
            target_version: v(0, 2, 0),
            behavioral_deltas: vec![],
            required_invariants: vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
            ],
            verified_invariants: vec!["a".to_string()],
            broken_invariants: vec![],
        };
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        assert_eq!(result.ledger.entries[0].confidence_millionths, 250_000);
    }

    // =========================================================================
    // Enrichment: should_block_gate for non-blocking outcomes
    // =========================================================================

    #[test]
    fn test_should_not_block_gate_compatible_with_adapters() {
        let a = SemanticTransportAnalyzer::new();
        let spec = simple_spec("test", vec![delta(200_000, true)]);
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        assert_eq!(
            result.outcome,
            TransportAnalysisOutcome::CompatibleWithAdapters,
        );
        assert!(!should_block_gate(&result));
    }

    // =========================================================================
    // Enrichment: render report with morphisms and masks sections
    // =========================================================================

    #[test]
    fn test_render_report_with_morphisms() {
        let a = SemanticTransportAnalyzer::new();
        let input = TransportAnalysisInput {
            entries: vec![],
            morphisms: vec![MorphismSpec {
                name: "report-morph".to_string(),
                domain: ContractDomain::Effect,
                source_version: v(0, 1, 0),
                target_version: v(0, 2, 0),
                preserved_invariants: vec!["inv".to_string()],
                broken_invariants: vec![],
                verified: true,
                description: "Test.".to_string(),
                adapter_ref: None,
            }],
            epoch: 42,
        };
        let result = a.analyze(&input).unwrap();
        let report = render_transport_report(&result);
        assert!(report.contains("Morphisms"));
        assert!(report.contains("report-morph"));
    }

    #[test]
    fn test_render_report_with_regression_masks() {
        let a = SemanticTransportAnalyzer::new();
        let input = TransportAnalysisInput {
            entries: vec![TransportEntrySpec {
                fragment_name: "hook.order".to_string(),
                domain: ContractDomain::Hook,
                source_version: v(0, 1, 0),
                target_version: v(0, 2, 0),
                behavioral_deltas: vec![],
                required_invariants: vec!["inv1".to_string(), "inv2".to_string()],
                verified_invariants: vec!["inv1".to_string()],
                broken_invariants: vec![],
            }],
            morphisms: vec![],
            epoch: 1,
        };
        let result = a.analyze(&input).unwrap();
        let report = render_transport_report(&result);
        assert!(report.contains("Regression Masks"));
    }

    // =========================================================================
    // Enrichment: serde round-trip for enums
    // =========================================================================

    #[test]
    fn test_all_contract_domains_serde() {
        let domains = [
            ContractDomain::Hook,
            ContractDomain::Effect,
            ContractDomain::Context,
            ContractDomain::Capability,
            ContractDomain::Suspense,
            ContractDomain::Hydration,
            ContractDomain::ErrorBoundary,
            ContractDomain::Ref,
            ContractDomain::Portal,
        ];
        for d in &domains {
            let json = serde_json::to_string(d).unwrap();
            let back: ContractDomain = serde_json::from_str(&json).unwrap();
            assert_eq!(*d, back);
        }
    }

    #[test]
    fn test_all_transport_verdicts_serde() {
        let verdicts = [
            TransportVerdict::Unchanged,
            TransportVerdict::AdapterRequired,
            TransportVerdict::Incompatible,
            TransportVerdict::Unknown,
        ];
        for v in &verdicts {
            let json = serde_json::to_string(v).unwrap();
            let back: TransportVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn test_all_analysis_outcomes_serde() {
        let outcomes = [
            TransportAnalysisOutcome::FullyCompatible,
            TransportAnalysisOutcome::CompatibleWithAdapters,
            TransportAnalysisOutcome::HasIncompatibilities,
            TransportAnalysisOutcome::RegressionMaskDetected,
            TransportAnalysisOutcome::BudgetExhausted,
        ];
        for o in &outcomes {
            let json = serde_json::to_string(o).unwrap();
            let back: TransportAnalysisOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*o, back);
        }
    }

    #[test]
    fn test_transport_error_serde() {
        let errors = [
            TransportError::BudgetExhausted {
                resource: "entries".to_string(),
                limit: 100,
            },
            TransportError::DuplicateEntry("test".to_string()),
            TransportError::InvalidVersionPair("bad".to_string()),
            TransportError::MorphismConflict("conflict".to_string()),
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: TransportError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, back);
        }
    }

    // =========================================================================
    // Enrichment: VersionPair same version (equal)
    // =========================================================================

    #[test]
    fn test_version_pair_same_version() {
        let pair = VersionPair::new(v(1, 2, 3), v(1, 2, 3));
        assert!(pair.is_same_major());
        assert!(!pair.is_upgrade());
        assert!(!pair.is_downgrade());
    }

    // =========================================================================
    // Enrichment: ledger incompatible_count and adapter_required_count
    // =========================================================================

    #[test]
    fn test_ledger_incompatible_and_adapter_counts() {
        let a = SemanticTransportAnalyzer::new();
        let s1 = simple_spec("hook1", vec![]);
        let s2 = simple_spec("hook2", vec![delta(200_000, true)]);
        let mut s3 = simple_spec("hook3", vec![]);
        s3.broken_invariants = vec!["broken".to_string()];
        let mut s4 = simple_spec("hook4", vec![]);
        s4.broken_invariants = vec!["also-broken".to_string()];
        let input = simple_input(vec![s1, s2, s3, s4]);
        let result = a.analyze(&input).unwrap();

        assert_eq!(result.ledger.unchanged_count(), 1);
        assert_eq!(result.ledger.adapter_required_count(), 1);
        assert_eq!(result.ledger.incompatible_count(), 2);
        assert_eq!(result.ledger.entry_count(), 4);
    }

    // =========================================================================
    // Enrichment: analysis result summary line
    // =========================================================================

    #[test]
    fn test_analysis_result_summary_line() {
        let a = SemanticTransportAnalyzer::new();
        let input = simple_input(vec![
            simple_spec("f1", vec![]),
            simple_spec("f2", vec![delta(200_000, true)]),
        ]);
        let result = a.analyze(&input).unwrap();
        let s = result.summary_line();
        assert!(s.contains("compatible-with-adapters"));
        assert!(s.contains("2 entries"));
    }

    // =========================================================================
    // Enrichment: behavioral delta serde
    // =========================================================================

    #[test]
    fn test_behavioral_delta_serde() {
        let d = delta(500_000, true);
        let json = serde_json::to_string(&d).unwrap();
        let back: BehavioralDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // =========================================================================
    // Enrichment: version pair serde
    // =========================================================================

    #[test]
    fn test_version_pair_serde() {
        let pair = VersionPair::new(v(1, 2, 3), v(4, 5, 6));
        let json = serde_json::to_string(&pair).unwrap();
        let back: VersionPair = serde_json::from_str(&json).unwrap();
        assert_eq!(pair, back);
    }

    // =========================================================================
    // Enrichment: morphism with adapter_ref
    // =========================================================================

    #[test]
    fn test_morphism_with_adapter_ref() {
        let a = SemanticTransportAnalyzer::new();
        let input = TransportAnalysisInput {
            entries: vec![],
            morphisms: vec![MorphismSpec {
                name: "ref-adapter".to_string(),
                domain: ContractDomain::Hydration,
                source_version: v(0, 1, 0),
                target_version: v(0, 2, 0),
                preserved_invariants: vec!["inv".to_string()],
                broken_invariants: vec![],
                verified: true,
                description: "Has ref.".to_string(),
                adapter_ref: Some("adapters::hydration_v2".to_string()),
            }],
            epoch: 1,
        };
        let result = a.analyze(&input).unwrap();
        let m = &result.ledger.morphisms[0];
        assert_eq!(m.adapter_ref.as_deref(), Some("adapters::hydration_v2"));
    }

    // =========================================================================
    // Enrichment: can_release for all outcomes
    // =========================================================================

    #[test]
    fn test_can_release_has_incompatibilities() {
        let a = SemanticTransportAnalyzer::new();
        let mut spec = simple_spec("test", vec![]);
        spec.broken_invariants = vec!["broken".to_string()];
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        assert!(!result.can_release());
    }

    // =========================================================================
    // Enrichment: regression mask not high risk
    // =========================================================================

    #[test]
    fn test_regression_mask_below_threshold_not_high_risk() {
        let mask = RegressionMask {
            id: derive_id(
                ObjectDomain::EvidenceRecord,
                "test",
                &SchemaId::from_definition(b"test"),
                b"low-risk",
            )
            .unwrap(),
            entry_id: derive_id(
                ObjectDomain::EvidenceRecord,
                "test",
                &SchemaId::from_definition(b"test"),
                b"low-entry",
            )
            .unwrap(),
            morphism_id: None,
            masked_aspect: "timing".to_string(),
            reason: "low risk".to_string(),
            risk_millionths: 400_000,
            debt_code: DEBT_REGRESSION_MASKED.to_string(),
            evidence_hash: ContentHash::compute(b"low"),
        };
        assert!(!mask.is_high_risk());
    }

    // =========================================================================
    // Enrichment: multi-domain entries
    // =========================================================================

    #[test]
    fn test_entries_across_all_domains() {
        let a = SemanticTransportAnalyzer::new();
        let domains = [
            ContractDomain::Hook,
            ContractDomain::Effect,
            ContractDomain::Context,
            ContractDomain::Capability,
            ContractDomain::Suspense,
            ContractDomain::Hydration,
            ContractDomain::ErrorBoundary,
            ContractDomain::Ref,
            ContractDomain::Portal,
        ];
        let specs: Vec<TransportEntrySpec> = domains
            .iter()
            .enumerate()
            .map(|(i, d)| TransportEntrySpec {
                fragment_name: format!("frag-{i}"),
                domain: d.clone(),
                source_version: v(0, 1, 0),
                target_version: v(0, 2, 0),
                behavioral_deltas: vec![],
                required_invariants: vec!["inv".to_string()],
                verified_invariants: vec!["inv".to_string()],
                broken_invariants: vec![],
            })
            .collect();
        let input = simple_input(specs);
        let result = a.analyze(&input).unwrap();
        assert_eq!(result.total_entries, 9);
        assert_eq!(result.outcome, TransportAnalysisOutcome::FullyCompatible);
        for d in &domains {
            assert_eq!(result.ledger.entries_by_domain(d).len(), 1);
        }
    }

    // =========================================================================
    // Enrichment: deterministic hash stability
    // =========================================================================

    #[test]
    fn test_different_inputs_different_hashes() {
        let a = SemanticTransportAnalyzer::new();
        let r1 = a
            .analyze(&simple_input(vec![simple_spec("frag-a", vec![])]))
            .unwrap();
        let r2 = a
            .analyze(&simple_input(vec![simple_spec("frag-b", vec![])]))
            .unwrap();
        assert_ne!(r1.result_hash, r2.result_hash);
        assert_ne!(r1.ledger.ledger_hash, r2.ledger.ledger_hash);
    }

    // =========================================================================
    // Enrichment: input spec serde round-trip
    // =========================================================================

    #[test]
    fn test_transport_analysis_input_serde() {
        let input = TransportAnalysisInput {
            entries: vec![simple_spec("test", vec![delta(100_000, true)])],
            morphisms: vec![MorphismSpec {
                name: "m1".to_string(),
                domain: ContractDomain::Hook,
                source_version: v(0, 1, 0),
                target_version: v(0, 2, 0),
                preserved_invariants: vec!["inv".to_string()],
                broken_invariants: vec![],
                verified: true,
                description: "Test.".to_string(),
                adapter_ref: None,
            }],
            epoch: 99,
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: TransportAnalysisInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    // -- Enrichment: PearlTower 2026-02-26 session 6 --

    #[test]
    fn test_can_release_budget_exhausted_is_false() {
        let config = TransportAnalyzerConfig {
            max_entries: 1,
            ..TransportAnalyzerConfig::default()
        };
        let a = SemanticTransportAnalyzer::with_config(config);
        let specs = vec![simple_spec("a", vec![]), simple_spec("b", vec![])];
        let input = simple_input(specs);
        let result = a.analyze(&input).unwrap();
        assert_eq!(result.outcome, TransportAnalysisOutcome::BudgetExhausted);
        assert!(!result.can_release());
    }

    #[test]
    fn test_can_release_regression_mask_detected_is_false() {
        // Create an adapter-required entry with a lossy morphism to trigger regression mask.
        let a = SemanticTransportAnalyzer::new();
        let spec = TransportEntrySpec {
            fragment_name: "masked-frag".to_string(),
            domain: ContractDomain::Hook,
            source_version: v(0, 1, 0),
            target_version: v(0, 2, 0),
            behavioral_deltas: vec![delta(200_000, true)],
            required_invariants: vec!["inv-a".to_string()],
            verified_invariants: vec!["inv-a".to_string()],
            broken_invariants: vec![],
        };
        let morph = MorphismSpec {
            name: "lossy-morph".to_string(),
            domain: ContractDomain::Hook,
            source_version: v(0, 1, 0),
            target_version: v(0, 2, 0),
            preserved_invariants: vec!["inv-a".to_string()],
            broken_invariants: vec!["inv-b".to_string()],
            verified: true,
            description: "Lossy adapter.".to_string(),
            adapter_ref: None,
        };
        let input = TransportAnalysisInput {
            entries: vec![spec],
            morphisms: vec![morph],
            epoch: 10,
        };
        let result = a.analyze(&input).unwrap();
        assert_eq!(
            result.outcome,
            TransportAnalysisOutcome::RegressionMaskDetected
        );
        assert!(!result.can_release());
    }

    #[test]
    fn test_coverage_millionths_partial_unknown() {
        let a = SemanticTransportAnalyzer::new();
        // Two entries: one unchanged (known), one with Unknown verdict.
        // simple_spec with no deltas → Unchanged. For Unknown, we need no deltas
        // but that gives Unchanged. The Unknown variant isn't produced by the
        // analyzer directly — it's a data-level concept. So we test the ledger
        // method directly by constructing a ledger.
        let spec_known = simple_spec("known", vec![]);
        let input = simple_input(vec![spec_known]);
        let mut result = a.analyze(&input).unwrap();
        // Manually add an Unknown entry to test coverage calculation.
        let unknown_entry = TransportEntry {
            id: result.ledger.entries[0].id.clone(),
            fragment_name: "unknown-frag".to_string(),
            domain: ContractDomain::Effect,
            version_pair: VersionPair::new(v(0, 1, 0), v(0, 2, 0)),
            verdict: TransportVerdict::Unknown,
            behavioral_deltas: vec![],
            required_invariants: vec![],
            verified_invariants: vec![],
            broken_invariants: vec![],
            debt_code: None,
            confidence_millionths: 0,
            entry_hash: ContentHash::compute(b"unknown"),
        };
        result.ledger.entries.push(unknown_entry);
        // 1 known out of 2 = 500_000
        assert_eq!(result.ledger.coverage_millionths(), 500_000);
    }

    #[test]
    fn test_version_pair_is_upgrade() {
        let pair = VersionPair::new(v(1, 0, 0), v(2, 0, 0));
        assert!(pair.is_upgrade());
        assert!(!pair.is_downgrade());

        let pair2 = VersionPair::new(v(1, 0, 0), v(1, 1, 0));
        assert!(pair2.is_upgrade());
        assert!(pair2.is_same_major());
    }

    #[test]
    fn test_all_debt_codes_includes_mask_codes() {
        let a = SemanticTransportAnalyzer::new();
        // Create conditions for regression mask (adapter + lossy morphism).
        let spec = TransportEntrySpec {
            fragment_name: "debt-test".to_string(),
            domain: ContractDomain::Context,
            source_version: v(0, 1, 0),
            target_version: v(0, 2, 0),
            behavioral_deltas: vec![delta(100_000, true)],
            required_invariants: vec!["i1".to_string()],
            verified_invariants: vec!["i1".to_string()],
            broken_invariants: vec![],
        };
        let morph = MorphismSpec {
            name: "lossy-for-debt".to_string(),
            domain: ContractDomain::Context,
            source_version: v(0, 1, 0),
            target_version: v(0, 2, 0),
            preserved_invariants: vec![],
            broken_invariants: vec!["dropped".to_string()],
            verified: true,
            description: "Test.".to_string(),
            adapter_ref: None,
        };
        let input = TransportAnalysisInput {
            entries: vec![spec],
            morphisms: vec![morph],
            epoch: 20,
        };
        let result = a.analyze(&input).unwrap();
        let codes = result.ledger.all_debt_codes();
        assert!(
            codes.contains(DEBT_REGRESSION_MASKED),
            "debt codes should include mask-side code"
        );
        assert!(
            codes.contains(DEBT_ADAPTER_REQUIRED),
            "debt codes should include entry-side code"
        );
    }

    #[test]
    fn test_entry_all_invariants_verified_false_with_broken() {
        // An entry with required_invariants == verified_invariants in count
        // but broken_invariants non-empty should return false.
        let a = SemanticTransportAnalyzer::new();
        let spec = TransportEntrySpec {
            fragment_name: "broken-check".to_string(),
            domain: ContractDomain::Hook,
            source_version: v(0, 1, 0),
            target_version: v(0, 2, 0),
            behavioral_deltas: vec![],
            required_invariants: vec!["i1".to_string()],
            verified_invariants: vec!["i1".to_string()],
            broken_invariants: vec!["i2".to_string()],
        };
        let input = simple_input(vec![spec]);
        let result = a.analyze(&input).unwrap();
        let entry = &result.ledger.entries[0];
        assert!(
            !entry.all_invariants_verified(),
            "broken_invariants non-empty means not all verified"
        );
    }

    #[test]
    fn test_render_report_groups_by_verdict() {
        let a = SemanticTransportAnalyzer::new();
        let specs = vec![
            simple_spec("unchanged-1", vec![]),
            simple_spec("adapted-1", vec![delta(100_000, true)]),
            {
                let mut s = simple_spec("incompat-1", vec![]);
                s.broken_invariants = vec!["broken".to_string()];
                s
            },
        ];
        let input = simple_input(specs);
        let result = a.analyze(&input).unwrap();
        let report = render_transport_report(&result);
        assert!(
            report.contains("incompatible"),
            "report should group incompatible entries"
        );
        assert!(
            report.contains("adapter-required"),
            "report should group adapter entries"
        );
        assert!(
            report.contains("unchanged"),
            "report should group unchanged entries"
        );
    }

    #[test]
    fn test_morphism_summary_safe_label() {
        // Verified, not lossy → "safe" in summary.
        let a = SemanticTransportAnalyzer::new();
        let morph_spec = MorphismSpec {
            name: "safe-morph".to_string(),
            domain: ContractDomain::Effect,
            source_version: v(0, 1, 0),
            target_version: v(0, 2, 0),
            preserved_invariants: vec!["i1".to_string()],
            broken_invariants: vec![],
            verified: true,
            description: "Safe transformation.".to_string(),
            adapter_ref: None,
        };
        let input = TransportAnalysisInput {
            entries: vec![],
            morphisms: vec![morph_spec],
            epoch: 30,
        };
        let result = a.analyze(&input).unwrap();
        let m = &result.ledger.morphisms[0];
        assert!(m.is_safe());
        assert!(m.summary_line().contains("safe"));
        assert!(!m.summary_line().contains("UNVERIFIED"));
    }
}
