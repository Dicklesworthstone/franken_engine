//! Bead: bd-1lsy.7.16.3 [RGC-616C]
//!
//! Gate hardware-board claims, promotion, and unsupported-hardware surfacing
//! on localization residuals.
//!
//! When a benchmark result or optimized artifact claims a speedup, this module
//! decomposes the observed improvement into:
//!
//! - **Hardware-attributable** gain: speedup from specific hardware features
//!   (AVX-512, NEON, large pages, etc.) that do not transfer to other
//!   microarchitectures.
//! - **Algorithmic** gain: speedup from genuine algorithmic improvement that
//!   transfers across hardware families.
//! - **Measurement noise**: variance explained by system jitter, scheduling,
//!   or thermal throttling.
//! - **Unexplained**: residual not accounted for by the other categories.
//!
//! Promotion is gated on the fraction of gain that is truly algorithmic:
//! cross-microarchitecture wins are only claimed where transport evidence
//! actually supports them.
//!
//! # Design
//!
//! - `LocalizationBoard` collects per-optimization entries across hardware
//!   families.
//! - `PromotionPolicy` configures the minimum algorithmic gain, maximum
//!   hardware-attributable fraction, and cross-ISA requirements.
//! - `LocalizationReport` is the auditable output, including a content hash.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-616C]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for localization residual artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.hardware-localization-residual.v1";

/// Component name for diagnostics and evidence linkage.
pub const COMPONENT: &str = "hardware_localization_residual";

/// Bead identifier.
pub const BEAD_ID: &str = "bd-1lsy.7.16.3";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-616C";

/// Fixed-point unit: 1.0 in millionths.
pub const MILLIONTHS: u64 = 1_000_000;

/// Default minimum algorithmic gain fraction required for promotion (millionths).
/// 600_000 = 60%: at least 60% of the observed speedup must be algorithmic.
pub const DEFAULT_MIN_ALGORITHMIC_GAIN: u64 = 600_000;

/// Default maximum hardware-attributable fraction before promotion is blocked (millionths).
/// 300_000 = 30%: if >30% of the speedup is hardware-attributable, promotion is denied.
pub const DEFAULT_MAX_HARDWARE_ATTRIBUTABLE: u64 = 300_000;

/// Default minimum number of distinct hardware families tested.
pub const DEFAULT_MIN_FAMILIES_TESTED: usize = 2;

/// Maximum localization entries per board.
pub const MAX_BOARD_ENTRIES: usize = 256;

/// Maximum unsupported-hardware entries per report.
pub const MAX_UNSUPPORTED_ENTRIES: usize = 64;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn append_str(buf: &mut Vec<u8>, val: &str) {
    let bytes = val.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn compute_digest(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

// ---------------------------------------------------------------------------
// HardwareFeature
// ---------------------------------------------------------------------------

/// Specific hardware feature that may contribute to localized speedup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareFeature {
    /// x86 Advanced Vector Extensions 2.
    Avx2,
    /// x86 512-bit vector extensions.
    Avx512,
    /// ARM NEON SIMD.
    Neon,
    /// ARM Scalable Vector Extension.
    Sve,
    /// Hardware population-count instruction.
    PopcntHw,
    /// x86 Bit Manipulation Instruction Set 2.
    Bmi2,
    /// Hardware AES acceleration.
    Aes,
    /// Hardware cache-line prefetch.
    CacheLinePrefetch,
    /// Non-Uniform Memory Access topology.
    Numa,
    /// OS-level large/huge pages.
    LargePages,
    /// Advanced branch predictor (TAGE or equivalent).
    BranchPredictor,
    /// Hardware SHA acceleration.
    Sha,
    /// x86 CLMUL carry-less multiply.
    Clmul,
}

impl HardwareFeature {
    /// All known hardware features.
    pub const ALL: &[Self] = &[
        Self::Avx2,
        Self::Avx512,
        Self::Neon,
        Self::Sve,
        Self::PopcntHw,
        Self::Bmi2,
        Self::Aes,
        Self::CacheLinePrefetch,
        Self::Numa,
        Self::LargePages,
        Self::BranchPredictor,
        Self::Sha,
        Self::Clmul,
    ];

    /// Stable string tag for this feature.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Avx2 => "avx2",
            Self::Avx512 => "avx512",
            Self::Neon => "neon",
            Self::Sve => "sve",
            Self::PopcntHw => "popcnt_hw",
            Self::Bmi2 => "bmi2",
            Self::Aes => "aes",
            Self::CacheLinePrefetch => "cache_line_prefetch",
            Self::Numa => "numa",
            Self::LargePages => "large_pages",
            Self::BranchPredictor => "branch_predictor",
            Self::Sha => "sha",
            Self::Clmul => "clmul",
        }
    }

    /// Whether this feature is x86-specific.
    pub const fn is_x86(self) -> bool {
        matches!(self, Self::Avx2 | Self::Avx512 | Self::Bmi2 | Self::Clmul)
    }

    /// Whether this feature is ARM-specific.
    pub const fn is_arm(self) -> bool {
        matches!(self, Self::Neon | Self::Sve)
    }

    /// Whether this feature is architecture-neutral (available on both).
    pub const fn is_neutral(self) -> bool {
        !self.is_x86() && !self.is_arm()
    }
}

impl fmt::Display for HardwareFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// MicroarchFamily
// ---------------------------------------------------------------------------

/// CPU microarchitecture family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicroarchFamily {
    /// AMD Zen 4.
    Zen4,
    /// AMD Zen 5.
    Zen5,
    /// Intel Alder Lake (hybrid).
    AlderLake,
    /// Intel Raptor Lake (hybrid).
    RaptorLake,
    /// AWS Graviton (ARM).
    GravitonArm,
    /// Apple Silicon (ARM).
    AppleM,
    /// Generic x86-64 (no specific microarch).
    GenericX64,
    /// Generic ARM64 (no specific microarch).
    GenericArm64,
}

impl MicroarchFamily {
    /// All known families.
    pub const ALL: &[Self] = &[
        Self::Zen4,
        Self::Zen5,
        Self::AlderLake,
        Self::RaptorLake,
        Self::GravitonArm,
        Self::AppleM,
        Self::GenericX64,
        Self::GenericArm64,
    ];

    /// Stable string tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Zen4 => "zen4",
            Self::Zen5 => "zen5",
            Self::AlderLake => "alder_lake",
            Self::RaptorLake => "raptor_lake",
            Self::GravitonArm => "graviton_arm",
            Self::AppleM => "apple_m",
            Self::GenericX64 => "generic_x64",
            Self::GenericArm64 => "generic_arm64",
        }
    }

    /// Whether this family is ARM-based.
    pub const fn is_arm(self) -> bool {
        matches!(self, Self::GravitonArm | Self::AppleM | Self::GenericArm64)
    }

    /// Whether this family is x86-based.
    pub const fn is_x86(self) -> bool {
        matches!(
            self,
            Self::Zen4 | Self::Zen5 | Self::AlderLake | Self::RaptorLake | Self::GenericX64
        )
    }

    /// Typical features available on this family.
    pub fn typical_features(self) -> BTreeSet<HardwareFeature> {
        let mut s = BTreeSet::new();
        match self {
            Self::Zen4 => {
                s.insert(HardwareFeature::Avx2);
                s.insert(HardwareFeature::Avx512);
                s.insert(HardwareFeature::PopcntHw);
                s.insert(HardwareFeature::Bmi2);
                s.insert(HardwareFeature::Aes);
                s.insert(HardwareFeature::BranchPredictor);
            }
            Self::Zen5 => {
                s.insert(HardwareFeature::Avx2);
                s.insert(HardwareFeature::Avx512);
                s.insert(HardwareFeature::PopcntHw);
                s.insert(HardwareFeature::Bmi2);
                s.insert(HardwareFeature::Aes);
                s.insert(HardwareFeature::BranchPredictor);
                s.insert(HardwareFeature::Sha);
            }
            Self::AlderLake | Self::RaptorLake => {
                s.insert(HardwareFeature::Avx2);
                s.insert(HardwareFeature::PopcntHw);
                s.insert(HardwareFeature::Bmi2);
                s.insert(HardwareFeature::Aes);
                s.insert(HardwareFeature::BranchPredictor);
            }
            Self::GravitonArm => {
                s.insert(HardwareFeature::Neon);
                s.insert(HardwareFeature::PopcntHw);
                s.insert(HardwareFeature::Aes);
                s.insert(HardwareFeature::Sha);
            }
            Self::AppleM => {
                s.insert(HardwareFeature::Neon);
                s.insert(HardwareFeature::PopcntHw);
                s.insert(HardwareFeature::Aes);
                s.insert(HardwareFeature::Sha);
                s.insert(HardwareFeature::BranchPredictor);
            }
            Self::GenericX64 => {
                s.insert(HardwareFeature::PopcntHw);
            }
            Self::GenericArm64 => {
                s.insert(HardwareFeature::Neon);
            }
        }
        s
    }
}

impl fmt::Display for MicroarchFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ResidualCategory
// ---------------------------------------------------------------------------

/// Category of residual in a localization decomposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidualCategory {
    /// Speedup attributable to hardware-specific features.
    HardwareAttributable,
    /// Speedup from genuine algorithmic improvement.
    AlgorithmicGain,
    /// Variance from measurement jitter, scheduling, thermals.
    MeasurementNoise,
    /// Residual not accounted for by the other categories.
    Unexplained,
}

impl ResidualCategory {
    /// All residual categories.
    pub const ALL: &[Self] = &[
        Self::HardwareAttributable,
        Self::AlgorithmicGain,
        Self::MeasurementNoise,
        Self::Unexplained,
    ];

    /// Stable string tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HardwareAttributable => "hardware_attributable",
            Self::AlgorithmicGain => "algorithmic_gain",
            Self::MeasurementNoise => "measurement_noise",
            Self::Unexplained => "unexplained",
        }
    }
}

impl fmt::Display for ResidualCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// LocalizationEntry
// ---------------------------------------------------------------------------

/// A single measurement entry in the localization board, recording a benchmark
/// observation on a specific hardware family with a residual decomposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalizationEntry {
    /// Hardware family this entry was measured on.
    pub hardware_family: MicroarchFamily,
    /// Hardware features required by the optimized code path.
    pub required_features: BTreeSet<HardwareFeature>,
    /// Baseline execution time in nanoseconds (un-optimized).
    pub baseline_ns: u64,
    /// Optimized execution time in nanoseconds.
    pub optimized_ns: u64,
    /// Residual breakdown: category -> fraction in millionths (must sum to ~MILLIONTHS).
    pub residual_breakdown: BTreeMap<ResidualCategory, u64>,
    /// Content hash sealing this entry.
    pub entry_hash: ContentHash,
}

impl LocalizationEntry {
    /// Create a new localization entry and compute its hash.
    pub fn new(
        hardware_family: MicroarchFamily,
        required_features: BTreeSet<HardwareFeature>,
        baseline_ns: u64,
        optimized_ns: u64,
        residual_breakdown: BTreeMap<ResidualCategory, u64>,
    ) -> Self {
        let mut entry = Self {
            hardware_family,
            required_features,
            baseline_ns,
            optimized_ns,
            residual_breakdown,
            entry_hash: ContentHash::compute(b""),
        };
        entry.seal();
        entry
    }

    /// Recompute the content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_str(&mut buf, self.hardware_family.as_str());
        for feat in &self.required_features {
            append_str(&mut buf, feat.as_str());
        }
        append_u64(&mut buf, self.baseline_ns);
        append_u64(&mut buf, self.optimized_ns);
        for (cat, val) in &self.residual_breakdown {
            append_str(&mut buf, cat.as_str());
            append_u64(&mut buf, *val);
        }
        self.entry_hash = compute_digest(&buf);
    }

    /// Observed speedup ratio in millionths. Returns 0 if baseline is zero
    /// or optimized >= baseline.
    pub fn speedup_millionths(&self) -> u64 {
        if self.baseline_ns == 0 || self.optimized_ns >= self.baseline_ns {
            return 0;
        }
        let saved = self.baseline_ns - self.optimized_ns;
        saved
            .saturating_mul(MILLIONTHS)
            .checked_div(self.baseline_ns)
            .unwrap_or(0)
    }

    /// Fraction of the residual attributed to algorithmic gain (millionths).
    pub fn algorithmic_fraction(&self) -> u64 {
        self.residual_breakdown
            .get(&ResidualCategory::AlgorithmicGain)
            .copied()
            .unwrap_or(0)
    }

    /// Fraction of the residual attributed to hardware (millionths).
    pub fn hardware_fraction(&self) -> u64 {
        self.residual_breakdown
            .get(&ResidualCategory::HardwareAttributable)
            .copied()
            .unwrap_or(0)
    }

    /// Sum of all residual fractions.
    pub fn residual_sum(&self) -> u64 {
        self.residual_breakdown.values().sum()
    }

    /// Whether this entry's required features are all available on the given
    /// hardware family (based on typical features).
    pub fn features_available_on(&self, family: MicroarchFamily) -> bool {
        let typical = family.typical_features();
        self.required_features.is_subset(&typical)
    }
}

impl fmt::Display for LocalizationEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}ns->{}ns (algo={}%, hw={}%)",
            self.hardware_family,
            self.baseline_ns,
            self.optimized_ns,
            self.algorithmic_fraction() / 10_000,
            self.hardware_fraction() / 10_000,
        )
    }
}

// ---------------------------------------------------------------------------
// PromotionPolicy
// ---------------------------------------------------------------------------

/// Policy governing when an optimization may be promoted (claimed as a
/// cross-architecture win).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionPolicy {
    /// Minimum algorithmic-gain fraction across all entries (millionths).
    pub min_algorithmic_gain_millionths: u64,
    /// Maximum hardware-attributable fraction across any entry (millionths).
    pub max_hardware_attributable_millionths: u64,
    /// Minimum number of distinct hardware families tested.
    pub min_hardware_families_tested: usize,
    /// Whether both ARM and x86 families must be present.
    pub require_arm_and_x64: bool,
    /// Maximum allowed measurement noise fraction (millionths).
    /// If any entry exceeds this, evidence quality is insufficient.
    pub max_noise_millionths: u64,
    /// Maximum allowed unexplained fraction (millionths).
    pub max_unexplained_millionths: u64,
}

impl PromotionPolicy {
    /// Strict policy suitable for production promotion gates.
    pub fn strict() -> Self {
        Self {
            min_algorithmic_gain_millionths: DEFAULT_MIN_ALGORITHMIC_GAIN,
            max_hardware_attributable_millionths: DEFAULT_MAX_HARDWARE_ATTRIBUTABLE,
            min_hardware_families_tested: 3,
            require_arm_and_x64: true,
            max_noise_millionths: 100_000,       // 10%
            max_unexplained_millionths: 100_000, // 10%
        }
    }

    /// Relaxed policy for development / CI use.
    pub fn relaxed() -> Self {
        Self {
            min_algorithmic_gain_millionths: 400_000,      // 40%
            max_hardware_attributable_millionths: 500_000, // 50%
            min_hardware_families_tested: DEFAULT_MIN_FAMILIES_TESTED,
            require_arm_and_x64: false,
            max_noise_millionths: 200_000,       // 20%
            max_unexplained_millionths: 200_000, // 20%
        }
    }
}

impl Default for PromotionPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

// ---------------------------------------------------------------------------
// PromotionVerdict
// ---------------------------------------------------------------------------

/// Outcome of promotion evaluation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionVerdict {
    /// Optimization is promotable: algorithmic gain dominates.
    Promotable,
    /// Too much of the speedup comes from hardware locality.
    HardwareDependent,
    /// Not enough hardware families were tested.
    InsufficientEvidence,
    /// Rejected for one or more policy violations.
    Rejected,
}

impl PromotionVerdict {
    /// Stable string tag.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Promotable => "promotable",
            Self::HardwareDependent => "hardware_dependent",
            Self::InsufficientEvidence => "insufficient_evidence",
            Self::Rejected => "rejected",
        }
    }

    /// Whether this is a passing verdict.
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Promotable)
    }
}

impl fmt::Display for PromotionVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RejectionDetail
// ---------------------------------------------------------------------------

/// Detailed reason for a non-promotable verdict.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionDetail {
    /// Algorithmic gain below threshold.
    AlgorithmicGainTooLow {
        observed_millionths: u64,
        threshold_millionths: u64,
    },
    /// Hardware-attributable fraction too high.
    HardwareAttributableTooHigh {
        observed_millionths: u64,
        threshold_millionths: u64,
    },
    /// Not enough hardware families tested.
    TooFewFamilies { tested: usize, required: usize },
    /// Missing required ISA coverage.
    MissingIsaCoverage { has_arm: bool, has_x64: bool },
    /// Measurement noise too high on a specific entry.
    ExcessiveNoise {
        family: MicroarchFamily,
        noise_millionths: u64,
        threshold_millionths: u64,
    },
    /// Unexplained residual too high.
    ExcessiveUnexplained {
        family: MicroarchFamily,
        unexplained_millionths: u64,
        threshold_millionths: u64,
    },
    /// No entries in the board.
    EmptyBoard,
    /// No speedup observed (optimized >= baseline on all entries).
    NoSpeedupObserved,
}

impl fmt::Display for RejectionDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlgorithmicGainTooLow {
                observed_millionths,
                threshold_millionths,
            } => write!(
                f,
                "algorithmic gain {observed_millionths} < threshold {threshold_millionths}"
            ),
            Self::HardwareAttributableTooHigh {
                observed_millionths,
                threshold_millionths,
            } => write!(
                f,
                "hardware attributable {observed_millionths} > threshold {threshold_millionths}"
            ),
            Self::TooFewFamilies { tested, required } => {
                write!(f, "tested {tested} families, need {required}")
            }
            Self::MissingIsaCoverage { has_arm, has_x64 } => {
                write!(f, "ISA coverage: arm={has_arm}, x64={has_x64}")
            }
            Self::ExcessiveNoise {
                family,
                noise_millionths,
                threshold_millionths,
            } => write!(
                f,
                "noise on {family}: {noise_millionths} > {threshold_millionths}"
            ),
            Self::ExcessiveUnexplained {
                family,
                unexplained_millionths,
                threshold_millionths,
            } => write!(
                f,
                "unexplained on {family}: {unexplained_millionths} > {threshold_millionths}"
            ),
            Self::EmptyBoard => write!(f, "no entries in board"),
            Self::NoSpeedupObserved => write!(f, "no speedup observed"),
        }
    }
}

// ---------------------------------------------------------------------------
// UnsupportedHardwareEntry
// ---------------------------------------------------------------------------

/// Record of a hardware family that cannot run the optimized code path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedHardwareEntry {
    /// Hardware family.
    pub family: MicroarchFamily,
    /// Features missing on this family that the optimization requires.
    pub missing_features: BTreeSet<HardwareFeature>,
    /// Estimated performance regression if fallback is used (millionths).
    pub estimated_regression_millionths: u64,
    /// Whether a software fallback is available.
    pub fallback_available: bool,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl UnsupportedHardwareEntry {
    /// Create a new entry with computed hash.
    pub fn new(
        family: MicroarchFamily,
        missing_features: BTreeSet<HardwareFeature>,
        estimated_regression_millionths: u64,
        fallback_available: bool,
    ) -> Self {
        let mut entry = Self {
            family,
            missing_features,
            estimated_regression_millionths,
            fallback_available,
            content_hash: ContentHash::compute(b""),
        };
        entry.seal();
        entry
    }

    /// Recompute content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_str(&mut buf, self.family.as_str());
        for feat in &self.missing_features {
            append_str(&mut buf, feat.as_str());
        }
        append_u64(&mut buf, self.estimated_regression_millionths);
        buf.push(if self.fallback_available { 1 } else { 0 });
        self.content_hash = compute_digest(&buf);
    }
}

impl fmt::Display for UnsupportedHardwareEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} missing feature(s), regression={}%, fallback={}",
            self.family,
            self.missing_features.len(),
            self.estimated_regression_millionths / 10_000,
            self.fallback_available,
        )
    }
}

// ---------------------------------------------------------------------------
// LocalizationBoard
// ---------------------------------------------------------------------------

/// Collects localization entries for a single optimization and evaluates
/// promotion readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalizationBoard {
    /// Identifier for the optimization being evaluated.
    pub optimization_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Collected localization entries.
    pub entries: Vec<LocalizationEntry>,
    /// Policy for promotion evaluation.
    pub policy: PromotionPolicy,
    /// Content hash of the board state.
    pub content_hash: ContentHash,
}

impl LocalizationBoard {
    /// Create a new empty board.
    pub fn new(
        optimization_id: impl Into<String>,
        epoch: SecurityEpoch,
        policy: PromotionPolicy,
    ) -> Self {
        let optimization_id = optimization_id.into();
        let mut board = Self {
            optimization_id,
            epoch,
            entries: Vec::new(),
            policy,
            content_hash: ContentHash::compute(b""),
        };
        board.seal();
        board
    }

    /// Add a localization entry. Returns false if the board is full.
    pub fn add_entry(&mut self, entry: LocalizationEntry) -> bool {
        if self.entries.len() >= MAX_BOARD_ENTRIES {
            return false;
        }
        self.entries.push(entry);
        self.seal();
        true
    }

    /// Number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Distinct hardware families represented.
    pub fn distinct_families(&self) -> BTreeSet<MicroarchFamily> {
        self.entries.iter().map(|e| e.hardware_family).collect()
    }

    /// Number of distinct families.
    pub fn family_count(&self) -> usize {
        self.distinct_families().len()
    }

    /// Whether both ARM and x86 families are represented.
    pub fn has_arm_and_x64(&self) -> bool {
        let families = self.distinct_families();
        let has_arm = families.iter().any(|f| f.is_arm());
        let has_x64 = families.iter().any(|f| f.is_x86());
        has_arm && has_x64
    }

    /// Average algorithmic gain across all entries (millionths).
    pub fn avg_algorithmic_gain(&self) -> u64 {
        if self.entries.is_empty() {
            return 0;
        }
        let total: u64 = self.entries.iter().map(|e| e.algorithmic_fraction()).sum();
        total / self.entries.len() as u64
    }

    /// Maximum hardware-attributable fraction across all entries (millionths).
    pub fn max_hardware_attributable(&self) -> u64 {
        self.entries
            .iter()
            .map(|e| e.hardware_fraction())
            .max()
            .unwrap_or(0)
    }

    /// Average speedup across all entries (millionths).
    pub fn avg_speedup(&self) -> u64 {
        if self.entries.is_empty() {
            return 0;
        }
        let total: u64 = self.entries.iter().map(|e| e.speedup_millionths()).sum();
        total / self.entries.len() as u64
    }

    /// Identify unsupported hardware families based on required features
    /// across all entries. For each family not already tested, checks whether
    /// the union of required features across entries is available.
    pub fn identify_unsupported_hardware(&self) -> Vec<UnsupportedHardwareEntry> {
        let tested = self.distinct_families();

        // Union of all required features across entries.
        let mut all_required = BTreeSet::new();
        for entry in &self.entries {
            for feat in &entry.required_features {
                all_required.insert(*feat);
            }
        }

        let mut unsupported = Vec::new();
        for family in MicroarchFamily::ALL {
            if tested.contains(family) {
                continue;
            }
            let typical = family.typical_features();
            let missing: BTreeSet<HardwareFeature> = all_required
                .iter()
                .filter(|f| !typical.contains(f))
                .copied()
                .collect();

            if !missing.is_empty() {
                // Estimate regression: proportional to missing features.
                let regression = missing.len() as u64 * 50_000; // 5% per missing feature as heuristic

                // Fallback available if at most half the features are missing.
                let fallback = missing.len() * 2 <= all_required.len();

                unsupported.push(UnsupportedHardwareEntry::new(
                    *family, missing, regression, fallback,
                ));
            }
        }
        unsupported
    }

    /// Evaluate promotion readiness against the configured policy.
    pub fn evaluate_promotion(&self) -> (PromotionVerdict, Vec<RejectionDetail>) {
        let mut details = Vec::new();

        // Empty board.
        if self.entries.is_empty() {
            details.push(RejectionDetail::EmptyBoard);
            return (PromotionVerdict::InsufficientEvidence, details);
        }

        // Check for any speedup.
        let has_speedup = self.entries.iter().any(|e| e.speedup_millionths() > 0);
        if !has_speedup {
            details.push(RejectionDetail::NoSpeedupObserved);
            return (PromotionVerdict::Rejected, details);
        }

        // Family count.
        let fam_count = self.family_count();
        if fam_count < self.policy.min_hardware_families_tested {
            details.push(RejectionDetail::TooFewFamilies {
                tested: fam_count,
                required: self.policy.min_hardware_families_tested,
            });
        }

        // ARM + x64 requirement.
        if self.policy.require_arm_and_x64 {
            let families = self.distinct_families();
            let has_arm = families.iter().any(|f| f.is_arm());
            let has_x64 = families.iter().any(|f| f.is_x86());
            if !has_arm || !has_x64 {
                details.push(RejectionDetail::MissingIsaCoverage { has_arm, has_x64 });
            }
        }

        // Algorithmic gain check.
        let avg_algo = self.avg_algorithmic_gain();
        if avg_algo < self.policy.min_algorithmic_gain_millionths {
            details.push(RejectionDetail::AlgorithmicGainTooLow {
                observed_millionths: avg_algo,
                threshold_millionths: self.policy.min_algorithmic_gain_millionths,
            });
        }

        // Hardware-attributable check.
        let max_hw = self.max_hardware_attributable();
        if max_hw > self.policy.max_hardware_attributable_millionths {
            details.push(RejectionDetail::HardwareAttributableTooHigh {
                observed_millionths: max_hw,
                threshold_millionths: self.policy.max_hardware_attributable_millionths,
            });
        }

        // Per-entry noise and unexplained checks.
        for entry in &self.entries {
            let noise = entry
                .residual_breakdown
                .get(&ResidualCategory::MeasurementNoise)
                .copied()
                .unwrap_or(0);
            if noise > self.policy.max_noise_millionths {
                details.push(RejectionDetail::ExcessiveNoise {
                    family: entry.hardware_family,
                    noise_millionths: noise,
                    threshold_millionths: self.policy.max_noise_millionths,
                });
            }

            let unexplained = entry
                .residual_breakdown
                .get(&ResidualCategory::Unexplained)
                .copied()
                .unwrap_or(0);
            if unexplained > self.policy.max_unexplained_millionths {
                details.push(RejectionDetail::ExcessiveUnexplained {
                    family: entry.hardware_family,
                    unexplained_millionths: unexplained,
                    threshold_millionths: self.policy.max_unexplained_millionths,
                });
            }
        }

        // Determine verdict.
        if details.is_empty() {
            (PromotionVerdict::Promotable, details)
        } else {
            // Classify the primary reason.
            let has_family_issue = details.iter().any(|d| {
                matches!(
                    d,
                    RejectionDetail::TooFewFamilies { .. }
                        | RejectionDetail::MissingIsaCoverage { .. }
                )
            });
            let has_hw_dominant = details.iter().any(|d| {
                matches!(
                    d,
                    RejectionDetail::HardwareAttributableTooHigh { .. }
                        | RejectionDetail::AlgorithmicGainTooLow { .. }
                )
            });

            if has_family_issue && !has_hw_dominant {
                (PromotionVerdict::InsufficientEvidence, details)
            } else if has_hw_dominant {
                (PromotionVerdict::HardwareDependent, details)
            } else {
                (PromotionVerdict::Rejected, details)
            }
        }
    }

    /// Generate a full localization report.
    pub fn generate_report(&self) -> LocalizationReport {
        let (verdict, rejection_details) = self.evaluate_promotion();
        let unsupported_hardware = self.identify_unsupported_hardware();

        LocalizationReport::new(
            self.optimization_id.clone(),
            self.epoch,
            verdict,
            rejection_details,
            self.entries.clone(),
            unsupported_hardware,
            self.avg_algorithmic_gain(),
            self.max_hardware_attributable(),
        )
    }

    /// Recompute content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_str(&mut buf, SCHEMA_VERSION);
        append_str(&mut buf, &self.optimization_id);
        append_u64(&mut buf, self.epoch.as_u64());
        append_u64(&mut buf, self.entries.len() as u64);
        for entry in &self.entries {
            buf.extend_from_slice(entry.entry_hash.as_bytes());
        }
        self.content_hash = compute_digest(&buf);
    }
}

impl fmt::Display for LocalizationBoard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LocalizationBoard(opt={}, entries={}, families={})",
            self.optimization_id,
            self.entries.len(),
            self.family_count(),
        )
    }
}

// ---------------------------------------------------------------------------
// LocalizationReport
// ---------------------------------------------------------------------------

/// Auditable report from a localization residual evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalizationReport {
    /// Schema version.
    pub schema_version: String,
    /// Optimization identifier.
    pub optimization_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Promotion verdict.
    pub verdict: PromotionVerdict,
    /// Detailed rejection reasons (empty if Promotable).
    pub rejection_details: Vec<RejectionDetail>,
    /// All localization entries.
    pub entries: Vec<LocalizationEntry>,
    /// Unsupported hardware families.
    pub unsupported_hardware: Vec<UnsupportedHardwareEntry>,
    /// Average algorithmic gain across entries (millionths).
    pub algorithmic_gain_millionths: u64,
    /// Maximum hardware-attributable fraction (millionths).
    pub hardware_attributable_millionths: u64,
    /// Content hash of the report.
    pub content_hash: ContentHash,
}

impl LocalizationReport {
    /// Create a new report with computed hash.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        optimization_id: String,
        epoch: SecurityEpoch,
        verdict: PromotionVerdict,
        rejection_details: Vec<RejectionDetail>,
        entries: Vec<LocalizationEntry>,
        unsupported_hardware: Vec<UnsupportedHardwareEntry>,
        algorithmic_gain_millionths: u64,
        hardware_attributable_millionths: u64,
    ) -> Self {
        let mut report = Self {
            schema_version: SCHEMA_VERSION.to_string(),
            optimization_id,
            epoch,
            verdict,
            rejection_details,
            entries,
            unsupported_hardware,
            algorithmic_gain_millionths,
            hardware_attributable_millionths,
            content_hash: ContentHash::compute(b""),
        };
        report.seal();
        report
    }

    /// Recompute content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_str(&mut buf, SCHEMA_VERSION);
        append_str(&mut buf, &self.optimization_id);
        append_u64(&mut buf, self.epoch.as_u64());
        append_str(&mut buf, self.verdict.as_str());
        append_u64(&mut buf, self.entries.len() as u64);
        for entry in &self.entries {
            buf.extend_from_slice(entry.entry_hash.as_bytes());
        }
        append_u64(&mut buf, self.unsupported_hardware.len() as u64);
        for uh in &self.unsupported_hardware {
            buf.extend_from_slice(uh.content_hash.as_bytes());
        }
        append_u64(&mut buf, self.algorithmic_gain_millionths);
        append_u64(&mut buf, self.hardware_attributable_millionths);
        self.content_hash = compute_digest(&buf);
    }

    /// Total entries in the report.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Number of unsupported hardware families.
    pub fn unsupported_count(&self) -> usize {
        self.unsupported_hardware.len()
    }

    /// Whether promotion was granted.
    pub fn is_promotable(&self) -> bool {
        self.verdict.is_pass()
    }

    /// Whether any unsupported hardware was found.
    pub fn has_unsupported_hardware(&self) -> bool {
        !self.unsupported_hardware.is_empty()
    }

    /// Families with fallback available.
    pub fn fallback_families(&self) -> Vec<MicroarchFamily> {
        self.unsupported_hardware
            .iter()
            .filter(|uh| uh.fallback_available)
            .map(|uh| uh.family)
            .collect()
    }

    /// Families without fallback (high risk).
    pub fn no_fallback_families(&self) -> Vec<MicroarchFamily> {
        self.unsupported_hardware
            .iter()
            .filter(|uh| !uh.fallback_available)
            .map(|uh| uh.family)
            .collect()
    }
}

impl fmt::Display for LocalizationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LocalizationReport(opt={}, verdict={}, entries={}, unsupported={})",
            self.optimization_id,
            self.verdict,
            self.entries.len(),
            self.unsupported_hardware.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(900)
    }

    /// Build an entry with the standard residual breakdown.
    fn make_entry(
        family: MicroarchFamily,
        baseline_ns: u64,
        optimized_ns: u64,
        algo: u64,
        hw: u64,
        noise: u64,
        unexplained: u64,
        features: BTreeSet<HardwareFeature>,
    ) -> LocalizationEntry {
        let mut breakdown = BTreeMap::new();
        breakdown.insert(ResidualCategory::AlgorithmicGain, algo);
        breakdown.insert(ResidualCategory::HardwareAttributable, hw);
        breakdown.insert(ResidualCategory::MeasurementNoise, noise);
        breakdown.insert(ResidualCategory::Unexplained, unexplained);
        LocalizationEntry::new(family, features, baseline_ns, optimized_ns, breakdown)
    }

    /// A good algorithmic entry: 70% algo, 10% hw, 10% noise, 10% unexplained.
    fn algo_dominant_entry(family: MicroarchFamily) -> LocalizationEntry {
        make_entry(
            family,
            1_000_000,
            700_000,
            700_000,
            100_000,
            100_000,
            100_000,
            BTreeSet::new(),
        )
    }

    /// A hardware-dominant entry: 20% algo, 60% hw, 10% noise, 10% unexplained.
    fn hw_dominant_entry(family: MicroarchFamily) -> LocalizationEntry {
        let mut feats = BTreeSet::new();
        feats.insert(HardwareFeature::Avx512);
        make_entry(
            family, 1_000_000, 600_000, 200_000, 600_000, 100_000, 100_000, feats,
        )
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(SCHEMA_VERSION.contains("hardware-localization-residual"));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "hardware_localization_residual");
    }

    #[test]
    fn bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn policy_id_format() {
        assert!(POLICY_ID.starts_with("RGC-"));
    }

    #[test]
    fn constant_invariants() {
        assert!(DEFAULT_MIN_ALGORITHMIC_GAIN > 0);
        assert!(DEFAULT_MAX_HARDWARE_ATTRIBUTABLE > 0);
        assert!(DEFAULT_MIN_FAMILIES_TESTED >= 2);
        assert!(MAX_BOARD_ENTRIES > 0);
        assert!(MAX_UNSUPPORTED_ENTRIES > 0);
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // --- HardwareFeature ---

    #[test]
    fn hardware_feature_all_length() {
        assert_eq!(HardwareFeature::ALL.len(), 13);
    }

    #[test]
    fn hardware_feature_names_unique() {
        let names: BTreeSet<&str> = HardwareFeature::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(names.len(), HardwareFeature::ALL.len());
    }

    #[test]
    fn hardware_feature_ordering() {
        let mut sorted = HardwareFeature::ALL.to_vec();
        sorted.sort();
        // Verify the ordering is consistent (Avx2 < Avx512 < ... since we
        // derive Ord on enum discriminant order).
        assert_eq!(sorted[0], HardwareFeature::Avx2);
        assert_eq!(sorted[1], HardwareFeature::Avx512);
    }

    #[test]
    fn hardware_feature_display_matches_as_str() {
        for f in HardwareFeature::ALL {
            assert_eq!(f.to_string(), f.as_str());
        }
    }

    #[test]
    fn hardware_feature_serde_roundtrip() {
        for f in HardwareFeature::ALL {
            let json = serde_json::to_string(f).unwrap();
            let back: HardwareFeature = serde_json::from_str(&json).unwrap();
            assert_eq!(*f, back);
        }
    }

    #[test]
    fn hardware_feature_x86_arm_neutral() {
        assert!(HardwareFeature::Avx2.is_x86());
        assert!(!HardwareFeature::Avx2.is_arm());
        assert!(HardwareFeature::Neon.is_arm());
        assert!(!HardwareFeature::Neon.is_x86());
        assert!(HardwareFeature::Aes.is_neutral());
        assert!(!HardwareFeature::Aes.is_x86());
        assert!(!HardwareFeature::Aes.is_arm());
    }

    // --- MicroarchFamily ---

    #[test]
    fn microarch_family_all_length() {
        assert_eq!(MicroarchFamily::ALL.len(), 8);
    }

    #[test]
    fn microarch_family_names_unique() {
        let names: BTreeSet<&str> = MicroarchFamily::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(names.len(), MicroarchFamily::ALL.len());
    }

    #[test]
    fn microarch_family_ordering() {
        let mut sorted = MicroarchFamily::ALL.to_vec();
        sorted.sort();
        assert_eq!(sorted[0], MicroarchFamily::Zen4);
    }

    #[test]
    fn microarch_family_display() {
        for f in MicroarchFamily::ALL {
            assert_eq!(f.to_string(), f.as_str());
        }
    }

    #[test]
    fn microarch_family_serde_roundtrip() {
        for f in MicroarchFamily::ALL {
            let json = serde_json::to_string(f).unwrap();
            let back: MicroarchFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(*f, back);
        }
    }

    #[test]
    fn microarch_family_isa_classification() {
        assert!(MicroarchFamily::Zen4.is_x86());
        assert!(!MicroarchFamily::Zen4.is_arm());
        assert!(MicroarchFamily::GravitonArm.is_arm());
        assert!(!MicroarchFamily::GravitonArm.is_x86());
        assert!(MicroarchFamily::AppleM.is_arm());
        assert!(MicroarchFamily::GenericX64.is_x86());
        assert!(MicroarchFamily::GenericArm64.is_arm());
    }

    #[test]
    fn typical_features_non_empty_for_all() {
        for f in MicroarchFamily::ALL {
            let feats = f.typical_features();
            assert!(!feats.is_empty(), "family {} should have features", f);
        }
    }

    #[test]
    fn typical_features_zen4_has_avx512() {
        let feats = MicroarchFamily::Zen4.typical_features();
        assert!(feats.contains(&HardwareFeature::Avx512));
        assert!(feats.contains(&HardwareFeature::Avx2));
    }

    #[test]
    fn typical_features_graviton_has_neon() {
        let feats = MicroarchFamily::GravitonArm.typical_features();
        assert!(feats.contains(&HardwareFeature::Neon));
        assert!(!feats.contains(&HardwareFeature::Avx2));
    }

    // --- ResidualCategory ---

    #[test]
    fn residual_category_all_length() {
        assert_eq!(ResidualCategory::ALL.len(), 4);
    }

    #[test]
    fn residual_category_names_unique() {
        let names: BTreeSet<&str> = ResidualCategory::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), ResidualCategory::ALL.len());
    }

    #[test]
    fn residual_category_display() {
        for c in ResidualCategory::ALL {
            assert_eq!(c.to_string(), c.as_str());
        }
    }

    #[test]
    fn residual_category_serde_roundtrip() {
        for c in ResidualCategory::ALL {
            let json = serde_json::to_string(c).unwrap();
            let back: ResidualCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*c, back);
        }
    }

    // --- LocalizationEntry ---

    #[test]
    fn entry_hash_determinism() {
        let e1 = algo_dominant_entry(MicroarchFamily::Zen4);
        let e2 = algo_dominant_entry(MicroarchFamily::Zen4);
        assert_eq!(e1.entry_hash, e2.entry_hash);
    }

    #[test]
    fn entry_hash_varies_by_family() {
        let e1 = algo_dominant_entry(MicroarchFamily::Zen4);
        let e2 = algo_dominant_entry(MicroarchFamily::GravitonArm);
        assert_ne!(e1.entry_hash, e2.entry_hash);
    }

    #[test]
    fn entry_speedup_calculation() {
        let e = make_entry(
            MicroarchFamily::Zen4,
            1_000_000,
            800_000,
            MILLIONTHS,
            0,
            0,
            0,
            BTreeSet::new(),
        );
        // saved 200_000 / 1_000_000 = 20% = 200_000 millionths
        assert_eq!(e.speedup_millionths(), 200_000);
    }

    #[test]
    fn entry_speedup_zero_when_no_improvement() {
        let e = make_entry(
            MicroarchFamily::Zen4,
            1_000_000,
            1_000_000,
            MILLIONTHS,
            0,
            0,
            0,
            BTreeSet::new(),
        );
        assert_eq!(e.speedup_millionths(), 0);
    }

    #[test]
    fn entry_speedup_zero_when_regression() {
        let e = make_entry(
            MicroarchFamily::Zen4,
            800_000,
            1_000_000,
            MILLIONTHS,
            0,
            0,
            0,
            BTreeSet::new(),
        );
        assert_eq!(e.speedup_millionths(), 0);
    }

    #[test]
    fn entry_speedup_zero_when_baseline_zero() {
        let e = make_entry(
            MicroarchFamily::Zen4,
            0,
            100,
            MILLIONTHS,
            0,
            0,
            0,
            BTreeSet::new(),
        );
        assert_eq!(e.speedup_millionths(), 0);
    }

    #[test]
    fn entry_algorithmic_and_hardware_fractions() {
        let e = make_entry(
            MicroarchFamily::Zen4,
            1_000_000,
            700_000,
            600_000,
            300_000,
            50_000,
            50_000,
            BTreeSet::new(),
        );
        assert_eq!(e.algorithmic_fraction(), 600_000);
        assert_eq!(e.hardware_fraction(), 300_000);
        assert_eq!(e.residual_sum(), 1_000_000);
    }

    #[test]
    fn entry_features_available_on() {
        let mut feats = BTreeSet::new();
        feats.insert(HardwareFeature::Avx512);
        let e = make_entry(
            MicroarchFamily::Zen4,
            1_000_000,
            700_000,
            MILLIONTHS,
            0,
            0,
            0,
            feats,
        );
        assert!(e.features_available_on(MicroarchFamily::Zen4));
        assert!(!e.features_available_on(MicroarchFamily::AlderLake));
        assert!(!e.features_available_on(MicroarchFamily::GravitonArm));
    }

    #[test]
    fn entry_display() {
        let e = algo_dominant_entry(MicroarchFamily::Zen4);
        let s = e.to_string();
        assert!(s.contains("zen4"));
    }

    // --- PromotionPolicy ---

    #[test]
    fn strict_policy_defaults() {
        let p = PromotionPolicy::strict();
        assert_eq!(
            p.min_algorithmic_gain_millionths,
            DEFAULT_MIN_ALGORITHMIC_GAIN
        );
        assert_eq!(
            p.max_hardware_attributable_millionths,
            DEFAULT_MAX_HARDWARE_ATTRIBUTABLE
        );
        assert!(p.require_arm_and_x64);
        assert!(p.min_hardware_families_tested >= 2);
    }

    #[test]
    fn relaxed_policy_less_strict() {
        let strict = PromotionPolicy::strict();
        let relaxed = PromotionPolicy::relaxed();
        assert!(relaxed.min_algorithmic_gain_millionths < strict.min_algorithmic_gain_millionths);
        assert!(
            relaxed.max_hardware_attributable_millionths
                > strict.max_hardware_attributable_millionths
        );
        assert!(!relaxed.require_arm_and_x64);
    }

    #[test]
    fn default_policy_is_strict() {
        let d = PromotionPolicy::default();
        let s = PromotionPolicy::strict();
        assert_eq!(d, s);
    }

    // --- PromotionVerdict ---

    #[test]
    fn verdict_promotable_is_pass() {
        assert!(PromotionVerdict::Promotable.is_pass());
        assert!(!PromotionVerdict::HardwareDependent.is_pass());
        assert!(!PromotionVerdict::InsufficientEvidence.is_pass());
        assert!(!PromotionVerdict::Rejected.is_pass());
    }

    #[test]
    fn verdict_display() {
        assert_eq!(PromotionVerdict::Promotable.to_string(), "promotable");
        assert_eq!(
            PromotionVerdict::HardwareDependent.to_string(),
            "hardware_dependent"
        );
        assert_eq!(
            PromotionVerdict::InsufficientEvidence.to_string(),
            "insufficient_evidence"
        );
        assert_eq!(PromotionVerdict::Rejected.to_string(), "rejected");
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for v in &[
            PromotionVerdict::Promotable,
            PromotionVerdict::HardwareDependent,
            PromotionVerdict::InsufficientEvidence,
            PromotionVerdict::Rejected,
        ] {
            let json = serde_json::to_string(v).unwrap();
            let back: PromotionVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // --- UnsupportedHardwareEntry ---

    #[test]
    fn unsupported_entry_hash_determinism() {
        let mut missing = BTreeSet::new();
        missing.insert(HardwareFeature::Avx512);
        let e1 = UnsupportedHardwareEntry::new(
            MicroarchFamily::GravitonArm,
            missing.clone(),
            50_000,
            true,
        );
        let e2 = UnsupportedHardwareEntry::new(MicroarchFamily::GravitonArm, missing, 50_000, true);
        assert_eq!(e1.content_hash, e2.content_hash);
    }

    #[test]
    fn unsupported_entry_display() {
        let mut missing = BTreeSet::new();
        missing.insert(HardwareFeature::Avx512);
        let e = UnsupportedHardwareEntry::new(MicroarchFamily::GravitonArm, missing, 50_000, false);
        let s = e.to_string();
        assert!(s.contains("graviton_arm"));
        assert!(s.contains("1 missing"));
    }

    // --- LocalizationBoard ---

    #[test]
    fn empty_board_insufficient_evidence() {
        let board = LocalizationBoard::new("opt-1", epoch(), PromotionPolicy::relaxed());
        let (verdict, details) = board.evaluate_promotion();
        assert_eq!(verdict, PromotionVerdict::InsufficientEvidence);
        assert!(
            details
                .iter()
                .any(|d| matches!(d, RejectionDetail::EmptyBoard))
        );
    }

    #[test]
    fn board_add_entry() {
        let mut board = LocalizationBoard::new("opt-2", epoch(), PromotionPolicy::relaxed());
        let entry = algo_dominant_entry(MicroarchFamily::Zen4);
        assert!(board.add_entry(entry));
        assert_eq!(board.entry_count(), 1);
    }

    #[test]
    fn board_distinct_families() {
        let mut board = LocalizationBoard::new("opt-3", epoch(), PromotionPolicy::relaxed());
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        board.add_entry(algo_dominant_entry(MicroarchFamily::GravitonArm));
        assert_eq!(board.family_count(), 2);
        assert!(board.distinct_families().contains(&MicroarchFamily::Zen4));
        assert!(
            board
                .distinct_families()
                .contains(&MicroarchFamily::GravitonArm)
        );
    }

    #[test]
    fn board_has_arm_and_x64() {
        let mut board = LocalizationBoard::new("opt-4", epoch(), PromotionPolicy::relaxed());
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        assert!(!board.has_arm_and_x64());
        board.add_entry(algo_dominant_entry(MicroarchFamily::GravitonArm));
        assert!(board.has_arm_and_x64());
    }

    #[test]
    fn board_avg_algorithmic_gain() {
        let mut board = LocalizationBoard::new("opt-5", epoch(), PromotionPolicy::relaxed());
        // entry with 700_000 algo
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        // entry with 200_000 algo
        board.add_entry(hw_dominant_entry(MicroarchFamily::AlderLake));
        // avg = (700_000 + 200_000) / 2 = 450_000
        assert_eq!(board.avg_algorithmic_gain(), 450_000);
    }

    #[test]
    fn board_max_hardware_attributable() {
        let mut board = LocalizationBoard::new("opt-6", epoch(), PromotionPolicy::relaxed());
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4)); // hw = 100_000
        board.add_entry(hw_dominant_entry(MicroarchFamily::AlderLake)); // hw = 600_000
        assert_eq!(board.max_hardware_attributable(), 600_000);
    }

    #[test]
    fn board_promotion_algorithmic_gain_dominates() {
        let mut board = LocalizationBoard::new("opt-7", epoch(), PromotionPolicy::relaxed());
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        board.add_entry(algo_dominant_entry(MicroarchFamily::GravitonArm));
        let (verdict, details) = board.evaluate_promotion();
        assert_eq!(verdict, PromotionVerdict::Promotable);
        assert!(details.is_empty());
    }

    #[test]
    fn board_promotion_hardware_dominant_blocks() {
        let mut board = LocalizationBoard::new("opt-8", epoch(), PromotionPolicy::relaxed());
        board.add_entry(hw_dominant_entry(MicroarchFamily::Zen4));
        board.add_entry(hw_dominant_entry(MicroarchFamily::GravitonArm));
        let (verdict, _details) = board.evaluate_promotion();
        assert_eq!(verdict, PromotionVerdict::HardwareDependent);
    }

    #[test]
    fn board_promotion_single_family_insufficient() {
        let policy = PromotionPolicy {
            min_hardware_families_tested: 2,
            require_arm_and_x64: false,
            ..PromotionPolicy::relaxed()
        };
        let mut board = LocalizationBoard::new("opt-9", epoch(), policy);
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        let (verdict, details) = board.evaluate_promotion();
        assert_eq!(verdict, PromotionVerdict::InsufficientEvidence);
        assert!(
            details
                .iter()
                .any(|d| matches!(d, RejectionDetail::TooFewFamilies { .. }))
        );
    }

    #[test]
    fn board_promotion_arm_x64_requirement() {
        let policy = PromotionPolicy {
            min_hardware_families_tested: 2,
            require_arm_and_x64: true,
            min_algorithmic_gain_millionths: 400_000,
            max_hardware_attributable_millionths: 500_000,
            max_noise_millionths: 200_000,
            max_unexplained_millionths: 200_000,
        };
        let mut board = LocalizationBoard::new("opt-10", epoch(), policy);
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        board.add_entry(algo_dominant_entry(MicroarchFamily::AlderLake));
        let (verdict, details) = board.evaluate_promotion();
        // Two x86 families but no ARM.
        assert_eq!(verdict, PromotionVerdict::InsufficientEvidence);
        assert!(details.iter().any(|d| matches!(
            d,
            RejectionDetail::MissingIsaCoverage { has_arm: false, .. }
        )));
    }

    #[test]
    fn board_unsupported_hardware_detection() {
        let mut board = LocalizationBoard::new("opt-11", epoch(), PromotionPolicy::relaxed());
        let mut feats = BTreeSet::new();
        feats.insert(HardwareFeature::Avx512);
        let entry = make_entry(
            MicroarchFamily::Zen4,
            1_000_000,
            700_000,
            700_000,
            100_000,
            100_000,
            100_000,
            feats,
        );
        board.add_entry(entry);
        let unsupported = board.identify_unsupported_hardware();
        // AlderLake and RaptorLake lack Avx512 in our typical features model.
        let unsupported_families: BTreeSet<MicroarchFamily> =
            unsupported.iter().map(|u| u.family).collect();
        assert!(unsupported_families.contains(&MicroarchFamily::AlderLake));
        assert!(unsupported_families.contains(&MicroarchFamily::GravitonArm));
    }

    #[test]
    fn board_no_speedup_rejected() {
        let mut board = LocalizationBoard::new("opt-12", epoch(), PromotionPolicy::relaxed());
        let entry = make_entry(
            MicroarchFamily::Zen4,
            1_000_000,
            1_000_000,
            500_000,
            500_000,
            0,
            0,
            BTreeSet::new(),
        );
        board.add_entry(entry);
        let (verdict, details) = board.evaluate_promotion();
        assert_eq!(verdict, PromotionVerdict::Rejected);
        assert!(
            details
                .iter()
                .any(|d| matches!(d, RejectionDetail::NoSpeedupObserved))
        );
    }

    #[test]
    fn board_content_hash_determinism() {
        let mut b1 = LocalizationBoard::new("opt-13", epoch(), PromotionPolicy::relaxed());
        b1.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));

        let mut b2 = LocalizationBoard::new("opt-13", epoch(), PromotionPolicy::relaxed());
        b2.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));

        assert_eq!(b1.content_hash, b2.content_hash);
    }

    #[test]
    fn board_display() {
        let board = LocalizationBoard::new("opt-14", epoch(), PromotionPolicy::relaxed());
        let s = board.to_string();
        assert!(s.contains("opt-14"));
        assert!(s.contains("entries=0"));
    }

    // --- LocalizationReport ---

    #[test]
    fn report_generation() {
        let mut board = LocalizationBoard::new("opt-15", epoch(), PromotionPolicy::relaxed());
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        board.add_entry(algo_dominant_entry(MicroarchFamily::GravitonArm));
        let report = board.generate_report();
        assert!(report.is_promotable());
        assert_eq!(report.entry_count(), 2);
        assert_eq!(report.optimization_id, "opt-15");
        assert_eq!(report.epoch, epoch());
    }

    #[test]
    fn report_content_hash_determinism() {
        let mut b1 = LocalizationBoard::new("opt-16", epoch(), PromotionPolicy::relaxed());
        b1.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        b1.add_entry(algo_dominant_entry(MicroarchFamily::GravitonArm));
        let r1 = b1.generate_report();

        let mut b2 = LocalizationBoard::new("opt-16", epoch(), PromotionPolicy::relaxed());
        b2.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        b2.add_entry(algo_dominant_entry(MicroarchFamily::GravitonArm));
        let r2 = b2.generate_report();

        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_unsupported_hardware_tracking() {
        let mut board = LocalizationBoard::new("opt-17", epoch(), PromotionPolicy::relaxed());
        let mut feats = BTreeSet::new();
        feats.insert(HardwareFeature::Avx512);
        let entry = make_entry(
            MicroarchFamily::Zen4,
            1_000_000,
            700_000,
            700_000,
            100_000,
            100_000,
            100_000,
            feats,
        );
        board.add_entry(entry);
        let report = board.generate_report();
        assert!(report.has_unsupported_hardware());
        assert!(report.unsupported_count() > 0);
    }

    #[test]
    fn report_fallback_families() {
        let mut board = LocalizationBoard::new("opt-18", epoch(), PromotionPolicy::relaxed());
        let mut feats = BTreeSet::new();
        feats.insert(HardwareFeature::Avx512);
        feats.insert(HardwareFeature::PopcntHw);
        let entry = make_entry(
            MicroarchFamily::Zen4,
            1_000_000,
            700_000,
            700_000,
            100_000,
            100_000,
            100_000,
            feats,
        );
        board.add_entry(entry);
        let report = board.generate_report();
        // Some families will have fallback, some won't.
        let all_unsupported = &report.unsupported_hardware;
        let with_fallback: Vec<_> = all_unsupported
            .iter()
            .filter(|u| u.fallback_available)
            .collect();
        let without_fallback: Vec<_> = all_unsupported
            .iter()
            .filter(|u| !u.fallback_available)
            .collect();
        // At least one family should exist in each category or combined.
        assert!(!all_unsupported.is_empty());
        assert_eq!(
            with_fallback.len() + without_fallback.len(),
            all_unsupported.len()
        );
    }

    #[test]
    fn report_display() {
        let mut board = LocalizationBoard::new("opt-19", epoch(), PromotionPolicy::relaxed());
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        let report = board.generate_report();
        let s = report.to_string();
        assert!(s.contains("opt-19"));
        assert!(s.contains("LocalizationReport"));
    }

    // --- Mixed / boundary tests ---

    #[test]
    fn mixed_residuals_across_families() {
        let mut board = LocalizationBoard::new("opt-20", epoch(), PromotionPolicy::relaxed());
        // Algo-dominant on Zen4.
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        // HW-dominant on Graviton.
        board.add_entry(hw_dominant_entry(MicroarchFamily::GravitonArm));
        let (verdict, _) = board.evaluate_promotion();
        // avg algo = (700_000 + 200_000)/2 = 450_000 >= relaxed 400_000
        // max hw = 600_000 > relaxed 500_000
        assert_eq!(verdict, PromotionVerdict::HardwareDependent);
    }

    #[test]
    fn policy_boundary_algo_gain_exactly_at_threshold() {
        let policy = PromotionPolicy {
            min_algorithmic_gain_millionths: 700_000,
            max_hardware_attributable_millionths: 500_000,
            min_hardware_families_tested: 1,
            require_arm_and_x64: false,
            max_noise_millionths: 200_000,
            max_unexplained_millionths: 200_000,
        };
        let mut board = LocalizationBoard::new("opt-21", epoch(), policy);
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4)); // algo = 700_000
        let (verdict, details) = board.evaluate_promotion();
        assert_eq!(verdict, PromotionVerdict::Promotable);
        assert!(details.is_empty());
    }

    #[test]
    fn policy_boundary_algo_gain_just_below_threshold() {
        let policy = PromotionPolicy {
            min_algorithmic_gain_millionths: 700_001,
            max_hardware_attributable_millionths: 500_000,
            min_hardware_families_tested: 1,
            require_arm_and_x64: false,
            max_noise_millionths: 200_000,
            max_unexplained_millionths: 200_000,
        };
        let mut board = LocalizationBoard::new("opt-22", epoch(), policy);
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4)); // algo = 700_000
        let (verdict, _) = board.evaluate_promotion();
        assert_eq!(verdict, PromotionVerdict::HardwareDependent);
    }

    #[test]
    fn excessive_noise_rejection() {
        let policy = PromotionPolicy {
            min_algorithmic_gain_millionths: 400_000,
            max_hardware_attributable_millionths: 500_000,
            min_hardware_families_tested: 1,
            require_arm_and_x64: false,
            max_noise_millionths: 50_000,
            max_unexplained_millionths: 200_000,
        };
        let mut board = LocalizationBoard::new("opt-23", epoch(), policy);
        // Entry with 100_000 noise > 50_000 threshold.
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        let (verdict, details) = board.evaluate_promotion();
        assert_eq!(verdict, PromotionVerdict::Rejected);
        assert!(
            details
                .iter()
                .any(|d| matches!(d, RejectionDetail::ExcessiveNoise { .. }))
        );
    }

    #[test]
    fn board_avg_speedup() {
        let mut board = LocalizationBoard::new("opt-24", epoch(), PromotionPolicy::relaxed());
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4)); // 300_000 millionths
        assert_eq!(board.avg_speedup(), 300_000);
    }

    #[test]
    fn rejection_detail_display() {
        let d = RejectionDetail::AlgorithmicGainTooLow {
            observed_millionths: 100_000,
            threshold_millionths: 600_000,
        };
        let s = d.to_string();
        assert!(s.contains("100000"));
        assert!(s.contains("600000"));
    }

    #[test]
    fn board_seal_updates_hash() {
        let mut board = LocalizationBoard::new("opt-25", epoch(), PromotionPolicy::relaxed());
        let h1 = board.content_hash;
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        let h2 = board.content_hash;
        assert_ne!(h1, h2);
    }

    #[test]
    fn report_serde_roundtrip() {
        let mut board = LocalizationBoard::new("opt-26", epoch(), PromotionPolicy::relaxed());
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        board.add_entry(algo_dominant_entry(MicroarchFamily::GravitonArm));
        let report = board.generate_report();
        let json = serde_json::to_string(&report).unwrap();
        let back: LocalizationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn three_family_strict_policy_promotable() {
        let mut board = LocalizationBoard::new("opt-27", epoch(), PromotionPolicy::strict());
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        board.add_entry(algo_dominant_entry(MicroarchFamily::AlderLake));
        board.add_entry(algo_dominant_entry(MicroarchFamily::GravitonArm));
        let (verdict, details) = board.evaluate_promotion();
        assert_eq!(verdict, PromotionVerdict::Promotable);
        assert!(details.is_empty());
    }

    #[test]
    fn strict_policy_two_families_insufficient() {
        let mut board = LocalizationBoard::new("opt-28", epoch(), PromotionPolicy::strict());
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        board.add_entry(algo_dominant_entry(MicroarchFamily::GravitonArm));
        let (verdict, details) = board.evaluate_promotion();
        // Strict requires 3 families.
        assert_eq!(verdict, PromotionVerdict::InsufficientEvidence);
        assert!(details.iter().any(|d| matches!(
            d,
            RejectionDetail::TooFewFamilies {
                tested: 2,
                required: 3
            }
        )));
    }

    #[test]
    fn board_multiple_entries_same_family() {
        let mut board = LocalizationBoard::new("opt-29", epoch(), PromotionPolicy::relaxed());
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        board.add_entry(algo_dominant_entry(MicroarchFamily::GravitonArm));
        assert_eq!(board.entry_count(), 3);
        assert_eq!(board.family_count(), 2);
    }

    #[test]
    fn report_not_promotable_when_hardware_dependent() {
        let mut board = LocalizationBoard::new("opt-30", epoch(), PromotionPolicy::relaxed());
        board.add_entry(hw_dominant_entry(MicroarchFamily::Zen4));
        board.add_entry(hw_dominant_entry(MicroarchFamily::GravitonArm));
        let report = board.generate_report();
        assert!(!report.is_promotable());
        assert_eq!(report.verdict, PromotionVerdict::HardwareDependent);
    }

    #[test]
    fn report_algorithmic_gain_field() {
        let mut board = LocalizationBoard::new("opt-31", epoch(), PromotionPolicy::relaxed());
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4));
        let report = board.generate_report();
        assert_eq!(report.algorithmic_gain_millionths, 700_000);
        assert_eq!(report.hardware_attributable_millionths, 100_000);
    }

    #[test]
    fn entry_empty_residual_breakdown() {
        let entry = LocalizationEntry::new(
            MicroarchFamily::Zen4,
            BTreeSet::new(),
            1_000,
            500,
            BTreeMap::new(),
        );
        assert_eq!(entry.algorithmic_fraction(), 0);
        assert_eq!(entry.hardware_fraction(), 0);
        assert_eq!(entry.residual_sum(), 0);
    }

    #[test]
    fn excessive_unexplained_rejection() {
        let policy = PromotionPolicy {
            min_algorithmic_gain_millionths: 100_000,
            max_hardware_attributable_millionths: 800_000,
            min_hardware_families_tested: 1,
            require_arm_and_x64: false,
            max_noise_millionths: 200_000,
            max_unexplained_millionths: 50_000,
        };
        let mut board = LocalizationBoard::new("opt-32", epoch(), policy);
        board.add_entry(algo_dominant_entry(MicroarchFamily::Zen4)); // unexplained = 100_000
        let (verdict, details) = board.evaluate_promotion();
        assert_eq!(verdict, PromotionVerdict::Rejected);
        assert!(
            details
                .iter()
                .any(|d| matches!(d, RejectionDetail::ExcessiveUnexplained { .. }))
        );
    }
}
