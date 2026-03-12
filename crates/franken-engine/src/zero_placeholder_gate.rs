#![forbid(unsafe_code)]
//! Bead: bd-1lsy.9.5.2 [RGC-805B]
//!
//! Enforce zero-placeholder semantics in CI/release with explicit waiver
//! policy.
//!
//! Wires the zero-placeholder rule into CI/release gates with explicit waiver
//! mechanics and artifact-rich failure reporting. Ensures no placeholder/stub
//! semantics ship in production — every shipped path must have real
//! implementation or an explicit, time-bounded waiver.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.zero-placeholder-gate.v1";

/// Component name.
pub const COMPONENT: &str = "zero_placeholder_gate";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.9.5.2";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-805B";

/// Fixed-point unit: 1.0 in millionths.
pub const MILLIONTHS: u64 = 1_000_000;

/// Default maximum active waivers.
pub const DEFAULT_MAX_ACTIVE_WAIVERS: usize = 20;

/// Default maximum waiver duration (epochs).
pub const DEFAULT_WAIVER_MAX_DURATION_EPOCHS: u64 = 100;

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

// ---------------------------------------------------------------------------
// Subsystem
// ---------------------------------------------------------------------------

/// Subsystem being scanned for placeholders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Subsystem {
    Parser,
    Lowering,
    Interpreter,
    Runtime,
    ModuleLoader,
    TypeChecker,
    Optimizer,
    Cli,
}

impl Subsystem {
    pub const ALL: &[Self] = &[
        Self::Parser,
        Self::Lowering,
        Self::Interpreter,
        Self::Runtime,
        Self::ModuleLoader,
        Self::TypeChecker,
        Self::Optimizer,
        Self::Cli,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parser => "parser",
            Self::Lowering => "lowering",
            Self::Interpreter => "interpreter",
            Self::Runtime => "runtime",
            Self::ModuleLoader => "module_loader",
            Self::TypeChecker => "type_checker",
            Self::Optimizer => "optimizer",
            Self::Cli => "cli",
        }
    }
}

impl fmt::Display for Subsystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// PlaceholderKind
// ---------------------------------------------------------------------------

/// Kind of placeholder detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaceholderKind {
    UnimplementedPanic,
    TodoMacro,
    StubReturn,
    HardcodedFallback,
    EmptyHandler,
    UnsupportedError,
}

impl PlaceholderKind {
    pub const ALL: &[Self] = &[
        Self::UnimplementedPanic,
        Self::TodoMacro,
        Self::StubReturn,
        Self::HardcodedFallback,
        Self::EmptyHandler,
        Self::UnsupportedError,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnimplementedPanic => "unimplemented_panic",
            Self::TodoMacro => "todo_macro",
            Self::StubReturn => "stub_return",
            Self::HardcodedFallback => "hardcoded_fallback",
            Self::EmptyHandler => "empty_handler",
            Self::UnsupportedError => "unsupported_error",
        }
    }
}

impl fmt::Display for PlaceholderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// PlaceholderSeverity
// ---------------------------------------------------------------------------

/// Severity of a detected placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaceholderSeverity {
    /// Must fix before release.
    Blocking,
    /// Should fix before release.
    High,
    /// Should address at some point.
    Medium,
    /// Informational.
    Low,
}

impl PlaceholderSeverity {
    pub const ALL: &[Self] = &[Self::Blocking, Self::High, Self::Medium, Self::Low];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocking => "blocking",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

impl fmt::Display for PlaceholderSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// PlaceholderEntry
// ---------------------------------------------------------------------------

/// A detected placeholder in the codebase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaceholderEntry {
    /// Which subsystem the placeholder belongs to.
    pub subsystem: Subsystem,
    /// Kind of placeholder.
    pub kind: PlaceholderKind,
    /// File path where the placeholder was found.
    pub location_file: String,
    /// Line number within the file.
    pub location_line: u64,
    /// Human-readable description.
    pub description: String,
    /// Severity level.
    pub severity: PlaceholderSeverity,
    /// Content hash of the placeholder region.
    pub content_hash: ContentHash,
}

impl PlaceholderEntry {
    /// Create a new entry with computed content hash.
    pub fn new(
        subsystem: Subsystem,
        kind: PlaceholderKind,
        location_file: impl Into<String>,
        location_line: u64,
        description: impl Into<String>,
        severity: PlaceholderSeverity,
    ) -> Self {
        let location_file = location_file.into();
        let description = description.into();
        let mut buf = Vec::new();
        append_str(&mut buf, subsystem.as_str());
        append_str(&mut buf, kind.as_str());
        append_str(&mut buf, &location_file);
        append_u64(&mut buf, location_line);
        append_str(&mut buf, &description);
        append_str(&mut buf, severity.as_str());
        let content_hash = ContentHash::compute(&buf);
        Self {
            subsystem,
            kind,
            location_file,
            location_line,
            description,
            severity,
            content_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// WaiverStatus
// ---------------------------------------------------------------------------

/// Status of a waiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaiverStatus {
    Active,
    Expired,
    Revoked,
}

impl WaiverStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

impl fmt::Display for WaiverStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Waiver
// ---------------------------------------------------------------------------

/// An explicit, time-bounded waiver for a placeholder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiver {
    /// Unique waiver identifier.
    pub waiver_id: String,
    /// Hash of the placeholder this waiver covers.
    pub placeholder_hash: ContentHash,
    /// Subsystem the waiver applies to.
    pub subsystem: Subsystem,
    /// Justification for the waiver.
    pub justification: String,
    /// Owner responsible for resolving the placeholder.
    pub owner: String,
    /// Epoch at which this waiver expires.
    pub expires_epoch: u64,
    /// Current status.
    pub status: WaiverStatus,
    /// Epoch when this waiver was created.
    pub created_epoch: u64,
}

// ---------------------------------------------------------------------------
// GateAction
// ---------------------------------------------------------------------------

/// What the gate does for each severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateAction {
    /// Block the release.
    Block,
    /// Emit a warning but allow.
    Warn,
    /// Allow silently.
    Allow,
}

impl GateAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Warn => "warn",
            Self::Allow => "allow",
        }
    }
}

impl fmt::Display for GateAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the zero-placeholder gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// What action to take for each severity level.
    pub severity_actions: BTreeMap<PlaceholderSeverity, GateAction>,
    /// Maximum number of active waivers allowed.
    pub max_active_waivers: usize,
    /// Maximum duration of a waiver in epochs.
    pub waiver_max_duration_epochs: u64,
    /// Whether waivers must include a justification.
    pub require_justification: bool,
    /// Whether waivers must include an owner.
    pub require_owner: bool,
}

impl GateConfig {
    /// Default strict configuration: Blocking blocks, High warns, Medium/Low allow.
    pub fn default_config() -> Self {
        let mut severity_actions = BTreeMap::new();
        severity_actions.insert(PlaceholderSeverity::Blocking, GateAction::Block);
        severity_actions.insert(PlaceholderSeverity::High, GateAction::Warn);
        severity_actions.insert(PlaceholderSeverity::Medium, GateAction::Allow);
        severity_actions.insert(PlaceholderSeverity::Low, GateAction::Allow);
        Self {
            severity_actions,
            max_active_waivers: DEFAULT_MAX_ACTIVE_WAIVERS,
            waiver_max_duration_epochs: DEFAULT_WAIVER_MAX_DURATION_EPOCHS,
            require_justification: true,
            require_owner: true,
        }
    }

    /// Strict configuration: all severities block.
    pub fn strict() -> Self {
        let mut severity_actions = BTreeMap::new();
        severity_actions.insert(PlaceholderSeverity::Blocking, GateAction::Block);
        severity_actions.insert(PlaceholderSeverity::High, GateAction::Block);
        severity_actions.insert(PlaceholderSeverity::Medium, GateAction::Block);
        severity_actions.insert(PlaceholderSeverity::Low, GateAction::Block);
        Self {
            severity_actions,
            max_active_waivers: 0,
            waiver_max_duration_epochs: 0,
            require_justification: true,
            require_owner: true,
        }
    }

    /// Permissive configuration: all severities allow.
    pub fn permissive() -> Self {
        let mut severity_actions = BTreeMap::new();
        severity_actions.insert(PlaceholderSeverity::Blocking, GateAction::Allow);
        severity_actions.insert(PlaceholderSeverity::High, GateAction::Allow);
        severity_actions.insert(PlaceholderSeverity::Medium, GateAction::Allow);
        severity_actions.insert(PlaceholderSeverity::Low, GateAction::Allow);
        Self {
            severity_actions,
            max_active_waivers: usize::MAX,
            waiver_max_duration_epochs: u64::MAX,
            require_justification: false,
            require_owner: false,
        }
    }

    /// Look up the action for a given severity. Defaults to Block if not mapped.
    pub fn action_for(&self, severity: PlaceholderSeverity) -> GateAction {
        self.severity_actions
            .get(&severity)
            .copied()
            .unwrap_or(GateAction::Block)
    }
}

impl Default for GateConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

/// Result of scanning one subsystem for placeholders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    /// Which subsystem was scanned.
    pub subsystem: Subsystem,
    /// Placeholders found during the scan.
    pub placeholders_found: Vec<PlaceholderEntry>,
    /// Epoch at which the scan ran.
    pub scan_epoch: SecurityEpoch,
    /// Content hash of the scan output.
    pub scan_content_hash: ContentHash,
}

impl ScanResult {
    /// Create a scan result with computed content hash.
    pub fn new(
        subsystem: Subsystem,
        placeholders_found: Vec<PlaceholderEntry>,
        scan_epoch: SecurityEpoch,
    ) -> Self {
        let mut buf = Vec::new();
        append_str(&mut buf, subsystem.as_str());
        append_u64(&mut buf, scan_epoch.as_u64());
        append_u64(&mut buf, placeholders_found.len() as u64);
        for p in &placeholders_found {
            buf.extend_from_slice(p.content_hash.as_bytes());
        }
        let scan_content_hash = ContentHash::compute(&buf);
        Self {
            subsystem,
            placeholders_found,
            scan_epoch,
            scan_content_hash,
        }
    }

    /// Total placeholder count.
    pub fn placeholder_count(&self) -> usize {
        self.placeholders_found.len()
    }

    /// Whether no placeholders were found.
    pub fn is_clean(&self) -> bool {
        self.placeholders_found.is_empty()
    }
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

/// Overall verdict from the zero-placeholder gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    /// All placeholders are waived or allowed.
    Pass,
    /// Some placeholders produced warnings but nothing blocked.
    Warn,
    /// At least one placeholder caused a block.
    Block,
}

impl GateVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }

    pub const fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }

    pub const fn is_block(self) -> bool {
        matches!(self, Self::Block)
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Auditable receipt for a gate decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub policy_id: String,
    pub epoch: SecurityEpoch,
    pub input_hash: ContentHash,
    pub verdict_hash: ContentHash,
    pub timestamp_micros: u64,
}

impl DecisionReceipt {
    /// Create a receipt from gate evaluation context.
    pub fn new(
        epoch: SecurityEpoch,
        input_hash: ContentHash,
        verdict: GateVerdict,
        timestamp_micros: u64,
    ) -> Self {
        let mut buf = Vec::new();
        append_str(&mut buf, SCHEMA_VERSION);
        append_str(&mut buf, COMPONENT);
        append_str(&mut buf, BEAD_ID);
        append_str(&mut buf, POLICY_ID);
        append_u64(&mut buf, epoch.as_u64());
        buf.extend_from_slice(input_hash.as_bytes());
        append_str(&mut buf, verdict.as_str());
        append_u64(&mut buf, timestamp_micros);
        let verdict_hash = ContentHash::compute(&buf);
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            bead_id: BEAD_ID.to_string(),
            policy_id: POLICY_ID.to_string(),
            epoch,
            input_hash,
            verdict_hash,
            timestamp_micros,
        }
    }
}

// ---------------------------------------------------------------------------
// GateReport
// ---------------------------------------------------------------------------

/// Full report from a gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    /// All scan results fed into the gate.
    pub scan_results: Vec<ScanResult>,
    /// Waivers that were considered.
    pub waivers: Vec<Waiver>,
    /// Overall verdict.
    pub verdict: GateVerdict,
    /// Entries that caused a block.
    pub blocked_entries: Vec<PlaceholderEntry>,
    /// Entries that caused a warning.
    pub warned_entries: Vec<PlaceholderEntry>,
    /// Entries that were waived.
    pub waived_entries: Vec<PlaceholderEntry>,
    /// Auditable decision receipt.
    pub receipt: DecisionReceipt,
}

impl GateReport {
    /// Total placeholder count across all scans.
    pub fn total_placeholders(&self) -> usize {
        self.scan_results
            .iter()
            .map(|s| s.placeholder_count())
            .sum()
    }

    /// Whether the gate passed.
    pub fn is_pass(&self) -> bool {
        self.verdict.is_pass()
    }

    /// Whether the gate blocked.
    pub fn is_block(&self) -> bool {
        self.verdict.is_block()
    }

    /// Count of blocked entries.
    pub fn blocked_count(&self) -> usize {
        self.blocked_entries.len()
    }

    /// Count of warned entries.
    pub fn warned_count(&self) -> usize {
        self.warned_entries.len()
    }

    /// Count of waived entries.
    pub fn waived_count(&self) -> usize {
        self.waived_entries.len()
    }
}

// ---------------------------------------------------------------------------
// GateError
// ---------------------------------------------------------------------------

/// Errors from the gate evaluation pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum GateError {
    #[error("too many active waivers: {active} exceeds limit {limit}")]
    TooManyWaivers { active: usize, limit: usize },

    #[error("waiver {waiver_id} missing justification")]
    MissingJustification { waiver_id: String },

    #[error("waiver {waiver_id} missing owner")]
    MissingOwner { waiver_id: String },

    #[error("waiver {waiver_id} duration {duration} exceeds max {max_duration}")]
    WaiverDurationExceeded {
        waiver_id: String,
        duration: u64,
        max_duration: u64,
    },

    #[error("no scan results provided")]
    EmptyScans,

    #[error("duplicate subsystem in scans: {subsystem}")]
    DuplicateSubsystem { subsystem: String },
}

// ---------------------------------------------------------------------------
// validate_waiver
// ---------------------------------------------------------------------------

/// Determine the effective status of a waiver at a given epoch.
pub fn validate_waiver(waiver: &Waiver, current_epoch: u64) -> WaiverStatus {
    match waiver.status {
        WaiverStatus::Revoked => WaiverStatus::Revoked,
        WaiverStatus::Expired => WaiverStatus::Expired,
        WaiverStatus::Active => {
            if current_epoch > waiver.expires_epoch {
                WaiverStatus::Expired
            } else {
                WaiverStatus::Active
            }
        }
    }
}

// ---------------------------------------------------------------------------
// evaluate_gate
// ---------------------------------------------------------------------------

/// Evaluate the zero-placeholder gate.
///
/// For each placeholder found in the scans:
/// 1. Check if there is an active, non-expired waiver matching the
///    placeholder's content hash.
/// 2. If waived, add to waived entries.
/// 3. If not waived, look up the severity → action mapping in the config.
/// 4. Collect blocked, warned entries accordingly.
///
/// Returns a `GateReport` with the overall verdict.
pub fn evaluate_gate(
    scans: &[ScanResult],
    waivers: &[Waiver],
    config: &GateConfig,
    epoch: &SecurityEpoch,
    ts: u64,
) -> Result<GateReport, GateError> {
    // Validate: non-empty scans.
    if scans.is_empty() {
        return Err(GateError::EmptyScans);
    }

    // Validate: no duplicate subsystems.
    let mut seen_subsystems = BTreeSet::new();
    for scan in scans {
        if !seen_subsystems.insert(scan.subsystem) {
            return Err(GateError::DuplicateSubsystem {
                subsystem: scan.subsystem.as_str().to_string(),
            });
        }
    }

    // Build waiver index: placeholder_hash -> Waiver (only active ones).
    let active_waivers: Vec<&Waiver> = waivers
        .iter()
        .filter(|w| validate_waiver(w, epoch.as_u64()) == WaiverStatus::Active)
        .collect();

    // Validate: waiver count.
    if active_waivers.len() > config.max_active_waivers {
        return Err(GateError::TooManyWaivers {
            active: active_waivers.len(),
            limit: config.max_active_waivers,
        });
    }

    // Validate waivers.
    for w in &active_waivers {
        if config.require_justification && w.justification.is_empty() {
            return Err(GateError::MissingJustification {
                waiver_id: w.waiver_id.clone(),
            });
        }
        if config.require_owner && w.owner.is_empty() {
            return Err(GateError::MissingOwner {
                waiver_id: w.waiver_id.clone(),
            });
        }
        let duration = w.expires_epoch.saturating_sub(w.created_epoch);
        if duration > config.waiver_max_duration_epochs {
            return Err(GateError::WaiverDurationExceeded {
                waiver_id: w.waiver_id.clone(),
                duration,
                max_duration: config.waiver_max_duration_epochs,
            });
        }
    }

    // Build lookup set of waived hashes.
    let waived_hashes: BTreeSet<&[u8; 32]> = active_waivers
        .iter()
        .map(|w| w.placeholder_hash.as_bytes())
        .collect();

    let mut blocked_entries = Vec::new();
    let mut warned_entries = Vec::new();
    let mut waived_entries = Vec::new();

    for scan in scans {
        for entry in &scan.placeholders_found {
            if waived_hashes.contains(entry.content_hash.as_bytes()) {
                waived_entries.push(entry.clone());
            } else {
                match config.action_for(entry.severity) {
                    GateAction::Block => blocked_entries.push(entry.clone()),
                    GateAction::Warn => warned_entries.push(entry.clone()),
                    GateAction::Allow => {}
                }
            }
        }
    }

    let verdict = if !blocked_entries.is_empty() {
        GateVerdict::Block
    } else if !warned_entries.is_empty() {
        GateVerdict::Warn
    } else {
        GateVerdict::Pass
    };

    // Compute input hash from all scan content hashes.
    let mut input_buf = Vec::new();
    for scan in scans {
        input_buf.extend_from_slice(scan.scan_content_hash.as_bytes());
    }
    for w in waivers {
        append_str(&mut input_buf, &w.waiver_id);
    }
    let input_hash = ContentHash::compute(&input_buf);

    let receipt = DecisionReceipt::new(*epoch, input_hash, verdict, ts);

    Ok(GateReport {
        scan_results: scans.to_vec(),
        waivers: waivers.to_vec(),
        verdict,
        blocked_entries,
        warned_entries,
        waived_entries,
        receipt,
    })
}

// ---------------------------------------------------------------------------
// summarize_report
// ---------------------------------------------------------------------------

/// Produce a human-readable summary of a gate report.
pub fn summarize_report(report: &GateReport) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "Zero-Placeholder Gate — verdict: {}",
        report.verdict
    ));
    lines.push(format!(
        "  total placeholders: {}",
        report.total_placeholders()
    ));
    lines.push(format!("  blocked: {}", report.blocked_count()));
    lines.push(format!("  warned:  {}", report.warned_count()));
    lines.push(format!("  waived:  {}", report.waived_count()));

    if !report.blocked_entries.is_empty() {
        lines.push("  blocked entries:".to_string());
        for e in &report.blocked_entries {
            lines.push(format!(
                "    - [{}] {}:{} ({})",
                e.subsystem, e.location_file, e.location_line, e.kind
            ));
        }
    }
    if !report.warned_entries.is_empty() {
        lines.push("  warned entries:".to_string());
        for e in &report.warned_entries {
            lines.push(format!(
                "    - [{}] {}:{} ({})",
                e.subsystem, e.location_file, e.location_line, e.kind
            ));
        }
    }
    if !report.waived_entries.is_empty() {
        lines.push("  waived entries:".to_string());
        for e in &report.waived_entries {
            lines.push(format!(
                "    - [{}] {}:{} ({})",
                e.subsystem, e.location_file, e.location_line, e.kind
            ));
        }
    }

    lines.push(format!("  receipt epoch: {}", report.receipt.epoch));
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(100)
    }

    fn blocking_entry(subsystem: Subsystem) -> PlaceholderEntry {
        PlaceholderEntry::new(
            subsystem,
            PlaceholderKind::UnimplementedPanic,
            "src/lib.rs",
            42,
            "unimplemented!() in hot path",
            PlaceholderSeverity::Blocking,
        )
    }

    fn high_entry(subsystem: Subsystem) -> PlaceholderEntry {
        PlaceholderEntry::new(
            subsystem,
            PlaceholderKind::TodoMacro,
            "src/parser.rs",
            100,
            "todo!() in error recovery",
            PlaceholderSeverity::High,
        )
    }

    fn medium_entry(subsystem: Subsystem) -> PlaceholderEntry {
        PlaceholderEntry::new(
            subsystem,
            PlaceholderKind::StubReturn,
            "src/lowering.rs",
            200,
            "stub return value",
            PlaceholderSeverity::Medium,
        )
    }

    fn low_entry(subsystem: Subsystem) -> PlaceholderEntry {
        PlaceholderEntry::new(
            subsystem,
            PlaceholderKind::HardcodedFallback,
            "src/runtime.rs",
            300,
            "hardcoded fallback",
            PlaceholderSeverity::Low,
        )
    }

    fn make_waiver(entry: &PlaceholderEntry, subsystem: Subsystem) -> Waiver {
        Waiver {
            waiver_id: format!("waiver-{}", entry.location_line),
            placeholder_hash: entry.content_hash,
            subsystem,
            justification: "deferred to next sprint".to_string(),
            owner: "team-alpha".to_string(),
            expires_epoch: 150,
            status: WaiverStatus::Active,
            created_epoch: 50,
        }
    }

    fn clean_scan(subsystem: Subsystem) -> ScanResult {
        ScanResult::new(subsystem, Vec::new(), test_epoch())
    }

    fn scan_with(subsystem: Subsystem, entries: Vec<PlaceholderEntry>) -> ScanResult {
        ScanResult::new(subsystem, entries, test_epoch())
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(SCHEMA_VERSION.contains("zero-placeholder-gate"));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "zero_placeholder_gate");
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
    fn millionths_value() {
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    #[test]
    fn default_max_waivers() {
        assert_eq!(DEFAULT_MAX_ACTIVE_WAIVERS, 20);
    }

    #[test]
    fn default_waiver_max_duration() {
        assert_eq!(DEFAULT_WAIVER_MAX_DURATION_EPOCHS, 100);
    }

    // --- Subsystem ---

    #[test]
    fn subsystem_all_count() {
        assert_eq!(Subsystem::ALL.len(), 8);
    }

    #[test]
    fn subsystem_names_unique() {
        let names: BTreeSet<&str> = Subsystem::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), Subsystem::ALL.len());
    }

    #[test]
    fn subsystem_display_matches_as_str() {
        for s in Subsystem::ALL {
            assert_eq!(s.to_string(), s.as_str());
        }
    }

    #[test]
    fn subsystem_serde_roundtrip() {
        for s in Subsystem::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: Subsystem = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn subsystem_clone_copy() {
        let s = Subsystem::Parser;
        let c = s;
        assert_eq!(s, c);
    }

    // --- PlaceholderKind ---

    #[test]
    fn kind_all_count() {
        assert_eq!(PlaceholderKind::ALL.len(), 6);
    }

    #[test]
    fn kind_names_unique() {
        let names: BTreeSet<&str> = PlaceholderKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), PlaceholderKind::ALL.len());
    }

    #[test]
    fn kind_display_matches_as_str() {
        for k in PlaceholderKind::ALL {
            assert_eq!(k.to_string(), k.as_str());
        }
    }

    #[test]
    fn kind_serde_roundtrip() {
        for k in PlaceholderKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: PlaceholderKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // --- PlaceholderSeverity ---

    #[test]
    fn severity_all_count() {
        assert_eq!(PlaceholderSeverity::ALL.len(), 4);
    }

    #[test]
    fn severity_ordering() {
        assert!(PlaceholderSeverity::Blocking < PlaceholderSeverity::High);
        assert!(PlaceholderSeverity::High < PlaceholderSeverity::Medium);
        assert!(PlaceholderSeverity::Medium < PlaceholderSeverity::Low);
    }

    #[test]
    fn severity_display_matches_as_str() {
        for s in PlaceholderSeverity::ALL {
            assert_eq!(s.to_string(), s.as_str());
        }
    }

    #[test]
    fn severity_serde_roundtrip() {
        for s in PlaceholderSeverity::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: PlaceholderSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // --- PlaceholderEntry ---

    #[test]
    fn entry_content_hash_deterministic() {
        let e1 = PlaceholderEntry::new(
            Subsystem::Parser,
            PlaceholderKind::TodoMacro,
            "a.rs",
            10,
            "desc",
            PlaceholderSeverity::High,
        );
        let e2 = PlaceholderEntry::new(
            Subsystem::Parser,
            PlaceholderKind::TodoMacro,
            "a.rs",
            10,
            "desc",
            PlaceholderSeverity::High,
        );
        assert_eq!(e1.content_hash, e2.content_hash);
    }

    #[test]
    fn entry_different_inputs_different_hash() {
        let e1 = PlaceholderEntry::new(
            Subsystem::Parser,
            PlaceholderKind::TodoMacro,
            "a.rs",
            10,
            "desc",
            PlaceholderSeverity::High,
        );
        let e2 = PlaceholderEntry::new(
            Subsystem::Lowering,
            PlaceholderKind::TodoMacro,
            "a.rs",
            10,
            "desc",
            PlaceholderSeverity::High,
        );
        assert_ne!(e1.content_hash, e2.content_hash);
    }

    #[test]
    fn entry_serde_roundtrip() {
        let e = blocking_entry(Subsystem::Parser);
        let json = serde_json::to_string(&e).unwrap();
        let back: PlaceholderEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- WaiverStatus ---

    #[test]
    fn waiver_status_display() {
        assert_eq!(WaiverStatus::Active.to_string(), "active");
        assert_eq!(WaiverStatus::Expired.to_string(), "expired");
        assert_eq!(WaiverStatus::Revoked.to_string(), "revoked");
    }

    #[test]
    fn waiver_status_serde_roundtrip() {
        for s in [
            WaiverStatus::Active,
            WaiverStatus::Expired,
            WaiverStatus::Revoked,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: WaiverStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    // --- validate_waiver ---

    #[test]
    fn validate_waiver_active() {
        let e = blocking_entry(Subsystem::Parser);
        let w = make_waiver(&e, Subsystem::Parser);
        assert_eq!(validate_waiver(&w, 100), WaiverStatus::Active);
    }

    #[test]
    fn validate_waiver_expired_by_epoch() {
        let e = blocking_entry(Subsystem::Parser);
        let w = make_waiver(&e, Subsystem::Parser);
        assert_eq!(validate_waiver(&w, 201), WaiverStatus::Expired);
    }

    #[test]
    fn validate_waiver_at_boundary() {
        let e = blocking_entry(Subsystem::Parser);
        let w = make_waiver(&e, Subsystem::Parser);
        // At exactly expires_epoch, still active.
        assert_eq!(validate_waiver(&w, 200), WaiverStatus::Active);
    }

    #[test]
    fn validate_waiver_revoked_regardless_of_epoch() {
        let e = blocking_entry(Subsystem::Parser);
        let mut w = make_waiver(&e, Subsystem::Parser);
        w.status = WaiverStatus::Revoked;
        assert_eq!(validate_waiver(&w, 50), WaiverStatus::Revoked);
    }

    #[test]
    fn validate_waiver_expired_status() {
        let e = blocking_entry(Subsystem::Parser);
        let mut w = make_waiver(&e, Subsystem::Parser);
        w.status = WaiverStatus::Expired;
        assert_eq!(validate_waiver(&w, 50), WaiverStatus::Expired);
    }

    // --- GateAction ---

    #[test]
    fn gate_action_display() {
        assert_eq!(GateAction::Block.to_string(), "block");
        assert_eq!(GateAction::Warn.to_string(), "warn");
        assert_eq!(GateAction::Allow.to_string(), "allow");
    }

    #[test]
    fn gate_action_serde_roundtrip() {
        for a in [GateAction::Block, GateAction::Warn, GateAction::Allow] {
            let json = serde_json::to_string(&a).unwrap();
            let back: GateAction = serde_json::from_str(&json).unwrap();
            assert_eq!(a, back);
        }
    }

    // --- GateConfig ---

    #[test]
    fn default_config_severity_mapping() {
        let cfg = GateConfig::default_config();
        assert_eq!(
            cfg.action_for(PlaceholderSeverity::Blocking),
            GateAction::Block
        );
        assert_eq!(cfg.action_for(PlaceholderSeverity::High), GateAction::Warn);
        assert_eq!(
            cfg.action_for(PlaceholderSeverity::Medium),
            GateAction::Allow
        );
        assert_eq!(cfg.action_for(PlaceholderSeverity::Low), GateAction::Allow);
    }

    #[test]
    fn strict_config_all_block() {
        let cfg = GateConfig::strict();
        for sev in PlaceholderSeverity::ALL {
            assert_eq!(cfg.action_for(*sev), GateAction::Block);
        }
    }

    #[test]
    fn permissive_config_all_allow() {
        let cfg = GateConfig::permissive();
        for sev in PlaceholderSeverity::ALL {
            assert_eq!(cfg.action_for(*sev), GateAction::Allow);
        }
    }

    #[test]
    fn config_default_trait() {
        let a = GateConfig::default();
        let b = GateConfig::default_config();
        assert_eq!(a, b);
    }

    #[test]
    fn config_action_for_missing_defaults_to_block() {
        let cfg = GateConfig {
            severity_actions: BTreeMap::new(),
            max_active_waivers: 10,
            waiver_max_duration_epochs: 50,
            require_justification: false,
            require_owner: false,
        };
        assert_eq!(
            cfg.action_for(PlaceholderSeverity::Blocking),
            GateAction::Block
        );
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = GateConfig::default_config();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    // --- ScanResult ---

    #[test]
    fn scan_result_clean() {
        let s = clean_scan(Subsystem::Parser);
        assert!(s.is_clean());
        assert_eq!(s.placeholder_count(), 0);
    }

    #[test]
    fn scan_result_with_entries() {
        let s = scan_with(
            Subsystem::Parser,
            vec![
                blocking_entry(Subsystem::Parser),
                high_entry(Subsystem::Parser),
            ],
        );
        assert!(!s.is_clean());
        assert_eq!(s.placeholder_count(), 2);
    }

    #[test]
    fn scan_result_hash_deterministic() {
        let entries = vec![blocking_entry(Subsystem::Parser)];
        let s1 = ScanResult::new(Subsystem::Parser, entries.clone(), test_epoch());
        let s2 = ScanResult::new(Subsystem::Parser, entries, test_epoch());
        assert_eq!(s1.scan_content_hash, s2.scan_content_hash);
    }

    #[test]
    fn scan_result_serde_roundtrip() {
        let s = scan_with(Subsystem::Lowering, vec![medium_entry(Subsystem::Lowering)]);
        let json = serde_json::to_string(&s).unwrap();
        let back: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // --- GateVerdict ---

    #[test]
    fn verdict_display() {
        assert_eq!(GateVerdict::Pass.to_string(), "pass");
        assert_eq!(GateVerdict::Warn.to_string(), "warn");
        assert_eq!(GateVerdict::Block.to_string(), "block");
    }

    #[test]
    fn verdict_is_pass() {
        assert!(GateVerdict::Pass.is_pass());
        assert!(!GateVerdict::Block.is_pass());
    }

    #[test]
    fn verdict_is_block() {
        assert!(GateVerdict::Block.is_block());
        assert!(!GateVerdict::Pass.is_block());
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for v in [GateVerdict::Pass, GateVerdict::Warn, GateVerdict::Block] {
            let json = serde_json::to_string(&v).unwrap();
            let back: GateVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // --- DecisionReceipt ---

    #[test]
    fn receipt_fields() {
        let r = DecisionReceipt::new(
            test_epoch(),
            ContentHash::compute(b"input"),
            GateVerdict::Pass,
            1000,
        );
        assert_eq!(r.schema_version, SCHEMA_VERSION);
        assert_eq!(r.component, COMPONENT);
        assert_eq!(r.bead_id, BEAD_ID);
        assert_eq!(r.policy_id, POLICY_ID);
        assert_eq!(r.epoch, test_epoch());
        assert_eq!(r.timestamp_micros, 1000);
    }

    #[test]
    fn receipt_deterministic() {
        let ih = ContentHash::compute(b"x");
        let r1 = DecisionReceipt::new(test_epoch(), ih, GateVerdict::Pass, 500);
        let r2 = DecisionReceipt::new(test_epoch(), ih, GateVerdict::Pass, 500);
        assert_eq!(r1.verdict_hash, r2.verdict_hash);
    }

    #[test]
    fn receipt_different_verdict_different_hash() {
        let ih = ContentHash::compute(b"x");
        let r1 = DecisionReceipt::new(test_epoch(), ih, GateVerdict::Pass, 500);
        let r2 = DecisionReceipt::new(test_epoch(), ih, GateVerdict::Block, 500);
        assert_ne!(r1.verdict_hash, r2.verdict_hash);
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let r = DecisionReceipt::new(
            test_epoch(),
            ContentHash::compute(b"input"),
            GateVerdict::Warn,
            999,
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- evaluate_gate ---

    #[test]
    fn gate_clean_scans_pass() {
        let scans = vec![clean_scan(Subsystem::Parser)];
        let r = evaluate_gate(&scans, &[], &GateConfig::default(), &test_epoch(), 1).unwrap();
        assert!(r.is_pass());
        assert_eq!(r.blocked_count(), 0);
        assert_eq!(r.warned_count(), 0);
    }

    #[test]
    fn gate_blocking_without_waiver_blocks() {
        let entry = blocking_entry(Subsystem::Parser);
        let scans = vec![scan_with(Subsystem::Parser, vec![entry])];
        let r = evaluate_gate(&scans, &[], &GateConfig::default(), &test_epoch(), 1).unwrap();
        assert!(r.is_block());
        assert_eq!(r.blocked_count(), 1);
    }

    #[test]
    fn gate_blocking_with_waiver_passes() {
        let entry = blocking_entry(Subsystem::Parser);
        let waiver = make_waiver(&entry, Subsystem::Parser);
        let scans = vec![scan_with(Subsystem::Parser, vec![entry])];
        let r = evaluate_gate(&scans, &[waiver], &GateConfig::default(), &test_epoch(), 1).unwrap();
        assert!(r.is_pass());
        assert_eq!(r.waived_count(), 1);
    }

    #[test]
    fn gate_high_without_waiver_warns() {
        let entry = high_entry(Subsystem::Parser);
        let scans = vec![scan_with(Subsystem::Parser, vec![entry])];
        let r = evaluate_gate(&scans, &[], &GateConfig::default(), &test_epoch(), 1).unwrap();
        assert_eq!(r.verdict, GateVerdict::Warn);
        assert_eq!(r.warned_count(), 1);
    }

    #[test]
    fn gate_medium_and_low_allowed() {
        let scans = vec![scan_with(
            Subsystem::Runtime,
            vec![
                medium_entry(Subsystem::Runtime),
                low_entry(Subsystem::Runtime),
            ],
        )];
        let r = evaluate_gate(&scans, &[], &GateConfig::default(), &test_epoch(), 1).unwrap();
        assert!(r.is_pass());
    }

    #[test]
    fn gate_empty_scans_error() {
        let r = evaluate_gate(&[], &[], &GateConfig::default(), &test_epoch(), 1);
        assert!(matches!(r, Err(GateError::EmptyScans)));
    }

    #[test]
    fn gate_duplicate_subsystem_error() {
        let scans = vec![clean_scan(Subsystem::Parser), clean_scan(Subsystem::Parser)];
        let r = evaluate_gate(&scans, &[], &GateConfig::default(), &test_epoch(), 1);
        assert!(matches!(r, Err(GateError::DuplicateSubsystem { .. })));
    }

    #[test]
    fn gate_too_many_waivers_error() {
        let cfg = GateConfig {
            max_active_waivers: 0,
            ..GateConfig::default()
        };
        let entry = blocking_entry(Subsystem::Parser);
        let waiver = make_waiver(&entry, Subsystem::Parser);
        let scans = vec![scan_with(Subsystem::Parser, vec![entry])];
        let r = evaluate_gate(&scans, &[waiver], &cfg, &test_epoch(), 1);
        assert!(matches!(r, Err(GateError::TooManyWaivers { .. })));
    }

    #[test]
    fn gate_waiver_missing_justification_error() {
        let entry = blocking_entry(Subsystem::Parser);
        let mut w = make_waiver(&entry, Subsystem::Parser);
        w.justification = String::new();
        let scans = vec![scan_with(Subsystem::Parser, vec![entry])];
        let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &test_epoch(), 1);
        assert!(matches!(r, Err(GateError::MissingJustification { .. })));
    }

    #[test]
    fn gate_waiver_missing_owner_error() {
        let entry = blocking_entry(Subsystem::Parser);
        let mut w = make_waiver(&entry, Subsystem::Parser);
        w.owner = String::new();
        let scans = vec![scan_with(Subsystem::Parser, vec![entry])];
        let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &test_epoch(), 1);
        assert!(matches!(r, Err(GateError::MissingOwner { .. })));
    }

    #[test]
    fn gate_waiver_duration_exceeded_error() {
        let cfg = GateConfig {
            waiver_max_duration_epochs: 10,
            ..GateConfig::default()
        };
        let entry = blocking_entry(Subsystem::Parser);
        let w = make_waiver(&entry, Subsystem::Parser); // duration = 200 - 50 = 150
        let scans = vec![scan_with(Subsystem::Parser, vec![entry])];
        let r = evaluate_gate(&scans, &[w], &cfg, &test_epoch(), 1);
        assert!(matches!(r, Err(GateError::WaiverDurationExceeded { .. })));
    }

    #[test]
    fn gate_expired_waiver_not_counted() {
        let entry = blocking_entry(Subsystem::Parser);
        let mut w = make_waiver(&entry, Subsystem::Parser);
        w.expires_epoch = 50; // expires before epoch 100
        w.created_epoch = 40;
        let scans = vec![scan_with(Subsystem::Parser, vec![entry])];
        let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &test_epoch(), 1).unwrap();
        assert!(r.is_block());
        assert_eq!(r.waived_count(), 0);
    }

    #[test]
    fn gate_revoked_waiver_not_counted() {
        let entry = blocking_entry(Subsystem::Parser);
        let mut w = make_waiver(&entry, Subsystem::Parser);
        w.status = WaiverStatus::Revoked;
        let scans = vec![scan_with(Subsystem::Parser, vec![entry])];
        let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &test_epoch(), 1).unwrap();
        assert!(r.is_block());
    }

    #[test]
    fn gate_multiple_scans() {
        let scans = vec![
            clean_scan(Subsystem::Parser),
            clean_scan(Subsystem::Lowering),
            clean_scan(Subsystem::Runtime),
        ];
        let r = evaluate_gate(&scans, &[], &GateConfig::default(), &test_epoch(), 1).unwrap();
        assert!(r.is_pass());
        assert_eq!(r.total_placeholders(), 0);
    }

    #[test]
    fn gate_strict_blocks_low() {
        let entry = low_entry(Subsystem::Cli);
        let scans = vec![scan_with(Subsystem::Cli, vec![entry])];
        let r = evaluate_gate(&scans, &[], &GateConfig::strict(), &test_epoch(), 1).unwrap();
        assert!(r.is_block());
    }

    #[test]
    fn gate_permissive_allows_blocking() {
        let entry = blocking_entry(Subsystem::Parser);
        let scans = vec![scan_with(Subsystem::Parser, vec![entry])];
        let cfg = GateConfig::permissive();
        let r = evaluate_gate(&scans, &[], &cfg, &test_epoch(), 1).unwrap();
        assert!(r.is_pass());
    }

    #[test]
    fn gate_report_total_placeholders() {
        let scans = vec![
            scan_with(Subsystem::Parser, vec![blocking_entry(Subsystem::Parser)]),
            scan_with(
                Subsystem::Lowering,
                vec![
                    high_entry(Subsystem::Lowering),
                    medium_entry(Subsystem::Lowering),
                ],
            ),
        ];
        let r = evaluate_gate(&scans, &[], &GateConfig::default(), &test_epoch(), 1).unwrap();
        assert_eq!(r.total_placeholders(), 3);
    }

    // --- summarize_report ---

    #[test]
    fn summarize_contains_verdict() {
        let scans = vec![clean_scan(Subsystem::Parser)];
        let r = evaluate_gate(&scans, &[], &GateConfig::default(), &test_epoch(), 1).unwrap();
        let s = summarize_report(&r);
        assert!(s.contains("pass"));
    }

    #[test]
    fn summarize_blocked_entries_listed() {
        let entry = blocking_entry(Subsystem::Parser);
        let scans = vec![scan_with(Subsystem::Parser, vec![entry])];
        let r = evaluate_gate(&scans, &[], &GateConfig::default(), &test_epoch(), 1).unwrap();
        let s = summarize_report(&r);
        assert!(s.contains("blocked entries:"));
        assert!(s.contains("src/lib.rs:42"));
    }

    #[test]
    fn summarize_warned_entries_listed() {
        let entry = high_entry(Subsystem::Parser);
        let scans = vec![scan_with(Subsystem::Parser, vec![entry])];
        let r = evaluate_gate(&scans, &[], &GateConfig::default(), &test_epoch(), 1).unwrap();
        let s = summarize_report(&r);
        assert!(s.contains("warned entries:"));
    }

    #[test]
    fn summarize_waived_entries_listed() {
        let entry = blocking_entry(Subsystem::Parser);
        let waiver = make_waiver(&entry, Subsystem::Parser);
        let scans = vec![scan_with(Subsystem::Parser, vec![entry])];
        let r = evaluate_gate(&scans, &[waiver], &GateConfig::default(), &test_epoch(), 1).unwrap();
        let s = summarize_report(&r);
        assert!(s.contains("waived entries:"));
    }

    // --- GateError ---

    #[test]
    fn gate_error_display_too_many_waivers() {
        let e = GateError::TooManyWaivers {
            active: 5,
            limit: 3,
        };
        let msg = e.to_string();
        assert!(msg.contains("5"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn gate_error_display_missing_justification() {
        let e = GateError::MissingJustification {
            waiver_id: "w-1".into(),
        };
        assert!(e.to_string().contains("w-1"));
    }

    #[test]
    fn gate_error_display_missing_owner() {
        let e = GateError::MissingOwner {
            waiver_id: "w-2".into(),
        };
        assert!(e.to_string().contains("w-2"));
    }

    #[test]
    fn gate_error_display_duration_exceeded() {
        let e = GateError::WaiverDurationExceeded {
            waiver_id: "w-3".into(),
            duration: 500,
            max_duration: 100,
        };
        let msg = e.to_string();
        assert!(msg.contains("500"));
        assert!(msg.contains("100"));
    }

    #[test]
    fn gate_error_display_empty_scans() {
        let e = GateError::EmptyScans;
        assert!(e.to_string().contains("no scan results"));
    }

    #[test]
    fn gate_error_display_duplicate() {
        let e = GateError::DuplicateSubsystem {
            subsystem: "parser".into(),
        };
        assert!(e.to_string().contains("parser"));
    }

    #[test]
    fn gate_error_serde_roundtrip() {
        let e = GateError::EmptyScans;
        let json = serde_json::to_string(&e).unwrap();
        let back: GateError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- Mixed scenarios ---

    #[test]
    fn gate_block_dominates_warn() {
        let scans = vec![scan_with(
            Subsystem::Parser,
            vec![
                blocking_entry(Subsystem::Parser),
                high_entry(Subsystem::Parser),
            ],
        )];
        let r = evaluate_gate(&scans, &[], &GateConfig::default(), &test_epoch(), 1).unwrap();
        assert!(r.is_block());
        assert_eq!(r.blocked_count(), 1);
        assert_eq!(r.warned_count(), 1);
    }

    #[test]
    fn gate_waiver_only_covers_matching_hash() {
        let e1 = blocking_entry(Subsystem::Parser);
        let e2 = PlaceholderEntry::new(
            Subsystem::Parser,
            PlaceholderKind::UnimplementedPanic,
            "src/other.rs",
            99,
            "different placeholder",
            PlaceholderSeverity::Blocking,
        );
        let w = make_waiver(&e1, Subsystem::Parser);
        let scans = vec![scan_with(Subsystem::Parser, vec![e1, e2])];
        let r = evaluate_gate(&scans, &[w], &GateConfig::default(), &test_epoch(), 1).unwrap();
        assert!(r.is_block());
        assert_eq!(r.waived_count(), 1);
        assert_eq!(r.blocked_count(), 1);
    }

    #[test]
    fn gate_multiple_subsystems_mixed_verdicts() {
        let b = blocking_entry(Subsystem::Parser);
        let h = high_entry(Subsystem::Lowering);
        let waiver = make_waiver(&b, Subsystem::Parser);
        let scans = vec![
            scan_with(Subsystem::Parser, vec![b]),
            scan_with(Subsystem::Lowering, vec![h]),
        ];
        let r = evaluate_gate(&scans, &[waiver], &GateConfig::default(), &test_epoch(), 1).unwrap();
        // Blocking waived, but High warns.
        assert_eq!(r.verdict, GateVerdict::Warn);
        assert_eq!(r.waived_count(), 1);
        assert_eq!(r.warned_count(), 1);
    }

    #[test]
    fn gate_report_receipt_epoch_matches() {
        let scans = vec![clean_scan(Subsystem::Parser)];
        let r = evaluate_gate(&scans, &[], &GateConfig::default(), &test_epoch(), 42).unwrap();
        assert_eq!(r.receipt.epoch, test_epoch());
        assert_eq!(r.receipt.timestamp_micros, 42);
    }

    #[test]
    fn waiver_struct_serde_roundtrip() {
        let e = blocking_entry(Subsystem::Parser);
        let w = make_waiver(&e, Subsystem::Parser);
        let json = serde_json::to_string(&w).unwrap();
        let back: Waiver = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn gate_report_serde_roundtrip() {
        let scans = vec![scan_with(
            Subsystem::Parser,
            vec![blocking_entry(Subsystem::Parser)],
        )];
        let r = evaluate_gate(&scans, &[], &GateConfig::default(), &test_epoch(), 1).unwrap();
        let json = serde_json::to_string(&r).unwrap();
        let back: GateReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
