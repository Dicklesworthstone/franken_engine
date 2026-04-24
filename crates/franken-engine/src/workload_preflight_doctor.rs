#![forbid(unsafe_code)]

//! Deterministic workload preflight/doctor workflow for migration readiness.
//!
//! The workflow consumes caller-provided compatibility, performance, security,
//! and observability signals and returns a replayable readiness report with
//! fixed-point millionths scoring, deterministic remediation ordering, and a
//! stable artifact identifier.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema version for workload preflight doctor reports.
pub const WORKLOAD_PREFLIGHT_DOCTOR_SCHEMA_VERSION: &str =
    "franken-engine.workload-preflight-doctor.v1";

/// Bead identifier for the workload preflight doctor workflow.
pub const WORKLOAD_PREFLIGHT_DOCTOR_BEAD_ID: &str = "bd-1lsy.10.9";

/// Component identifier embedded in generated reports.
pub const WORKLOAD_PREFLIGHT_DOCTOR_COMPONENT: &str = "workload_preflight_doctor";

/// Fixed-point scale: 1_000_000 millionths = 1.0.
pub const MILLIONTHS: u64 = 1_000_000;

const DEFAULT_MAX_FINDINGS: usize = 10_000;
const DEFAULT_WORKLOAD_PREFLIGHT_COMMAND: &str =
    "runtime_diagnostics workload-preflight-doctor --input <path> --summary";

/// Readiness domain evaluated by workload preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadPreflightDomain {
    /// Node/Bun/FrankenEngine behavior and package compatibility.
    Compatibility,
    /// Throughput, latency, queueing, and resource budget readiness.
    Performance,
    /// Capability, secret, containment, and policy safety readiness.
    Security,
    /// Logs, metrics, traces, replay, and supportability readiness.
    Observability,
}

impl WorkloadPreflightDomain {
    /// Stable lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compatibility => "compatibility",
            Self::Performance => "performance",
            Self::Security => "security",
            Self::Observability => "observability",
        }
    }
}

impl fmt::Display for WorkloadPreflightDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Domains required for a complete preflight doctor pass.
pub const REQUIRED_PREFLIGHT_DOMAINS: &[WorkloadPreflightDomain] = &[
    WorkloadPreflightDomain::Compatibility,
    WorkloadPreflightDomain::Performance,
    WorkloadPreflightDomain::Security,
    WorkloadPreflightDomain::Observability,
];

/// Severity of one workload preflight signal or finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadPreflightSeverity {
    /// Signal passed.
    Pass,
    /// Informational remediation guidance.
    Advisory,
    /// Non-blocking readiness risk.
    Warning,
    /// Blocking readiness issue.
    Error,
    /// Blocking issue with security/data-loss/rollback impact.
    Critical,
}

impl WorkloadPreflightSeverity {
    /// Stable lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Advisory => "advisory",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    /// Fixed-point risk weight in millionths.
    #[must_use]
    pub const fn risk_millionths(self) -> u64 {
        match self {
            Self::Pass => 0,
            Self::Advisory => 50_000,
            Self::Warning => 300_000,
            Self::Error => 700_000,
            Self::Critical => MILLIONTHS,
        }
    }

    /// Whether this severity blocks workload promotion.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::Error | Self::Critical)
    }
}

impl fmt::Display for WorkloadPreflightSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Overall readiness verdict for the workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadPreflightVerdict {
    /// All required checks passed.
    Ready,
    /// Non-blocking findings require operator review.
    Conditional,
    /// One or more blocking findings must be remediated.
    Blocked,
}

impl WorkloadPreflightVerdict {
    /// Stable lowercase identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Conditional => "conditional",
            Self::Blocked => "blocked",
        }
    }
}

impl fmt::Display for WorkloadPreflightVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// One deterministic preflight signal supplied by a checker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadPreflightSignal {
    /// Unique signal identifier.
    pub signal_id: String,
    /// Domain evaluated by this signal.
    pub domain: WorkloadPreflightDomain,
    /// Signal severity.
    pub severity: WorkloadPreflightSeverity,
    /// Human-readable summary.
    pub summary: String,
    /// Deterministic remediation guidance.
    pub remediation: String,
    /// Observed fixed-point value, when the signal is threshold-based.
    pub observed_millionths: u64,
    /// Threshold fixed-point value. Zero disables threshold comparison.
    pub threshold_millionths: u64,
    /// Replayable evidence links.
    pub evidence_links: Vec<String>,
    /// Command that reproduces or refreshes this signal.
    pub reproducible_command: String,
}

/// Input consumed by the workload preflight doctor workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadPreflightDoctorInput {
    /// Stable workload identifier.
    pub workload_id: String,
    /// Package or application name.
    pub package_name: String,
    /// Target platform triples or labels.
    pub target_platforms: Vec<String>,
    /// Deterministic checker signals.
    pub signals: Vec<WorkloadPreflightSignal>,
}

/// Configuration for a workload preflight doctor run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadPreflightDoctorConfig {
    /// Domains required for readiness.
    pub required_domains: BTreeSet<WorkloadPreflightDomain>,
    /// Maximum number of emitted findings.
    pub max_findings: usize,
    /// Whether at least one target platform is mandatory.
    pub require_target_platforms: bool,
    /// Fallback reproduction command.
    pub default_reproducible_command: String,
}

impl Default for WorkloadPreflightDoctorConfig {
    fn default() -> Self {
        Self {
            required_domains: REQUIRED_PREFLIGHT_DOMAINS.iter().copied().collect(),
            max_findings: DEFAULT_MAX_FINDINGS,
            require_target_platforms: true,
            default_reproducible_command: DEFAULT_WORKLOAD_PREFLIGHT_COMMAND.to_string(),
        }
    }
}

/// Deterministic finding surfaced by workload preflight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadPreflightFinding {
    /// Stable finding identifier.
    pub finding_id: String,
    /// Readiness domain.
    pub domain: WorkloadPreflightDomain,
    /// Finding severity.
    pub severity: WorkloadPreflightSeverity,
    /// Deterministic rationale.
    pub rationale: String,
    /// Deterministic remediation guidance.
    pub remediation: String,
    /// Fixed-point impact score in millionths.
    pub impact_millionths: u64,
    /// Replayable evidence links.
    pub evidence_links: Vec<String>,
    /// Command that reproduces or refreshes the finding.
    pub reproducible_command: String,
}

/// Per-domain readiness score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadDomainScore {
    /// Readiness domain.
    pub domain: WorkloadPreflightDomain,
    /// Total input checks for this domain.
    pub total_checks: u64,
    /// Number of blocking findings.
    pub blocking_findings: u64,
    /// Number of warning findings.
    pub warning_findings: u64,
    /// Number of advisory findings.
    pub advisory_findings: u64,
    /// Readiness score in millionths.
    pub score_millionths: u64,
    /// Per-domain verdict.
    pub verdict: WorkloadPreflightVerdict,
}

/// Deterministic workload preflight doctor report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadPreflightDoctorReport {
    /// Schema version.
    pub schema_version: String,
    /// Bead that originated this workflow.
    pub bead_id: String,
    /// Component identifier.
    pub component: String,
    /// Stable workload identifier.
    pub workload_id: String,
    /// Package or application name.
    pub package_name: String,
    /// Normalized target platforms.
    pub target_platforms: Vec<String>,
    /// Overall readiness verdict.
    pub verdict: WorkloadPreflightVerdict,
    /// Per-domain scores keyed by domain identifier.
    pub domain_scores: BTreeMap<String, WorkloadDomainScore>,
    /// Deterministically ordered findings.
    pub findings: Vec<WorkloadPreflightFinding>,
    /// Missing required fields.
    pub missing_fields: Vec<String>,
    /// Deduplicated reproduction commands.
    pub reproducible_commands: Vec<String>,
    /// Stable report artifact ID.
    pub artifact_id: String,
}

/// Run the deterministic workload preflight doctor workflow.
#[must_use]
pub fn run_workload_preflight_doctor(
    input: &WorkloadPreflightDoctorInput,
    config: &WorkloadPreflightDoctorConfig,
) -> WorkloadPreflightDoctorReport {
    let workload_id = normalize_or_default(&input.workload_id, "unknown-workload");
    let package_name = normalize_or_default(&input.package_name, "unknown-package");
    let target_platforms = normalize_list(&input.target_platforms);
    let mut signals = input.signals.clone();
    normalize_signals(&mut signals, config);
    let mut missing_fields = collect_missing_fields(input, &target_platforms, config);
    let mut findings = build_signal_findings(&signals, config);
    findings.extend(build_contract_findings(&missing_fields, config));
    findings.extend(build_domain_coverage_findings(&signals, config));
    sort_and_cap_findings(&mut findings, config.max_findings);
    let domain_scores = build_domain_scores(&signals, &findings, config);
    let verdict = choose_verdict(&findings);
    let reproducible_commands = collect_reproducible_commands(&findings, config);
    missing_fields.sort();
    missing_fields.dedup();

    let artifact_id = compute_artifact_id(
        &workload_id,
        &package_name,
        &target_platforms,
        verdict,
        &domain_scores,
        &findings,
        &missing_fields,
        &reproducible_commands,
    );

    WorkloadPreflightDoctorReport {
        schema_version: WORKLOAD_PREFLIGHT_DOCTOR_SCHEMA_VERSION.to_string(),
        bead_id: WORKLOAD_PREFLIGHT_DOCTOR_BEAD_ID.to_string(),
        component: WORKLOAD_PREFLIGHT_DOCTOR_COMPONENT.to_string(),
        workload_id,
        package_name,
        target_platforms,
        verdict,
        domain_scores,
        findings,
        missing_fields,
        reproducible_commands,
        artifact_id,
    }
}

/// Render a deterministic, human-readable workload preflight summary.
#[must_use]
pub fn render_workload_preflight_summary(report: &WorkloadPreflightDoctorReport) -> String {
    let mut lines = vec![
        format!("schema_version: {}", report.schema_version),
        format!("artifact_id: {}", report.artifact_id),
        format!("workload_id: {}", report.workload_id),
        format!("package_name: {}", report.package_name),
        format!("verdict: {}", report.verdict),
        "target_platforms:".to_string(),
    ];
    for platform in &report.target_platforms {
        lines.push(format!("  - {platform}"));
    }
    lines.push("domain_scores:".to_string());
    for score in report.domain_scores.values() {
        lines.push(format!(
            "  - {} score={} verdict={} checks={} blocking={}",
            score.domain,
            score.score_millionths,
            score.verdict,
            score.total_checks,
            score.blocking_findings
        ));
    }
    lines.push(format!("findings: {}", report.findings.len()));
    for finding in &report.findings {
        lines.push(format!(
            "  - [{}] {} {} :: {}",
            finding.severity, finding.domain, finding.finding_id, finding.rationale
        ));
        lines.push(format!("    remediation: {}", finding.remediation));
        lines.push(format!(
            "    reproducible_command: {}",
            finding.reproducible_command
        ));
    }
    lines.push("reproducible_commands:".to_string());
    for command in &report.reproducible_commands {
        lines.push(format!("  - {command}"));
    }
    lines.join("\n")
}

fn normalize_or_default(value: &str, default: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalize_signals(
    signals: &mut [WorkloadPreflightSignal],
    config: &WorkloadPreflightDoctorConfig,
) {
    for signal in signals.iter_mut() {
        signal.signal_id = normalize_or_default(&signal.signal_id, "missing-signal-id");
        signal.summary = signal.summary.trim().to_string();
        signal.remediation = signal.remediation.trim().to_string();
        signal.evidence_links = normalize_list(&signal.evidence_links);
        signal.reproducible_command =
            normalize_command(&signal.reproducible_command, config).to_string();
        signal.observed_millionths = signal.observed_millionths.min(MILLIONTHS);
        signal.threshold_millionths = signal.threshold_millionths.min(MILLIONTHS);
    }
    signals.sort_by(|left, right| {
        left.domain
            .cmp(&right.domain)
            .then(left.signal_id.cmp(&right.signal_id))
            .then(left.summary.cmp(&right.summary))
    });
}

fn normalize_command<'a>(command: &'a str, config: &'a WorkloadPreflightDoctorConfig) -> &'a str {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        config.default_reproducible_command.as_str()
    } else {
        trimmed
    }
}

fn collect_missing_fields(
    input: &WorkloadPreflightDoctorInput,
    target_platforms: &[String],
    config: &WorkloadPreflightDoctorConfig,
) -> Vec<String> {
    let mut missing = Vec::new();
    if input.workload_id.trim().is_empty() {
        missing.push("workload_id".to_string());
    }
    if input.package_name.trim().is_empty() {
        missing.push("package_name".to_string());
    }
    if config.require_target_platforms && target_platforms.is_empty() {
        missing.push("target_platforms".to_string());
    }
    for signal in &input.signals {
        if signal.signal_id.trim().is_empty() {
            missing.push(format!("signals.{}.signal_id", signal.domain));
        }
        if signal.summary.trim().is_empty() {
            missing.push(format!("signals.{}.summary", signal.domain));
        }
        if signal.remediation.trim().is_empty()
            && signal.severity != WorkloadPreflightSeverity::Pass
        {
            missing.push(format!("signals.{}.remediation", signal.domain));
        }
    }
    missing.sort();
    missing.dedup();
    missing
}

fn build_signal_findings(
    signals: &[WorkloadPreflightSignal],
    config: &WorkloadPreflightDoctorConfig,
) -> Vec<WorkloadPreflightFinding> {
    let mut findings = Vec::new();
    for signal in signals {
        let threshold_exceeded = signal.threshold_millionths > 0
            && signal.observed_millionths > signal.threshold_millionths;
        let severity = if threshold_exceeded && signal.severity < WorkloadPreflightSeverity::Warning
        {
            WorkloadPreflightSeverity::Warning
        } else {
            signal.severity
        };
        if severity == WorkloadPreflightSeverity::Pass && !threshold_exceeded {
            continue;
        }

        let rationale = if threshold_exceeded {
            format!(
                "{} (observed={} threshold={})",
                normalize_or_default(&signal.summary, "threshold exceeded"),
                signal.observed_millionths,
                signal.threshold_millionths
            )
        } else {
            normalize_or_default(&signal.summary, "preflight signal requires review")
        };
        let impact_millionths = severity
            .risk_millionths()
            .max(threshold_impact_millionths(signal));
        findings.push(WorkloadPreflightFinding {
            finding_id: format!("signal:{}", signal.signal_id),
            domain: signal.domain,
            severity,
            rationale,
            remediation: normalize_or_default(
                &signal.remediation,
                "review workload preflight signal",
            ),
            impact_millionths,
            evidence_links: signal.evidence_links.clone(),
            reproducible_command: normalize_command(&signal.reproducible_command, config)
                .to_string(),
        });
    }
    findings
}

fn threshold_impact_millionths(signal: &WorkloadPreflightSignal) -> u64 {
    if signal.threshold_millionths == 0 || signal.observed_millionths <= signal.threshold_millionths
    {
        return 0;
    }
    signal
        .observed_millionths
        .saturating_sub(signal.threshold_millionths)
        .min(MILLIONTHS)
}

fn build_contract_findings(
    missing_fields: &[String],
    config: &WorkloadPreflightDoctorConfig,
) -> Vec<WorkloadPreflightFinding> {
    missing_fields
        .iter()
        .map(|field| WorkloadPreflightFinding {
            finding_id: format!("contract:missing:{field}"),
            domain: WorkloadPreflightDomain::Compatibility,
            severity: WorkloadPreflightSeverity::Critical,
            rationale: format!("required workload preflight field `{field}` is missing"),
            remediation: "provide the missing field and rerun workload preflight".to_string(),
            impact_millionths: MILLIONTHS,
            evidence_links: Vec::new(),
            reproducible_command: config.default_reproducible_command.clone(),
        })
        .collect()
}

fn build_domain_coverage_findings(
    signals: &[WorkloadPreflightSignal],
    config: &WorkloadPreflightDoctorConfig,
) -> Vec<WorkloadPreflightFinding> {
    let observed_domains = signals
        .iter()
        .map(|signal| signal.domain)
        .collect::<BTreeSet<_>>();
    config
        .required_domains
        .iter()
        .filter(|domain| !observed_domains.contains(domain))
        .map(|domain| WorkloadPreflightFinding {
            finding_id: format!("coverage:missing:{domain}"),
            domain: *domain,
            severity: WorkloadPreflightSeverity::Warning,
            rationale: format!("{domain} preflight signals are missing"),
            remediation: format!("add deterministic {domain} checks before promotion"),
            impact_millionths: WorkloadPreflightSeverity::Warning.risk_millionths(),
            evidence_links: Vec::new(),
            reproducible_command: config.default_reproducible_command.clone(),
        })
        .collect()
}

fn sort_and_cap_findings(findings: &mut Vec<WorkloadPreflightFinding>, max_findings: usize) {
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(left.domain.cmp(&right.domain))
            .then(left.finding_id.cmp(&right.finding_id))
            .then(left.rationale.cmp(&right.rationale))
    });
    findings.dedup_by(|left, right| {
        left.finding_id == right.finding_id
            && left.domain == right.domain
            && left.severity == right.severity
    });
    findings.truncate(max_findings);
}

fn build_domain_scores(
    signals: &[WorkloadPreflightSignal],
    findings: &[WorkloadPreflightFinding],
    config: &WorkloadPreflightDoctorConfig,
) -> BTreeMap<String, WorkloadDomainScore> {
    let mut domains = config.required_domains.clone();
    domains.extend(signals.iter().map(|signal| signal.domain));
    domains.extend(findings.iter().map(|finding| finding.domain));

    let mut scores = BTreeMap::new();
    for domain in domains {
        let total_checks = u64::try_from(
            signals
                .iter()
                .filter(|signal| signal.domain == domain)
                .count(),
        )
        .unwrap_or(u64::MAX);
        let domain_findings = findings
            .iter()
            .filter(|finding| finding.domain == domain)
            .collect::<Vec<_>>();
        let blocking_findings = u64::try_from(
            domain_findings
                .iter()
                .filter(|finding| finding.severity.is_blocking())
                .count(),
        )
        .unwrap_or(u64::MAX);
        let warning_findings = u64::try_from(
            domain_findings
                .iter()
                .filter(|finding| finding.severity == WorkloadPreflightSeverity::Warning)
                .count(),
        )
        .unwrap_or(u64::MAX);
        let advisory_findings = u64::try_from(
            domain_findings
                .iter()
                .filter(|finding| finding.severity == WorkloadPreflightSeverity::Advisory)
                .count(),
        )
        .unwrap_or(u64::MAX);
        let risk = domain_findings.iter().fold(0_u64, |acc, finding| {
            acc.saturating_add(finding.impact_millionths)
        });
        let score_millionths = MILLIONTHS.saturating_sub(risk.min(MILLIONTHS));
        let verdict = if blocking_findings > 0 {
            WorkloadPreflightVerdict::Blocked
        } else if warning_findings > 0 || advisory_findings > 0 || total_checks == 0 {
            WorkloadPreflightVerdict::Conditional
        } else {
            WorkloadPreflightVerdict::Ready
        };
        scores.insert(
            domain.as_str().to_string(),
            WorkloadDomainScore {
                domain,
                total_checks,
                blocking_findings,
                warning_findings,
                advisory_findings,
                score_millionths,
                verdict,
            },
        );
    }
    scores
}

fn choose_verdict(findings: &[WorkloadPreflightFinding]) -> WorkloadPreflightVerdict {
    if findings
        .iter()
        .any(|finding| finding.severity.is_blocking())
    {
        WorkloadPreflightVerdict::Blocked
    } else if findings.is_empty() {
        WorkloadPreflightVerdict::Ready
    } else {
        WorkloadPreflightVerdict::Conditional
    }
}

fn collect_reproducible_commands(
    findings: &[WorkloadPreflightFinding],
    config: &WorkloadPreflightDoctorConfig,
) -> Vec<String> {
    let mut commands = BTreeSet::new();
    commands.insert(config.default_reproducible_command.trim().to_string());
    for finding in findings {
        let command = finding.reproducible_command.trim();
        if !command.is_empty() {
            commands.insert(command.to_string());
        }
    }
    commands.into_iter().collect()
}

fn compute_artifact_id(
    workload_id: &str,
    package_name: &str,
    target_platforms: &[String],
    verdict: WorkloadPreflightVerdict,
    domain_scores: &BTreeMap<String, WorkloadDomainScore>,
    findings: &[WorkloadPreflightFinding],
    missing_fields: &[String],
    reproducible_commands: &[String],
) -> String {
    let mut hasher = Sha256::new();
    hash_str(&mut hasher, WORKLOAD_PREFLIGHT_DOCTOR_SCHEMA_VERSION);
    hash_str(&mut hasher, WORKLOAD_PREFLIGHT_DOCTOR_BEAD_ID);
    hash_str(&mut hasher, WORKLOAD_PREFLIGHT_DOCTOR_COMPONENT);
    hash_str(&mut hasher, workload_id);
    hash_str(&mut hasher, package_name);
    hash_string_slice(&mut hasher, target_platforms);
    hash_str(&mut hasher, verdict.as_str());
    for (domain, score) in domain_scores {
        hash_str(&mut hasher, domain);
        hash_str(&mut hasher, score.domain.as_str());
        hash_u64(&mut hasher, score.total_checks);
        hash_u64(&mut hasher, score.blocking_findings);
        hash_u64(&mut hasher, score.warning_findings);
        hash_u64(&mut hasher, score.advisory_findings);
        hash_u64(&mut hasher, score.score_millionths);
        hash_str(&mut hasher, score.verdict.as_str());
    }
    for finding in findings {
        hash_str(&mut hasher, &finding.finding_id);
        hash_str(&mut hasher, finding.domain.as_str());
        hash_str(&mut hasher, finding.severity.as_str());
        hash_str(&mut hasher, &finding.rationale);
        hash_str(&mut hasher, &finding.remediation);
        hash_u64(&mut hasher, finding.impact_millionths);
        hash_string_slice(&mut hasher, &finding.evidence_links);
        hash_str(&mut hasher, &finding.reproducible_command);
    }
    hash_string_slice(&mut hasher, missing_fields);
    hash_string_slice(&mut hasher, reproducible_commands);
    let hex = hex::encode(hasher.finalize());
    format!(
        "workload-preflight-{}",
        hex.get(..16).unwrap_or(hex.as_str())
    )
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn hash_str(hasher: &mut Sha256, value: &str) {
    hash_u64(hasher, u64::try_from(value.len()).unwrap_or(u64::MAX));
    hasher.update(value.as_bytes());
}

fn hash_string_slice(hasher: &mut Sha256, values: &[String]) {
    hash_u64(hasher, u64::try_from(values.len()).unwrap_or(u64::MAX));
    for value in values {
        hash_str(hasher, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(
        signal_id: &str,
        domain: WorkloadPreflightDomain,
        severity: WorkloadPreflightSeverity,
    ) -> WorkloadPreflightSignal {
        WorkloadPreflightSignal {
            signal_id: signal_id.to_string(),
            domain,
            severity,
            summary: format!("{domain} summary"),
            remediation: format!("fix {domain} issue"),
            observed_millionths: 0,
            threshold_millionths: 0,
            evidence_links: vec![format!("artifacts/{domain}/{signal_id}.json")],
            reproducible_command: format!("runtime_diagnostics check {domain}"),
        }
    }

    fn clean_input() -> WorkloadPreflightDoctorInput {
        WorkloadPreflightDoctorInput {
            workload_id: "pkg/weather".to_string(),
            package_name: "weather".to_string(),
            target_platforms: vec![
                "linux-x64".to_string(),
                "macos-arm64".to_string(),
                "linux-x64".to_string(),
            ],
            signals: REQUIRED_PREFLIGHT_DOMAINS
                .iter()
                .copied()
                .map(|domain| signal(domain.as_str(), domain, WorkloadPreflightSeverity::Pass))
                .collect(),
        }
    }

    fn run(input: &WorkloadPreflightDoctorInput) -> WorkloadPreflightDoctorReport {
        run_workload_preflight_doctor(input, &WorkloadPreflightDoctorConfig::default())
    }

    #[test]
    fn constants_are_stable() {
        assert_eq!(
            WORKLOAD_PREFLIGHT_DOCTOR_SCHEMA_VERSION,
            "franken-engine.workload-preflight-doctor.v1"
        );
        assert_eq!(WORKLOAD_PREFLIGHT_DOCTOR_BEAD_ID, "bd-1lsy.10.9");
        assert_eq!(
            WORKLOAD_PREFLIGHT_DOCTOR_COMPONENT,
            "workload_preflight_doctor"
        );
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    #[test]
    fn domain_names_are_stable() {
        assert_eq!(
            WorkloadPreflightDomain::Compatibility.as_str(),
            "compatibility"
        );
        assert_eq!(WorkloadPreflightDomain::Performance.as_str(), "performance");
        assert_eq!(WorkloadPreflightDomain::Security.as_str(), "security");
        assert_eq!(
            WorkloadPreflightDomain::Observability.as_str(),
            "observability"
        );
    }

    #[test]
    fn severity_names_are_stable() {
        assert_eq!(WorkloadPreflightSeverity::Pass.as_str(), "pass");
        assert_eq!(WorkloadPreflightSeverity::Advisory.as_str(), "advisory");
        assert_eq!(WorkloadPreflightSeverity::Warning.as_str(), "warning");
        assert_eq!(WorkloadPreflightSeverity::Error.as_str(), "error");
        assert_eq!(WorkloadPreflightSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn severity_weights_are_fixed_point_millionths() {
        assert_eq!(WorkloadPreflightSeverity::Pass.risk_millionths(), 0);
        assert_eq!(
            WorkloadPreflightSeverity::Advisory.risk_millionths(),
            50_000
        );
        assert_eq!(
            WorkloadPreflightSeverity::Warning.risk_millionths(),
            300_000
        );
        assert_eq!(WorkloadPreflightSeverity::Error.risk_millionths(), 700_000);
        assert_eq!(
            WorkloadPreflightSeverity::Critical.risk_millionths(),
            MILLIONTHS
        );
    }

    #[test]
    fn default_config_requires_all_domains() {
        let config = WorkloadPreflightDoctorConfig::default();
        for domain in REQUIRED_PREFLIGHT_DOMAINS {
            assert!(config.required_domains.contains(domain));
        }
        assert!(config.require_target_platforms);
    }

    #[test]
    fn clean_input_is_ready() {
        let report = run(&clean_input());
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Ready);
        assert!(report.findings.is_empty());
        assert!(report.missing_fields.is_empty());
    }

    #[test]
    fn target_platforms_are_sorted_and_deduplicated() {
        let report = run(&clean_input());
        assert_eq!(
            report.target_platforms,
            vec!["linux-x64".to_string(), "macos-arm64".to_string()]
        );
    }

    #[test]
    fn missing_workload_id_blocks_preflight() {
        let mut input = clean_input();
        input.workload_id = " ".to_string();
        let report = run(&input);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Blocked);
        assert!(report.missing_fields.contains(&"workload_id".to_string()));
    }

    #[test]
    fn missing_package_name_blocks_preflight() {
        let mut input = clean_input();
        input.package_name.clear();
        let report = run(&input);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Blocked);
        assert!(report.missing_fields.contains(&"package_name".to_string()));
    }

    #[test]
    fn missing_target_platforms_blocks_when_required() {
        let mut input = clean_input();
        input.target_platforms.clear();
        let report = run(&input);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Blocked);
        assert!(
            report
                .missing_fields
                .contains(&"target_platforms".to_string())
        );
    }

    #[test]
    fn target_platform_requirement_can_be_disabled() {
        let mut input = clean_input();
        input.target_platforms.clear();
        let config = WorkloadPreflightDoctorConfig {
            require_target_platforms: false,
            ..WorkloadPreflightDoctorConfig::default()
        };
        let report = run_workload_preflight_doctor(&input, &config);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Ready);
    }

    #[test]
    fn missing_signal_id_is_reported() {
        let mut input = clean_input();
        input.signals[0].signal_id.clear();
        let report = run(&input);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Blocked);
        assert!(
            report
                .missing_fields
                .iter()
                .any(|field| field.ends_with(".signal_id"))
        );
    }

    #[test]
    fn missing_signal_summary_is_reported() {
        let mut input = clean_input();
        input.signals[0].summary.clear();
        let report = run(&input);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Blocked);
        assert!(
            report
                .missing_fields
                .iter()
                .any(|field| field.ends_with(".summary"))
        );
    }

    #[test]
    fn missing_non_pass_remediation_is_reported() {
        let mut input = clean_input();
        input.signals[0].severity = WorkloadPreflightSeverity::Warning;
        input.signals[0].remediation.clear();
        let report = run(&input);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Blocked);
        assert!(
            report
                .missing_fields
                .iter()
                .any(|field| field.ends_with(".remediation"))
        );
    }

    #[test]
    fn missing_pass_remediation_is_not_reported() {
        let mut input = clean_input();
        input.signals[0].remediation.clear();
        let report = run(&input);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Ready);
    }

    #[test]
    fn missing_domain_coverage_is_conditional() {
        let mut input = clean_input();
        input
            .signals
            .retain(|signal| signal.domain != WorkloadPreflightDomain::Security);
        let report = run(&input);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Conditional);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.finding_id == "coverage:missing:security")
        );
    }

    #[test]
    fn custom_required_domains_skip_unused_coverage() {
        let mut input = clean_input();
        input
            .signals
            .retain(|signal| signal.domain == WorkloadPreflightDomain::Security);
        let config = WorkloadPreflightDoctorConfig {
            required_domains: [WorkloadPreflightDomain::Security].into_iter().collect(),
            ..WorkloadPreflightDoctorConfig::default()
        };
        let report = run_workload_preflight_doctor(&input, &config);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Ready);
        assert_eq!(report.domain_scores.len(), 1);
    }

    #[test]
    fn critical_signal_blocks_preflight() {
        let mut input = clean_input();
        input.signals[0].severity = WorkloadPreflightSeverity::Critical;
        let report = run(&input);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Blocked);
        assert_eq!(
            report.findings[0].severity,
            WorkloadPreflightSeverity::Critical
        );
    }

    #[test]
    fn error_signal_blocks_preflight() {
        let mut input = clean_input();
        input.signals[0].severity = WorkloadPreflightSeverity::Error;
        let report = run(&input);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Blocked);
        assert!(report.findings[0].severity.is_blocking());
    }

    #[test]
    fn warning_signal_is_conditional() {
        let mut input = clean_input();
        input.signals[0].severity = WorkloadPreflightSeverity::Warning;
        let report = run(&input);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Conditional);
    }

    #[test]
    fn advisory_signal_is_conditional() {
        let mut input = clean_input();
        input.signals[0].severity = WorkloadPreflightSeverity::Advisory;
        let report = run(&input);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Conditional);
    }

    #[test]
    fn threshold_exceeded_promotes_pass_signal_to_warning() {
        let mut input = clean_input();
        input.signals[0].observed_millionths = 800_000;
        input.signals[0].threshold_millionths = 700_000;
        let report = run(&input);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Conditional);
        assert_eq!(
            report.findings[0].severity,
            WorkloadPreflightSeverity::Warning
        );
    }

    #[test]
    fn threshold_not_exceeded_keeps_pass_signal_clean() {
        let mut input = clean_input();
        input.signals[0].observed_millionths = 500_000;
        input.signals[0].threshold_millionths = 700_000;
        let report = run(&input);
        assert_eq!(report.verdict, WorkloadPreflightVerdict::Ready);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn findings_are_sorted_by_severity_then_domain_then_id() {
        let mut input = clean_input();
        input.signals[3].severity = WorkloadPreflightSeverity::Warning;
        input.signals[0].severity = WorkloadPreflightSeverity::Critical;
        input.signals[1].severity = WorkloadPreflightSeverity::Error;
        let report = run(&input);
        let severities = report
            .findings
            .iter()
            .map(|finding| finding.severity)
            .collect::<Vec<_>>();
        assert_eq!(
            severities,
            vec![
                WorkloadPreflightSeverity::Critical,
                WorkloadPreflightSeverity::Error,
                WorkloadPreflightSeverity::Warning,
            ]
        );
    }

    #[test]
    fn reproducible_commands_are_deduplicated() {
        let mut input = clean_input();
        input.signals[0].severity = WorkloadPreflightSeverity::Warning;
        input.signals[1].severity = WorkloadPreflightSeverity::Warning;
        input.signals[1].reproducible_command = input.signals[0].reproducible_command.clone();
        let report = run(&input);
        let unique = report.reproducible_commands.iter().collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), report.reproducible_commands.len());
    }

    #[test]
    fn empty_reproducible_command_uses_default() {
        let mut input = clean_input();
        input.signals[0].severity = WorkloadPreflightSeverity::Warning;
        input.signals[0].reproducible_command.clear();
        let report = run(&input);
        assert!(
            report
                .reproducible_commands
                .iter()
                .any(|command| command == DEFAULT_WORKLOAD_PREFLIGHT_COMMAND)
        );
    }

    #[test]
    fn evidence_links_are_sorted_and_deduplicated() {
        let mut input = clean_input();
        input.signals[0].severity = WorkloadPreflightSeverity::Warning;
        input.signals[0].evidence_links = vec![
            "b.json".to_string(),
            "a.json".to_string(),
            "b.json".to_string(),
        ];
        let report = run(&input);
        assert_eq!(
            report.findings[0].evidence_links,
            vec!["a.json".to_string(), "b.json".to_string()]
        );
    }

    #[test]
    fn domain_scores_include_all_required_domains() {
        let report = run(&clean_input());
        for domain in REQUIRED_PREFLIGHT_DOMAINS {
            assert!(report.domain_scores.contains_key(domain.as_str()));
        }
    }

    #[test]
    fn blocking_domain_score_is_zero_for_critical() {
        let mut input = clean_input();
        input.signals[0].severity = WorkloadPreflightSeverity::Critical;
        let report = run(&input);
        let score = report
            .domain_scores
            .get(input.signals[0].domain.as_str())
            .expect("domain score");
        assert_eq!(score.score_millionths, 0);
        assert_eq!(score.verdict, WorkloadPreflightVerdict::Blocked);
    }

    #[test]
    fn warning_domain_score_subtracts_fixed_risk() {
        let mut input = clean_input();
        input.signals[0].severity = WorkloadPreflightSeverity::Warning;
        let report = run(&input);
        let score = report
            .domain_scores
            .get(input.signals[0].domain.as_str())
            .expect("domain score");
        assert_eq!(score.score_millionths, 700_000);
    }

    #[test]
    fn artifact_id_is_deterministic_for_reordered_signals() {
        let input = clean_input();
        let mut reordered = input.clone();
        reordered.signals.reverse();
        assert_eq!(run(&input).artifact_id, run(&reordered).artifact_id);
    }

    #[test]
    fn artifact_id_changes_when_signal_changes() {
        let input = clean_input();
        let mut changed = input.clone();
        changed.signals[0].severity = WorkloadPreflightSeverity::Warning;
        assert_ne!(run(&input).artifact_id, run(&changed).artifact_id);
    }

    #[test]
    fn max_findings_caps_output_deterministically() {
        let mut input = clean_input();
        for signal in &mut input.signals {
            signal.severity = WorkloadPreflightSeverity::Warning;
        }
        let config = WorkloadPreflightDoctorConfig {
            max_findings: 2,
            ..WorkloadPreflightDoctorConfig::default()
        };
        let report = run_workload_preflight_doctor(&input, &config);
        assert_eq!(report.findings.len(), 2);
    }

    #[test]
    fn summary_contains_core_operator_fields() {
        let mut input = clean_input();
        input.signals[0].severity = WorkloadPreflightSeverity::Warning;
        let rendered = render_workload_preflight_summary(&run(&input));
        assert!(rendered.contains("artifact_id: workload-preflight-"));
        assert!(rendered.contains("workload_id: pkg/weather"));
        assert!(rendered.contains("verdict: conditional"));
        assert!(rendered.contains("domain_scores:"));
        assert!(rendered.contains("reproducible_commands:"));
    }

    #[test]
    fn serde_round_trip_preserves_report() {
        let report = run(&clean_input());
        let json = serde_json::to_string(&report).expect("report serializes");
        let restored: WorkloadPreflightDoctorReport =
            serde_json::from_str(&json).expect("report deserializes");
        assert_eq!(report, restored);
    }
}
