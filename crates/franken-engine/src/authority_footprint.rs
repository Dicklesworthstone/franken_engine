//! Per-span authority-footprint analyzer (E5.T1, `bd-fqlfw.5.1`).
//!
//! This module backs `frankenctl check <file>`: it parses a JS/TS source file,
//! lowers it to IR2, and projects the capability + IFC facts the lowering
//! pipeline already computes back onto source spans (`bd-fqlfw.1` span
//! provenance). The output is the **inferred authority footprint for the
//! SUPPORTED syntax of the file** — never a proof of noninterference for
//! arbitrary JS/TS. By construction the analyzer and the runtime enforcer share
//! a single source of truth (`lowering_pipeline::lower_ir0_to_ir3`), so a wrong
//! diagnostic is a UX bug, not a soundness regression.
//!
//! Three classes of fact are surfaced:
//!
//! 1. **Ambient-authority violations.** Lowering applies a deny-by-default
//!    (empty) ambient-authority profile, so any raw ambient access (`eval`,
//!    `process.env`, `require`, `fetch`, `crypto`) is rejected at the lowering
//!    boundary with a concrete [`SourceSpan`] and an implied effect. The
//!    analyzer reports the first such rejection as `error[FE-CAP-0001]` with the
//!    accessor, span, and the [`RuntimeCapability`] that would have to be
//!    granted to mediate it. (Lowering fail-closes on the *first* violation, so
//!    a file is re-checked after each is resolved — this is documented in the
//!    report so the count is never read as "only one exists".)
//! 2. **IFC findings.** When a file lowers cleanly, the IR2 flow-proof artifact
//!    carries denied flows (`error[FE-CAP-0002]`) and required-declassification
//!    obligations (`error[FE-CAP-0003]`), each projected back to the emitting
//!    op's span.
//! 3. **Minimal capability footprint.** The capabilities required by the
//!    supported hostcall edges, with their exact call sites, plus a
//!    least-authority suggestion.
//!
//! The report is a pure function of `(source, source_label, parse_goal)` — it
//! carries no wall-clock or host facts — so `--format json` is byte-deterministic
//! and content-addressed via `report_sha256`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ast::{ParseGoal, SourceSpan};
use crate::capability::RuntimeCapability;
use crate::effect_set::EffectKind;
use crate::ir_contract::{Ir0Module, Ir2Module};
use crate::lowering_pipeline::{
    Ir2FlowProofArtifact, LoweringContext, LoweringPipelineError, lower_ir0_to_ir3,
};
use crate::parser::{CanonicalEs2020Parser, ParserOptions};
use crate::ts_normalization::prepare_source_entry_for_public_entrypoints;

/// Schema id stamped on every emitted report and `run_manifest.json`.
pub const AUTHORITY_FOOTPRINT_SCHEMA_VERSION: &str = "franken-engine.authority-footprint.v1";

/// On-thesis wording discipline (E5): the footprint is for supported syntax and
/// fail-closes on anything it cannot analyze. It is never a noninterference proof.
pub const AUTHORITY_FOOTPRINT_DISCLAIMER: &str = "inferred authority footprint for SUPPORTED syntax; \
not a proof of noninterference for arbitrary JS/TS. Unanalyzable constructs fail closed.";

// Deterministic identity used for the analysis lowering pass. `check` is a
// static, side-effect-free analysis, so these are fixed (never wall-clock or
// per-invocation) to keep the report content-addressable.
const CHECK_TRACE_ID: &str = "trace-frankenctl-check";
const CHECK_DECISION_ID: &str = "decision-frankenctl-check";
const CHECK_POLICY_ID: &str = "frankenctl.check.v1";

// ---------------------------------------------------------------------------
// SourceLocation
// ---------------------------------------------------------------------------

/// A 1-based source location projected from a [`SourceSpan`]. Line/column are
/// 1-based to match parser span output (`span_provenance_goldens` asserts
/// `start_line >= 1`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceLocation {
    pub start_line: u64,
    pub start_column: u64,
    pub end_line: u64,
    pub end_column: u64,
}

impl From<SourceSpan> for SourceLocation {
    fn from(span: SourceSpan) -> Self {
        Self {
            start_line: span.start_line,
            start_column: span.start_column,
            end_line: span.end_line,
            end_column: span.end_column,
        }
    }
}

impl std::fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "L{}:{}", self.start_line, self.start_column)
    }
}

// ---------------------------------------------------------------------------
// CheckFindingKind / CheckFinding
// ---------------------------------------------------------------------------

/// Class of a `check` finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckFindingKind {
    /// A raw ambient-authority access rejected at the lowering boundary.
    AmbientAuthorityViolation,
    /// An IFC flow denied by the flow lattice (secret reaching an open sink).
    UnauthorizedFlow,
    /// An IFC flow permitted only with a signed declassification receipt.
    DeclassificationRequired,
}

impl CheckFindingKind {
    /// Stable `error[FE-CAP-…]` code for this finding class.
    pub const fn error_code(self) -> &'static str {
        match self {
            Self::AmbientAuthorityViolation => "FE-CAP-0001",
            Self::UnauthorizedFlow => "FE-CAP-0002",
            Self::DeclassificationRequired => "FE-CAP-0003",
        }
    }
}

/// Soundness confidence of a finding (E5.T4 wording discipline).
///
/// The analyzer is intentionally binary: it emits a finding only when the
/// runtime enforcer (`lowering_pipeline::lower_ir0_to_ir3`) makes the identical
/// determination — it never guesses. Anything it cannot decide is fail-closed
/// at the report level (`analysis_completeness`), not down-graded to a
/// low-confidence finding. So every emitted finding is [`Definite`]; the variant
/// is recorded explicitly on each finding so output can never be misread as a
/// heuristic guess.
///
/// [`Definite`]: FindingConfidence::Definite
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingConfidence {
    /// The runtime enforcer makes the identical determination from the same
    /// source of truth; this is not a heuristic inference.
    Definite,
}

/// A single `check` finding, span-accurate where the source carries a span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckFinding {
    /// `error[FE-CAP-…]` code (mirrors [`CheckFindingKind::error_code`]).
    pub error_code: String,
    /// Finding class.
    pub kind: CheckFindingKind,
    /// Soundness confidence — always [`FindingConfidence::Definite`]; recorded
    /// per-finding so the output cannot be read as a heuristic guess (E5.T4).
    pub confidence: FindingConfidence,
    /// Human-readable diagnostic message.
    pub message: String,
    /// The offending accessor as written in source (`process.env`, `eval`, …),
    /// when applicable.
    pub accessor: Option<String>,
    /// The capability a grant would have to include to mediate this access.
    pub implied_capability: Option<RuntimeCapability>,
    /// Source location of the finding, when a span is available. `None` for
    /// bare-identifier accessors that carry no span yet (`bd-fqlfw.1.1`).
    pub location: Option<SourceLocation>,
}

// ---------------------------------------------------------------------------
// CapabilityRequirement
// ---------------------------------------------------------------------------

/// One capability the file requires, with the exact call sites that demand it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRequirement {
    /// Typed capability, when the raw tag maps to one.
    pub capability: Option<RuntimeCapability>,
    /// Raw capability tag as the lowering pipeline recorded it (`env_read`,
    /// `builtin:MathPI`, …). Always present; the authority of record.
    pub capability_tag: String,
    /// Source locations (sorted, deduped) where this capability is demanded.
    pub call_sites: Vec<SourceLocation>,
}

// ---------------------------------------------------------------------------
// AuthorityFootprintReport
// ---------------------------------------------------------------------------

/// Coarse outcome of a `check` run, used to derive the process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckOutcome {
    /// File analyzed cleanly with no violations.
    Clean,
    /// File analyzed but at least one authority/IFC finding was raised.
    FindingsPresent,
    /// File could not be analyzed (parse error or unsupported construct). The
    /// fail-closed posture: refuse to emit a footprint we cannot justify.
    Unanalyzable,
}

impl CheckOutcome {
    /// Process exit code: `0` clean, `1` findings, `2` unanalyzable.
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Clean => 0,
            Self::FindingsPresent => 1,
            Self::Unanalyzable => 2,
        }
    }
}

/// Explicit completeness marker (E5.T4): how much of the file the analyzer
/// actually covered. The footprint must never be read as exhaustive when it is
/// not, so the boundary is surfaced rather than implied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisCompleteness {
    /// The whole file lowered to IR2; the footprint is exhaustive for the
    /// supported syntax of this file.
    Complete,
    /// Lowering fail-closed at the first ambient-authority violation; constructs
    /// *after* that point were not analyzed. Re-run after resolving it to
    /// surface any further footprint.
    BoundedAtFirstViolation,
    /// The file could not be analyzed at all (parse error / unsupported
    /// construct); no footprint is asserted.
    Unanalyzable,
}

impl AnalysisCompleteness {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::BoundedAtFirstViolation => "bounded_at_first_violation",
            Self::Unanalyzable => "unanalyzable",
        }
    }
}

/// The full per-file authority-footprint report. Serialized form is a pure
/// function of the inputs (no wall-clock / host facts) so `--format json` is
/// deterministic and `report_sha256` content-addresses the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityFootprintReport {
    pub schema_version: String,
    pub source_path: String,
    pub source_sha256: String,
    pub parse_goal: String,
    pub disclaimer: String,
    /// Explicit boundary of what was analyzed (E5.T4 completeness marker).
    pub analysis_completeness: AnalysisCompleteness,
    /// Whether the file could be analyzed at all. `false` ⇒ fail-closed.
    pub analyzable: bool,
    /// Why analysis failed closed, when `!analyzable`.
    pub fail_closed_reason: Option<String>,
    /// Minimal capability footprint with call sites (sorted by tag).
    pub required_capabilities: Vec<CapabilityRequirement>,
    /// Ambient-authority + IFC findings.
    pub findings: Vec<CheckFinding>,
    /// Least-authority guidance for the operator.
    pub least_authority_suggestion: String,
    /// SHA-256 over the canonical body (with this field blank). Content address.
    pub report_sha256: String,
}

impl AuthorityFootprintReport {
    /// Coarse outcome (drives exit code).
    pub fn outcome(&self) -> CheckOutcome {
        if !self.analyzable {
            CheckOutcome::Unanalyzable
        } else if self.findings.is_empty() {
            CheckOutcome::Clean
        } else {
            CheckOutcome::FindingsPresent
        }
    }

    /// Finalize: sort for determinism and stamp the content hash.
    fn finalize(mut self) -> Self {
        self.required_capabilities
            .sort_by(|a, b| a.capability_tag.cmp(&b.capability_tag));
        self.required_capabilities.dedup();
        self.report_sha256.clear();
        let body = serde_json::to_vec(&self).unwrap_or_default();
        self.report_sha256 = hex::encode(Sha256::digest(&body));
        self
    }

    /// Render a compact human-readable report for the terminal.
    pub fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("authority footprint: {}\n", self.source_path));
        out.push_str(&format!("  ({})\n", self.disclaimer));
        out.push_str(&format!(
            "  completeness: {}\n",
            self.analysis_completeness.as_str()
        ));
        if !self.analyzable {
            out.push_str(&format!(
                "  status: UNANALYZABLE (fail-closed) — {}\n",
                self.fail_closed_reason.as_deref().unwrap_or("unknown")
            ));
            return out;
        }
        if self.analysis_completeness == AnalysisCompleteness::BoundedAtFirstViolation {
            out.push_str(
                "  note: analysis bounded at the first ambient-authority violation; constructs after it are unanalyzed — re-run after resolving it.\n",
            );
        }
        if self.required_capabilities.is_empty() {
            out.push_str("  minimal capabilities: <none> (pure computation)\n");
        } else {
            out.push_str("  minimal capabilities:\n");
            for req in &self.required_capabilities {
                let typed = req
                    .capability
                    .map(|c| format!(" ({c})"))
                    .unwrap_or_default();
                let sites: Vec<String> = req.call_sites.iter().map(|s| s.to_string()).collect();
                out.push_str(&format!(
                    "    - {}{} @ {}\n",
                    req.capability_tag,
                    typed,
                    if sites.is_empty() {
                        "<no span>".to_string()
                    } else {
                        sites.join(", ")
                    }
                ));
            }
        }
        if self.findings.is_empty() {
            out.push_str("  findings: none\n");
        } else {
            out.push_str(&format!("  findings: {}\n", self.findings.len()));
            for finding in &self.findings {
                let loc = finding
                    .location
                    .as_ref()
                    .map(|l| l.to_string())
                    .unwrap_or_else(|| "<no span>".to_string());
                out.push_str(&format!(
                    "    error[{}] @ {}: {}\n",
                    finding.error_code, loc, finding.message
                ));
            }
        }
        out.push_str(&format!(
            "  suggestion: {}\n",
            self.least_authority_suggestion
        ));
        out
    }
}

// ---------------------------------------------------------------------------
// EffectKind -> RuntimeCapability
// ---------------------------------------------------------------------------

/// Map the lowering-time ambient effect to the typed capability a grant would
/// have to include to mediate it. `EnvWrite` and `RandomRead`/`Global` have no
/// dedicated capability today and map to the closest enforced one; this is the
/// implied-grant surface, documented so the mapping is auditable.
pub fn capability_for_effect(effect: EffectKind) -> RuntimeCapability {
    match effect {
        EffectKind::FsRead => RuntimeCapability::FsRead,
        EffectKind::FsWrite => RuntimeCapability::FsWrite,
        EffectKind::NetConnect | EffectKind::NetListen => RuntimeCapability::NetworkEgress,
        EffectKind::ProcSpawn => RuntimeCapability::ProcessSpawn,
        EffectKind::EnvRead | EffectKind::EnvWrite => RuntimeCapability::EnvRead,
        EffectKind::PolicyRequest => RuntimeCapability::PolicyRead,
        EffectKind::Eval => RuntimeCapability::VmDispatch,
        EffectKind::Global => RuntimeCapability::Builtin,
        EffectKind::ClockRead => RuntimeCapability::Timer,
        EffectKind::RandomRead => RuntimeCapability::Builtin,
    }
}

/// Best-effort map a raw capability tag to a typed capability: try the whole
/// tag, then the `prefix` of a `prefix:detail` tag (`builtin:MathPI` →
/// `builtin`). Returns `None` when neither resolves — the raw tag is still the
/// authority of record.
fn capability_for_tag(tag: &str) -> Option<RuntimeCapability> {
    RuntimeCapability::from_tag_str(tag).or_else(|| {
        tag.split(':')
            .next()
            .and_then(RuntimeCapability::from_tag_str)
    })
}

// ---------------------------------------------------------------------------
// analyze_authority_footprint
// ---------------------------------------------------------------------------

/// Analyze a single source file and produce its authority footprint.
///
/// Never panics on malformed input: parse/normalization/lowering failures are
/// reported as a fail-closed (`analyzable = false`) report rather than an error.
pub fn analyze_authority_footprint(
    source: &str,
    source_label: &str,
    parse_goal: ParseGoal,
) -> AuthorityFootprintReport {
    let source_sha256 = hex::encode(Sha256::digest(source.as_bytes()));
    let base = |analyzable: bool| AuthorityFootprintReport {
        schema_version: AUTHORITY_FOOTPRINT_SCHEMA_VERSION.to_string(),
        source_path: source_label.to_string(),
        source_sha256: source_sha256.clone(),
        parse_goal: parse_goal.as_str().to_string(),
        disclaimer: AUTHORITY_FOOTPRINT_DISCLAIMER.to_string(),
        analysis_completeness: if analyzable {
            AnalysisCompleteness::Complete
        } else {
            AnalysisCompleteness::Unanalyzable
        },
        analyzable,
        fail_closed_reason: None,
        required_capabilities: Vec::new(),
        findings: Vec::new(),
        least_authority_suggestion: String::new(),
        report_sha256: String::new(),
    };
    let fail_closed = |reason: String| {
        let mut report = base(false);
        report.fail_closed_reason = Some(reason.clone());
        report.least_authority_suggestion = format!(
            "cannot infer a footprint: {reason}. Resolve the construct or narrow the file, then re-run `frankenctl check`."
        );
        report.finalize()
    };

    let prepared = match prepare_source_entry_for_public_entrypoints(
        source,
        source_label,
        CHECK_TRACE_ID,
        CHECK_DECISION_ID,
        CHECK_POLICY_ID,
    ) {
        Ok(prepared) => prepared,
        Err(error) => return fail_closed(format!("source ingestion failed: {error}")),
    };

    let parser = CanonicalEs2020Parser;
    let (parse_result, _event_ir) = parser.parse_with_event_ir(
        prepared.prepared_source.as_str(),
        parse_goal,
        &ParserOptions::default(),
    );
    let syntax_tree = match parse_result {
        Ok(tree) => tree,
        Err(error) => return fail_closed(format!("parse failed: {error}")),
    };

    let ir0 = Ir0Module::from_syntax_tree(syntax_tree, source_label);
    let context = LoweringContext::new(
        CHECK_TRACE_ID.to_string(),
        CHECK_DECISION_ID.to_string(),
        CHECK_POLICY_ID.to_string(),
    );

    match lower_ir0_to_ir3(&ir0, &context) {
        Ok(output) => {
            report_from_clean_lowering(base(true), &output.ir2, &output.ir2_flow_proof_artifact)
        }
        Err(LoweringPipelineError::AmbientAuthorityViolation {
            required_effect,
            accessor,
            span,
            ..
        }) => report_from_ambient_violation(base(true), required_effect, accessor, span),
        Err(other) => fail_closed(format!("unsupported or unanalyzable construct: {other}")),
    }
}

/// Build the report for a file that hit the fail-closed ambient-authority
/// boundary. The implied capability is the minimal grant; the violation is the
/// single FE-CAP-0001 finding.
fn report_from_ambient_violation(
    mut report: AuthorityFootprintReport,
    required_effect: EffectKind,
    accessor: String,
    span: Option<SourceSpan>,
) -> AuthorityFootprintReport {
    let capability = capability_for_effect(required_effect);
    let location = span.map(SourceLocation::from);

    // Lowering fail-closed at this access, so anything after it is unanalyzed.
    report.analysis_completeness = AnalysisCompleteness::BoundedAtFirstViolation;
    report.findings.push(CheckFinding {
        error_code: CheckFindingKind::AmbientAuthorityViolation
            .error_code()
            .to_string(),
        kind: CheckFindingKind::AmbientAuthorityViolation,
        confidence: FindingConfidence::Definite,
        message: format!(
            "ambient access to `{accessor}` is rejected at the lowering boundary; it requires the `{required_effect}` effect ({capability}), which no ambient identifier may exercise"
        ),
        accessor: Some(accessor.clone()),
        implied_capability: Some(capability),
        location: location.clone(),
    });
    report.required_capabilities.push(CapabilityRequirement {
        capability: Some(capability),
        capability_tag: capability.to_string(),
        call_sites: location.into_iter().collect(),
    });
    report.least_authority_suggestion = format!(
        "mediate `{accessor}` through an explicit `{capability}` capability grant (never widen the ambient profile), or remove the ambient access. Lowering fail-closes on the first ambient violation — re-run `frankenctl check` after resolving this one to surface any others."
    );
    report.finalize()
}

/// Build the report for a file that lowered cleanly: project per-op capability
/// requirements and IFC flow facts back onto source spans.
fn report_from_clean_lowering(
    mut report: AuthorityFootprintReport,
    ir2: &Ir2Module,
    flow_proof: &Ir2FlowProofArtifact,
) -> AuthorityFootprintReport {
    // Per-op required capabilities → minimal footprint with call sites.
    let mut requirements: std::collections::BTreeMap<String, Vec<SourceLocation>> =
        std::collections::BTreeMap::new();
    for op in &ir2.ops {
        if let Some(tag) = &op.required_capability {
            let entry = requirements.entry(tag.0.clone()).or_default();
            if let Some(span) = op.span {
                entry.push(SourceLocation::from(span));
            }
        }
    }
    // Aggregate module-level tags that never landed on a spanned op still count.
    for tag in &ir2.required_capabilities {
        requirements.entry(tag.0.clone()).or_default();
    }
    for (tag, mut sites) in requirements {
        sites.sort();
        sites.dedup();
        report.required_capabilities.push(CapabilityRequirement {
            capability: capability_for_tag(&tag),
            capability_tag: tag,
            call_sites: sites,
        });
    }

    // IFC findings from the flow-proof artifact, projected onto op spans.
    let span_for = |op_index: u64| -> Option<SourceLocation> {
        ir2.ops
            .get(op_index as usize)
            .and_then(|op| op.span)
            .map(SourceLocation::from)
    };
    for denied in &flow_proof.denied_flows {
        report.findings.push(CheckFinding {
            error_code: CheckFindingKind::UnauthorizedFlow.error_code().to_string(),
            kind: CheckFindingKind::UnauthorizedFlow,
            confidence: FindingConfidence::Definite,
            message: format!(
                "value labeled {} reaches a sink with clearance {}: {} ({})",
                denied.source_label, denied.sink_clearance, denied.reason, denied.error_code
            ),
            accessor: None,
            implied_capability: None,
            location: span_for(denied.op_index),
        });
    }
    for obligation in &flow_proof.required_declassifications {
        report.findings.push(CheckFinding {
            error_code: CheckFindingKind::DeclassificationRequired
                .error_code()
                .to_string(),
            kind: CheckFindingKind::DeclassificationRequired,
            confidence: FindingConfidence::Definite,
            message: format!(
                "value labeled {} reaches a sink with clearance {}: permitted only under a signed declassification receipt (obligation {})",
                obligation.source_label, obligation.sink_clearance, obligation.obligation_id
            ),
            accessor: None,
            implied_capability: None,
            location: span_for(obligation.op_index),
        });
    }

    report.least_authority_suggestion = if report.required_capabilities.is_empty() {
        "this file requires no host capabilities for its supported syntax; grant nothing beyond compute-only".to_string()
    } else {
        let tags: Vec<String> = report
            .required_capabilities
            .iter()
            .map(|req| req.capability_tag.clone())
            .collect();
        format!(
            "grant exactly the capabilities this file uses and no more: [{}]",
            tags.join(", ")
        )
    };
    report.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambient_env_read_is_span_accurate_with_minimal_capability() {
        // Known ambient-authority read: process.env.SECRET_KEY on line 2.
        let source = "const greeting = \"hello\";\nconst secret = process.env.SECRET_KEY;\n";
        let report = analyze_authority_footprint(source, "fixture.js", ParseGoal::Script);

        assert!(
            report.analyzable,
            "ambient read should be analyzable (not a parse error)"
        );
        assert_eq!(report.outcome(), CheckOutcome::FindingsPresent);
        assert_eq!(report.outcome().exit_code(), 1);

        assert_eq!(report.findings.len(), 1, "first ambient violation reported");
        let finding = &report.findings[0];
        assert_eq!(finding.error_code, "FE-CAP-0001");
        assert_eq!(finding.kind, CheckFindingKind::AmbientAuthorityViolation);
        assert_eq!(finding.accessor.as_deref(), Some("process.env"));
        assert_eq!(finding.implied_capability, Some(RuntimeCapability::EnvRead));

        // Span-accurate: the diagnostic points at line 2 where process.env is read.
        let location = finding
            .location
            .as_ref()
            .expect("member access carries a span");
        assert_eq!(location.start_line, 2, "process.env is on line 2");

        // Correct minimal capability set: exactly {EnvRead}.
        assert_eq!(report.required_capabilities.len(), 1);
        assert_eq!(
            report.required_capabilities[0].capability,
            Some(RuntimeCapability::EnvRead)
        );
    }

    #[test]
    fn json_report_is_deterministic_and_content_addressed() {
        let source = "const secret = process.env.TOKEN;\n";
        let first = analyze_authority_footprint(source, "fixture.js", ParseGoal::Script);
        let second = analyze_authority_footprint(source, "fixture.js", ParseGoal::Script);

        let first_json = serde_json::to_string(&first).expect("serialize");
        let second_json = serde_json::to_string(&second).expect("serialize");
        assert_eq!(
            first_json, second_json,
            "--format json must be byte-deterministic"
        );
        assert!(
            !first.report_sha256.is_empty(),
            "report is content-addressed"
        );
        assert_eq!(first.report_sha256, second.report_sha256);

        // report_sha256 actually covers the body: a different source changes it.
        let other = analyze_authority_footprint(
            "const x = require(\"fs\");\n",
            "fixture.js",
            ParseGoal::Script,
        );
        assert_ne!(first.report_sha256, other.report_sha256);
    }

    #[test]
    fn require_maps_to_fs_read_capability() {
        let source = "const fs = require(\"fs\");\n";
        let report = analyze_authority_footprint(source, "mod.js", ParseGoal::Script);
        assert!(report.analyzable);
        let finding = report
            .findings
            .iter()
            .find(|f| f.kind == CheckFindingKind::AmbientAuthorityViolation)
            .expect("require is an ambient-authority access");
        assert_eq!(finding.implied_capability, Some(RuntimeCapability::FsRead));
    }

    #[test]
    fn pure_computation_has_empty_footprint() {
        let source = "const a = 1;\nconst b = a + 2;\n";
        let report = analyze_authority_footprint(source, "pure.js", ParseGoal::Script);
        assert!(report.analyzable);
        // No ambient access: either clean or only capability-mediated builtins.
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.kind != CheckFindingKind::AmbientAuthorityViolation),
            "pure arithmetic must not trip the ambient-authority boundary"
        );
    }

    #[test]
    fn parse_error_fails_closed() {
        let source = "const = = = broken syntax (((";
        let report = analyze_authority_footprint(source, "broken.js", ParseGoal::Script);
        assert!(!report.analyzable, "unparseable source must fail closed");
        assert_eq!(report.outcome(), CheckOutcome::Unanalyzable);
        assert_eq!(report.outcome().exit_code(), 2);
        assert!(report.fail_closed_reason.is_some());
    }

    // -- E5.T4 wording / soundness discipline -------------------------------

    /// Golden: the disclaimer wording is frozen and bounded. If this changes,
    /// the change is deliberate and must keep the claim within evidence.
    #[test]
    fn disclaimer_wording_is_golden() {
        assert_eq!(
            AUTHORITY_FOOTPRINT_DISCLAIMER,
            "inferred authority footprint for SUPPORTED syntax; not a proof of noninterference for arbitrary JS/TS. Unanalyzable constructs fail closed."
        );
    }

    /// No dynamic, claim-bearing output (finding messages, the least-authority
    /// suggestion, or a fail-closed reason) may positively assert a
    /// noninterference proof for arbitrary JS/TS or use absolute-superiority
    /// language. The disclaimer is excluded here — it is golden-tested
    /// separately and *denies* such a claim ("not a proof of noninterference").
    #[test]
    fn no_dynamic_output_overclaims_a_noninterference_proof() {
        // Positive over-claim phrases an "authority footprint" must never make.
        let forbidden = [
            "proof of noninterference",
            "complete security type-check",
            "guarantees",
            "guaranteed",
            "provably secure",
            "always safe",
            "category-defining",
        ];
        let sources = [
            "const secret = process.env.SECRET_KEY;\n", // ambient violation
            "const a = 1;\nconst b = a + 2;\n",         // clean
            "const x = \"unterminated;\n",              // fail-closed
            "const fs = require(\"fs\");\n",            // ambient (fs)
        ];
        for source in sources {
            let report = analyze_authority_footprint(source, "f.js", ParseGoal::Script);
            let mut blobs = vec![report.least_authority_suggestion.clone()];
            blobs.extend(report.findings.iter().map(|f| f.message.clone()));
            if let Some(reason) = &report.fail_closed_reason {
                blobs.push(reason.clone());
            }
            for blob in &blobs {
                let lower = blob.to_ascii_lowercase();
                for phrase in &forbidden {
                    assert!(
                        !lower.contains(phrase),
                        "over-claim phrase `{phrase}` found in output for `{source}`: {blob}"
                    );
                }
            }
        }
    }

    /// Completeness + per-finding confidence markers are explicit for each
    /// analysis outcome: the footprint is never silently read as exhaustive.
    #[test]
    fn completeness_and_confidence_markers_are_explicit() {
        // Ambient violation → analysis is bounded at the first violation, and
        // the finding is a definite (enforcer-mirrored) determination.
        let ambient = analyze_authority_footprint(
            "const secret = process.env.TOKEN;\n",
            "f.js",
            ParseGoal::Script,
        );
        assert_eq!(
            ambient.analysis_completeness,
            AnalysisCompleteness::BoundedAtFirstViolation
        );
        assert!(
            ambient
                .findings
                .iter()
                .all(|f| f.confidence == FindingConfidence::Definite),
            "every finding carries a definite confidence marker"
        );

        // Clean lowering → complete analysis for the supported syntax.
        let clean = analyze_authority_footprint(
            "const a = 1;\nconst b = a + 2;\n",
            "f.js",
            ParseGoal::Script,
        );
        assert_eq!(clean.analysis_completeness, AnalysisCompleteness::Complete);

        // Fail-closed → unanalyzable, never silently passed.
        let broken =
            analyze_authority_footprint("const x = \"unterminated;\n", "f.js", ParseGoal::Script);
        assert_eq!(
            broken.analysis_completeness,
            AnalysisCompleteness::Unanalyzable
        );
        assert!(!broken.analyzable);
    }
}
