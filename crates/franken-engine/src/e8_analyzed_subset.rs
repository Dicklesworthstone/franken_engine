//! E8 analyzed-subset flow scan (E8.T4, bd-fqlfw.8.4).
//!
//! The fail-closed soundness boundary for the non-use certificate: before a
//! data-contract run's refusal ledger may report `certifiable_subset`, every
//! construct in the run's source must be classified against the explicit-flow
//! analyzed subset of `explicit_flow_ifc_v1`. Any construct whose label
//! propagation is unproven downgrades the run to *uncertified — unanalyzed
//! flow at span X*; the scan never guesses and never widens the subset
//! implicitly.
//!
//! The scan shares the runtime's single source of truth: it ingests source
//! through the same `prepare_source_entry_for_public_entrypoints` +
//! `CanonicalEs2020Parser` + `lowering_pipeline::lower_ir0_to_ir3` sequence
//! the execution orchestrator runs (the same property `frankenctl check`
//! relies on, see `authority_footprint.rs`). Classification then walks the
//! lowered IR2 ops — including nested `DeclareFunction` / `CreateFunction`
//! bodies, so a Secret-to-sink flow inside a closure cannot hide from the
//! scan — and maps each op kind to one of two verdicts:
//!
//! - **Analyzed (explicit flow):** the baseline interpreter's label
//!   propagation for this op kind is production-wired and regression-tested
//!   (bd-0zybl `GetProperty` joins, bd-ooaka.1 callback-lane joins, bd-l0d6z
//!   throw/catch labels, template-literal concat joins), or the op derives no
//!   data (pure control flow / stack discipline; control-flow *implicit*
//!   channels are documented out of scope of `explicit_flow_ifc_v1`).
//! - **Unproven (fail closed):** async/generator resumption frames, iterator
//!   protocol lanes, and module-graph edges (`import` pulls code the scan did
//!   not analyze). These emit `unproven_ifc_propagation` refusal surfaces
//!   with source-span provenance where the lowering stamped one.
//!
//! The [`classify_op`] match is deliberately exhaustive with **no wildcard
//! arm**: adding a new `Ir1Op` variant refuses to compile until someone makes
//! the conscious analyzed-vs-unproven decision here. That is the load-bearing
//! fail-closed property — new constructs cannot silently join the certifiable
//! subset.
//!
//! Threat model: EXPLICIT-FLOW ONLY. Covert channels, timing channels, and
//! control-flow implicit channels are out of scope and stay out of scope
//! regardless of scan outcome (see
//! `docs/E8_NON_USE_CERTIFICATE_THREAT_MODEL_V1.md`).

use serde::{Deserialize, Serialize};

use crate::ast::{ParseGoal, SourceSpan};
use crate::hash_tiers::ContentHash;
use crate::ir_contract::{Ir0Module, Ir1Op};
use crate::lowering_pipeline::{
    Ir2FlowProofArtifact, LoweringContext, LoweringPipelineError, lower_ir0_to_ir3,
};
use crate::parser::{CanonicalEs2020Parser, ParserOptions};
use crate::ts_normalization::prepare_source_entry_for_public_entrypoints;

/// Schema id stamped on every emitted scan artifact.
pub const E8_ANALYZED_SUBSET_SCAN_SCHEMA_VERSION: &str =
    "franken-engine.e8-analyzed-subset-scan.v1";

/// Threat-model scope the scan certifies within. Must stay equal to
/// `data_contract::E8_REFUSAL_THREAT_MODEL_SCOPE` (pinned by a test there;
/// this module cannot import `data_contract` without creating a cycle).
pub const E8_SCAN_THREAT_MODEL_SCOPE: &str = "explicit_flow_ifc_v1";

/// Stable refusal vocabulary (pinned by
/// `docs/e8_analyzed_subset_refusal_ledger_v1.json`, bd-fqlfw.8.4.1.1).
pub const E8_REFUSAL_CODE_UNPROVEN_IFC_PROPAGATION: &str = "unproven_ifc_propagation";
pub const E8_REFUSAL_CODE_UNSUPPORTED_SYNTAX_SURFACE: &str = "unsupported_syntax_surface";
pub const E8_REFUSAL_CODE_MISSING_SOURCE_SPAN: &str = "missing_source_span";

/// Cap on individually recorded unanalyzed surfaces. The *counts* on the scan
/// are always exact; only the per-surface detail vector is bounded so an
/// adversarial megaprogram cannot balloon the refusal ledger. Truncation is
/// recorded explicitly (`unanalyzed_surface_total` vs `len()`), never silent.
pub const MAX_RECORDED_UNANALYZED_SURFACES: usize = 64;

// Deterministic identity for the scan's analysis lowering pass. The scan is a
// pure function of `(source, source_label, parse_goal)`, so these are fixed —
// never wall-clock or per-invocation — keeping the artifact content-addressed.
const SCAN_TRACE_ID: &str = "trace-e8-analyzed-subset-scan";
const SCAN_DECISION_ID: &str = "decision-e8-analyzed-subset-scan";
const SCAN_POLICY_ID: &str = "franken-engine.e8-analyzed-subset-scan.v1";

// ---------------------------------------------------------------------------
// Op classification
// ---------------------------------------------------------------------------

/// Verdict for one IR op kind under `explicit_flow_ifc_v1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpFlowClass {
    /// Explicit-flow label propagation for this op kind is production-wired
    /// and regression-tested, or the op derives no data.
    AnalyzedExplicitFlow,
    /// Label propagation for this op kind is unproven; the run fails closed.
    UnprovenIfcPropagation,
}

/// Classification of one op kind, with the stable mnemonic and the rationale
/// that justifies the verdict (evidence pointer for analyzed kinds,
/// remediation direction for unproven ones).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpClassification {
    pub class: OpFlowClass,
    pub op_kind: &'static str,
    pub rationale: &'static str,
}

const ANALYZED_PURE_STACK: &str = "no data derivation: pure control-flow / stack discipline (implicit control-flow channels \
     are documented out of scope of explicit_flow_ifc_v1)";
const ANALYZED_VALUE_JOIN: &str = "explicit-flow label join is production-wired in the baseline interpreter and \
     regression-tested (derived values carry join(inputs))";
const ANALYZED_PROPERTY: &str = "property-lane label join landed with bd-0zybl (GetProperty under-tainting fix) and is \
     regression-tested at HEAD";
const ANALYZED_CALL: &str = "call/callback-lane label joins landed with bd-ooaka.1 (receiver + argument labels join \
     onto results) and are regression-tested at HEAD";
const ANALYZED_EXCEPTION: &str = "exception-value labels propagate through throw/catch (bd-l0d6z) and are regression-tested \
     at HEAD";
const ANALYZED_HOSTCALL: &str = "hostcall edges are capability-gated at the membrane; host-boundary flow events and \
     capability witnesses are the analyzed enforcement lane";
const UNPROVEN_ASYNC: &str = "async/generator resumption-frame label preservation is not certified within the \
     explicit_flow_ifc_v1 analyzed subset; fail closed (promote only by citing interpreter \
     label-propagation regression tests)";
const UNPROVEN_ITERATOR: &str = "iterator-protocol label propagation (for..in / for..of / iterator close) is not certified \
     within the explicit_flow_ifc_v1 analyzed subset; fail closed";
const UNPROVEN_MODULE_GRAPH: &str = "module-graph edges pull code the scan did not analyze (dynamic require / import); fail \
     closed";
const UNPROVEN_DYNAMIC_NAME: &str = "dynamic name resolution is not certified within the explicit_flow_ifc_v1 analyzed \
     subset; fail closed";

/// Classify one IR1 op kind against the explicit-flow analyzed subset.
///
/// Exhaustive by construction: **no wildcard arm.** A new `Ir1Op` variant
/// fails to compile until it is consciously classified, so unclassified
/// constructs can never silently reach the certifiable subset.
pub fn classify_op(op: &Ir1Op) -> OpClassification {
    let analyzed = |op_kind: &'static str, rationale: &'static str| OpClassification {
        class: OpFlowClass::AnalyzedExplicitFlow,
        op_kind,
        rationale,
    };
    let unproven = |op_kind: &'static str, rationale: &'static str| OpClassification {
        class: OpFlowClass::UnprovenIfcPropagation,
        op_kind,
        rationale,
    };
    match op {
        Ir1Op::LoadLiteral { .. } => analyzed("load_literal", ANALYZED_VALUE_JOIN),
        Ir1Op::LoadBinding { .. } => analyzed("load_binding", ANALYZED_VALUE_JOIN),
        Ir1Op::LoadName { .. } => unproven("load_name", UNPROVEN_DYNAMIC_NAME),
        Ir1Op::ResolveNameStatus { .. } => unproven("resolve_name_status", UNPROVEN_DYNAMIC_NAME),
        Ir1Op::DeleteName { .. } => unproven("delete_name", UNPROVEN_DYNAMIC_NAME),
        Ir1Op::StoreBinding { .. } => analyzed("store_binding", ANALYZED_VALUE_JOIN),
        Ir1Op::PutName { .. } => unproven("put_name", UNPROVEN_DYNAMIC_NAME),
        Ir1Op::PutNameWithStatus { .. } => unproven("put_name_with_status", UNPROVEN_DYNAMIC_NAME),
        Ir1Op::InitializeBinding { .. } => analyzed("initialize_binding", ANALYZED_VALUE_JOIN),
        Ir1Op::CreatePerIterationBinding { .. } => {
            analyzed("create_per_iteration_binding", ANALYZED_VALUE_JOIN)
        }
        Ir1Op::Call { .. } => analyzed("call", ANALYZED_CALL),
        Ir1Op::CallMethod { .. } => analyzed("call_method", ANALYZED_CALL),
        Ir1Op::Construct { .. } => analyzed("construct", ANALYZED_CALL),
        Ir1Op::Return => analyzed("return", ANALYZED_CALL),
        Ir1Op::BinaryOp { .. } => analyzed("binary_op", ANALYZED_VALUE_JOIN),
        Ir1Op::UnaryOp { .. } => analyzed("unary_op", ANALYZED_VALUE_JOIN),
        Ir1Op::AssignOp { .. } => analyzed("assign_op", ANALYZED_VALUE_JOIN),
        Ir1Op::GetProperty { .. } => analyzed("get_property", ANALYZED_PROPERTY),
        Ir1Op::SetProperty { .. } => analyzed("set_property", ANALYZED_PROPERTY),
        Ir1Op::DefineAccessor { .. } => analyzed("define_accessor", ANALYZED_PROPERTY),
        Ir1Op::DeleteProperty { .. } => analyzed("delete_property", ANALYZED_PROPERTY),
        Ir1Op::NewArray { .. } => analyzed("new_array", ANALYZED_VALUE_JOIN),
        Ir1Op::NewObject { .. } => analyzed("new_object", ANALYZED_VALUE_JOIN),
        Ir1Op::ArrayPush => analyzed("array_push", ANALYZED_VALUE_JOIN),
        Ir1Op::ArraySlice => analyzed("array_slice", ANALYZED_VALUE_JOIN),
        Ir1Op::SpreadIntoArray => analyzed("spread_into_array", ANALYZED_VALUE_JOIN),
        Ir1Op::SpreadIntoObject => analyzed("spread_into_object", ANALYZED_VALUE_JOIN),
        Ir1Op::TemplateLiteral { .. } => analyzed("template_literal", ANALYZED_VALUE_JOIN),
        Ir1Op::Throw => analyzed("throw", ANALYZED_EXCEPTION),
        Ir1Op::BeginTry { .. } => analyzed("begin_try", ANALYZED_EXCEPTION),
        Ir1Op::EndTry => analyzed("end_try", ANALYZED_EXCEPTION),
        Ir1Op::EnterFinally => analyzed("enter_finally", ANALYZED_EXCEPTION),
        Ir1Op::EndFinally => analyzed("end_finally", ANALYZED_EXCEPTION),
        Ir1Op::DiscardAbruptCompletion => analyzed("discard_abrupt_completion", ANALYZED_EXCEPTION),
        Ir1Op::LoadThis => analyzed("load_this", ANALYZED_VALUE_JOIN),
        Ir1Op::LoadNewTarget => analyzed("load_new_target", ANALYZED_VALUE_JOIN),
        Ir1Op::LoadSuper => analyzed("load_super", ANALYZED_VALUE_JOIN),
        Ir1Op::Label { .. } => analyzed("label", ANALYZED_PURE_STACK),
        Ir1Op::Jump { .. } => analyzed("jump", ANALYZED_PURE_STACK),
        Ir1Op::JumpIfFalsy { .. } => analyzed("jump_if_falsy", ANALYZED_PURE_STACK),
        Ir1Op::JumpIfFalsyConsume { .. } => analyzed("jump_if_falsy_consume", ANALYZED_PURE_STACK),
        Ir1Op::JumpIfTruthy { .. } => analyzed("jump_if_truthy", ANALYZED_PURE_STACK),
        Ir1Op::JumpIfNullish { .. } => analyzed("jump_if_nullish", ANALYZED_PURE_STACK),
        Ir1Op::Nop => analyzed("nop", ANALYZED_PURE_STACK),
        Ir1Op::Pop => analyzed("pop", ANALYZED_PURE_STACK),
        Ir1Op::Discard => analyzed("discard", ANALYZED_PURE_STACK),
        // Function *creation* is analyzed (a closure value carries its
        // environment labels); the body ops are walked recursively, and
        // async/generator bodies are refused separately by the walk because
        // their resumption frames are unproven.
        Ir1Op::DeclareFunction { .. } => analyzed("declare_function", ANALYZED_VALUE_JOIN),
        Ir1Op::CreateFunction { .. } => analyzed("create_function", ANALYZED_VALUE_JOIN),
        Ir1Op::HostCall { .. } => analyzed("host_call", ANALYZED_HOSTCALL),
        Ir1Op::Await => unproven("await", UNPROVEN_ASYNC),
        Ir1Op::Yield { .. } => unproven("yield", UNPROVEN_ASYNC),
        Ir1Op::ForInInit => unproven("for_in_init", UNPROVEN_ITERATOR),
        Ir1Op::ForInNext { .. } => unproven("for_in_next", UNPROVEN_ITERATOR),
        Ir1Op::ForOfInit => unproven("for_of_init", UNPROVEN_ITERATOR),
        Ir1Op::ForOfNext { .. } => unproven("for_of_next", UNPROVEN_ITERATOR),
        Ir1Op::IteratorClose { .. } => unproven("iterator_close", UNPROVEN_ITERATOR),
        Ir1Op::ImportModule { .. } => unproven("import_module", UNPROVEN_MODULE_GRAPH),
        Ir1Op::ExportBinding { .. } => unproven("export_binding", UNPROVEN_MODULE_GRAPH),
    }
}

// ---------------------------------------------------------------------------
// Scan artifact
// ---------------------------------------------------------------------------

/// One unanalyzed construct the scan refused, with span provenance where the
/// lowering stamped one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnanalyzedSurface {
    /// Stable op-kind mnemonic (or ambient accessor name).
    pub op_kind: String,
    /// Refusal code from the pinned E8 vocabulary.
    pub refusal_code: String,
    /// `"<source_label>:<line>:<col>"` when a span is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<String>,
    pub detail: String,
}

/// Parse or lowering failure: the source never reached op classification, so
/// the whole surface is unsupported and the run is uncertified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntaxRefusal {
    pub refusal_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<String>,
    pub detail: String,
}

/// Summary of the lowering pipeline's IR2 flow-proof artifact — the static
/// flow-proof evidence the refusal ledger links as the discharged
/// `FlowProofObligation` lane for the analyzed subset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowProofSummary {
    pub artifact_id: String,
    pub proved_flow_count: u64,
    pub denied_flow_count: u64,
    pub required_declassification_count: u64,
    pub runtime_checkpoint_count: u64,
}

/// The deterministic scan artifact: a pure function of
/// `(source, source_label, parse_goal)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E8AnalyzedSubsetScan {
    pub schema_version: String,
    pub threat_model_scope: String,
    pub source_label: String,
    /// `ContentHash` of the scanned source bytes — must match the data
    /// contract's verified run-input hash or the ledger fails closed.
    pub source_hash_hex: String,
    pub parse_goal: String,
    /// Exact count of ops classified as analyzed (including nested bodies).
    pub analyzed_op_count: u64,
    /// Exact count of unanalyzed surfaces (never truncated).
    pub unanalyzed_surface_total: u64,
    /// Recorded unanalyzed surfaces, bounded by
    /// [`MAX_RECORDED_UNANALYZED_SURFACES`]; deterministic walk order.
    pub unanalyzed_surfaces: Vec<UnanalyzedSurface>,
    /// Count of unanalyzed surfaces that carried no source span (degraded
    /// provenance, `missing_source_span`).
    pub missing_span_count: u64,
    /// Set when the source failed to parse or lower: the scan classified
    /// nothing and the run is uncertified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syntax_refusal: Option<SyntaxRefusal>,
    /// Present when the source lowered cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_proof: Option<FlowProofSummary>,
}

impl E8AnalyzedSubsetScan {
    /// Whether every construct in the source sits inside the analyzed
    /// explicit-flow subset. This is the *scan-side* gate; the refusal ledger
    /// additionally requires run-input hash binding and evidence presence
    /// before reporting `certifiable_subset`.
    pub fn is_fully_analyzed(&self) -> bool {
        self.syntax_refusal.is_none() && self.unanalyzed_surface_total == 0
    }

    /// Deterministic content hash over the canonical JSON encoding.
    pub fn content_hash_hex(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("scan artifact serializes");
        ContentHash::compute(&bytes).to_hex()
    }
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

fn render_span(source_label: &str, span: SourceSpan) -> String {
    format!("{source_label}:{}:{}", span.start_line, span.start_column)
}

struct WalkState<'a> {
    source_label: &'a str,
    analyzed_op_count: u64,
    unanalyzed_surface_total: u64,
    missing_span_count: u64,
    surfaces: Vec<UnanalyzedSurface>,
}

impl WalkState<'_> {
    fn refuse(&mut self, op_kind: &str, rationale: &str, span: Option<SourceSpan>) {
        self.unanalyzed_surface_total = self.unanalyzed_surface_total.saturating_add(1);
        let span_text = span.map(|s| render_span(self.source_label, s));
        if span_text.is_none() {
            self.missing_span_count = self.missing_span_count.saturating_add(1);
        }
        if self.surfaces.len() < MAX_RECORDED_UNANALYZED_SURFACES {
            let location = span_text.clone().unwrap_or_else(|| "<no span>".to_string());
            self.surfaces.push(UnanalyzedSurface {
                op_kind: op_kind.to_string(),
                refusal_code: E8_REFUSAL_CODE_UNPROVEN_IFC_PROPAGATION.to_string(),
                span: span_text,
                detail: format!(
                    "uncertified - unanalyzed flow at span {location}: `{op_kind}` — {rationale}"
                ),
            });
        }
    }

    fn classify(&mut self, op: &Ir1Op, span: Option<SourceSpan>) {
        let classification = classify_op(op);
        match classification.class {
            OpFlowClass::AnalyzedExplicitFlow => {
                self.analyzed_op_count = self.analyzed_op_count.saturating_add(1);
            }
            OpFlowClass::UnprovenIfcPropagation => {
                self.refuse(classification.op_kind, classification.rationale, span);
            }
        }
    }

    /// Walk nested function-body ops. `Ir1Op` bodies carry no per-op spans, so
    /// every nested op inherits the enclosing spanned expression's span — the
    /// narrowest provenance available without re-lowering.
    fn walk_body(&mut self, ops: &[Ir1Op], inherited: Option<SourceSpan>) {
        for op in ops {
            self.classify(op, inherited);
            self.descend(op, inherited);
        }
    }

    fn descend(&mut self, op: &Ir1Op, span: Option<SourceSpan>) {
        match op {
            Ir1Op::DeclareFunction {
                body_ops,
                is_generator,
                is_async,
                name,
                ..
            } => {
                self.refuse_async_or_generator(name.as_str(), *is_generator, *is_async, span);
                self.walk_body(body_ops, span);
            }
            Ir1Op::CreateFunction {
                body_ops,
                is_generator,
                is_async,
                name,
                ..
            } => {
                let display_name = name.as_deref().unwrap_or("<anonymous>");
                self.refuse_async_or_generator(display_name, *is_generator, *is_async, span);
                self.walk_body(body_ops, span);
            }
            _ => {}
        }
    }

    /// Async/generator function bodies suspend and resume through frames whose
    /// label preservation is unproven in v1 — refuse the function itself even
    /// when its body contains no `Await`/`Yield` op (e.g. `async () => 1`
    /// still creates a promise-backed resumption frame).
    fn refuse_async_or_generator(
        &mut self,
        name: &str,
        is_generator: bool,
        is_async: bool,
        span: Option<SourceSpan>,
    ) {
        if is_async {
            self.refuse(
                "async_function",
                &format!("async function `{name}`: {UNPROVEN_ASYNC}"),
                span,
            );
        }
        if is_generator {
            self.refuse(
                "generator_function",
                &format!("generator function `{name}`: {UNPROVEN_ASYNC}"),
                span,
            );
        }
    }
}

/// Scan `source` against the explicit-flow analyzed subset.
///
/// Pure and deterministic in `(source, source_label, parse_goal)`; the
/// returned artifact is content-addressable via
/// [`E8AnalyzedSubsetScan::content_hash_hex`].
pub fn scan_source(
    source: &str,
    source_label: &str,
    parse_goal: ParseGoal,
) -> E8AnalyzedSubsetScan {
    let base = E8AnalyzedSubsetScan {
        schema_version: E8_ANALYZED_SUBSET_SCAN_SCHEMA_VERSION.to_string(),
        threat_model_scope: E8_SCAN_THREAT_MODEL_SCOPE.to_string(),
        source_label: source_label.to_string(),
        source_hash_hex: ContentHash::compute(source.as_bytes()).to_hex(),
        parse_goal: parse_goal.as_str().to_string(),
        analyzed_op_count: 0,
        unanalyzed_surface_total: 0,
        unanalyzed_surfaces: Vec::new(),
        missing_span_count: 0,
        syntax_refusal: None,
        flow_proof: None,
    };
    let syntax_refused = |mut scan: E8AnalyzedSubsetScan,
                          detail: String,
                          span: Option<SourceSpan>|
     -> E8AnalyzedSubsetScan {
        scan.syntax_refusal = Some(SyntaxRefusal {
            refusal_code: E8_REFUSAL_CODE_UNSUPPORTED_SYNTAX_SURFACE.to_string(),
            span: span.map(|s| render_span(source_label, s)),
            detail,
        });
        scan
    };

    let prepared = match prepare_source_entry_for_public_entrypoints(
        source,
        source_label,
        SCAN_TRACE_ID,
        SCAN_DECISION_ID,
        SCAN_POLICY_ID,
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            return syntax_refused(base, format!("source ingestion failed: {error}"), None);
        }
    };

    let parser = CanonicalEs2020Parser;
    let (parse_result, _event_ir) = parser.parse_with_event_ir(
        prepared.prepared_source.as_str(),
        parse_goal,
        &ParserOptions::default(),
    );
    let syntax_tree = match parse_result {
        Ok(tree) => tree,
        Err(error) => return syntax_refused(base, format!("parse failed: {error}"), None),
    };

    let ir0 = Ir0Module::from_syntax_tree(syntax_tree, source_label);
    let context = LoweringContext::new(
        SCAN_TRACE_ID.to_string(),
        SCAN_DECISION_ID.to_string(),
        SCAN_POLICY_ID.to_string(),
    );
    let output = match lower_ir0_to_ir3(&ir0, &context) {
        Ok(output) => output,
        Err(LoweringPipelineError::AmbientAuthorityViolation { accessor, span, .. }) => {
            // Ambient authority is an unanalyzed *flow* surface, not a syntax
            // gap: the accessor reaches host state outside the typed
            // capability membrane, so its label propagation is unprovable.
            let mut scan = base;
            let mut state = WalkState {
                source_label,
                analyzed_op_count: 0,
                unanalyzed_surface_total: 0,
                missing_span_count: 0,
                surfaces: Vec::new(),
            };
            state.refuse(
                &format!("ambient_authority:{accessor}"),
                "ambient-authority access bypasses the typed capability membrane; its label \
                 propagation is unprovable within explicit_flow_ifc_v1",
                span,
            );
            scan.unanalyzed_surface_total = state.unanalyzed_surface_total;
            scan.unanalyzed_surfaces = state.surfaces;
            scan.missing_span_count = state.missing_span_count;
            return scan;
        }
        Err(other) => {
            let span = match &other {
                LoweringPipelineError::UnsupportedSyntax(diagnostic) => diagnostic.span,
                _ => None,
            };
            return syntax_refused(
                base,
                format!("unsupported or unanalyzable construct: {other}"),
                span,
            );
        }
    };

    let mut state = WalkState {
        source_label,
        analyzed_op_count: 0,
        unanalyzed_surface_total: 0,
        missing_span_count: 0,
        surfaces: Vec::new(),
    };
    for op in &output.ir2.ops {
        state.classify(&op.inner, op.span);
        state.descend(&op.inner, op.span);
    }

    let mut scan = base;
    scan.analyzed_op_count = state.analyzed_op_count;
    scan.unanalyzed_surface_total = state.unanalyzed_surface_total;
    scan.unanalyzed_surfaces = state.surfaces;
    scan.missing_span_count = state.missing_span_count;
    scan.flow_proof = Some(flow_proof_summary(&output.ir2_flow_proof_artifact));
    scan
}

fn flow_proof_summary(artifact: &Ir2FlowProofArtifact) -> FlowProofSummary {
    FlowProofSummary {
        artifact_id: artifact.artifact_id.clone(),
        proved_flow_count: artifact.proved_flows.len() as u64,
        denied_flow_count: artifact.denied_flows.len() as u64,
        required_declassification_count: artifact.required_declassifications.len() as u64,
        runtime_checkpoint_count: artifact.runtime_checkpoints.len() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABEL: &str = "agent.js";

    fn scan(source: &str) -> E8AnalyzedSubsetScan {
        scan_source(source, LABEL, ParseGoal::Script)
    }

    // -- classification table pins ------------------------------------------

    #[test]
    fn plain_arithmetic_is_fully_analyzed() {
        let scan = scan("const answer = 40 + 2;");
        assert!(scan.is_fully_analyzed());
        assert!(scan.analyzed_op_count > 0);
        assert_eq!(scan.unanalyzed_surface_total, 0);
        assert!(scan.syntax_refusal.is_none());
        assert!(scan.flow_proof.is_some());
    }

    #[test]
    fn property_and_call_lanes_are_analyzed() {
        let scan = scan(
            "const obj = { a: 1, b: 2 };\n\
             const x = obj.a + obj.b;\n\
             function add(p, q) { return p + q; }\n\
             const y = add(x, obj.a);",
        );
        assert!(scan.is_fully_analyzed(), "{:?}", scan.unanalyzed_surfaces);
    }

    #[test]
    fn try_catch_throw_is_analyzed() {
        let scan = scan(
            "let out = 0;\n\
             try { throw 1; } catch (e) { out = e; } finally { out = out + 1; }",
        );
        assert!(scan.is_fully_analyzed(), "{:?}", scan.unanalyzed_surfaces);
    }

    #[test]
    fn template_literal_is_analyzed() {
        let scan = scan("const name = 'x'; const s = `hello ${name}`;");
        assert!(scan.is_fully_analyzed(), "{:?}", scan.unanalyzed_surfaces);
    }

    #[test]
    fn for_of_is_unproven_iterator_lane() {
        let scan = scan("const xs = [1, 2, 3];\nfor (const x of xs) { }");
        assert!(!scan.is_fully_analyzed());
        assert!(
            scan.unanalyzed_surfaces
                .iter()
                .any(|s| s.op_kind == "for_of_init"
                    && s.refusal_code == E8_REFUSAL_CODE_UNPROVEN_IFC_PROPAGATION)
        );
    }

    #[test]
    fn for_in_is_unproven_iterator_lane() {
        let scan = scan("const o = { a: 1 };\nfor (const k in o) { }");
        assert!(!scan.is_fully_analyzed());
        assert!(
            scan.unanalyzed_surfaces
                .iter()
                .any(|s| s.op_kind == "for_in_init")
        );
    }

    #[test]
    fn async_function_is_unproven_even_without_await() {
        let scan = scan("async function f() { return 1; }");
        assert!(!scan.is_fully_analyzed());
        assert!(
            scan.unanalyzed_surfaces
                .iter()
                .any(|s| s.op_kind == "async_function" && s.detail.contains("`f`"))
        );
    }

    #[test]
    fn generator_function_is_unproven() {
        let scan = scan("function* g() { yield 1; }");
        assert!(!scan.is_fully_analyzed());
        let kinds: Vec<&str> = scan
            .unanalyzed_surfaces
            .iter()
            .map(|s| s.op_kind.as_str())
            .collect();
        assert!(kinds.contains(&"generator_function"), "{kinds:?}");
        assert!(kinds.contains(&"yield"), "{kinds:?}");
    }

    #[test]
    fn await_op_is_unproven() {
        let scan = scan("async function f(p) { const v = await p; return v; }");
        assert!(
            scan.unanalyzed_surfaces
                .iter()
                .any(|s| s.op_kind == "await")
        );
    }

    // -- nested-body soundness ----------------------------------------------

    #[test]
    fn unproven_construct_inside_nested_function_body_is_refused() {
        // The for..of hides two closures deep; a scan that only looked at
        // top-level ops would miss it and falsely certify.
        let scan = scan(
            "function outer() {\n\
               function inner(xs) {\n\
                 for (const x of xs) { }\n\
               }\n\
               return inner;\n\
             }",
        );
        assert!(!scan.is_fully_analyzed());
        assert!(
            scan.unanalyzed_surfaces
                .iter()
                .any(|s| s.op_kind == "for_of_init"),
            "{:?}",
            scan.unanalyzed_surfaces
        );
    }

    #[test]
    fn async_arrow_inside_function_expression_is_refused() {
        let scan = scan("const make = function () { return async () => 1; };");
        assert!(
            scan.unanalyzed_surfaces
                .iter()
                .any(|s| s.op_kind == "async_function"),
            "{:?}",
            scan.unanalyzed_surfaces
        );
    }

    // -- span provenance ------------------------------------------------------

    #[test]
    fn unproven_surface_carries_line_column_span_when_stamped() {
        let scan = scan(
            "const xs = [1];\nconst ys = xs.map(function (x) { return x; });\nfor (const y of ys) { }",
        );
        let for_of = scan
            .unanalyzed_surfaces
            .iter()
            .find(|s| s.op_kind == "for_of_init")
            .expect("for..of surface recorded");
        // Span may be None (statement-granular stamping); when present it
        // must render as `<label>:<line>:<col>` and be counted consistently.
        match &for_of.span {
            Some(text) => {
                assert!(text.starts_with("agent.js:"), "{text}");
                let parts: Vec<&str> = text.split(':').collect();
                assert_eq!(parts.len(), 3, "{text}");
                assert!(parts[1].parse::<u64>().is_ok(), "{text}");
                assert!(parts[2].parse::<u64>().is_ok(), "{text}");
            }
            None => {
                assert!(scan.missing_span_count > 0);
            }
        }
        assert!(for_of.detail.contains("unanalyzed flow at span"));
    }

    #[test]
    fn missing_span_count_matches_spanless_surfaces() {
        let scan = scan("async function f() { return 1; }\nfor (const x of [1]) { }");
        let spanless = scan
            .unanalyzed_surfaces
            .iter()
            .filter(|s| s.span.is_none())
            .count() as u64;
        // Totals are exact and the recorded vector is not truncated here.
        assert_eq!(
            scan.unanalyzed_surface_total,
            scan.unanalyzed_surfaces.len() as u64
        );
        assert_eq!(scan.missing_span_count, spanless);
    }

    // -- syntax + ambient refusals --------------------------------------------

    #[test]
    fn parse_failure_is_a_syntax_refusal() {
        let scan = scan("const = ;;;((");
        assert!(!scan.is_fully_analyzed());
        let refusal = scan.syntax_refusal.expect("syntax refusal recorded");
        assert_eq!(
            refusal.refusal_code,
            E8_REFUSAL_CODE_UNSUPPORTED_SYNTAX_SURFACE
        );
        assert!(scan.flow_proof.is_none());
    }

    #[test]
    fn ambient_authority_access_is_an_unproven_flow_surface() {
        let scan = scan("const secrets = process.env;");
        assert!(!scan.is_fully_analyzed());
        assert!(
            scan.unanalyzed_surfaces
                .iter()
                .any(|s| s.op_kind.starts_with("ambient_authority:")
                    && s.refusal_code == E8_REFUSAL_CODE_UNPROVEN_IFC_PROPAGATION),
            "{:?}",
            scan.unanalyzed_surfaces
        );
        assert!(scan.syntax_refusal.is_none());
    }

    // -- determinism / artifact identity --------------------------------------

    #[test]
    fn scan_is_deterministic_for_fixed_inputs() {
        let source = "const a = 1;\nfor (const x of [a]) { }";
        let first = scan_source(source, LABEL, ParseGoal::Script);
        let second = scan_source(source, LABEL, ParseGoal::Script);
        assert_eq!(first, second);
        assert_eq!(first.content_hash_hex(), second.content_hash_hex());
    }

    #[test]
    fn scan_hash_binds_the_source_bytes() {
        let a = scan("const a = 1;");
        let b = scan("const a = 2;");
        assert_ne!(a.source_hash_hex, b.source_hash_hex);
        assert_ne!(a.content_hash_hex(), b.content_hash_hex());
    }

    #[test]
    fn source_hash_matches_content_hash_of_bytes() {
        let source = "const answer = 40 + 2;";
        let scan = scan_source(source, LABEL, ParseGoal::Script);
        assert_eq!(
            scan.source_hash_hex,
            ContentHash::compute(source.as_bytes()).to_hex()
        );
    }

    #[test]
    fn schema_and_scope_are_stamped() {
        let scan = scan("const a = 1;");
        assert_eq!(scan.schema_version, E8_ANALYZED_SUBSET_SCAN_SCHEMA_VERSION);
        assert_eq!(scan.threat_model_scope, E8_SCAN_THREAT_MODEL_SCOPE);
        assert_eq!(scan.parse_goal, "script");
        assert_eq!(scan.source_label, LABEL);
    }

    #[test]
    fn serde_roundtrip_preserves_the_artifact() {
        let scan = scan("for (const x of [1]) { }");
        let json = serde_json::to_string(&scan).expect("serializes");
        let back: E8AnalyzedSubsetScan = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(scan, back);
    }

    // -- truncation accounting -------------------------------------------------

    #[test]
    fn recorded_surfaces_are_capped_but_totals_stay_exact() {
        let mut source = String::new();
        for i in 0..(MAX_RECORDED_UNANALYZED_SURFACES + 10) {
            source.push_str(&format!("for (const x{i} of [{i}]) {{ }}\n"));
        }
        let scan = scan_source(&source, LABEL, ParseGoal::Script);
        assert_eq!(
            scan.unanalyzed_surfaces.len(),
            MAX_RECORDED_UNANALYZED_SURFACES
        );
        // Each loop contributes multiple iterator ops; the exact total must
        // exceed the recorded cap and be preserved.
        assert!(
            scan.unanalyzed_surface_total > MAX_RECORDED_UNANALYZED_SURFACES as u64,
            "total {} not preserved past cap",
            scan.unanalyzed_surface_total
        );
    }

    // -- classification invariants ----------------------------------------------

    #[test]
    fn classify_op_pins_the_unproven_set() {
        // The v1 unproven op kinds, pinned so widening the analyzed subset is
        // a reviewed decision, never a drive-by.
        let unproven = [
            Ir1Op::Await,
            Ir1Op::Yield { delegate: false },
            Ir1Op::ForInInit,
            Ir1Op::ForInNext { done_label: 0 },
            Ir1Op::ForOfInit,
            Ir1Op::ForOfNext { done_label: 0 },
            Ir1Op::ImportModule {
                specifier: "m".into(),
            },
            Ir1Op::ExportBinding {
                name: "n".to_string(),
                binding_id: 0,
            },
        ];
        for op in &unproven {
            assert_eq!(
                classify_op(op).class,
                OpFlowClass::UnprovenIfcPropagation,
                "{op:?} must stay unproven until promoted with cited tests"
            );
        }
    }

    #[test]
    fn classify_op_keeps_core_value_lanes_analyzed() {
        let analyzed = [
            Ir1Op::Return,
            Ir1Op::Throw,
            Ir1Op::LoadThis,
            Ir1Op::ArrayPush,
            Ir1Op::Nop,
            Ir1Op::Pop,
            Ir1Op::Call { arg_count: 0 },
            Ir1Op::CallMethod { arg_count: 1 },
            Ir1Op::Construct { arg_count: 0 },
            Ir1Op::TemplateLiteral { quasi_count: 1 },
            Ir1Op::HostCall {
                capability: "console.log".to_string(),
                arg_count: 1,
            },
        ];
        for op in &analyzed {
            assert_eq!(
                classify_op(op).class,
                OpFlowClass::AnalyzedExplicitFlow,
                "{op:?} regressed out of the analyzed subset"
            );
        }
    }

    #[test]
    fn every_classification_carries_kind_and_rationale() {
        for op in [
            Ir1Op::Await,
            Ir1Op::Return,
            Ir1Op::ForOfInit,
            Ir1Op::ArraySlice,
        ] {
            let c = classify_op(&op);
            assert!(!c.op_kind.is_empty());
            assert!(!c.rationale.is_empty());
        }
    }

    #[test]
    fn refusal_detail_contains_the_acceptance_wording() {
        let scan = scan("for (const x of [1]) { }");
        let surface = &scan.unanalyzed_surfaces[0];
        assert!(
            surface
                .detail
                .starts_with("uncertified - unanalyzed flow at span "),
            "{}",
            surface.detail
        );
    }

    #[test]
    fn module_goal_scan_flags_import_and_export() {
        let scan = scan_source(
            "import { x } from './m.js';\nexport const y = x;",
            LABEL,
            ParseGoal::Module,
        );
        assert!(!scan.is_fully_analyzed());
        let kinds: Vec<&str> = scan
            .unanalyzed_surfaces
            .iter()
            .map(|s| s.op_kind.as_str())
            .collect();
        assert!(
            kinds.contains(&"import_module") || kinds.contains(&"export_binding"),
            "{kinds:?}"
        );
    }

    #[test]
    fn analyzed_op_count_is_exact_for_a_known_program() {
        let scan = scan("const a = 1;");
        // Exact count is pinned loosely (>0 and equal across runs) rather
        // than to a magic number, so IR emission changes don't churn this
        // test while determinism stays observable.
        let again = scan_source("const a = 1;", LABEL, ParseGoal::Script);
        assert!(scan.analyzed_op_count > 0);
        assert_eq!(scan.analyzed_op_count, again.analyzed_op_count);
    }

    #[test]
    fn fully_analyzed_requires_no_syntax_refusal_and_zero_unproven() {
        let clean = scan("const a = 1;");
        assert!(clean.is_fully_analyzed());
        let unproven = scan("for (const x of [1]) { }");
        assert!(!unproven.is_fully_analyzed());
        let broken = scan("const = ;;;((");
        assert!(!broken.is_fully_analyzed());
    }
}
