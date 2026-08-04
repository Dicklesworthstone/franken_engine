//! Real-engine evaluation adapter for the metamorphic oracle.
//!
//! # Why this exists (bd-x9t1n.1, under epic bd-x9t1n; surfaced by bd-q90jg)
//!
//! Historically every relation in [`crate::relations::catalog_backed`] ran a
//! self-contained *toy* parser/lowering/interpreter that never touched
//! `frankenengine-engine`. That made the H7.3/H2.5 "0 / N divergence" results a
//! FALSE GREEN: any allocator/IR/interpreter regression in the real engine was
//! invisible to the suite (see bd-q90jg).
//!
//! [`EngineEvalAdapter`] is the foundation that fixes this: it drives JS source
//! through the *real* engine —
//!   * parse  → [`CanonicalEs2020Parser`] (`ParseGoal::Script`),
//!   * lower  → [`Ir0Module::from_syntax_tree`] + [`lower_ir0_to_ir3`] (the real pipeline),
//!   * execute → [`HybridRouter::eval`],
//!
//! It returns a *normalized, comparison-stable* [`EngineEval`] triple
//! `(parse_outcome, ir_digest, exec_value)`.
//!
//! Downstream beads route the oracles through this adapter (bd-x9t1n.2 parser,
//! bd-x9t1n.3 IR, bd-x9t1n.4 execution), replacing the toy paths. This bead only
//! adds the dependency + adapter + its own tests; it does not yet rewire the
//! relations.
//!
//! ## Normalization contract
//! Relations compare *verdicts*, not the engine's internal AST/IR types (which
//! are intentionally opaque and large). So the adapter collapses results to:
//!   * [`ParseOutcome`] — accepted vs rejected,
//!   * `ir_digest` — a `sha256:` fingerprint of the lowered IR3 (`None` if
//!     parse/lower failed); equal iff the lowered programs are byte-equal,
//!   * `exec_value` — the engine's evaluation value string (`None` if eval
//!     errored).
//!
//! Every engine error is mapped to a `Rejected`/`None` verdict — the adapter
//! never panics, so relations fail closed rather than crashing the suite.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use sha2::{Digest, Sha256};

/// Normalized parse verdict: did the canonical ES2020 parser accept the source?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseOutcome {
    /// Source parsed to a syntax tree.
    Parsed,
    /// Source was rejected (syntax error / early error / empty input error).
    Rejected,
}

/// Normalized result of evaluating one source through the real engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineEval {
    /// Whether [`CanonicalEs2020Parser`] accepted the source.
    pub parse_outcome: ParseOutcome,
    /// `sha256:` digest of the lowered IR3 module, or `None` if parsing or
    /// lowering failed. Two sources that lower to byte-identical IR3 share a
    /// digest; any lowering change (what the `ir_*` relations guard) changes it.
    pub ir_digest: Option<String>,
    /// Normalized [`HybridRouter::eval`] value, or `None` if evaluation errored.
    pub exec_value: Option<String>,
}

/// Stateless adapter over the real engine. Each [`evaluate`](Self::evaluate)
/// builds a fresh [`HybridRouter`] so evaluations stay independent and
/// deterministic (no carried interpreter state between metamorphic pairs).
#[derive(Debug, Default, Clone, Copy)]
pub struct EngineEvalAdapter;

impl EngineEvalAdapter {
    /// Construct a new adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse, lower, and execute `source` through the real engine and return the
    /// normalized verdict triple. Never panics: engine errors map to
    /// `Rejected` / `None`.
    #[must_use]
    pub fn evaluate(&self, source: &str) -> EngineEval {
        let (parse_outcome, ir_digest) = parse_and_lower(source);
        let exec_value = execute(source);
        EngineEval {
            parse_outcome,
            ir_digest,
            exec_value,
        }
    }
}

/// Parse via the canonical parser and, on success, lower through the real
/// pipeline, returning the parse verdict and (if lowering succeeded) an IR3
/// digest.
fn parse_and_lower(source: &str) -> (ParseOutcome, Option<String>) {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let tree = match parser.parse_with_options(source, ParseGoal::Script, &options) {
        Ok(tree) => tree,
        Err(_) => return (ParseOutcome::Rejected, None),
    };

    let ir0 = Ir0Module::from_syntax_tree(tree, "metamorphic-engine-adapter");
    let context = LoweringContext::new(
        "metamorphic-adapter",
        "metamorphic-adapter",
        "metamorphic-adapter",
    );
    let ir_digest = match lower_ir0_to_ir3(&ir0, &context) {
        Ok(output) => Some(digest_ir3(&output.ir3)),
        Err(_) => None,
    };
    (ParseOutcome::Parsed, ir_digest)
}

/// Execute via the hybrid router, returning the normalized value (or `None` on
/// engine error).
fn execute(source: &str) -> Option<String> {
    let mut router = HybridRouter::default();
    match router.eval(source) {
        Ok(outcome) => Some(normalize_value(&outcome.value)),
        Err(_) => None,
    }
}

/// Deterministic, comparison-stable fingerprint of a lowered IR3 module.
/// `serde_json` is deterministic for the (deterministic) IR, so the digest is
/// stable across runs and compact for relation comparisons.
fn digest_ir3(ir3: &Ir3Module) -> String {
    let bytes = serde_json::to_vec(ir3).unwrap_or_default();
    let digest = Sha256::digest(&bytes);
    format!("sha256:{}", hex::encode(digest))
}

/// Normalize an execution value so cosmetic formatting differences do not show
/// up as spurious metamorphic divergences.
fn normalize_value(value: &str) -> String {
    value.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_parses_lowers_and_executes_valid_source() {
        let adapter = EngineEvalAdapter::new();
        let result = adapter.evaluate("1 + 2");
        assert_eq!(
            result.parse_outcome,
            ParseOutcome::Parsed,
            "valid source must parse through the real engine"
        );
        assert!(
            result.ir_digest.is_some(),
            "valid source must lower through the real pipeline to an IR3 digest"
        );
        assert!(
            result.exec_value.is_some(),
            "valid source must execute through HybridRouter, got {result:?}"
        );
    }

    #[test]
    fn adapter_rejects_syntactically_invalid_source() {
        let adapter = EngineEvalAdapter::new();
        let result = adapter.evaluate("const = = ;");
        assert_eq!(
            result.parse_outcome,
            ParseOutcome::Rejected,
            "the real parser must reject malformed source"
        );
        assert!(
            result.ir_digest.is_none(),
            "rejected source must not produce an IR digest"
        );
    }

    #[test]
    fn adapter_is_deterministic() {
        // The same source evaluated twice must yield identical verdicts — a
        // precondition for using the adapter as a metamorphic oracle.
        let adapter = EngineEvalAdapter::new();
        let a = adapter.evaluate("1 + 2 * 3");
        let b = adapter.evaluate("1 + 2 * 3");
        assert_eq!(a, b, "real-engine evaluation must be deterministic");
    }

    #[test]
    fn adapter_exec_value_is_whitespace_invariant() {
        // Demonstrates the adapter exercises the real engine in a way usable by
        // metamorphic relations: a whitespace-only variant must compute the same
        // value (this is exactly what `parser_whitespace_invariance` will assert
        // once routed through the adapter in bd-x9t1n.2/.4). We compare the
        // execution value (definitionally whitespace-invariant) rather than the
        // IR digest, which may legitimately encode source spans.
        let adapter = EngineEvalAdapter::new();
        let tight = adapter.evaluate("1+2");
        let spaced = adapter.evaluate("1  +  2");
        assert_eq!(tight.parse_outcome, ParseOutcome::Parsed);
        assert_eq!(spaced.parse_outcome, ParseOutcome::Parsed);
        assert_eq!(
            tight.exec_value, spaced.exec_value,
            "whitespace must not change the engine's computed value"
        );
    }
}
