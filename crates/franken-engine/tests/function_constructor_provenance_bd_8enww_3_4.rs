//! bd-8enww.3.4 (YTBG-C4): provenance, budgets, and security accounting for
//! `Function`-constructor-generated code.
//!
//! The 3.3 slice made `new Function(...)`-generated code *callable*. BotGuard
//! code is intentionally adversarial and heavy, so 3.4 makes generated code
//! **auditable and bounded**: every construction and invocation is recorded with
//! a deterministic, content-addressed source identity and the exact instruction
//! budget the body consumed, and the runtime's existing budget/capability/IFC
//! accounting applies to generated code with no escape hatch.
//!
//! Acceptance criteria exercised end-to-end through the eval path:
//!   AC#1 — generated functions carry deterministic source IDs / provenance.
//!   AC#2 — runtime logs include generated source identity and budget consumption.
//!   AC#3 — infinite/heavy generated code stops at deterministic budget limits.
//!   AC#4 — generated code cannot bypass security/capability boundaries by being
//!          constructed at runtime.

use frankenengine_engine::baseline_interpreter::{GeneratedCodeAuditEntry, GeneratedCodeEventKind};
use frankenengine_engine::{EvalOutcome, HybridRouter, JsEngine, QuickJsInspiredNativeEngine};

/// Evaluate through the direct native engine and return the full outcome so the
/// generated-code audit trail is observable.
fn eval_outcome(source: &str) -> EvalOutcome {
    let mut engine = QuickJsInspiredNativeEngine;
    engine
        .eval(source)
        .expect("source should evaluate successfully")
}

fn eval_value(source: &str) -> String {
    eval_outcome(source).value
}

fn eval_error(source: &str) -> String {
    let mut router = HybridRouter::default();
    router
        .eval(source)
        .expect_err("source should fail deterministically")
        .to_string()
}

fn audit(source: &str) -> Vec<GeneratedCodeAuditEntry> {
    eval_outcome(source).generated_code_audit
}

// --- AC#1: deterministic, content-addressed provenance -----------------------

#[test]
fn construction_records_provenance_with_synthetic_source_id() {
    let entries = audit(r#"new Function("x", "return x * 2;");"#);
    let constructed: Vec<_> = entries
        .iter()
        .filter(|e| e.kind == GeneratedCodeEventKind::Constructed)
        .collect();
    assert_eq!(constructed.len(), 1, "exactly one construction event");
    let provenance = constructed[0];
    assert!(
        provenance.source_id.starts_with("genfn:"),
        "{}",
        provenance.source_id
    );
    assert_eq!(provenance.source_hash.len(), 64);
    assert_eq!(provenance.parameter_hash.len(), 64);
    // Top-level dynamic construction happens in the `<eval>` module.
    assert_eq!(provenance.construction_site, "<eval>");
}

#[test]
fn provenance_source_id_is_stable_across_runs() {
    let src = r#"new Function("x", "return x * 2;");"#;
    let first = audit(src);
    let second = audit(src);
    let id_of = |entries: &[GeneratedCodeAuditEntry]| {
        entries
            .iter()
            .find(|e| e.kind == GeneratedCodeEventKind::Constructed)
            .map(|e| e.source_id.clone())
            .expect("a construction event")
    };
    // Content-addressed ⇒ identical source in identical context ⇒ identical id.
    assert_eq!(id_of(&first), id_of(&second));
}

#[test]
fn distinct_generated_bodies_get_distinct_source_ids() {
    let a = audit(r#"new Function("return 1;");"#);
    let b = audit(r#"new Function("return 2;");"#);
    let id = |entries: &[GeneratedCodeAuditEntry]| entries[0].source_id.clone();
    assert_ne!(id(&a), id(&b));
}

// --- AC#2: logs include source identity AND budget consumption ----------------

#[test]
fn invocation_audit_links_source_id_and_records_budget() {
    let entries = audit(r#"var f = new Function("x", "return x * 2;"); f(21);"#);
    let constructed = entries
        .iter()
        .find(|e| e.kind == GeneratedCodeEventKind::Constructed)
        .expect("a construction event");
    let invoked = entries
        .iter()
        .find(|e| e.kind == GeneratedCodeEventKind::Invoked)
        .expect("an invocation event");

    // The invocation is attributable to the constructed source.
    assert_eq!(invoked.source_id, constructed.source_id);
    assert_eq!(invoked.outcome, "completed");
    // Budget consumption is recorded and non-zero (the body ran real work).
    assert!(
        invoked.instructions_consumed > 0,
        "expected non-zero budget spend, got {}",
        invoked.instructions_consumed
    );
}

#[test]
fn invocation_audit_records_granted_safe_capabilities() {
    // A generated body that calls a realm builtin (`Math.max`) is granted the
    // safe `builtin` capability — and the audit records exactly that grant.
    let entries = audit(r#"new Function("return Math.max(10, 42);")();"#);
    assert_eq!(
        eval_value(r#"new Function("return Math.max(10, 42);")();"#),
        "42"
    );
    let invoked = entries
        .iter()
        .find(|e| e.kind == GeneratedCodeEventKind::Invoked)
        .expect("an invocation event");
    assert!(
        invoked.granted_capabilities.iter().any(|c| c == "builtin"),
        "expected the `builtin` grant to be recorded, got {:?}",
        invoked.granted_capabilities
    );
    // Dangerous authority is never present in a generated-code grant.
    for forbidden in ["fs_read", "fs_write", "process_spawn", "network_egress"] {
        assert!(
            !invoked.granted_capabilities.iter().any(|c| c == forbidden),
            "generated code must never be granted {forbidden}"
        );
    }
}

#[test]
fn audit_trail_survives_into_the_eval_outcome_value() {
    // The audited run still produces the correct observable value (the audit is
    // additive observability, not behavior change).
    let outcome = eval_outcome(r#"var f = new Function("a", "b", "return a + b;"); f(2, 3);"#);
    assert_eq!(outcome.value, "5");
    assert_eq!(outcome.generated_code_audit.len(), 2); // one construct + one invoke
}

// --- AC#3: heavy/infinite generated code stops at deterministic budget --------

#[test]
fn infinite_generated_loop_halts_at_the_shared_budget() {
    // An unbounded loop inside generated code must not run forever: it shares the
    // interpreter's instruction budget and fails closed at the limit.
    let err = eval_error(r#"var f = new Function("while (true) {}"); f();"#);
    assert!(
        err.to_lowercase().contains("budget"),
        "expected a budget-exhaustion error, got: {err}"
    );
}

#[test]
fn budget_exhaustion_for_generated_code_is_deterministic() {
    let src = r#"var f = new Function("while (true) {}"); f();"#;
    assert_eq!(eval_error(src), eval_error(src));
}

// --- AC#4: generated code cannot bypass security boundaries -------------------

#[test]
fn generated_code_cannot_reach_ambient_process_binding() {
    // The red-team `function_constructor_evasion` vector: `new Function("return
    // process")()` is the classic eval-equivalent reach for ambient authority.
    // FrankenEngine fails closed — `process` is neither a recognized builtin nor
    // a live global, so the runtime-compiled body cannot resolve it.
    let _err = eval_error(r#"var f = new Function("return process"); f().env.PATH;"#);
}

#[test]
fn generated_code_cannot_acquire_filesystem_authority_by_declaring_it() {
    // A generated body that names a filesystem-style global gets no ambient fs
    // authority: the reference fails closed rather than resolving to a host
    // surface. (The capability-envelope filter that guarantees a *declared*
    // dangerous capability is dropped is unit-tested directly in
    // `contained_codegen_envelope_filters_out_dangerous_capabilities`.)
    let _err =
        eval_error(r#"new Function("return require('fs').readFileSync('/etc/passwd');")();"#);
}

#[test]
fn ambient_authority_refusal_is_deterministic() {
    let src = r#"var f = new Function("return process"); f();"#;
    assert_eq!(eval_error(src), eval_error(src));
}
