//! Member-target logical assignment (`o.k ||= v`, `o[k] &&= v`, `o[k] ??= v`)
//! evaluates to the current property value when it short-circuits and to the
//! assigned RHS otherwise. The lowering left one stack value per path and the
//! two paths used different registers, so the short-circuit path produced
//! whatever the assignment path's register held. Twin of the engine's
//! logical_assignment_member_value.rs.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, QuickJsLane, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

use std::collections::BTreeSet;

fn run(source: &str) -> ExecutionResult {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "logical_member");
    let context = LoweringContext::new(
        "logical-member-trace",
        "logical-member-decision",
        "logical-member-policy",
    );
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    QuickJsLane::with_config(config)
        .execute(&module, "logical-member-trace")
        .expect("execution should succeed")
}

fn completion(source: &str) -> Value {
    run(source).value
}

#[test]
fn short_circuited_member_logical_assignment_yields_the_current_value() {
    let or_assign = "(function () { var o = {k: 1}; var v = (o.k ||= 2); return v; })();";
    assert_eq!(completion(or_assign), Value::Int(1));
    let and_assign = "(function () { var o = {k: 0}; var key = \"k\"; return (o[key] &&= 5); })();";
    assert_eq!(completion(and_assign), Value::Int(0));
    let nullish_assign = "(function () { var o = {k: 3}; return (o.k ??= 9); })();";
    assert_eq!(completion(nullish_assign), Value::Int(3));
}

#[test]
fn assigning_member_logical_assignment_yields_the_rhs_and_stores_it() {
    let or_assign =
        "(function () { var o = {k: 0}; var v = (o.k ||= 2); return v * 10 + o.k; })();";
    assert_eq!(completion(or_assign), Value::Int(22));
    let nullish_assign = "(function () { var o = {}; var key = \"k\"; \
                          var v = (o[key] ??= 4); return v * 10 + o.k; })();";
    assert_eq!(completion(nullish_assign), Value::Int(44));
}
