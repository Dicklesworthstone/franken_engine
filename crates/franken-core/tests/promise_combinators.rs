//! Source-level Promise combinators share the ordinary resolution and reaction
//! machinery, including thenable adoption and observable microtask ordering.

use std::collections::BTreeSet;

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn assert_output(source: &str, expected: &[&str]) {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("parse Promise combinator source");
    let ir0 = Ir0Module::from_syntax_tree(tree, "promise-combinators.js");
    let module = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("combinators", "combinators", "combinators"),
    )
    .expect("lower Promise combinator source")
    .ir3;

    for throughput in [false, true] {
        let mut config = if throughput {
            InterpreterConfig::v8_defaults()
        } else {
            InterpreterConfig::quickjs_defaults()
        };
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        let result = InterpreterCore::new(config, "combinators")
            .execute(&module)
            .expect("execute Promise combinator source");
        let output: Vec<_> = result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect();
        assert_eq!(output, expected, "throughput={throughput}: {source}");
    }
}

#[test]
fn all_adopts_thenables_and_preserves_input_order() {
    assert_output(
        r#"
        const delayed = {
            then(resolve) { Promise.resolve().then(() => resolve(5)); }
        };
        Promise.all([delayed, 2, Promise.resolve(3)]).then(values => {
            console.log(values[0] + ',' + values[1] + ',' + values[2]);
        });
        "#,
        &["5,2,3"],
    );
}

#[test]
fn nonempty_combinators_settle_after_their_element_reaction_jobs() {
    assert_output(
        r#"
        Promise.all([1]).then(() => console.log('all'));
        Promise.race([Promise.resolve(2)]).then(() => console.log('race'));
        Promise.any([3]).then(() => console.log('any'));
        Promise.allSettled([Promise.reject(4)]).then(() => console.log('settled'));
        Promise.resolve().then(() => console.log('tick'));
        "#,
        &["tick", "all", "race", "any", "settled"],
    );
}

#[test]
fn race_uses_resolution_order_and_still_processes_later_thenables() {
    assert_output(
        r#"
        const slower = { then(resolve) { resolve(1); } };
        Promise.race([slower, 2]).then(value => console.log('winner:' + value));
        let visited = 0;
        const later = { then(resolve) { visited += 1; resolve(9); } };
        Promise.race([3, later]).then(value => console.log(value + ':' + visited));
        "#,
        &["winner:2", "3:1"],
    );
}

#[test]
fn all_settled_adopts_each_input_and_records_its_completion_kind() {
    assert_output(
        r#"
        const fulfilled = { then(resolve) { resolve(4); } };
        const rejected = { then(resolve, reject) { reject('no'); } };
        Promise.allSettled([fulfilled, rejected, 7]).then(values => {
            console.log(values[0].status + ':' + values[0].value);
            console.log(values[1].status + ':' + values[1].reason);
            console.log(values[2].status + ':' + values[2].value);
        });
        "#,
        &["fulfilled:4", "rejected:no", "fulfilled:7"],
    );
}

#[test]
fn any_waits_for_rejections_and_preserves_error_input_order() {
    assert_output(
        r#"
        const first = {
            then(resolve, reject) { Promise.resolve().then(() => reject('first')); }
        };
        const second = { then(resolve, reject) { reject('second'); } };
        Promise.any([first, second]).catch(error => {
            console.log(error.name + ':' + error.errors[0] + ',' + error.errors[1]);
        });
        "#,
        &["AggregateError:first,second"],
    );
}

#[test]
fn all_propagates_thenable_rejection() {
    assert_output(
        r#"
        const rejected = { then(resolve, reject) { reject('failed'); } };
        Promise.all([Promise.resolve(1), rejected]).then(
            () => console.log('unexpected fulfillment'),
            reason => console.log(reason)
        );
        "#,
        &["failed"],
    );
}

#[test]
fn aggregate_elements_preserve_identity_while_race_and_any_resolve_the_winner() {
    assert_output(
        r#"
        const value = {};
        const ready = Promise.resolve(value);
        value.then = resolve => resolve(99);
        Promise.all([ready]).then(values => console.log('all:' + (values[0] === value)));
        Promise.race([ready]).then(result => console.log('race:' + result));
        Promise.any([ready]).then(result => console.log('any:' + result));
        "#,
        &["all:true", "race:99", "any:99"],
    );
}

#[test]
fn empty_combinators_preserve_their_distinct_settlement_rules() {
    assert_output(
        r#"
        Promise.all([]).then(values => console.log('all:' + values.length));
        Promise.allSettled([]).then(values => console.log('settled:' + values.length));
        Promise.any([]).catch(error => console.log('any:' + error.name + ':' + error.errors.length));
        Promise.race([]).then(
            () => console.log('unexpected fulfillment'),
            () => console.log('unexpected rejection')
        );
        Promise.resolve().then(() => console.log('tick'));
        "#,
        &["all:0", "settled:0", "any:AggregateError:0", "tick"],
    );
}
