//! Source timer calls reach the deterministic event loop while respecting
//! lexical bindings and the microtask checkpoint between timer callbacks.

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
        .expect("parse timer source");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "timers.js"),
        &LoweringContext::new("timers", "timers", "timers"),
    )
    .expect("lower timer source")
    .ir3;
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        let result = InterpreterCore::new(config, "source-timers")
            .execute(&module)
            .expect("execute timer source");
        let actual: Vec<_> = result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect();
        assert_eq!(actual, expected, "{source}");
    }
}

#[test]
fn source_timeouts_use_default_delay_and_drain_microtasks_between_callbacks() {
    assert_output(
        r#"
        setTimeout(() => {
            console.log('first');
            Promise.resolve().then(() => console.log('after first'));
            setTimeout(() => console.log('nested'));
        });
        setTimeout(() => console.log('second'), 0);
        Promise.resolve().then(() => console.log('micro'));
        console.log('sync');
        "#,
        &["sync", "micro", "first", "after first", "second", "nested"],
    );
}

#[test]
fn both_source_cancellation_functions_cancel_timeouts() {
    assert_output(
        r#"
        const first = setTimeout(() => console.log('cancelled first'), 0);
        clearTimeout(first);
        const second = setTimeout(() => console.log('cancelled second'), 0);
        clearInterval(second);
        setTimeout(() => console.log('kept'), 0);
        "#,
        &["kept"],
    );
}

#[test]
fn outer_lexical_timer_bindings_shadow_intrinsics_in_nested_functions() {
    assert_output(
        r#"
        function outer(setTimeout, clearTimeout, clearInterval) {
            return function inner() {
                const id = setTimeout(4, 5);
                clearTimeout(id);
                clearInterval(id + 1);
            };
        }
        outer(
            (first, second) => { console.log(first + second); return 7; },
            id => console.log('clear:' + id),
            id => console.log('interval:' + id)
        )();
        "#,
        &["9", "clear:7", "interval:8"],
    );
}
