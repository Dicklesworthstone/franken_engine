//! Source timers retain callable values and arguments through the event loop.

use std::collections::BTreeSet;
use std::path::PathBuf;

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn assert_output(source: &str, expected: &[&str]) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/modules")
        .canonicalize()
        .unwrap();
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Module)
        .expect("parse timer source");
    let ir0 = Ir0Module::from_syntax_tree(tree, root.join("timer-entry.mjs").display().to_string());
    let module = lower_ir0_to_ir3(&ir0, &LoweringContext::new("timers", "timers", "timers"))
        .expect("lower timer source")
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
            RuntimeCapability::ModuleLoad,
        ]);
        config.module_root = Some(root.display().to_string());
        let result = InterpreterCore::new(config, "timers")
            .execute(&module)
            .expect("execute timer source");
        let output: Vec<_> = result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect();
        assert_eq!(output, expected, "throughput={throughput}: {source}");
    }
}

#[test]
fn native_promise_resolvers_receive_timer_arguments() {
    assert_output(
        r#"
        new Promise(resolve => setTimeout(resolve, 0, 42))
            .then(value => console.log(value));
        new Promise((resolve, reject) => setTimeout(reject, 0, { marker: 'rejected' }))
            .catch(error => console.log(error.marker));
        console.log('sync');
        "#,
        &["sync", "42", "rejected"],
    );
}

#[test]
fn omitted_delay_and_no_forwarded_arguments_resolve_to_undefined() {
    assert_output(
        r#"
        new Promise(resolve => setTimeout(resolve))
            .then(value => console.log(value === undefined));
        setTimeout((...args) => console.log(args.length));
        "#,
        &["true", "0"],
    );
}

#[test]
fn timer_arguments_capture_values_preserve_object_identity_and_populate_rest() {
    assert_output(
        r#"
        let number = 20;
        const object = { value: 1 };
        function handler(first, ...rest) {
            console.log(first + rest[0]);
            console.log(rest[1] === object);
            console.log(rest[1].value);
            console.log(rest.length);
        }
        setTimeout(handler, 0, number, 22, object);
        number = 90;
        object.value = 7;
        "#,
        &["42", "true", "7", "2"],
    );
}

#[test]
fn repeated_callbacks_keep_each_registration_and_microtask_checkpoint() {
    assert_output(
        r#"
        function emit(value) {
            console.log(value);
            Promise.resolve().then(() => console.log('micro:' + value));
        }
        setTimeout(emit, 0, 'first');
        setTimeout(emit, 0, 'second');
        Promise.resolve().then(() => console.log('startup'));
        "#,
        &["startup", "first", "micro:first", "second", "micro:second"],
    );
}

#[test]
fn cancelled_native_callback_does_not_settle_its_promise() {
    assert_output(
        r#"
        let cancelled;
        new Promise(resolve => { cancelled = setTimeout(resolve, 0, 99); })
            .then(() => console.log('cancelled callback ran'));
        clearTimeout(cancelled);
        new Promise(resolve => setTimeout(resolve, 0, 42))
            .then(value => console.log(value));
        "#,
        &["42"],
    );
}

#[test]
fn imported_timer_callbacks_use_their_owner_and_can_call_forwarded_closures() {
    assert_output(
        r#"
        import { apply } from './operations.mjs';
        function unrelated(value) { return -900; }
        setTimeout(apply, 0, value => console.log(value + 2), 40);
        console.log('sync');
        "#,
        &["sync", "42"],
    );
}
