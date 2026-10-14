//! Native label regressions: guest hooks execute through the real interpreter.
//! Labels are planted only after setup, so public later callbacks cannot
//! accidentally inherit the secret from source construction or static analysis.
use super::*;

struct Fixture {
    core: InterpreterCore,
    module: Ir3Module,
    state: ObjectId,
    receiver: Value,
    other: Value,
}

fn property(core: &InterpreterCore, object: ObjectId, name: &str) -> Value {
    core.heap[object.0 as usize]
        .properties
        .get(name)
        .unwrap_or_else(|| panic!("missing fixture property {name}"))
        .clone()
}

fn object(value: Value) -> ObjectId {
    let Value::Object(id) = value else {
        panic!("expected fixture object");
    };
    id
}

impl Fixture {
    fn new(source: &str, throughput: bool) -> Self {
        let tree = CanonicalEs2020Parser
            .parse_with_options(source, ParseGoal::Script, &ParserOptions::default())
            .expect("fixture parses");
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "set-observation.js"),
            &LoweringContext::new("set-observation", "set-observation", "builtin-only"),
        )
        .expect("fixture lowers")
        .ir3;
        let mut config = if throughput {
            InterpreterConfig::v8_defaults()
        } else {
            InterpreterConfig::quickjs_defaults()
        };
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "set-observation");
        let state = object(core.execute(&module).expect("fixture executes").value);
        let receiver = property(&core, state, "receiver");
        let other = property(&core, state, "other");
        // Keep the complete fixture reachable while its methods reenter JS.
        core.seed_register(0, Value::Object(state)).unwrap();
        core.seed_register(1, other.clone()).unwrap();
        core.replace_pending_hostcall_result_label(None).unwrap();
        Self {
            core,
            module,
            state,
            receiver,
            other,
        }
    }

    fn mark(&mut self, owner: &str, key: &str) {
        let owner = object(property(&self.core, self.state, owner));
        self.core.set_own_runtime_property_label(
            owner, &InterpreterCore::set_record_key(key), &Label::Secret,
        ).unwrap();
        self.core.replace_pending_hostcall_result_label(None).unwrap();
    }

    fn call(&mut self, method: &str) -> Result<Value, InterpreterError> {
        self.core.seed_register(1, self.other.clone())?;
        self.core.set_algebra_method(
            &self.module, method, self.receiver.clone(), RegRange { start: 1, count: 1 },
        )
    }

    fn assert_released(&self) {
        assert!(self.core.active_inline_callback_context_label.is_none());
        assert_eq!(self.core.json_parse_temporary_bytes, 0);
        assert!(self.core.collection_for_each_cursors.is_empty());
        assert_eq!(self.core.estimated_memory_bytes(), self.core.recompute_estimated_memory_bytes());
    }

    fn assert_secret_result(&self) {
        assert_eq!(self.core.pending_hostcall_result_label, Some(Label::Secret));
        self.assert_released();
    }
}

const RECORD: &str = r#"
const receiver = new Set([1, 2]);
const other = { size: 2, has(value) { return value === 2; },
  keys() { return [2, 3].values(); } };
({ receiver, other });
"#;

#[test]
fn every_set_method_retains_protocol_property_selection_labels() {
    for throughput in [false, true] {
        for method in SET_ALGEBRA_METHODS {
            for key in ["size", "has", "keys"] {
                let mut fixture = Fixture::new(RECORD, throughput);
                fixture.mark("other", key);
                fixture.call(method).unwrap_or_else(|error| panic!("{method}/{key}: {error}"));
                fixture.assert_secret_result();
            }
        }
    }
}

#[test]
fn membership_observations_survive_later_public_callbacks_and_nested_sets() {
    for throughput in [false, true] {
        for (method, answer) in [
            ("intersection", true), ("difference", true), ("isSubsetOf", true),
            ("isDisjointFrom", false),
        ] {
            let source = format!(r#"
const receiver = new Set([1, 2]);
const secret = {{ answer: {answer} }};
const other = {{ size: 2, has(value) {{
  if (value === 1) return secret.answer;
  new Set([5]).isSubsetOf(new Set([5]));
  return {answer};
}}, keys() {{ throw new Error('wrong branch'); }} }};
({{ receiver, other, secret }});
"#);
            let mut fixture = Fixture::new(&source, throughput);
            fixture.mark("secret", "answer");
            fixture.call(method).unwrap();
            fixture.assert_secret_result();
        }
    }
}

#[test]
fn iterator_done_and_value_labels_survive_the_final_public_done_step() {
    for throughput in [false, true] {
        for method in ["union", "intersection", "difference", "symmetricDifference", "isSupersetOf", "isDisjointFrom"] {
            for field in ["done", "value"] {
                let source = format!(r#"
const receiver = new Set([1, 2]);
const first = {{ done: false, value: {} }};
const other = {{ size: 0, has() {{ throw new Error('wrong branch'); }}, keys() {{
  let count = 0;
  return {{ next() {{ return count++ === 0 ? first : {{ done: true }}; }},
    return() {{ return {{ done: true }}; }} }};
}} }};
({{ receiver, other, first }});
"#, if method == "isDisjointFrom" { 9 } else { 1 });
                let mut fixture = Fixture::new(&source, throughput);
                fixture.mark("first", field);
                fixture.call(method).unwrap();
                fixture.assert_secret_result();
            }
        }
    }
}

#[test]
fn early_normal_iterator_close_keeps_return_selection_and_result_labels() {
    for throughput in [false, true] {
        for method in ["isSupersetOf", "isDisjointFrom"] {
            for (owner, key) in [("iterator", "return"), ("secret", "result")] {
                let source = format!(r#"
const receiver = new Set([1, 2]);
const secret = {{ result: {{ done: true }} }};
const iterator = {{ next() {{ return {{ done: false, value: {} }}; }},
  return() {{ return secret.result; }} }};
const other = {{ size: 0, has() {{ throw new Error('wrong branch'); }},
  keys() {{ return iterator; }} }};
({{ receiver, other, secret, iterator }});
"#, if method == "isSupersetOf" { 9 } else { 1 });
                let mut fixture = Fixture::new(&source, throughput);
                fixture.mark(owner, key);
                assert_eq!(fixture.call(method).unwrap(), Value::Bool(false));
                fixture.assert_secret_result();
            }
        }
    }
}

#[test]
fn native_type_errors_keep_the_property_label_that_caused_them() {
    for throughput in [false, true] {
        for (key, bad) in [("size", "NaN"), ("has", "1"), ("keys", "false")] {
            let source = format!(r#"
const receiver = new Set([1]);
const other = {{ size: 1, has() {{ return true; }}, keys() {{ return [].values(); }} }};
other['{key}'] = {bad};
({{ receiver, other }});
"#);
            let mut fixture = Fixture::new(&source, throughput);
            fixture.mark("other", key);
            assert!(matches!(fixture.call("union"), Err(InterpreterError::UncaughtException { .. })));
            assert_eq!(fixture.core.pending_exception_label, Label::Secret);
            assert!(fixture.core.pending_exception.is_some());
            fixture.assert_released();
        }
    }
}

#[test]
fn guest_falsy_throws_keep_the_exact_value_and_label() {
    for throughput in [false, true] {
        for (spelling, expected) in [
            ("undefined", Value::Undefined), ("null", Value::Null),
            ("false", Value::Bool(false)), ("0", Value::Int(0)),
        ] {
            let source = format!(r#"
const receiver = new Set([1]);
const secret = {{ reason: {spelling} }};
const other = {{ size: 1, has() {{ throw secret.reason; }}, keys() {{ return [].values(); }} }};
({{ receiver, other, secret }});
"#);
            let mut fixture = Fixture::new(&source, throughput);
            fixture.mark("secret", "reason");
            assert!(matches!(fixture.call("isSubsetOf"), Err(InterpreterError::UncaughtException { .. })));
            assert_eq!(fixture.core.pending_exception, Some(expected));
            assert_eq!(fixture.core.pending_exception_label, Label::Secret);
            fixture.assert_released();
        }
    }
}

#[test]
fn scoped_observations_restore_a_custom_parent_and_admit_its_live_storage() {
    for refuse in [false, true] {
        let mut fixture = Fixture::new(RECORD, false);
        let context = Label::Custom {
            name: "parent-observation".repeat(32),
            level: 1,
        };
        let bytes = InterpreterCore::estimate_label_bytes(&context);
        fixture.core.apply_memory_component_delta(0, bytes).unwrap();
        fixture.core.active_inline_callback_context_label = Some(context.clone());
        fixture.core.sync_estimated_memory_bytes().unwrap();
        if refuse {
            fixture.core.config.max_total_memory_bytes = fixture.core.estimated_memory_bytes();
        }
        let result = fixture.call("isSubsetOf");
        if refuse {
            assert!(matches!(result, Err(InterpreterError::MemoryBudgetExceeded { .. })));
            assert!(fixture.core.pending_exception.is_none());
        } else {
            assert_eq!(result.unwrap(), Value::Bool(false));
        }
        assert_eq!(fixture.core.active_inline_callback_context_label, Some(context));
        assert_eq!(fixture.core.json_parse_temporary_bytes, 0);
        assert_eq!(fixture.core.estimated_memory_bytes(), fixture.core.recompute_estimated_memory_bytes());
    }
}

#[test]
fn exhausted_work_is_not_converted_to_a_guest_exception_or_iterator_close() {
    let mut fixture = Fixture::new(RECORD, false);
    fixture.core.config.instruction_budget = fixture.core.instructions_executed;
    let error = fixture.call("union").expect_err("exhausted work must stop");
    assert!(InterpreterCore::js_catchable_error_name(&error).is_none());
    assert!(!matches!(error, InterpreterError::UncaughtException { .. }));
    assert!(fixture.core.pending_exception.is_none());
    fixture.assert_released();
}

#[test]
fn public_protocols_do_not_inherit_a_previous_operations_observations() {
    for throughput in [false, true] {
        for method in SET_ALGEBRA_METHODS {
            let mut fixture = Fixture::new(RECORD, throughput);
            fixture.call(method).unwrap();
            assert_eq!(fixture.core.pending_hostcall_result_label, Some(Label::Public));
            fixture.assert_released();
        }
        let mut fixture = Fixture::new(RECORD, throughput);
        fixture.mark("other", "has");
        fixture.call("isSubsetOf").unwrap();
        fixture.assert_secret_result();
        let other = object(fixture.other.clone());
        fixture.core.set_own_runtime_property_label(
            other, &InterpreterCore::set_record_key("has"), &Label::Public,
        ).unwrap();
        // This models the caller consuming the previous result, not an IFC
        // downgrade within an operation. The next operation starts public.
        fixture.core.replace_pending_hostcall_result_label(None).unwrap();
        fixture.call("isSubsetOf").unwrap();
        assert_eq!(fixture.core.pending_hostcall_result_label, Some(Label::Public));
        fixture.assert_released();
    }
}

#[test]
fn size_coercion_and_inherited_getters_keep_receiver_and_return_labels() {
    for throughput in [false, true] {
        for value in ["secret.value", "({ valueOf() { return secret.value; } })"] {
            let source = format!(r#"
const receiver = new Set([1]);
const secret = {{ value: 1 }};
let other;
const prototype = {{ get size() {{
  if (this !== other) throw new Error('getter receiver');
  return {value};
}}, has() {{ return true; }}, keys() {{ return [].values(); }} }};
other = Object.create(prototype);
({{ receiver, other, secret }});
"#);
            let mut fixture = Fixture::new(&source, throughput);
            fixture.mark("secret", "value");
            assert_eq!(fixture.call("isSubsetOf").unwrap(), Value::Bool(true));
            fixture.assert_secret_result();
        }
    }
}
