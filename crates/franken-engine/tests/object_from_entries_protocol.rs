#![forbid(unsafe_code)]

//! ES2020 19.1.2.7 Object.fromEntries (AddEntriesFromIterable): each
//! entry's key and value are Get(entry, "0") / Get(entry, "1") and the key
//! goes through ToPropertyKey; an entry that is not an object, a throwing
//! getter or a throwing key conversion closes the iterator. The engine read
//! entries as array elements (an accessor entry keyed "[accessor]", an
//! object key "[object#N]", a String object entry undefined) and never
//! closed the iterator (8 Node-passing Test262 tests in the rc-next33
//! merged-tree census).

use frankenengine_engine::HybridRouter;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::flow_lattice::Label;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir0Module, Ir3Instruction, Ir3Module, RegRange,
};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

fn configurations() -> [InterpreterConfig; 2] {
    [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ]
    .map(|mut config| {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        config
    })
}

fn lower(source: &str) -> Ir3Module {
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(
            parse_script(source).expect("source parses"),
            "from-entries.js",
        ),
        &LoweringContext::new("from-entries", "protocol", "builtin-only"),
    )
    .expect("source lowers")
    .ir3
}

fn labelled_source(source: &str, input_register: u32) -> Ir3Module {
    let mut module = lower(source);
    let marker = module
        .constant_pool
        .iter()
        .position(|text| text == "label-marker")
        .expect("one labelled input") as u32;
    let mut replacements = 0;
    for instruction in &mut module.instructions {
        if let Ir3Instruction::LoadStr { dst, pool_index } = instruction
            && *pool_index == marker
        {
            *instruction = Ir3Instruction::Move {
                dst: *dst,
                src: input_register,
            };
            replacements += 1;
        }
    }
    assert_eq!(replacements, 1);
    module
}

#[test]
fn native_entries_cannot_bypass_the_instruction_budget() {
    // Seed a previously allocated iterable so creating it cannot consume the
    // budget on behalf of Object.fromEntries. Duplicate keys keep the result
    // small: a memory cap is not a substitute for metering native iteration.
    let mut module = lower("undefined;");
    module.instructions = vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:ObjectFromEntries".into()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Return { value: 1 },
    ];
    for mut config in configurations() {
        config.instruction_budget = 128;
        for count in [1, 1024] {
            let mut core = InterpreterCore::new(config.clone(), "from-entries-native-budget");
            let entry = core.alloc_array_with_prototype(None).unwrap();
            core.set_object_property(entry, "0".into(), Value::str("key"))
                .unwrap();
            core.set_object_property(entry, "1".into(), Value::Int(7))
                .unwrap();
            let entries = core.alloc_array_with_prototype(None).unwrap();
            for index in 0..count {
                core.set_object_property(entries, index.to_string(), Value::Object(entry))
                    .unwrap();
            }
            core.set_object_property(entries, "length".into(), Value::Int(count))
                .unwrap();
            core.seed_register(0, Value::Object(entries)).unwrap();
            let result = core.execute(&module);
            if count == 1 {
                assert!(result.is_ok(), "{result:?}");
            } else {
                assert!(
                    matches!(result, Err(InterpreterError::BudgetExhausted { .. })),
                    "{result:?}"
                );
            }
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn later_entry_callbacks_cannot_erase_observed_key_provenance() {
    let source = r#"
const sensitive = 'label-marker';
const first = {
    get 0() { return sensitive; },
    get 1() { return Math.abs(-7); }
};
const second = {
    get 0() { return String('public'); },
    get 1() { return Math.abs(-9); }
};
Object.fromEntries([first, second]);
"#;
    for config in configurations() {
        let input_register = config.max_registers - 1;
        let module = labelled_source(source, input_register);
        for stress in [None, Some(1), Some(7)] {
            let mut core = InterpreterCore::new(config.clone(), "from-entries-provenance");
            core.set_gc_stress_interval(stress);
            core.seed_register(input_register, Value::str("private-key"))
                .unwrap();
            core.set_register_label(input_register, Label::Secret)
                .unwrap();
            let execution = core.execute(&module).expect("entries execute");
            assert_eq!(execution.completion_label, Label::Secret, "gc={stress:?}");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn entry_value_getter_cannot_exfiltrate_a_previously_observed_secret_key() {
    let source = r#"
const sensitive = 'label-marker';
const log = console.log;
Object.fromEntries([{
    get 0() { return sensitive; },
    get 1() { log('observed'); return 7; }
}]);
"#;
    for config in configurations() {
        let input_register = config.max_registers - 1;
        let module = labelled_source(source, input_register);
        let mut core = InterpreterCore::new(config, "from-entries-key-observation");
        core.seed_register(input_register, Value::str("private-key"))
            .unwrap();
        core.set_register_label(input_register, Label::Secret)
            .unwrap();
        assert!(matches!(
            core.execute(&module),
            Err(InterpreterError::CapabilityDenied { .. })
        ));
        assert!(core.console_output().is_empty());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

/// Abrupt entries with the iterator's return counted, a throwing return
/// (the entry's TypeError wins), String object and accessor entries, key
/// conversion (object, number, symbol), short and long entries, a Map, and
/// the result's prototype. Expected lines are Node v22.2.0's output,
/// captured programmatically.
#[test]
fn from_entries_reads_entries_and_closes_the_iterator() {
    let source = r#"function k(f) { try { return JSON.stringify(f()); } catch (e) { return e.constructor.name + (e.message === 'boom' ? ':boom' : ''); } }
function tracked(entries) {
  var log = { closed: 0 };
  var index = 0;
  log.iterable = {};
  log.iterable[Symbol.iterator] = function () {
    return {
      next: function () { return index < entries.length ? { value: entries[index++], done: false } : { value: undefined, done: true }; },
      return: function () { log.closed++; return {}; }
    };
  };
  return log;
}
var nullEntry = tracked([['a', 1], null]);
var stringEntry = tracked(['ab']);
var throwingKey = tracked([{ get 0() { throw new Error('boom'); }, 1: 'v' }]);
var throwingToString = tracked([[{ toString: function () { throw new Error('boom'); } }, 'v']]);
console.log(k(function () { return Object.fromEntries(nullEntry.iterable); }), nullEntry.closed, k(function () { return Object.fromEntries(stringEntry.iterable); }), stringEntry.closed, k(function () { return Object.fromEntries(throwingKey.iterable); }), throwingKey.closed, k(function () { return Object.fromEntries(throwingToString.iterable); }), throwingToString.closed);
console.log(k(function () { return Object.fromEntries([new String('ab'), new String('cd')]); }), k(function () { return Object.fromEntries([[{ toString: function () { return 'key'; } }, 'value'], [1, 'one'], [Symbol.iterator, 's']]); }));
var accessorEntry = { get 0() { return 'g'; }, get 1() { return 'h'; } };
console.log(k(function () { return Object.fromEntries([accessorEntry, ['x', 1, 2], [], ['y']]); }), k(function () { return Object.fromEntries(new Map([['m', 1]])); }), Object.getPrototypeOf(Object.fromEntries([])) === Object.prototype);
var badReturn = tracked([7]);
badReturn.iterable[Symbol.iterator] = (function (make) { return function () { var it = make(); it.return = function () { throw new Error('return'); }; return it; }; })(badReturn.iterable[Symbol.iterator]);
console.log(k(function () { return Object.fromEntries(badReturn.iterable); }));
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            "TypeError 1 TypeError 1 Error:boom 1 Error:boom 1",
            "{\"a\":\"b\",\"c\":\"d\"} {\"1\":\"one\",\"key\":\"value\"}",
            "{\"g\":\"h\",\"x\":1} {\"m\":1} true",
            "TypeError",
        ]
    );
}
