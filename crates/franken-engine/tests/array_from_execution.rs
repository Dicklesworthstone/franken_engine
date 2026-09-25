//! Source-level regressions for ordinary Array.from callbacks (bd-9vouw.42).
//! These run the real parser, lowerer and native interpreter, not a model VM.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "array-from-execution.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("Array.from regression source must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "array-from-execution.js"),
        &LoweringContext::new("from-trace", "from-decision", "from-policy"),
    )
    .expect("Array.from regression source must lower")
    .ir3
}

fn configurations() -> impl Iterator<Item = InterpreterConfig> {
    [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ]
    .into_iter()
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

fn assert_source(source: &str, expected: &str) {
    let module = lower(source);
    for config in configurations() {
        let mut core = InterpreterCore::new(config, "array-from-execution");
        let execution = core.execute(&module).expect("Array.from must execute");
        assert_eq!(execution.value, Value::str(expected), "{source}");
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "Array.from leaked temporary accounting: {source}"
        );
    }
}

macro_rules! source_case {
    ($name:ident, $source:literal, $expected:literal) => {
        #[test]
        fn $name() {
            assert_source($source, $expected);
        }
    };
}

source_case!(
    mapper_method_calls,
    r####"
Array.from('abc', c => c.toUpperCase()).join('');
"####,
    "ABC"
);

source_case!(
    mapper_captures_its_lexical_environment,
    r####"
function make(prefix) {
    let count = 0;
    return function(value, index) {
        count += 1;
        return prefix + value.trim() + ':' + index + ':' + count;
    };
}
const prefix = 'wrong';
Array.from([' a ', ' b '], make('right:')).join('|');
"####,
    "right:a:0:1|right:b:1:2"
);

source_case!(
    mapper_this_and_exact_argument_list,
    r####"
const receiver = {prefix: 'p'};
Array.from(['a', 'b'], function(value, index) {
    return this.prefix + value + ':' + index + ':' + arguments.length;
}, receiver).join('|');
"####,
    "pa:0:2|pb:1:2"
);

source_case!(
    nested_mapping_preserves_outer_locals,
    r####"
let visits = 0;
const result = Array.from(['ab', 'cd'], function(text, outer) {
    visits += 1;
    const inner = Array.from(text, function(letter, index) {
        return letter.toUpperCase() + outer + index;
    }).join(',');
    return inner + ':' + text;
}).join('|');
result + ':' + visits;
"####,
    "A00,B01:ab|C10,D11:cd:2"
);

source_case!(
    mapper_side_effects_are_not_replayed,
    r####"
let calls = 0;
const result = Array.from(['a', 'b', 'c'], function(value, index) {
    calls += 1;
    return value.toUpperCase() + index;
});
result.join(',') + ':' + calls;
"####,
    "A0,B1,C2:3"
);

source_case!(
    throwing_mapper_preserves_exception_identity,
    r####"
const token = {};
let calls = 0;
let caught = false;
try {
    Array.from(['a', 'b', 'c'], function(value, index) {
        calls += 1;
        value.toUpperCase();
        if (index === 1) { throw token; }
        return value;
    });
} catch (error) { caught = error === token; }
String(caught) + ':' + calls;
"####,
    "true:2"
);

source_case!(
    native_mapper_errors_are_catchable,
    r####"
let caught = '';
try { Array.from(['a'], function(value) { return value.notAMethod(); }); }
catch (error) { caught = error.name; }
caught + ':' + Array.from('x', c => c.toUpperCase()).join('');
"####,
    "TypeError:X"
);

source_case!(
    live_array_like_reads_interleave_with_mapping,
    r####"
let trace = '';
const source = {
    get length() { trace += 'L'; return 3; },
    get 0() { trace += 'G0'; return 'a'; },
    get 1() { trace += 'G1'; return 'b'; },
    get 2() { trace += 'G2'; return 'c'; }
};
const result = Array.from(source, function(value, index) {
    trace += 'M' + index;
    return value.toUpperCase();
});
result.join('') + ':' + trace;
"####,
    "ABC:LG0M0G1M1G2M2"
);

source_case!(
    array_like_length_coercion_and_mutation,
    r####"
let calls = 0;
const source = {
    length: { valueOf() { calls += 1; return 3.8; } },
    0: 'a', 1: 'b', 2: 'c'
};
const result = Array.from(source, function(value, index) {
    if (index === 0) { source[1] = 'changed'; source.length = 1; }
    return value;
});
result.join(',') + ':' + calls;
"####,
    "a,changed,c:1"
);

source_case!(
    array_like_gets_inherited_values_and_materializes_holes,
    r####"
const parent = {1: 'inherited'};
const source = Object.create(parent);
source.length = 3;
source[0] = 'first';
const result = Array.from(source);
result[0] + ':' + result[1] + ':' + String(2 in result) + ':' + String(result[2]);
"####,
    "first:inherited:true:undefined"
);

source_case!(
    array_like_index_getter_stops_mapping,
    r####"
let trace = '';
const source = {
    length: 3,
    get 0() { trace += 'G0'; return 'a'; },
    get 1() { trace += 'G1'; throw 17; },
    get 2() { trace += 'bad'; return 'c'; }
};
let caught = 0;
try { Array.from(source, function(value, index) { trace += 'M' + index; return value; }); }
catch (error) { caught = error; }
trace + ':' + caught;
"####,
    "G0M0G1:17"
);

source_case!(
    strings_iterate_exact_code_points,
    r####"
const result = Array.from('A\uD83D\uDE00\uD800Z', function(value, index) {
    return index + ':' + value.length + ':' + value.charCodeAt(0);
});
result.join('|');
"####,
    "0:1:65|1:2:55357|2:1:55296|3:1:90"
);

source_case!(
    mapper_validation_precedes_source_getters,
    r####"
let trace = '';
const source = { get length() { trace += 'bad'; return 1; } };
let caught = '';
try { Array.from(source, 42); } catch (error) { caught = error.name; }
caught + ':' + trace;
"####,
    "TypeError:"
);

source_case!(
    nullish_sources_throw_and_ordinary_primitives_are_empty,
    r####"
let count = 0;
try { Array.from(); } catch (error) { count += error.name === 'TypeError'; }
try { Array.from(null); } catch (error) { count += error.name === 'TypeError'; }
try { Array.from(undefined); } catch (error) { count += error.name === 'TypeError'; }
count + ':' + Array.from(17).length + ':' + Array.from(false).length;
"####,
    "3:0:0"
);

#[test]
fn array_from_callbacks_share_the_instruction_budget() {
    let module = lower(
        "let caught = false; try { Array.from({length: 10000}, function(value, index) { return index; }); } catch (error) { caught = true; } caught;",
    );
    for mut config in configurations() {
        config.instruction_budget = 4096;
        let mut core = InterpreterCore::new(config, "array-from-budget");
        assert!(matches!(
            core.execute(&module),
            Err(InterpreterError::BudgetExhausted { .. })
        ));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

// Replace exactly one main-program literal load with a seeded labelled input.
// This is an actual execution test; the mapper still runs ordinary lowered JS.
fn labelled_source(source: &str, input_register: u32) -> Ir3Module {
    let mut module = lower(source);
    let pool_index = module
        .constant_pool
        .iter()
        .position(|text| text == "label-marker")
        .expect("test must have the unique labelled literal") as u32;
    let mut replacements = 0;
    for instruction in &mut module.instructions {
        if let Ir3Instruction::LoadStr {
            dst,
            pool_index: index,
        } = instruction
            && *index == pool_index
        {
            *instruction = Ir3Instruction::Move {
                dst: *dst,
                src: input_register,
            };
            replacements += 1;
        }
    }
    assert_eq!(replacements, 1, "only the source literal is replaced");
    module
}

#[test]
fn later_public_mapper_results_do_not_erase_input_provenance() {
    let source = "Array.from('label-marker', function(value, index) { if (index === 0) { return value; } return 'public'; });";
    for config in configurations() {
        let input_register = config.max_registers - 1;
        let module = labelled_source(source, input_register);
        let mut core = InterpreterCore::new(config, "array-from-label");
        core.seed_register(input_register, Value::str("ab"))
            .unwrap();
        core.set_register_label(input_register, Label::Secret)
            .unwrap();
        let execution = core.execute(&module).unwrap();
        assert_eq!(execution.completion_label, Label::Secret);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn mapper_cannot_publish_secret_input_through_a_public_console_alias() {
    let source = "const log = console.log; Array.from('label-marker', function(value) { log(value); return value; });";
    for config in configurations() {
        let input_register = config.max_registers - 1;
        let module = labelled_source(source, input_register);
        let mut core = InterpreterCore::new(config, "array-from-sink");
        core.seed_register(input_register, Value::str("secret"))
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

#[test]
fn mapper_throw_preserves_its_observation_label_through_catch() {
    let source = "let caught = ''; try { Array.from('label-marker', function(value) { throw 'public'; }); } catch (error) { caught = error; } caught;";
    for config in configurations() {
        let input_register = config.max_registers - 1;
        let module = labelled_source(source, input_register);
        let mut core = InterpreterCore::new(config, "array-from-throw-label");
        core.seed_register(input_register, Value::str("secret"))
            .unwrap();
        core.set_register_label(input_register, Label::Secret)
            .unwrap();
        let execution = core.execute(&module).unwrap();
        assert_eq!(execution.value, Value::str("public"));
        assert_eq!(execution.completion_label, Label::Secret);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

source_case!(
    custom_iterator_getters_and_mapper_order,
    r####"
let trace = '';
let index = 0;
const iterator = {
    get next() {
        trace += 'N';
        return function() {
            trace += 'C';
            const current = index++;
            return {
                get done() { trace += 'D'; return current === 2; },
                get value() { trace += 'V'; return 'a' + current; }
            };
        };
    }
};
const source = {
    get [Symbol.iterator]() {
        trace += 'I';
        return function() { trace += 'S'; return iterator; };
    },
    get length() { trace += 'bad'; return 10; }
};
const result = Array.from(source, function(value) {
    trace += 'M';
    return value.toUpperCase();
});
result.join(',') + ':' + trace;
"####,
    "A0,A1:ISNCDVMCDVMCD"
);

source_case!(
    iterator_next_is_captured_once_with_its_receiver,
    r####"
let index = 0;
const iterator = {
    next() {
        if (this !== iterator) { throw 'receiver'; }
        return {done: index === 3, value: index++};
    }
};
const source = {[Symbol.iterator]() { return iterator; }};
Array.from(source, function(value) {
    iterator.next = function() { throw 'replacement must not run'; };
    return value * 2;
}).join(',');
"####,
    "0,2,4"
);

source_case!(
    mapper_throw_wins_over_iterator_return_throw,
    r####"
const token = {};
let getterCalls = 0;
let returnCalls = 0;
const iterator = {
    next() { return {done: false, value: 'a'}; },
    get return() {
        getterCalls += 1;
        return function() {
            if (this !== iterator) { throw 'wrong receiver'; }
            returnCalls += 1;
            throw 'cleanup error';
        };
    }
};
let original = false;
try {
    Array.from({[Symbol.iterator]() { return iterator; }}, function(value) {
        value.toUpperCase();
        throw token;
    });
} catch (error) { original = error === token; }
String(original) + ':' + getterCalls + ':' + returnCalls;
"####,
    "true:1:1"
);

source_case!(
    mapper_throw_wins_over_return_getter_throw,
    r####"
let returnGets = 0;
const iterator = {
    next() { return {done: false, value: 1}; },
    get return() { returnGets += 1; throw 'cleanup'; }
};
let caught = '';
try { Array.from({[Symbol.iterator]() { return iterator; }}, function() { throw 'original'; }); }
catch (error) { caught = error; }
caught + ':' + returnGets;
"####,
    "original:1"
);

source_case!(
    mapper_throw_wins_over_primitive_return_result,
    r####"
let returns = 0;
const source = {[Symbol.iterator]() {
    return {
        next() { return {value: 1, done: false}; },
        return() { returns += 1; return 17; }
    };
}};
let caught = '';
try { Array.from(source, function() { throw 'original'; }); }
catch (error) { caught = error; }
caught + ':' + returns;
"####,
    "original:1"
);

source_case!(
    next_failures_do_not_close_the_iterator,
    r####"
let returns = 0;
const source = {[Symbol.iterator]() {
    return {
        next() { throw 'next error'; },
        return() { returns += 1; return {}; }
    };
}};
let caught = '';
try { Array.from(source); } catch (error) { caught = error; }
caught + ':' + returns;
"####,
    "next error:0"
);

source_case!(
    value_getter_failures_do_not_close_the_iterator,
    r####"
let returns = 0;
const source = {[Symbol.iterator]() {
    return {
        next() { return {done: false, get value() { throw 'value error'; }}; },
        return() { returns += 1; return {}; }
    };
}};
let caught = '';
try { Array.from(source); } catch (error) { caught = error; }
caught + ':' + returns;
"####,
    "value error:0"
);

source_case!(
    normal_exhaustion_does_not_call_return_or_read_final_value,
    r####"
let returns = 0;
let values = 0;
const source = {[Symbol.iterator]() {
    return {
        next() { return {done: true, get value() { values += 1; return 7; }}; },
        return() { returns += 1; return {}; }
    };
}};
Array.from(source).length + ':' + returns + ':' + values;
"####,
    "0:0:0"
);

source_case!(
    noncallable_iterator_does_not_fall_back_to_length,
    r####"
let reads = 0;
const source = {[Symbol.iterator]: 17, get length() { reads += 1; return 1; }};
let caught = '';
try { Array.from(source); } catch (error) { caught = error.name; }
caught + ':' + reads;
"####,
    "TypeError:0"
);

source_case!(
    null_iterator_selects_array_like_branch,
    r####"
const source = {[Symbol.iterator]: null, length: 2, 0: ' a ', 1: ' b '};
Array.from(source, value => value.trim()).join(',');
"####,
    "a,b"
);

source_case!(
    generator_sources_use_the_native_resume_path,
    r####"
function* source() { yield 'a'; yield 'b'; }
Array.from(source(), function(value, index) { return value.toUpperCase() + index; }).join(',');
"####,
    "A0,B1"
);

source_case!(
    native_array_iterator_sources,
    r####"
Array.from(['a', 'b'].values(), function(value, index) {
    return value.toUpperCase() + index;
}).join(',');
"####,
    "A0,B1"
);

source_case!(
    array_iterator_observes_length_growth_during_mapping,
    r####"
const source = ['a', 'b'];
const result = Array.from(source, function(value, index) {
    if (index === 0) { source.push('c'); }
    return value.toUpperCase();
});
result.join('') + ':' + result.length;
"####,
    "ABC:3"
);

source_case!(
    custom_array_iterator_takes_precedence,
    r####"
const source = ['wrong'];
source[Symbol.iterator] = function() {
    let done = false;
    return {next() {
        if (done) { return {done: true}; }
        done = true;
        return {done: false, value: 'correct'};
    }};
};
Array.from(source, value => value.toUpperCase()).join(',');
"####,
    "CORRECT"
);

source_case!(
    set_sources_preserve_insertion_order_and_mapper_indices,
    r####"
Array.from(new Set(['b', 'a', 'b', 'c']), function(value, index) {
    return value.toUpperCase() + index;
}).join(',');
"####,
    "B0,A1,C2"
);

source_case!(
    map_entry_sources_are_mapped_by_ordinary_callbacks,
    r####"
Array.from(new Map([[3, 'c'], [1, 'a'], [2, 'b']]), function(entry, index) {
    return entry[0] + entry[1].toUpperCase() + ':' + index;
}).join(',');
"####,
    "3C:0,1A:1,2B:2"
);

source_case!(
    explicit_null_set_iterator_is_not_bypassed,
    r####"
const source = new Set(['a']);
source[Symbol.iterator] = null;
source.length = 1;
source[0] = 'array-like';
Array.from(source).join(',');
"####,
    "array-like"
);

source_case!(
    null_string_iterator_selects_code_unit_indexing,
    r####"
const saved = String.prototype[Symbol.iterator];
let result;
try {
    String.prototype[Symbol.iterator] = null;
    result = Array.from('\uD83D\uDE00', function(value) {
        return value.charCodeAt(0);
    }).join(',');
} finally { String.prototype[Symbol.iterator] = saved; }
result;
"####,
    "55357,56832"
);

#[test]
fn iterator_budget_refusal_does_not_execute_guest_cleanup() {
    let module = lower(
        "const log = console.log; const source = {[Symbol.iterator]() { return {next() { return {value: 1, done: false}; }, return() { log('cleanup after containment'); return {}; }}; }}; Array.from(source, function(value) { return value; });",
    );
    for mut config in configurations() {
        config.instruction_budget = 4096;
        let mut core = InterpreterCore::new(config, "array-from-iterator-budget");
        assert!(matches!(
            core.execute(&module),
            Err(InterpreterError::BudgetExhausted { .. })
        ));
        assert!(core.console_output().is_empty());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

source_case!(
    invalid_array_like_length_throws_before_indexed_get,
    r####"
let trace = '';
const source = {
    get length() { trace += 'L'; return 4294967296; },
    get 0() { trace += 'bad'; return 'x'; }
};
let caught = '';
try { Array.from(source); } catch (error) { caught = error.name; }
caught + ':' + trace;
"####,
    "RangeError:L"
);
