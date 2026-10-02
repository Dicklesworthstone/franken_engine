//! bd-9vouw.94: ArraySpeciesCreate and @@species for the Array methods.
//!
//! map, filter, slice, splice, concat, flat and flatMap built a plain array
//! whatever the receiver's `constructor` said, so `class A extends Array {}`
//! instances returned Arrays, a `constructor[Symbol.species]` was never
//! consulted, and a non-object `constructor` did not throw. The built-in
//! constructors had no `[Symbol.species]`, and `new A(3)` ignored its
//! argument (length 0). PROGRAM covers subclass results, a species
//! override, a species function that builds a non-array, a null species,
//! the @@species reads, the order in splice (species before the receiver
//! changes), the TypeErrors, and a non-array receiver (no species).
//! NODE_OUTPUT is Node v22.2.0's output.
//!
//! No-claim: TypedArray and ArrayBuffer species (TypedArraySpeciesCreate)
//! are not covered here; Array.from/of ignore their `this`.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = r#"class A extends Array {}
const a = new A(); a.push(1, 2, 3);
console.log(a.map((x) => x) instanceof A, a.filter(Boolean) instanceof A, a.slice(1) instanceof A, a.splice(0, 1) instanceof A, a.concat([4]) instanceof A, a.flat() instanceof A, a.flatMap((x) => [x]) instanceof A);
console.log(a.map((x) => x * 2).join(), a.filter((x) => x > 2).join(), a.slice(0, 1).length, new A(3).length, Reflect.construct(A, [3]).length, new A(1, 2).join(), new A('x').length);
class B extends Array { static get [Symbol.species]() { return Array; } }
const b = new B(); b.push(1, 2);
console.log(b.map((x) => x) instanceof B, b.map((x) => x).constructor === Array, B[Symbol.species] === Array);
const custom = [1, 2];
custom.constructor = { [Symbol.species]: function (n) { this.made = n; } };
const mapped = custom.map((x) => x + 1);
console.log(mapped.made, mapped[0], mapped[1], Array.isArray(mapped), mapped.length);
const nullSpecies = [1]; nullSpecies.constructor = { [Symbol.species]: null };
console.log(Array.isArray(nullSpecies.map((x) => x)), Object.getPrototypeOf(nullSpecies.slice()) === Array.prototype);
console.log(Array[Symbol.species] === Array, Map[Symbol.species] === Map, Set[Symbol.species] === Set, Promise[Symbol.species] === Promise, RegExp[Symbol.species] === RegExp, ArrayBuffer[Symbol.species] === ArrayBuffer, Uint8Array[Symbol.species] === Uint8Array, A[Symbol.species] === A);
function F() {}
console.log(F[Symbol.species], typeof Object[Symbol.species]);
const order = [];
const spliced = [1, 2, 3];
spliced.constructor = { [Symbol.species]: function (n) { order.push('species:' + n + ':' + spliced.length); } };
spliced.splice(0, 2);
console.log(order.join(), spliced.join());
for (const [label, run] of [
  ['constructor not object', () => { const x = [1]; x.constructor = 5; x.map((v) => v); }],
  ['species not constructor', () => { const x = [1]; x.constructor = { [Symbol.species]: 7 }; x.filter(Boolean); }],
  ['non-array receiver ignores constructor', () => { const o = { length: 1, 0: 'a', constructor: 5 }; return Array.prototype.map.call(o, (v) => v); }],
]) {
  try { const r = run(); console.log(label, 'no throw', Array.isArray(r)); } catch (e) { console.log(label, e.constructor.name); }
}"#;

const NODE_OUTPUT: &str = r#"true true true true true true true
4,6 3 1 3 3 1,2 1
false true true
2 2 3 false undefined
true true
true true true true true true true true
undefined undefined
species:2:3 3
constructor not object TypeError
species not constructor TypeError
non-array receiver ignores constructor no throw true"#;

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "array-species.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "array-species.js"),
        &LoweringContext::new("species-trace", "species-decision", "species-policy"),
    )
    .map_err(|error| format!("lower: {error:?}"))?
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "array-species");
    let result = core.execute(&module);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift"
    );
    let result = result.map_err(|error| format!("execute: {error:?}"))?;
    Ok(result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n"))
}

#[test]
fn array_methods_use_species_like_node() {
    let output = console_output(PROGRAM).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT.lines().count());
}
