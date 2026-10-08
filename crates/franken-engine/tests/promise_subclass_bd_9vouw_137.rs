//! bd-9vouw.137: Promise can be subclassed.
//!
//! `new (class extends Promise {})(executor)` threw "expected object result
//! from constructible builtin target", and then/catch/finally and the
//! statics ignored the constructor. PROGRAM covers:
//! - a subclass instance (instanceof, getPrototypeOf, a subclass method,
//!   String());
//! - then/catch/finally returning the subclass through SpeciesConstructor
//!   and NewPromiseCapability;
//! - a constructor that wraps the executor;
//! - a species override back to Promise;
//! - resolve, reject, all, race, allSettled and any on the subclass, with
//!   PromiseResolve's same-constructor shortcut;
//! - the TypeErrors for a constructor that never calls the executor or
//!   that is not an object, and for a species that is not a constructor;
//! - the settled values, awaited.
//!
//! POISONED checks that a throwing `constructor` getter propagates from
//! then (Test262 Promise/prototype/then/ctor-poisoned). Both outputs are
//! Node v22.2.0's.
//!
//! Additional bd-9vouw.295 coverage checks native element job order and
//! observable per-element `C.resolve`, `then`, constructor and species reads.
//! Class fields on a Promise subclass are not covered.

#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

#[test]
fn dense_intrinsic_inputs_use_native_jobs_without_extra_promises_bd_9vouw_295() {
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::promise_model::PromiseState;

    for (element, aggregate) in [("7", 0), ("Promise.resolve(7)", 1)] {
        let source = format!(
            "Object.getOwnPropertyDescriptor(Promise, Symbol.species); Promise.prototype; \
             Array.prototype; const value = {element}; Promise.all(Array(10000).fill(value)); \
             process.exit(0);"
        );
        let module = lower_promise_source(&source);
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = RuntimeCapability::ALL.into_iter().collect();
        let mut core = InterpreterCore::new(config, "native-combinator");
        // Process exit stops before the job checkpoint so ordinary
        // per-element derived promises would still be pending and observable
        // through this read-only public API, even after collection.
        assert_eq!(core.execute(&module).unwrap().exit_code, Some(0));
        assert_eq!(core.promise_state(aggregate), Some(PromiseState::Pending));
        assert_eq!(core.promise_state(aggregate + 1), None);
        assert_eq!(core.promise_state(aggregate + 2), None);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn pending_combinators_preserve_first_secret_through_public_alias_bd_9vouw_295() {
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ifc_artifacts::Label;
    use frankenengine_engine::ir_contract::Ir3Instruction;

    for own_then in [false, true] {
        let source = format!(
            r#"const output = 424241;
function save(values) {{ output.result = values[0]; }}
let resolveFirst, resolveSecond;
const p = new Promise(r => {{ resolveFirst = r; }});
const q = new Promise(r => {{ resolveSecond = r; }});
{}
Promise.all([p, q]).then(save);
resolveFirst(424242);
resolveSecond(11);
0;
"#,
            if own_then {
                "p.then = Promise.prototype.then;"
            } else {
                ""
            }
        );
        let mut module = lower_promise_source(&source);
        let mut markers = [0, 0];
        for instruction in &mut module.instructions {
            if let Ir3Instruction::LoadInt { dst, value } = instruction {
                let marker = match *value {
                    424241 => Some((0, 200)),
                    424242 => Some((1, 201)),
                    _ => None,
                };
                if let Some((index, seed)) = marker {
                    markers[index] += 1;
                    *instruction = Ir3Instruction::Move {
                        dst: *dst,
                        src: seed,
                    };
                }
            }
        }
        assert_eq!(markers, [1, 1]);
        for label in [Label::Public, Label::Secret] {
            let mut config = InterpreterConfig::quickjs_defaults();
            config.granted_capabilities = RuntimeCapability::ALL.into_iter().collect();
            let mut core = InterpreterCore::new(config, "combinator-alias-label");
            let output = core.alloc_object_with_prototype(None).unwrap();
            core.set_object_property(output, "untouched".into(), Value::Int(19))
                .unwrap();
            core.seed_register(200, Value::Object(output)).unwrap();
            core.seed_register(201, Value::Int(7)).unwrap();
            core.set_register_label(201, label.clone()).unwrap();
            core.execute(&module).unwrap();
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
            // A fresh execution clears object mutation labels but preserves
            // stored property labels. This therefore proves output.result's
            // own stored label, independent of the callback context or shape.
            // Fresh seeded executions retain the prior IP; harmless padding
            // beyond every original instruction reaches the same probe.
            let mut observation = lower_promise_source("0;");
            observation.instructions =
                vec![Ir3Instruction::LoadUndefined { dst: 2 }; module.instructions.len() + 1];
            observation.instructions.extend([
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 3,
                    dst: 4,
                },
                Ir3Instruction::LoadInt { dst: 5, value: 0 },
                Ir3Instruction::Add {
                    dst: 4,
                    lhs: 4,
                    rhs: 5,
                },
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 1,
                    dst: 2,
                },
                Ir3Instruction::Add {
                    dst: 2,
                    lhs: 2,
                    rhs: 4,
                },
                Ir3Instruction::Return { value: 2 },
            ]);
            for (register, value) in [
                (0, Value::Object(output)),
                (1, Value::str("result")),
                (2, Value::Undefined),
                (3, Value::str("untouched")),
                (4, Value::Undefined),
                (5, Value::Undefined),
            ] {
                core.seed_register(register, value).unwrap();
                core.set_register_label(register, Label::Public).unwrap();
            }
            let observed = core.execute(&observation).unwrap();
            assert_eq!(observed.value, Value::Int(26));
            assert_eq!(
                core.get_register_label(4).unwrap(),
                &Label::Public,
                "an untouched public property and control arithmetic stay Public"
            );
            assert_eq!(observed.completion_label, label, "own_then={own_then}");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

fn lower_promise_source(source: &str) -> frankenengine_engine::ir_contract::Ir3Module {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "promise-jobs.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .unwrap();
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "promise-jobs.js"),
        &LoweringContext::new("promise-jobs", "test", "test"),
    )
    .unwrap()
    .ir3
}

/// bd-9vouw.295: every non-empty intrinsic combinator settles through its
/// element reaction jobs, interleaved with ordinary `.then` registrations.
/// Expected order captured from Node in the same session.
#[test]
fn intrinsic_combinators_preserve_element_job_order_bd_9vouw_295() {
    let source = r#"const log = [];
const p = Promise.resolve(7);
p.then(() => log.push('before'));
Promise.all([p, p]).then(v => log.push('all:' + v.join('+')));
p.then(() => log.push('after'));
Promise.allSettled([Promise.reject('no'), 2]).then(v => log.push('settled:' + v.map(x => x.status).join('+')));
Promise.race([Promise.resolve('win'), Promise.reject('lose')]).then(v => log.push('race:' + v));
Promise.any([Promise.reject('no'), Promise.resolve('yes')]).then(v => log.push('any:' + v));
queueMicrotask(() => log.push('queue'));
Promise.resolve().then(() => log.push('tick1')).then(() => log.push('tick2')).then(() => log.push('tick3')).then(() => console.log(log.join('|')));
"#;
    assert_eq!(
        console(source),
        "before|after|queue|tick1|all:7+7|settled:rejected+fulfilled|race:win|any:yes|tick2|tick3"
    );
}

#[test]
fn null_prototype_arrays_are_not_iterable_bd_9vouw_295() {
    let source = r#"function rejects(input, label) {
    for (const name of ['all', 'allSettled', 'any', 'race']) {
        Promise[name](input).catch(error => console.log(label + ':' + name + ':' + (error instanceof TypeError)));
    }
}
rejects(Object.setPrototypeOf([1], null), 'null');
rejects(Object.setPrototypeOf([2], Object.prototype), 'object');
rejects(Object.setPrototypeOf([3], {}), 'custom');
const own = Object.setPrototypeOf([4], null);
own[Symbol.iterator] = Array.prototype.values;
Promise.all(own).then(values => console.log('own:' + values.join(',')));
const inherited = Object.setPrototypeOf([5], Object.create(Array.prototype));
Promise.all(inherited).then(values => console.log('inherited:' + values.join(',')));
"#;
    assert_eq!(
        console(source),
        "null:all:true\nnull:allSettled:true\nnull:any:true\nnull:race:true\nobject:all:true\nobject:allSettled:true\nobject:any:true\nobject:race:true\ncustom:all:true\ncustom:allSettled:true\ncustom:any:true\ncustom:race:true\nown:4\ninherited:5"
    );
}

#[test]
fn pending_combinators_and_empty_inputs_preserve_job_order_bd_9vouw_295() {
    let source = r#"const log = [];
let resolve, reject;
const p = new Promise(r => { resolve = r; });
const q = new Promise((r, j) => { reject = j; });
p.then(() => log.push('before'));
Promise.all([p, p]).then(v => log.push('all:' + v.join('+')));
Promise.race([q, p]).catch(e => log.push('race:' + e));
Promise.any([q, p]).then(v => log.push('any:' + v));
Promise.allSettled([p, q]).then(v => log.push('settled:' + v.map(x => x.status).join('+')));
p.then(() => log.push('after'));
Promise.all([]).then(() => log.push('empty-all'));
Promise.allSettled([]).then(() => log.push('empty-settled'));
Promise.any([]).catch(e => log.push('empty-any:' + e.errors.length));
Promise.race([]).then(() => log.push('empty-race'));
reject('rejected'); resolve('resolved');
queueMicrotask(() => log.push('queue'));
Promise.resolve().then(() => log.push('tick1')).then(() => log.push('tick2')).then(() => log.push('tick3')).then(() => console.log(log.join('|')));
"#;
    assert_eq!(
        console(source),
        "empty-all|empty-settled|empty-any:0|before|after|queue|tick1|race:rejected|all:resolved+resolved|any:resolved|settled:fulfilled+rejected|tick2|tick3"
    );
}

#[test]
fn combinators_observe_each_promise_constructor_and_then_bd_9vouw_295() {
    let source = r#"const log = [];
const nativeThen = Promise.prototype.then;
const p = Promise.resolve(3);
Object.defineProperty(p, 'constructor', {get() { log.push('constructor'); return Promise; }});
Object.defineProperty(p, 'then', {get() { log.push('get-then'); return function(f, r) { log.push('call-then'); return nativeThen.call(this, f, r); }; }});
Promise.all([p, p]).then(v => log.push('all:' + v.join('+')));
class Sub extends Promise { then(f, r) { log.push('sub-then'); return super.then(f, r); } }
Promise.all([new Sub(r => r(4))]).then(v => log.push('sub-all:' + v[0]));
const poisoned = Promise.resolve(0);
Object.defineProperty(poisoned, 'constructor', {get() { throw new RangeError('constructor-poison'); }});
try { Promise.resolve(poisoned); } catch (e) { log.push(e.name + ':' + e.message); }
log.push('sync');
queueMicrotask(() => log.push('queue'));
let last = Promise.resolve();
for (let i = 0; i < 8; i++) last = last.then(() => {});
last.then(() => console.log(log.join('|')));
"#;
    assert_eq!(
        console(source),
        "constructor|get-then|call-then|constructor|constructor|get-then|call-then|constructor|RangeError:constructor-poison|sync|sub-then|queue|all:3+3|sub-all:4"
    );
}

#[test]
fn combinators_observe_intrinsic_constructor_species_bd_9vouw_295() {
    let source = r#"const log = [];
const original = Object.getOwnPropertyDescriptor(Promise, Symbol.species);
Object.defineProperty(Promise, Symbol.species, {configurable: true, get() { log.push('species'); return Promise; }});
Promise.all([1, 2]).then(v => log.push('all:' + v.join('+')));
Promise.race([Promise.resolve('race')]).then(v => log.push(v));
log.push('sync');
Object.defineProperty(Promise, Symbol.species, original);
queueMicrotask(() => log.push('queue'));
Promise.resolve().then(() => log.push('tick')).then(() => {}).then(() => console.log(log.join('|')));
"#;
    assert_eq!(
        console(source),
        "species|species|species|species|species|sync|queue|tick|all:1+2|race"
    );
}

#[test]
fn combinators_register_reactions_while_advancing_iterator_bd_9vouw_295() {
    let source = r#"const log = [];
let resolve;
const p = new Promise(r => { resolve = r; });
const nativeThen = Promise.prototype.then;
Object.defineProperty(p, 'then', {get() { log.push('get-then'); return function(f, r) { log.push('call-then'); return nativeThen.call(this, f, r); }; }});
p.then(() => log.push('before'));
let index = 0;
const iterable = {[Symbol.iterator]() { log.push('iterator'); return {next() { log.push('next:' + index); if (index++ === 0) return {value: p, done: false}; resolve('value'); p.then(() => log.push('during-next')); return {done: true}; }}; }};
Promise.all(iterable).then(v => log.push('all:' + v[0]));
p.then(() => log.push('after'));
queueMicrotask(() => log.push('queue'));
Promise.resolve().then(() => log.push('tick1')).then(() => log.push('tick2')).then(() => console.log(log.join('|')));
"#;
    assert_eq!(
        console(source),
        "get-then|call-then|iterator|next:0|get-then|call-then|next:1|get-then|call-then|get-then|call-then|before|during-next|after|queue|tick1|all:value|tick2"
    );
}

#[test]
fn promise_resolve_wrapping_preserves_resolver_once_guard_bd_9vouw_295() {
    let source = r#"const log = [];
let gets = 0;
const input = Promise.resolve(9);
Object.defineProperty(input, 'then', {get() { gets++; return Promise.prototype.then; }});
function Settled(ex) { let r, j; const p = new Promise((a, b) => { r = a; j = b; }); ex(r, j); r(0); return p; }
function Following(ex) { let r, j; const p = new Promise((a, b) => { r = a; j = b; }); ex(r, j); r(new Promise(() => {})); return p; }
Promise.resolve.call(Settled, input).then(v => log.push('settled:' + v));
Promise.resolve.call(Following, input);
let selfResolve, selfReject;
const self = new Promise((r, j) => { selfResolve = r; selfReject = j; });
Object.defineProperty(self, 'then', {get() { gets++; return Promise.prototype.then; }});
function Self(ex) { ex(selfResolve, selfReject); return self; }
Promise.prototype.then.call(Promise.resolve.call(Self, self), undefined, e => log.push('self:' + e.name));
log.push('gets:' + gets);
let savedResolve;
function Reentrant(ex) { let r, j; const p = new Promise((a, b) => { r = a; j = b; }); savedResolve = r; ex(r, j); return p; }
const reentrant = Promise.resolve(1);
Object.defineProperty(reentrant, 'then', {get() { log.push('reenter-get'); savedResolve('ignored'); return r => r('thenable-value'); }});
Promise.resolve.call(Reentrant, reentrant).then(v => log.push('reentrant:' + v));
log.push('sync');
let last = Promise.resolve(); for (let i = 0; i < 8; i++) last = last.then(() => {});
last.then(() => console.log(log.join('|')));
"#;
    assert_eq!(
        console(source),
        "gets:0|reenter-get|sync|settled:0|self:TypeError|reentrant:thenable-value"
    );
}

const PROGRAM: &str = r#"const log = [];
class MyPromise extends Promise { tag() { return 'mine'; } }
class Wrapped extends Promise {
  constructor(executor) { super((resolve, reject) => { log.push('wrapped-executor'); executor(resolve, reject); }); this.extra = 'x'; }
}
class Plain extends Promise { static get [Symbol.species]() { return Promise; } }
function ZeroArg() {}
const p = new MyPromise((resolve) => resolve(1));
console.log(p instanceof MyPromise, p instanceof Promise, Object.getPrototypeOf(p) === MyPromise.prototype, p.tag(), String(p));
const t = p.then((v) => v + 1);
console.log(t instanceof MyPromise, p.catch(() => 0) instanceof MyPromise, p.finally(() => 0) instanceof MyPromise);
const w = new Wrapped((resolve) => resolve(5));
console.log(w instanceof Wrapped, w.extra, w.then((v) => v) instanceof Wrapped, log.join());
console.log(new Plain((r) => r(1)).then((v) => v) instanceof Plain, MyPromise.resolve(2) instanceof MyPromise, MyPromise.reject(3).catch(() => 0) instanceof MyPromise, MyPromise.resolve(p) === p, MyPromise.resolve(Promise.resolve(1)) instanceof MyPromise);
console.log(MyPromise.all([1, 2]) instanceof MyPromise, MyPromise.race([1]) instanceof MyPromise, MyPromise.allSettled([1]) instanceof MyPromise, MyPromise.any([1]) instanceof MyPromise, Promise[Symbol.species] === Promise, MyPromise[Symbol.species] === MyPromise);
for (const [label, run] of [
  ['all on non-capability ctor', () => Promise.all.call(ZeroArg, [])],
  ['resolve on non-capability ctor', () => Promise.resolve.call(ZeroArg, 1)],
  ['then with constructor 1', () => { const q = Promise.resolve(1); q.constructor = 1; q.then(() => 0); }],
  ['then with species non-ctor', () => { const q = Promise.resolve(1); q.constructor = { [Symbol.species]: 1 }; q.then(() => 0); }],
]) {
  try { run(); console.log(label, 'no throw'); } catch (e) { console.log(label, e.constructor.name); }
}
(async () => {
  const results = [];
  results.push(await t);
  results.push(await MyPromise.reject(new Error('no')).catch((e) => e.message));
  results.push(await p.finally(() => 'ignored'));
  results.push(JSON.stringify(await MyPromise.all([1, Promise.resolve(2), MyPromise.resolve(3)])));
  results.push(await MyPromise.race([MyPromise.resolve('first'), new MyPromise(() => {})]));
  results.push(JSON.stringify((await MyPromise.allSettled([MyPromise.reject(1), 2])).map((r) => r.status)));
  results.push(await MyPromise.any([MyPromise.reject(1), MyPromise.resolve('any')]));
  results.push(await w.then((v) => v * 2));
  results.push(await new MyPromise((resolve) => resolve(MyPromise.resolve('adopted'))));
  console.log(results.join(' | '));
})();"#;

const NODE_OUTPUT: &str = r#"true true true mine [object Promise]
true true true
true x true wrapped-executor,wrapped-executor
false true true true true
true true true true true true
all on non-capability ctor TypeError
resolve on non-capability ctor TypeError
then with constructor 1 TypeError
then with species non-ctor TypeError
2 | no | 1 | [1,2,3] | first | ["rejected","fulfilled"] | any | 10 | adopted"#;

const POISONED: &str = r#"var p = Promise.resolve("foo");
Object.defineProperty(p, "constructor", { get: function () { throw new RangeError("poison"); } });
try { p.then(function () {}, function () {}); console.log("no throw"); } catch (e) { console.log(e.constructor.name, e.message); }"#;

fn console(source: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine.eval(source).expect("the program runs");
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn promise_subclasses_behave_like_node() {
    let output = console(PROGRAM);
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT.lines().count());
}

#[test]
fn then_propagates_a_throwing_constructor_getter() {
    assert_eq!(console(POISONED), "RangeError poison");
}

/// bd-9vouw.282: NewPromiseCapability accepts any constructor (a
/// NotPromise that calls the executor itself and returns an object); the
/// GetCapabilitiesExecutor (length 2, name "", no constructor) rejects a
/// second call once resolve or reject is set and non-callable functions;
/// a non-object this is a TypeError for every static; Promise.all,
/// allSettled and any call C.resolve and each element's then, with
/// once-only element functions (length 1, name "", no constructor);
/// withResolvers and then honor a custom capability. Asynchronous results
/// are printed sorted after a 20-step chain. Expected lines: Node v22.2.0's
/// output, captured programmatically (Bun 1.4.2 agrees).
#[test]
fn promise_capabilities_of_any_constructor_bd_9vouw_282() {
    let source = r#"var out = {};
function k(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var executorFn;
function NotPromise(executor) { executorFn = executor; executor(function (v) { out.np_resolved = String(v); }, function (r) { out.np_rejected = String(r); }); }
var r1 = Promise.resolve.call(NotPromise, 5);
console.log(r1 instanceof NotPromise, typeof executorFn, executorFn.length, JSON.stringify(executorFn.name), Object.isExtensible(executorFn), executorFn.hasOwnProperty('prototype'), k(function () { return new executorFn(function () {}, function () {}); }));
console.log(k(function () { return Promise.resolve.call(function (ex) { ex(undefined, undefined); ex(function () {}, function () {}); }, 1) instanceof Object; }), k(function () { Promise.resolve.call(function (ex) { ex(function () {}, undefined); ex(function () {}, function () {}); }, 1); }), k(function () { Promise.reject.call(function (ex) { ex(1, 2); }, 1); }));
console.log(['all', 'allSettled', 'any', 'race', 'reject', 'resolve', 'withResolvers'].map(function (n) { return k(function () { return Promise[n].call(undefined, []); }); }).join());
var elements = [];
function C(executor) { executor(function (v) { out.all_values = JSON.stringify(v); }, function (r) { out.all_rejected = String(r); }); }
C.resolve = function (v) { return { then: function (f, r) { elements.push(f); } }; };
Promise.all.call(C, [1, 2]);
console.log(elements.length, elements[0].length, JSON.stringify(elements[0].name), elements[0] !== elements[1], k(function () { return new elements[0](); }), elements[0].hasOwnProperty('prototype'));
elements[1]('b'); elements[0]('a'); elements[0]('again');
var resolveCalls = 0;
var orig = Promise.resolve;
Promise.resolve = function (v) { resolveCalls++; return orig.call(this, v); };
Promise.all([1, 2, 3]).then(function (v) { out.patched = v.join() + ':' + resolveCalls; });
Promise.resolve = orig;
var settled = [];
function S(executor) { executor(function (v) { out.settled = JSON.stringify(v); }, function () {}); }
S.resolve = function (v) { return { then: function (f, r) { settled.push([f, r]); } }; };
Promise.allSettled.call(S, [1, 2]);
settled[0][0]('x'); settled[1][1]('y'); settled[0][1]('ignored');
var anyRejects = [];
function A(executor) { executor(function () {}, function (e) { out.any = e.constructor.name + ':' + JSON.stringify(e.errors); }); }
A.resolve = function (v) { return { then: function (f, r) { anyRejects.push(r); } }; };
Promise.any.call(A, [1, 2]);
anyRejects[1]('e2'); anyRejects[0]('e1');
var wr = Promise.withResolvers.call(NotPromise);
console.log(wr.promise instanceof NotPromise, typeof wr.resolve, typeof wr.reject);
function Spec(executor) { executor(function (v) { out.species = 'resolved:' + v; }, function (r) { out.species = 'rejected:' + r; }); }
var p = Promise.resolve(41);
p.constructor = { [Symbol.species]: Spec };
var t = p.then(function (v) { return v + 1; });
console.log(t instanceof Spec);
var last = Promise.resolve();
for (var i = 0; i < 20; i++) last = last.then(function () {});
last.then(function () { console.log(Object.keys(out).sort().map(function (key) { return key + '=' + out[key]; }).join(' ')); });
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
            "true function 2 \"\" true false TypeError",
            "true TypeError TypeError",
            "TypeError,TypeError,TypeError,TypeError,TypeError,TypeError,TypeError",
            "2 1 \"\" true TypeError false",
            "true function function",
            "true",
            "all_values=[\"a\",\"b\"] any=AggregateError:[\"e1\",\"e2\"] np_resolved=5 patched=1,2,3:3 settled=[{\"status\":\"fulfilled\",\"value\":\"x\"},{\"status\":\"rejected\",\"reason\":\"y\"}] species=resolved:42",
        ]
    );
}
