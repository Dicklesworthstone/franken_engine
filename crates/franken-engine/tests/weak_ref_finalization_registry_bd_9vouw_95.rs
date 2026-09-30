#![forbid(unsafe_code)]
//! bd-9vouw.95: ES2021 WeakRef and FinalizationRegistry were not defined
//! ("WeakRef is not defined"). A WeakRef holds its target strongly and
//! `deref()` always returns it; a FinalizationRegistry never runs its
//! cleanup callback. Both are conformant (when an object is collected is not
//! observable) and keep replay deterministic. Expected strings are Node
//! v22.2.0's completion values for the same programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn check(source: &str, node: &str) {
    let value = match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    };
    assert_eq!(value, node, "`{source}` must match Node v22.2.0");
}

#[test]
fn weak_ref_derefs_its_target() {
    check(
        "var o = {a: 1}; var w = new WeakRef(o); var f = new WeakRef(function () { return 7; }); \
         [w.deref() === o, w.deref().a, f.deref()(), w instanceof WeakRef, \
         Object.prototype.toString.call(w), Object.keys(w).length, \
         String(new WeakRef(Symbol('s')).deref())].join()",
        "true,1,7,true,[object WeakRef],0,Symbol(s)",
    );
    check(
        "[typeof WeakRef, WeakRef.name, WeakRef.length, WeakRef.prototype.deref.length, \
         WeakRef.prototype.deref === new WeakRef({}).deref].join()",
        "function,WeakRef,1,0,true",
    );
}

#[test]
fn finalization_registry_tracks_unregister_tokens() {
    check(
        "var r = new FinalizationRegistry(() => {}); var t = {}; \
         [String(r.register({}, 'held', t)), r.register({}, 2, t), r.unregister(t), r.unregister(t), \
         r.unregister({}), String(r.register(Symbol('s'), 1)), \
         Object.prototype.toString.call(r), r instanceof FinalizationRegistry].join()",
        "undefined,,true,false,false,undefined,[object FinalizationRegistry],true",
    );
    check(
        "[typeof FinalizationRegistry, FinalizationRegistry.length, \
         FinalizationRegistry.prototype.register.length, \
         FinalizationRegistry.prototype.unregister.length].join()",
        "function,1,2,1",
    );
}

#[test]
fn invalid_targets_and_calls_are_type_errors() {
    check(
        "var o = {}; var r = []; for (const bad of [() => new WeakRef(1), () => WeakRef({}), \
         () => new WeakRef(Symbol.for('x')), () => new FinalizationRegistry(1), \
         () => new FinalizationRegistry(() => {}).register(1), \
         () => new FinalizationRegistry(() => {}).register(o, o), \
         () => new FinalizationRegistry(() => {}).register({}, 1, 2), \
         () => new FinalizationRegistry(() => {}).unregister(1), \
         () => WeakRef.prototype.deref.call({})]) { \
         try { bad(); r.push('none'); } catch (e) { r.push(e.constructor.name); } } r.join()",
        "TypeError,TypeError,TypeError,TypeError,TypeError,TypeError,TypeError,TypeError,TypeError",
    );
}
