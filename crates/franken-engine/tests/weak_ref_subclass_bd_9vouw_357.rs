//! bd-9vouw.357: a class extending WeakRef or FinalizationRegistry
//! constructs its parent from super() (ES2021 26.1.1.1, 26.2.1.1 with
//! NewTarget the subclass), as Map and Set already did; so does
//! Reflect.construct with a subclass newTarget. super() threw "Constructor
//! WeakRef requires 'new'": construct_builtin_with_new_target sent both to
//! the call path. A plain call and a non-object target still throw. The
//! line is Node v22.2.0's (Bun 1.4.2 agrees).

use frankenengine_engine::HybridRouter;

#[test]
fn weak_ref_and_finalization_registry_subclass() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + ':' + JSON.stringify(f())); } catch (e) { out.push(name + ':' + e.constructor.name); } }
class W extends WeakRef { constructor(o) { super(o); this.tag = 'w'; } hi() { return 'hi'; } }
var target = {};
t('weakref-sub', function () { var w = new W(target); return [w instanceof W, w instanceof WeakRef, w.deref() === target, w.tag, w.hi(), Object.getPrototypeOf(w) === W.prototype, Object.prototype.toString.call(w)]; });
class F extends FinalizationRegistry { constructor() { super(function () {}); this.k = 1; } }
t('fr-sub', function () { var f = new F(); return [f instanceof F, f instanceof FinalizationRegistry, f.k, typeof f.register, f.unregister({})]; });
t('weakref-reflect', function () { var w = Reflect.construct(WeakRef, [target], W); return [w instanceof W, w.deref() === target]; });
t('weakref-bad', function () { return new W(1); });
t('weakref-call', function () { return WeakRef(target); });
console.log(out.join(' '));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "weakref-sub:[true,true,true,\"w\",\"hi\",true,\"[object WeakRef]\"] fr-sub:[true,true,1,\"function\",false] weakref-reflect:[true,true] weakref-bad:TypeError weakref-call:TypeError"
        ]
    );
}
