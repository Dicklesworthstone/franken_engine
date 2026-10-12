//! bd-9vouw.501: `f.apply(t, list)`, `Reflect.apply(f, t, list)` and the
//! spread call `f(...list)` run `f` as an ordinary frame of the calling run
//! loop when building the argument list is unobservable and unlabelled,
//! instead of an isolated activation in a nested run loop. The program runs
//! the direct cases (receiver and strict `this`, rest and default
//! parameters, `arguments`, a 300-element list past the register frame,
//! exceptions, a class constructor, a list the callee mutates) next to the
//! ones that keep the isolated call (holes, an element getter, an
//! array-like object, a Proxy and its trap order, a bound function, a
//! generator, a builtin target, an inherited element), and recursions 2,000
//! deep through each form: the nested run loops capped those at 256 ("call
//! stack overflow: depth 257 exceeds max 256" on the n69 frankenctl, which
//! prints the rest of the line). Node v22.2.0 prints the line.

use frankenengine_engine::HybridRouter;

fn console_lines(source: &str) -> Vec<String> {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect()
}

#[test]
fn apply_spread_and_reflect_apply_match_node() {
    let source = r#"const out = [];
function who(a, b) { 'use strict'; return [this === undefined ? 'u' : this.tag, a, b, arguments.length].join(':'); }
function sum(...xs) { return xs.reduce((a, b) => a + b, 0); }
function d(a, b = 7) { return a + b; }
function args() { return arguments.length + ':' + Array.prototype.join.call(arguments, '|'); }
function j(...xs) { return xs.join(','); }
function many() { return arguments.length + ':' + arguments[299]; }
function thrower(x) { throw new Error('t' + x); }
class K {}
function* g(a) { yield a; }
out.push(who.apply({ tag: 'T' }, [1, 2]), who.apply(undefined, [1]), Reflect.apply(who, { tag: 'R' }, [3, 4]));
out.push(sum.apply(null, [1, 2, 3, 4]), sum(...[5, 6]), Reflect.apply(sum, null, []), d.apply(null, [1]));
out.push(args.apply(null, [1, 'x', null]), args(...['s', 2]), args.apply(null), args.apply(null, null));
const big = Array.from({ length: 300 }, (_, i) => i);
out.push(sum.apply(null, big), many.apply(null, big), many(...big), Reflect.apply(many, null, big));
out.push(j.apply(null, [1, , 3]), j(...[1, , 3]));
const withGetter = [1, 2];
Object.defineProperty(withGetter, 1, { get() { out.push('get'); return 20; } });
out.push(j.apply(null, withGetter));
out.push(j.apply(null, { length: 2, 0: 'a', 1: 'b' }));
const traps = [];
out.push(j.apply(null, new Proxy([1, 2], { get(t, k) { traps.push(String(k)); return Reflect.get(t, k); } })), traps.join('|'));
out.push(j(...new Set([3, 4])), j(...'ab'), Math.max(...[1, 5, 3]), Math.max.apply(null, [2, 9]));
for (const call of [() => thrower.apply(null, [1]), () => thrower(...[2]), () => Reflect.apply(thrower, null, [3])]) {
  try { call(); } catch (e) { out.push(e.message); }
}
try { K.apply(null, []); } catch (e) { out.push(e.constructor.name); }
const bound = j.bind(null, 'b');
out.push(bound.apply(null, [1]), bound(...[2]), g.apply(null, [5]).next().value);
const lst = [1, 2];
function mut(a, b) { lst.push(9); return a + b + ':' + arguments.length; }
out.push(mut.apply(null, lst), lst.length);
function depth1(n) { return n === 0 ? 0 : 1 + depth1.apply(null, [n - 1]); }
function depth2(n) { return n === 0 ? 0 : 1 + depth2(...[n - 1]); }
function depth3(n) { return n === 0 ? 0 : 1 + Reflect.apply(depth3, null, [n - 1]); }
out.push(depth1(2000), depth2(2000), depth3(2000));
Array.prototype[1] = 'P';
out.push(j.apply(null, [1, , 3]), j(...[1, , 3]));
delete Array.prototype[1];
console.log(out.join(' '));"#;
    assert_eq!(
        console_lines(source),
        vec![
            "T:1:2:2 u:1::1 R:3:4:2 10 11 0 8 3:1|x| 2:s|2 0: 0: 44850 300:299 300:299 300:299 1,,3 1,,3 get 1,20 a,b 1,2 length|0|1 3,4 a,b 5 9 t1 t2 t3 TypeError b,1 b,2 5 3:2 3 2000 2000 2000 1,P,3 1,P,3"
        ]
    );
}
