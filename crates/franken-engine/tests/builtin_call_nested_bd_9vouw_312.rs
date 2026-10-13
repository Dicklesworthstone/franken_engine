//! bd-9vouw.312: a builtin reached through `fn.call(...)`, `fn.apply(...)`,
//! `Reflect.apply` or a bound function runs on the live stack (the nested
//! callback path) instead of snapshotting and restoring the whole module
//! execution. The program pins what that path must keep: results, a
//! builtin's throw caught by the caller's try, Error.call, a guest callback
//! inside a builtin inside a bound call, a generator resumed through a
//! detached next, and 50 nested Function.prototype.call.call frames. Node
//! v22.2.0 gives this value; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn builtins_called_through_call_apply_and_bind_keep_their_behaviour() {
    let source = r#"
var out = [];
var o = { a: 1 };
var hp = Object.prototype.hasOwnProperty;
var hasOwn = Function.call.bind(hp);
out.push(hp.call(o, 'a'), hasOwn(o, 'b'), hp.apply(o, ['a']), Reflect.apply(hp, o, ['a']));
out.push(Array.prototype.map.call([1, 2], function (x) { return x * 3; }).join('+'));
var slice = Function.prototype.call.bind(Array.prototype.slice);
out.push(slice({ length: 2, 0: 'p', 1: 'q' }).join(''));
try { JSON.parse.call(null, '{'); out.push('no'); } catch (e) { out.push(e.name); }
var parse = JSON.parse.bind(JSON);
try { parse('['); out.push('no'); } catch (e) { out.push(e.name); }
function Custom(message) { var e = Error.call(this, message); this.message = e.message; }
out.push(new Custom('m').message);
var join = Function.prototype.call.bind(Array.prototype.join);
out.push(join([[1, 2], [3]], '|'));
var forEach = Function.prototype.call.bind(Array.prototype.forEach);
var seen = []; forEach([5, 6], function (v, i) { seen.push(i + ':' + v + ':' + hasOwn(o, 'a')); });
out.push(seen.join(','));
function* g() { var x = yield 1; yield x * 2; }
var it = g(); var next = it.next;
out.push(next.call(it).value, next.call(it, 21).value, next.call(it).done);
var depth = 0;
function recurse(n) { depth = n; return n === 0 ? 0 : hp.call.call(recurse, null, n - 1); }
recurse(50); out.push(depth);
out.push(String.prototype.toUpperCase.call('ab'), Math.max.apply(null, [3, 9, 4]));
out.join(' ');
"#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "true false true true 3+6 pq SyntaxError SyntaxError m 1,2|3 0:5:true,1:6:true 1 42 true 0 AB 9"
    );
}
