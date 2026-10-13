//! bd-9vouw.347: Object.getOwnPropertyDescriptors applies ToObject and
//! reads [[OwnPropertyKeys]] and each key's [[GetOwnProperty]] (ES2020
//! 19.1.2.9), so a Proxy's ownKeys and getOwnPropertyDescriptor traps run
//! in key order and the `Object.create(proto,
//! Object.getOwnPropertyDescriptors(p))` clone keeps a proxied object's
//! properties; it gave {} for a Proxy and refused primitives. Object.entries
//! and Object.values of a Proxy read each key's descriptor and then its
//! value before the next key (7.3.22); they read every descriptor first.
//! Node v22.2.0 gives this line.

use frankenengine_engine::HybridRouter;

#[test]
fn own_property_descriptors_and_entries_follow_proxy_traps() {
    let source = r#"
var out = [];
var log = [];
var target = { a: 1, b: 2 };
Object.defineProperty(target, 'h', { value: 3, enumerable: false });
var proxy = new Proxy(target, {
  ownKeys: function (t) { log.push('ownKeys'); return Reflect.ownKeys(t); },
  getOwnPropertyDescriptor: function (t, k) { log.push('gopd:' + String(k)); return Reflect.getOwnPropertyDescriptor(t, k); },
  get: function (t, k, r) { log.push('get:' + String(k)); return Reflect.get(t, k, r); }
});
var descs = Object.getOwnPropertyDescriptors(proxy);
out.push(log.join('|'), Object.keys(descs).join(','), descs.h.enumerable);
log.length = 0;
out.push(JSON.stringify(Object.entries(proxy)), log.join('|'));
log.length = 0;
out.push(JSON.stringify(Object.values(proxy)), log.join('|'));
out.push(JSON.stringify(Object.getOwnPropertyDescriptors(true)), JSON.stringify(Object.getOwnPropertyDescriptors(3)));
var sd = Object.getOwnPropertyDescriptors('ab');
out.push(Object.keys(sd).join(','), sd[0].value, sd[0].writable, sd.length.value, sd.length.enumerable);
out.push(Object.getOwnPropertySymbols(Object.getOwnPropertyDescriptors(Symbol('s'))).length);
try { Object.getOwnPropertyDescriptors(null); out.push('no'); } catch (e) { out.push(e.constructor.name); }
var clone = Object.create(Object.getPrototypeOf(proxy), Object.getOwnPropertyDescriptors(proxy));
out.push(clone.a + clone.b + clone.h);
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
            "ownKeys|gopd:a|gopd:b|gopd:h a,b,h false [[\"a\",1],[\"b\",2]] \
             ownKeys|gopd:a|get:a|gopd:b|get:b|gopd:h [1,2] \
             ownKeys|gopd:a|get:a|gopd:b|get:b|gopd:h {} {} 0,1,length a false 2 false 0 TypeError 6"
        ]
    );
}
