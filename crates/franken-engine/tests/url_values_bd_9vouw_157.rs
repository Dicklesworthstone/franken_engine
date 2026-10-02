//! bd-9vouw.157: `URL` and `URLSearchParams` are global constructor values.
//!
//! Both existed only as lowering's rewrite of `new URL(...)` (bd-8y0gs kept
//! them lowering-only on purpose), so a bare reference threw "URL is not
//! defined": superjson's `value instanceof URL`, aliases and subclasses
//! failed. They are now standard constructors that build the same
//! engine-owned objects, instances inherit from URL.prototype /
//! URLSearchParams.prototype, and both prototypes carry Node's
//! @@toStringTag. Expected strings are Node v22.2.0's output for the same
//! programs.
//!
//! URL.prototype.toString and toJSON (the href) are added, so `String(url)`
//! and `JSON.stringify` no longer give "[object Object]" and `{}`.
//!
//! No-claim: `URL(...)` without `new` constructs instead of throwing a
//! TypeError; URL.prototype has no accessors of its own (instances answer
//! href, host, ...), and URLSearchParams.prototype no methods (instances
//! answer them); URL.createObjectURL and revokeObjectURL are not covered.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// `URL` and `URLSearchParams` are values: typeof, name, length, the global object's properties.
#[test]
fn url_global_values() {
    let source = "[typeof URL, typeof URLSearchParams, URL.name, URL.length, URLSearchParams.name, URLSearchParams.length,\n\
          globalThis.URL === URL, globalThis.URLSearchParams === URLSearchParams].join(' ');";
    assert_eq!(
        eval(source),
        "function function URL 1 URLSearchParams 0 true true"
    );
}

/// An alias constructs the same objects, which inherit from URL.prototype and carry its tag.
#[test]
fn url_instances_and_aliases() {
    let source = "const U = URL, P = URLSearchParams;\n\
         const u = new U('http://a.example:8080/p/q?x=1&y=2#h');\n\
         const p = new P({ a: '1', b: 'two words' });\n\
         [u.host, u.pathname, u.searchParams.get('y'), u.hash, u instanceof URL, u.searchParams instanceof URLSearchParams,\n\
          Object.getPrototypeOf(u) === URL.prototype, u.constructor === URL, Object.prototype.toString.call(u),\n\
          Object.prototype.toString.call(p), p.toString(), p instanceof URLSearchParams, new URL('http://x') instanceof URL].join(' ');";
    assert_eq!(
        eval(source),
        "a.example:8080 /p/q 2 #h true true true true [object URL] [object URLSearchParams] a=1&b=two+words true true"
    );
}

/// superjson-style `instanceof URL` checks and destructuring from globalThis.
#[test]
fn url_type_checks() {
    let source = "const { URL: GlobalURL } = globalThis;\n\
         function isURL(value) { return value instanceof URL; }\n\
         [isURL(new GlobalURL('https://b.example/')), isURL({ href: 'https://b.example/' }), isURL('https://b.example/'),\n\
          new URL('../c', 'https://b.example/a/b').href, String(new URL('https://b.example/?q=1')),\n\
          JSON.stringify({ u: new URL('https://b.example/x') })].join(' ');";
    assert_eq!(
        eval(source),
        "true false false https://b.example/c https://b.example/?q=1 {\"u\":\"https://b.example/x\"}"
    );
}

/// URL.canParse and URL.parse: whether the constructor would succeed, and the URL or null.
#[test]
fn url_statics() {
    let source = "[URL.canParse('https://a.example/'), URL.canParse('/x'), URL.canParse('/x', 'https://a.example/c'), URL.parse('nope'),\n\
          URL.parse('/p?q=1', 'https://a.example').href, URL.parse('https://a.example/') instanceof URL, URL.canParse.length,\n\
          URL.parse.name, typeof URL.canParse, URL.canParse({ toString() { return 'https://x.example'; } })].join(' ');";
    assert_eq!(
        eval(source),
        "true false true  https://a.example/p?q=1 true 1 parse function true"
    );
}

/// A subclass keeps the URL state and adds its own members.
#[test]
fn url_subclass() {
    let source = "class Tagged extends URL { get tag() { return 'tagged:' + this.hostname; } }\n\
         const t = new Tagged('https://sub.example/path');\n\
         [t.tag, t.pathname, t instanceof Tagged, t instanceof URL, Object.getPrototypeOf(Tagged.prototype) === URL.prototype].join(' ');";
    assert_eq!(eval(source), "tagged:sub.example /path true true true");
}
