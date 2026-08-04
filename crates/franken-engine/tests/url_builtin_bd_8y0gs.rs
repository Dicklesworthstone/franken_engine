//! bd-8y0gs: authenticated WHATWG URL and URLSearchParams pure-compute globals.
//!
//! These probes pin the exact `franken_node` compatibility-corpus floor slice
//! against Node 20.19.4 / Bun 1.3.14 while also preserving fail-closed lowering:
//! only unshadowed direct construction is intercepted, and engine-owned side
//! tables—not guest-writable tag properties—carry the URL brands and state.

use frankenengine_engine::HybridRouter;

fn eval_console(src: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(src)
        .unwrap_or_else(|error| panic!("eval failed for {src:?}: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn eval_err(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(outcome) => panic!("expected eval error for {src:?}, got {outcome:?}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn absolute_url_getters_normalize_like_node() {
    let src = r#"
        const u = new URL('http://example.com:8080/path/to/page');
        console.log(u.protocol, u.hostname, u.port, u.pathname);
        console.log(new URL('HTTP://EXAMPLE.COM').href);
        console.log(new URL('http://Example.Com/Mixed/Case').href);
        const a = new URL('http://example.com:80/x');
        const b = new URL('https://example.com:443/x');
        console.log(JSON.stringify(a.port), a.host);
        console.log(JSON.stringify(b.port), b.host);
        const c = new URL('https://example.com:8443/x');
        console.log(c.port, c.host, c.hostname);
        const idna = new URL('http://münchen.de/straße');
        console.log(idna.hostname, idna.pathname);
    "#;
    assert_eq!(
        eval_console(src),
        "http: example.com 8080 /path/to/page\nhttp://example.com/\nhttp://example.com/Mixed/Case\n\"\" example.com\n\"\" example.com\n8443 example.com:8443 example.com\nxn--mnchen-3ya.de /stra%C3%9Fe"
    );
}

#[test]
fn url_credentials_origin_search_hash_and_path_encoding_match_node() {
    let src = r#"
        console.log(new URL('https://user:pw@sub.example.com:8443/p?q=1#h').origin);
        console.log(new URL('http://example.com/a/b').origin);
        const u = new URL('https://alice:s3cret@example.com/');
        console.log(u.username, u.password);
        console.log(u.href);
        const q = new URL('http://example.com/p?a=1&b=2#sec-2');
        console.log(q.search, q.hash);
        const empty = new URL('http://example.com/p');
        console.log(JSON.stringify(empty.search), JSON.stringify(empty.hash));
        console.log(new URL('http://example.com/a b/c d').pathname);
        console.log(new URL('http://example.com/café').pathname);
    "#;
    assert_eq!(
        eval_console(src),
        "https://sub.example.com:8443\nhttp://example.com\nalice s3cret\nhttps://alice:s3cret@example.com/\n?a=1&b=2 #sec-2\n\"\" \"\"\n/a%20b/c%20d\n/caf%C3%A9"
    );
}

#[test]
fn url_base_resolution_clamps_roots_and_setters_refresh_href() {
    let src = r#"
        console.log(new URL('/one/two', 'http://example.com/a/b?q#f').href);
        console.log(new URL('three', 'http://example.com/a/b').href);
        console.log(new URL('?x=1', 'http://example.com/a/b').href);
        console.log(new URL('../x', 'http://example.com/a/b/c').pathname);
        console.log(new URL('../../y', 'http://example.com/a/b/c').pathname);
        console.log(new URL('../../../../z', 'http://example.com/a/b/c').pathname);
        const u = new URL('http://example.com/a');
        u.pathname = '/b c';
        u.hash = 'frag';
        console.log(u.href);
        u.hash = '';
        console.log(u.href);
    "#;
    assert_eq!(
        eval_console(src),
        "http://example.com/one/two\nhttp://example.com/a/three\nhttp://example.com/a/b?x=1\n/a/x\n/y\n/z\nhttp://example.com/b%20c#frag\nhttp://example.com/b%20c"
    );
}

#[test]
fn empty_delimiters_and_single_prefix_setter_rules_match_node() {
    let src = r#"
        const query = new URL('http://example.com/?');
        const hash = new URL('http://example.com/#');
        console.log(JSON.stringify(query.search), query.href);
        console.log(JSON.stringify(hash.hash), hash.href);
        const u = new URL('http://example.com/');
        u.hash = '##x';
        console.log(u.hash, u.href);
    "#;
    assert_eq!(
        eval_console(src),
        "\"\" http://example.com/?\n\"\" http://example.com/#\n##x http://example.com/##x"
    );
}

#[test]
fn linked_search_params_reads_and_mutations_preserve_order() {
    let src = r#"
        const u = new URL('http://example.com/?a=1&b=two&a=3');
        console.log(u.searchParams.get('a'), u.searchParams.get('b'));
        console.log(u.searchParams.has('a'), u.searchParams.has('zz'), u.searchParams.get('zz') === null);
        const p = new URL('http://example.com/?t=1&t=2&t=3').searchParams;
        console.log(p.getAll('t').join(','), p.getAll('none').length);
        u.searchParams.append('a', '4');
        u.searchParams.set('b', 'changed');
        console.log(u.search, u.href);
    "#;
    assert_eq!(
        eval_console(src),
        "1 two\ntrue false true\n1,2,3 0\n?a=1&b=changed&a=3&a=4 http://example.com/?a=1&b=changed&a=3&a=4"
    );
}

#[test]
fn standalone_search_params_mutations_match_node() {
    let src = r#"
        const a = new URLSearchParams('a=1');
        a.append('a', '2');
        a.append('b', '3');
        console.log(a.toString());
        const s = new URLSearchParams('c=3&a=1&b=2&a=0');
        s.sort();
        console.log(s.toString());
        const d = new URLSearchParams('a=1&b=2&a=3');
        d.delete('a');
        console.log(d.toString(), d.has('a'), d.has('b'));
        const p = new URLSearchParams('a=1&b=3&a=2');
        p.set('a', '9');
        console.log(p.toString());
        p.set('c', 'new');
        console.log(p.toString());
    "#;
    assert_eq!(
        eval_console(src),
        "a=1&a=2&b=3\na=1&a=0&b=2&c=3\nb=2 false true\na=9&b=3\na=9&b=3&c=new"
    );
}

#[test]
fn search_params_form_encoding_matches_node() {
    let src = r#"
        const p = new URLSearchParams('a=b+c&d=%2B&e=x%20y');
        console.log(p.get('a'), p.get('d'), p.get('e'));
        const q = new URLSearchParams();
        q.append('q', 'a b&c=d');
        q.append('u', '中');
        console.log(q.toString());
    "#;
    assert_eq!(eval_console(src), "b c + x y\nq=a+b%26c%3Dd&u=%E4%B8%AD");
}

#[test]
fn search_params_strip_one_leading_question_mark() {
    let src = r#"
        const p = new URLSearchParams('?a=1');
        console.log(p.get('a'), p.get('?a') === null, p.toString());
    "#;
    assert_eq!(eval_console(src), "1 true a=1");
}

#[test]
fn special_url_backslashes_and_invalid_url_errors_match_node() {
    let src = r#"
        const u = new URL('http://example.com\\foo\\bar');
        console.log(u.pathname);
        console.log(u.href);
        try {
          new URL('not a url');
          console.log('no-throw');
        } catch (e) {
          console.log(e instanceof TypeError, e.code);
        }
        try {
          new URL('/path/only');
          console.log('no-throw');
        } catch (e) {
          console.log(e instanceof TypeError);
        }
    "#;
    assert_eq!(
        eval_console(src),
        "/foo/bar\nhttp://example.com/foo/bar\ntrue ERR_INVALID_URL\ntrue"
    );
}

#[test]
fn constructor_lowering_is_shadow_aware_and_aliases_fail_closed() {
    let src = r#"
        class URL { constructor(value) { this.value = value; } }
        class URLSearchParams { constructor(value) { this.value = value; } }
        console.log(new URL('local').value, new URLSearchParams('params').value);
    "#;
    assert_eq!(eval_console(src), "local params");

    let error = eval_err("const Constructor = URL; new Constructor('http://example.com')");
    assert!(
        error.contains("undefined") || error.contains("function"),
        "unexpected alias failure: {error}"
    );

    assert_eq!(
        eval_console(
            "const fake = { __type: 'URLSearchParams' }; console.log(typeof fake.get, typeof fake.append)"
        ),
        "undefined undefined"
    );
}
