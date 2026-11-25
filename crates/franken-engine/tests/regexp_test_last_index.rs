//! ES2020 21.2.5.13: RegExp.prototype.test is `RegExpExec(R, S) !== null`, so
//! a global or sticky regex reads and advances `lastIndex` exactly like
//! `exec`. FrankenEngine's test ignored `lastIndex` and the flags: a /g regex
//! answered true forever (`while (re.test(s)) n++` never ended) and a sticky
//! regex matched anywhere. The original state cases use Node v22.2.0 output.

use frankenengine_engine::HybridRouter;

fn check_both_profiles(source: &str, expected: &str) {
    use frankenengine_engine::{JsEngine, QuickJsInspiredNativeEngine, V8InspiredNativeEngine};

    for engine in [
        &mut QuickJsInspiredNativeEngine as &mut dyn JsEngine,
        &mut V8InspiredNativeEngine as &mut dyn JsEngine,
    ] {
        let outcome = engine
            .eval(source)
            .unwrap_or_else(|error| panic!("{:?}: {error}\n{source}", engine.kind()));
        assert_eq!(outcome.value, expected, "{:?}: {source}", engine.kind());
    }
}

/// RegExpBuiltinExec performs ToLength(lastIndex) even for non-global
/// expressions. Primitive Symbol/BigInt must not silently become zero.
#[test]
fn last_index_rejects_symbol_and_bigint_before_matching() {
    check_both_profiles(
        r#"
        const out = [];
        for (const value of [Symbol('index'), 1n]) {
            for (const flags of ['', 'g', 'y', 'gy']) {
                for (const method of ['exec', 'test']) {
                    const re = new RegExp('a', flags);
                    re.lastIndex = value;
                    try { re[method]('a'); out.push('missed'); }
                    catch (error) { out.push(error.name + ':' + (re.lastIndex === value)); }
                }
            }
        }
        out.join(',');
        "#,
        &["TypeError:true"; 16].join(","),
    );
}

/// Receiver validation precedes both subject conversion and reading or
/// converting lastIndex. An invalid receiver must never run its hooks.
#[test]
fn exec_rejects_incompatible_receivers_without_conversion_hooks() {
    check_both_profiles(
        r#"
        const log = [];
        const index = { valueOf() { log.push('index'); throw 'wrong'; } };
        const input = { toString() { log.push('input'); throw 'wrong'; } };
        const receiver = { lastIndex: index };
        const proxy = new Proxy(/a/, {
            get(target, key) { log.push(String(key)); return Reflect.get(target, key); }
        });
        const out = [];
        for (const value of [receiver, proxy, {}, 1, null]) {
            try { RegExp.prototype.exec.call(value, input); out.push('missed'); }
            catch (error) { out.push(error.name); }
        }
        out.push(log.length);
        out.join(',');
        "#,
        "TypeError,TypeError,TypeError,TypeError,TypeError,0",
    );
}

/// Subject conversion comes first, lastIndex converts once with number
/// hint, and non-global expressions retain the original property value.
#[test]
fn exec_coercion_order_and_non_global_state_are_observable() {
    check_both_profiles(
        r#"
        const out = [];
        for (const flags of ['', 'g', 'y']) {
            const log = [];
            const re = new RegExp('a', flags);
            const index = { [Symbol.toPrimitive](hint) { log.push(hint); return '1'; } };
            re.lastIndex = Symbol('replaced by input conversion');
            const input = { toString() { log.push('input'); re.lastIndex = index; return 'ba'; } };
            const match = re.exec(input);
            out.push(match.index + ':' + log.join('/') + ':' + (flags ? re.lastIndex : re.lastIndex === index));
        }
        out.join(',');
        "#,
        "1:input/number:true,1:input/number:2,1:input/number:2",
    );
}

/// Non-global symbol methods reach RegExpBuiltinExec too. Search resets
/// lastIndex before executing and restores it; global match resets it.
#[test]
fn regexp_symbol_methods_share_last_index_conversion_and_reset_order() {
    check_both_profiles(
        r#"
        const out = [];
        for (const method of [Symbol.match, Symbol.replace]) {
            const re = /a/;
            re.lastIndex = 1n;
            try { re[method]('a', 'x'); out.push('missed'); }
            catch (error) { out.push(error.name + ':' + (re.lastIndex === 1n)); }
        }
        const searched = /a/;
        const original = Symbol('saved');
        searched.lastIndex = original;
        out.push('a'.search(searched), searched.lastIndex === original);
        const global = /a/g;
        global.lastIndex = 1n;
        out.push('a'.match(global)[0], global.lastIndex);
        out.join(',');
        "#,
        "TypeError:true,TypeError:true,0,true,a,0",
    );
}

/// RegExpExec calls a supplied exec method without applying the builtin's
/// lastIndex conversion to that receiver.
#[test]
fn custom_exec_keeps_control_of_its_last_index() {
    check_both_profiles(
        r#"
        const calls = [];
        const receiver = {
            lastIndex: Symbol('opaque'),
            exec(input) { calls.push(input); return { 0: 'a', index: 0, length: 1 }; }
        };
        const matched = RegExp.prototype.test.call(receiver, 'a');
        const re = /a/;
        re.lastIndex = 1n;
        re.exec = receiver.exec;
        [matched, re.test('b'), re.lastIndex === 1n, calls.join('/')].join(',');
        "#,
        "true,true,true,a/b",
    );
}

/// Subject conversion can invalidate a pristine RegExp before exec is read.
/// Both direct symbol calls and String methods must observe that mutation.
#[test]
fn match_observes_regexp_mutation_during_subject_conversion() {
    check_both_profiles(
        r#"
        const out = [];
        for (const viaString of [false, true]) {
            for (const index of [Symbol('index'), 1n]) {
                const re = /a/;
                let calls = 0;
                const input = { toString() { calls++; re.lastIndex = index; return 'a'; } };
                try {
                    if (viaString) String.prototype.match.call(input, re);
                    else re[Symbol.match](input);
                    out.push('missed');
                } catch (error) {
                    out.push(error.name + ':' + calls + ':' + (re.lastIndex === index));
                }
            }
            const re = /a/;
            const log = [];
            const input = {
                toString() {
                    log.push('subject');
                    re.exec = function (text) {
                        log.push('exec:' + (this === re) + ':' + text);
                        return ['custom'];
                    };
                    return 'a';
                }
            };
            const result = viaString ? String.prototype.match.call(input, re) : re[Symbol.match](input);
            out.push(result[0] + ':' + log.join('/'));
        }
        out.join(',');
        "#,
        "TypeError:1:true,TypeError:1:true,custom:subject/exec:true:a,TypeError:1:true,TypeError:1:true,custom:subject/exec:true:a",
    );
}

/// ToString(replaceValue) runs once before selecting exec. Its mutation can
/// require native lastIndex rejection or install a custom exec instead.
#[test]
fn replace_observes_replacement_conversion_before_selecting_exec() {
    check_both_profiles(
        r#"
        const out = [];
        for (const viaString of [false, true]) {
            for (const index of [Symbol('index'), 1n]) {
                const re = /a/;
                let calls = 0;
                const replacement = { toString() { calls++; re.lastIndex = index; return 'x'; } };
                try {
                    if (viaString) 'a'.replace(re, replacement);
                    else re[Symbol.replace]('a', replacement);
                    out.push('missed');
                } catch (error) {
                    out.push(error.name + ':' + calls + ':' + (re.lastIndex === index));
                }
            }
            const re = /a/;
            const log = [];
            const replacement = {
                toString() {
                    log.push('replacement');
                    re.lastIndex = 1n;
                    re.exec = function (text) {
                        log.push('exec:' + (this === re) + ':' + text);
                        return ['a'];
                    };
                    return 'x';
                }
            };
            const result = viaString ? 'a'.replace(re, replacement) : re[Symbol.replace]('a', replacement);
            out.push(result + ':' + (re.lastIndex === 1n) + ':' + log.join('/'));
        }
        out.join(',');
        "#,
        "TypeError:1:true,TypeError:1:true,x:true:replacement/exec:true:a,TypeError:1:true,TypeError:1:true,x:true:replacement/exec:true:a",
    );
}

/// Both split entry routes apply ToUint32 to their limit, observing hooks
/// and abrupt completions instead of approximating object/Symbol/BigInt as zero.
#[test]
fn regexp_split_limits_use_observable_numeric_conversion() {
    check_both_profiles(
        r#"
        const out = [];
        for (const viaString of [false, true]) {
            let calls = 0;
            const limit = { valueOf() { calls++; return 2; } };
            const result = viaString ? 'a,b,c'.split(/,/, limit) : /,/[Symbol.split]('a,b,c', limit);
            out.push(result.join(':') + ':' + calls);
            calls = 0;
            const throwing = { valueOf() { calls++; throw 'limit-stop'; } };
            try {
                if (viaString) 'a,b,c'.split(/,/, throwing);
                else /,/[Symbol.split]('a,b,c', throwing);
                out.push('missed');
            } catch (error) {
                out.push(String(error) + ':' + calls);
            }
            for (const invalid of [Symbol('limit'), 1n]) {
                try {
                    if (viaString) 'a,b,c'.split(/,/, invalid);
                    else /,/[Symbol.split]('a,b,c', invalid);
                    out.push('missed');
                } catch (error) {
                    out.push(error.name);
                }
            }
        }
        out.join(',');
        "#,
        "a:b:1,limit-stop:1,TypeError,TypeError,a:b:1,limit-stop:1,TypeError,TypeError",
    );
}

/// A lastIndex hook runs after exec selection, so replacing exec from that
/// hook affects later calls only. Subject conversion occurs before test selects exec.
#[test]
fn last_index_conversion_preserves_the_selected_exec() {
    check_both_profiles(
        r#"
        const out = [];
        for (const method of ['exec', 'test', 'match']) {
            const re = /a/y;
            const log = [];
            re.lastIndex = {
                valueOf() {
                    log.push('index');
                    re.exec = function () { log.push('override'); return null; };
                    return 0;
                }
            };
            const result = method === 'match' ? re[Symbol.match]('a') : RegExp.prototype[method].call(re, 'a');
            out.push((method === 'test' ? result : result[0]) + ':' + re.lastIndex + ':' + log.join('/'));
        }
        for (const method of ['exec', 'test']) {
            const re = /a/g;
            const log = [];
            const input = {
                toString() {
                    log.push('input');
                    re.exec = function () { log.push('override'); return null; };
                    return 'a';
                }
            };
            const result = RegExp.prototype[method].call(re, input);
            out.push((method === 'test' ? result : result[0]) + ':' + re.lastIndex + ':' + log.join('/'));
        }
        out.join(',');
        "#,
        "a:1:index,true:1:index,a:1:index,a:1:input,false:0:input/override",
    );
}

/// The search matcher may skip reset/restore only for writable lastIndex.
/// Read-only originals still work in operations that do not write to them.
#[test]
fn search_preserves_required_writes_to_read_only_last_index() {
    check_both_profiles(
        r#"
        const out = [];
        for (const viaString of [false, true]) {
            for (const flags of ['', 'g', 'y', 'gy']) {
                for (const start of [0, -0, 1]) {
                    const re = new RegExp('a', flags);
                    Object.defineProperty(re, 'lastIndex', { value: start, writable: false });
                    try {
                        const result = viaString ? 'a'.search(re) : re[Symbol.search]('a');
                        out.push(result + ':' + Object.is(re.lastIndex, start));
                    } catch (error) {
                        out.push(error.name + ':' + Object.is(re.lastIndex, start));
                    }
                }
            }
        }
        const plain = /a/;
        Object.defineProperty(plain, 'lastIndex', { value: 0, writable: false });
        out.push('a'.match(plain)[0], 'a'.replace(plain, 'x'), 'a'.search(plain));
        const copied = /,/g;
        Object.defineProperty(copied, 'lastIndex', { value: 1, writable: false });
        out.push('a,b'.split(copied).join(':'), Array.from('a,b'.matchAll(copied))[0].index, copied.lastIndex);
        out.join(',');
        "#,
        "0:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,0:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,TypeError:true,a,x,0,a:b,1,1",
    );
}

#[test]
fn global_and_sticky_test_advance_last_index() {
    let source = "const r = /a/g; const s = 'aXa'; \
                  const a = [r.test(s), r.lastIndex, r.test(s), r.lastIndex, r.test(s), r.lastIndex];\n\
                  const y = /a/y; y.lastIndex = 1; a.push(y.test('ba'), y.lastIndex, y.test('ba'), y.lastIndex);\n\
                  const re = /o/g; let n = 0; while (re.test('foo boo')) n++; a.push(n);\n\
                  const plain = /a/; a.push(plain.test('bab'), plain.lastIndex);\n\
                  a.join(',');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(value, "true,1,true,3,false,0,true,2,false,0,4,true,0");
}

/// `match` and `replace` read and write `lastIndex` as RegExpExec does
/// (ES2020 21.2.5.6, 21.2.5.8): a sticky pattern matches only at
/// `lastIndex` and stores the match end (or 0), a global one starts by
/// setting it to 0, and a plain one leaves it alone. `lastIndex` of
/// Infinity is past any input. Before this, `match` and `replace` ignored
/// `lastIndex` and the sticky flag, and left a global pattern's `lastIndex`
/// wherever it was.
#[test]
fn match_and_replace_use_last_index_like_exec() {
    let source = "const out = [];\n\
                  const y = /a/y; out.push(JSON.stringify('ba'.match(y)), y.lastIndex);\n\
                  y.lastIndex = 1; out.push(JSON.stringify('ba'.match(y)), y.lastIndex);\n\
                  const g = /a/g; g.lastIndex = 5; out.push('aXa'.match(g).length, g.lastIndex);\n\
                  g.lastIndex = 5; out.push('aXa'.replace(g, 'b'), g.lastIndex);\n\
                  const s = /a/y; out.push('ba'.replace(s, 'x'), s.lastIndex);\n\
                  s.lastIndex = 1; out.push('ba'.replace(s, 'x'), s.lastIndex);\n\
                  const p = /a/; p.lastIndex = 3; out.push('ba'.match(p).index, p.lastIndex);\n\
                  const inf = /a/g; inf.lastIndex = Infinity; out.push(String(inf.exec('a')), inf.lastIndex);\n\
                  out.join(',');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(value, r#"null,0,["a"],2,2,0,bXb,0,ba,0,bx,2,1,3,null,0"#);
}

/// `Set(R, "lastIndex", v, true)`: once `lastIndex` is read-only, every
/// builtin that writes it throws a TypeError (a plain pattern never
/// writes it, so its `match` still works). Before this the writes were
/// silently dropped or forced through.
#[test]
fn a_read_only_last_index_makes_its_writes_throw() {
    let source = "function attempt(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } }\n\
                  function frozen(re) { Object.defineProperty(re, 'lastIndex', { writable: false, value: 0 }); return re; }\n\
                  [attempt(() => 'b'.match(frozen(/a/g))), attempt(() => 'b'.replace(frozen(/a/g), 'x')), \
                  attempt(() => frozen(/a/g).exec('b')), attempt(() => frozen(/a/y).test('a')), \
                  attempt(() => 'ba'.match(frozen(/a/)).index), attempt(() => frozen(/a/g)[Symbol.match]('b'))].join();";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "TypeError,TypeError,TypeError,TypeError,ok,TypeError"
    );
}

/// RegExpBuiltinExec maps a UTF-16 lastIndex to its containing character.
/// In u/v mode the trailing surrogate therefore starts at the same scalar
/// as the leading surrogate; code-unit mode still matches the trailing half.
#[test]
fn unicode_exec_starts_at_the_character_containing_last_index() {
    let source = r#"
        const text = 'é😀\u{10000}z';
        const out = [];
        for (const flags of ['g', 'y', 'gu', 'uy', 'guy', 'gv', 'vy']) {
            const re = new RegExp('.', flags);
            re.lastIndex = 2;
            const match = re.exec(text);
            out.push(flags + ':' + match[0].codePointAt(0) + ':' + match.index + ':' + re.lastIndex);
        }
        const indexed = /(.)/dgu;
        indexed.lastIndex = 4;
        const match = indexed.exec(text);
        out.push(match[0].codePointAt(0), match.index, indexed.lastIndex,
                 match.indices[0].join('-'), match.indices[1].join('-'));
        out.join(',');
    "#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "g:56832:2:3,y:56832:2:3,gu:128512:1:3,uy:128512:1:3,guy:128512:1:3,gv:128512:1:3,vy:128512:1:3,65536,3,5,3-5,3-5"
    );
}

#[test]
fn unicode_test_match_replace_and_match_all_share_surrogate_start_semantics() {
    let source = r#"
        const text = 'A😀B';
        const out = [];
        const tested = /./uy;
        tested.lastIndex = 2;
        out.push(tested.test(text), tested.lastIndex);
        const matched = /./uy;
        matched.lastIndex = 2;
        const match = text.match(matched);
        out.push(match[0].codePointAt(0), match.index, matched.lastIndex);
        const replaced = /./uy;
        replaced.lastIndex = 2;
        out.push(text.replace(replaced, function (value, index) {
            out.push(value.codePointAt(0), index);
            return 'X';
        }), replaced.lastIndex);
        const all = /./ug;
        all.lastIndex = 2;
        out.push(Array.from(text.matchAll(all), function (m) {
            return m[0].codePointAt(0) + ':' + m.index;
        }).join('|'), all.lastIndex);
        out.join(',');
    "#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(value, "true,3,128512,1,3,128512,1,AXB,3,128512:1|66:3,2");
}

#[test]
fn unicode_surrogate_starts_preserve_empty_matches_and_failure_boundaries() {
    let source = r#"
        const text = 'A😀B';
        const out = [];
        const empty = /(?:)/uy;
        empty.lastIndex = 2;
        out.push(empty.exec(text).index, empty.lastIndex);
        const searched = /B/ug;
        searched.lastIndex = 2;
        out.push(searched.exec(text).index, searched.lastIndex);
        const sticky = /B/uy;
        sticky.lastIndex = 2;
        out.push(sticky.exec(text) === null, sticky.lastIndex);
        const end = /$/uy;
        end.lastIndex = text.length;
        out.push(end.exec(text).index, end.lastIndex);
        end.lastIndex = text.length + 1;
        out.push(end.exec(text) === null, end.lastIndex);
        const lone = /./uy;
        lone.lastIndex = 1;
        out.push(lone.exec('\uD800x').index, lone.lastIndex);
        out.join(',');
    "#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(value, "1,1,3,4,true,0,4,4,true,0,1,2");
}
