//! ES2020 21.2.5.13: RegExp.prototype.test is `RegExpExec(R, S) !== null`, so
//! a global or sticky regex reads and advances `lastIndex` exactly like
//! `exec`. FrankenEngine's test ignored `lastIndex` and the flags: a /g regex
//! answered true forever (`while (re.test(s)) n++` never ended) and a sticky
//! regex matched anywhere. Expected string is Node v22.2.0's output.

use frankenengine_engine::HybridRouter;

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
