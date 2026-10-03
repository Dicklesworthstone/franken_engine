//! bd-9vouw.162: the RegExp `d` flag (ES2022 hasIndices) and the order of
//! `flags`.
//!
//! `/(b)/d.exec(s).indices` was undefined: exec results now carry
//! `indices` (MakeIndicesArray: each capture's UTF-16 `[start, end]` or
//! undefined, with `groups` for named captures) when the regexp has `d`.
//! `flags` returned the letters as written (`/a/gd.flags` was "gd"); it now
//! lists them in "dgimsuvy" order (ES2025 22.2.6.4), and RegExp.prototype
//! has the hasIndices and unicodeSets accessors. Expected strings are Node
//! v22.2.0's output for the same programs.
//!
//! The flag accessors were only described, by getOwnPropertyDescriptor:
//! [[Get]] and `in` never found them, so `/a/g.global` and `/a/d.hasIndices`
//! were undefined (on every build back to the rc-next8 landing at least).
//! [[Get]] and [[HasProperty]] now find them on RegExp.prototype, as they
//! find Map.prototype.size and the other described accessors.
//!
//! No-claim: Object.getOwnPropertyNames(RegExp.prototype) and Reflect.ownKeys
//! still leave the accessors out.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// With the d flag an exec result carries `indices`: each capture's [start, end], undefined for one that did not participate, and `groups`.
#[test]
fn regexp_has_indices_match_indices() {
    let source = "var m = /(?<word>b+)(c)?(d)/d.exec('abbd');\n\
         [Object.keys(m).join(), JSON.stringify(m.indices), JSON.stringify(m.indices.groups), m.indices.length,\n\
          Array.isArray(m.indices[0]), /(b)/.exec('ab').indices === undefined, 'indices' in /(b)/.exec('ab')].join(' ');";
    assert_eq!(
        eval(source),
        "0,1,2,3,index,input,groups,indices [[1,4],[1,3],null,[3,4]] {\"word\":[1,3]} 4 true true false"
    );
}

/// Indices are UTF-16 code unit offsets, as `index` is.
#[test]
fn regexp_has_indices_utf16_offsets() {
    let source = "var astral = String.fromCodePoint(0x1F600);\n\
         [JSON.stringify(/(\u{e9})(x)/d.exec('a\u{e9}x').indices), JSON.stringify(/x(y)/du.exec(astral + 'xy').indices),\n\
          /x/d.exec(astral + astral + 'x').index].join(' ');";
    assert_eq!(eval(source), "[[1,3],[1,2],[2,3]] [[2,4],[3,4]] 4");
}

/// `flags` lists the flags in dgimsuy order whatever order they were written in; hasIndices and unicodeSets read d and v.
#[test]
fn regexp_has_indices_flags_and_getters() {
    let source = "[/a/gd.flags, new RegExp('a', 'yig').flags, /a/ysmiug.flags, /a/d.hasIndices, /a/g.hasIndices,\n\
          new RegExp('a', 'd').hasIndices, /a/v.unicodeSets, /a/u.unicodeSets, String(/a/dg)].join(' ');";
    assert_eq!(
        eval(source),
        "dg giy gimsuy true false true true false /a/dg"
    );
}

/// String.prototype.match (non-global), matchAll and a regexp from new RegExp(re) carry indices too.
#[test]
fn regexp_has_indices_other_entry_points() {
    let source = "var re = /(b)/dg;\n\
         [ 'zzb'.match(/(b)/d).indices[1].join(), [...'abcb'.matchAll(re)].map((m) => m.indices[1].join('-')).join(),\n\
          new RegExp(re).exec('xb').indices[0].join(), new RegExp(re.source, 'd').exec('b').indices[0].join()].join(' ');";
    assert_eq!(eval(source), "2,3 1-2,3-4 1,2 0,1");
}

/// The flag accessors live on RegExp.prototype: [[Get]] and `in` find them
/// for a regexp or a RegExp subclass instance; on RegExp.prototype itself they
/// answer undefined (source "(?:)", flags ""), and another receiver is a TypeError.
#[test]
fn regexp_has_indices_flag_accessors() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
         var r = /a/gimsuy, P = RegExp.prototype;\n\
         [r.global, r.ignoreCase, r.multiline, r.dotAll, r.unicode, r.sticky, /a/.global, 'global' in r, 'sticky' in /b/,\n\
          r.hasOwnProperty('global'), P.global, P.source, JSON.stringify(P.flags), attempt(() => Object.create(P).global),\n\
          Reflect.get(P, 'global', r), new (class R extends RegExp {})('x', 'y').sticky].join(' ');";
    assert_eq!(
        eval(source),
        "true true true true true true false true true false  (?:) \"\" TypeError true true"
    );
}
