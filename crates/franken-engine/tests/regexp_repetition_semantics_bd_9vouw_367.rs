//! bd-9vouw.367: a repeated RegExp atom follows ES2020's RepeatMatcher
//! (21.2.2.5.1): captures nested in the atom are cleared at every
//! iteration, and an iteration that matches the empty string fails. The
//! patterns that need either ran on the regex crate, which keeps an
//! earlier iteration's capture (`/((a)|(b))+/.exec('ab')[2]` was 'a') and
//! accepts empty iterations (`/(a?b??)*/.exec('ab')` matched 'a'); they now
//! run on the backtracking matcher. Tokenizer, key=value, CSV and global
//! match / replace / split / matchAll forms, a plain `(a)+` and an
//! IPv4-style pattern are checked too. The line is Node v22.2.0's (Bun
//! 1.4.2 agrees).

use frankenengine_engine::HybridRouter;

#[test]
fn repeated_atoms_follow_es_repeat_matcher() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + '=' + JSON.stringify(f())); } catch (e) { out.push(name + '!' + e.constructor.name); } }
t('alt-in-plus', function () { return /((a)|(b))+/.exec('ab'); });
t('nested-optional', function () { return /(z)((a+)?(b+)?(c))*/.exec('zaacbbbcac'); });
t('alt-star', function () { return /(?:(a)|b)*/.exec('ab'); });
t('nullable-star', function () { return /(a?b??)*/.exec('ab'); });
t('lazy-nullable', function () { return /(a*?)*/.exec('aa'); });
t('empty-alt', function () { return /(?:a|())*/.exec('aa'); });
t('tokens', function () { var re = /(?:(\d+)|([a-z]+)|(\s+))/g, m, r = []; while ((m = re.exec('ab 12 c'))) r.push([m[1] || '-', m[2] || '-', m[3] ? 's' : '-'].join('')); return r; });
t('kv-list', function () { return /^(?:(\w+)=(\w+);?)+$/.exec('a=1;b=2;c=3'); });
t('csv-row', function () { return /^(?:([^,]*),)*([^,]*)$/.exec('x,,y'); });
t('replace-groups', function () { return 'aXbXc'.replace(/(?:(a)|(b)|(c))/g, function (m, a, b, c) { return (a ? 'A' : '') + (b ? 'B' : '') + (c ? 'C' : ''); }); });
t('split-captures', function () { return 'a1b22c'.split(/(?:(\d)|(x))+/); });
t('match-global', function () { return 'ab ab'.match(/((a)|(b))+/g); });
t('matchall', function () { return [...'abba'.matchAll(/((a)|(b))+/g)].map(function (m) { return [m[0], m[2], m[3]]; }); });
t('plain-plus', function () { return /(a)+/.exec('aaa'); });
t('ip', function () { return /^(?:\d{1,3}\.){3}\d{1,3}$/.test('10.0.0.1'); });
console.log(out.join(' | '));
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
            "alt-in-plus=[\"ab\",\"b\",null,\"b\"] | nested-optional=[\"zaacbbbcac\",\"z\",\"ac\",\"a\",null,\"c\"] | alt-star=[\"ab\",null] | nullable-star=[\"ab\",\"b\"] | lazy-nullable=[\"aa\",\"a\"] | empty-alt=[\"aa\",null] | tokens=[\"-ab-\",\"--s\",\"12--\",\"--s\",\"-c-\"] | kv-list=[\"a=1;b=2;c=3\",\"c\",\"3\"] | csv-row=[\"x,,y\",\"\",\"y\"] | replace-groups=\"AXBXC\" | split-captures=[\"a\",\"1\",null,\"b\",\"2\",null,\"c\"] | match-global=[\"ab\",\"ab\"] | matchall=[[\"abba\",\"a\",null]] | plain-plus=[\"aaa\",\"a\"] | ip=true",
        ]
    );
}
