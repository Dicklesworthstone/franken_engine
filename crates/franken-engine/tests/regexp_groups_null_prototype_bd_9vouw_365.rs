//! bd-9vouw.365: a RegExp match's `groups` object, and `indices.groups`
//! under the d flag, has a null [[Prototype]] (ES2020 21.2.5.2.2 step 25,
//! OrdinaryObjectCreate(null)): nothing from Object.prototype is inherited
//! or enumerated, and a group named `__proto__` is an ordinary own
//! property. They inherited Object.prototype. The line is Node v22.2.0's
//! (Bun 1.4.2 agrees).

use frankenengine_engine::HybridRouter;

#[test]
fn match_groups_objects_have_a_null_prototype() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + '=' + f()); } catch (e) { out.push(name + '!' + e.constructor.name); } }
t('proto', function () { return Object.getPrototypeOf(/(?<x>.)/.exec('a').groups); });
t('proto-named-group', function () { var g = /(?<__proto__>.)/.exec('a').groups; return [g.__proto__, Object.getPrototypeOf(g), Object.keys(g).join()].join(); });
t('no-inherited', function () { Object.prototype.polluted = 1; var g = /(?<k>.)/.exec('z').groups; var keys = []; for (var k in g) keys.push(k); delete Object.prototype.polluted; return [keys.join(), 'toString' in g].join(); });
t('indices', function () { var ig = /(?<x>.)/d.exec('a').indices.groups; return [Object.getPrototypeOf(ig), ig.x.join('-')].join(); });
t('indices-proto-name', function () { var ig = /(?<__proto__>.)/d.exec('a').indices.groups; return [ig.__proto__.join('-'), Object.getPrototypeOf(ig)].join(); });
t('replace-named', function () { return 'ab'.replace(/(?<f>a)/, '[$<f>]'); });
t('replace-fn-groups', function () { return 'ab'.replace(/(?<f>a)/, function () { var g = arguments[arguments.length - 1]; return Object.getPrototypeOf(g) + ':' + g.f; }); });
t('matchall', function () { return [...'a1b2'.matchAll(/(?<d>\d)/g)].map(function (m) { return m.groups.d; }).join(); });
t('none', function () { return String(/(x)/.exec('x').groups); });
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
            "proto=null proto-named-group=a,,__proto__ no-inherited=k,false indices=,0-1 indices-proto-name=0-1, replace-named=[a]b replace-fn-groups=null:ab matchall=1,2 none=undefined",
        ]
    );
}
