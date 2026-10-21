//! Public-pipeline observables for operation-local character-class reuse.
//! Fixed expected outputs were captured separately with Node v22.16.0.
//! The unit tests also compare cached/uncached native work and capture state.

use frankenengine_engine::HybridRouter;

fn check(source: &str, expected: &str) {
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<_> = outcome.console_output.iter().map(|entry| entry.message.as_str()).collect();
    assert_eq!(lines, [expected]);
}

#[test]
fn public_classes() {
    check(
        r#"var out = [];
out.push(/(?=)([\w]+)(?=!)/.exec('abcXYZ_09!'));
out.push(/(?=)([a-z]+?)(?=[0-9])/.exec('abca1'));
out.push(/(?=)([A-Z0-9]{0,32}?)(?=!)/i.exec('aB09!'));
out.push(/(?<=([a-z]+))!/.exec('abc!'));
out.push(/(?!(\d))([\w]+)!/.exec('abc!'));
out.push('ab1cd2'.match(/(?=)[a-z]+(?=\d)/g));
out.push('ab1cd2'.replace(/(?=)([a-z]+)(?=\d)/g, '<$1>'));
out.push('a11b22c'.split(/(?=)([0-9]+)(?=[a-z])/));
var global = /(?=)[a-z]+(?=!)/g;
var matches = [], match;
while ((match = global.exec('ab!cd!'))) matches.push([match[0], match.index, global.lastIndex]);
out.push(matches); out.push(global.lastIndex);
console.log(JSON.stringify(out));
"#,
        r#"[["abcXYZ_09","abcXYZ_09"],["abca","abca"],["aB09","aB09"],["!","abc"],["abc!",null,"abc"],["ab","cd"],"<ab>1<cd>2",["a","11","b","22","c"],[["ab",0,2],["cd",3,5]],0]"#,
    );
}

#[test]
fn public_unicode_classes() {
    check(
        r#"var out = [];
out.push(/(?=)([\p{L}\p{N}_]+)(?=!)/u.exec('Ab9_é日!'));
out.push(/(?=)([^\p{Lu}]+?)(?=!)/u.exec('abc12!'));
out.push(/(?=)([a-z]+)(?=!)/iu.exec('KKſs!'));
out.push(/(?=)([^a-z]+)(?=!)/i.exec('09😀!'));
out.push(/(?<=([\p{L}]{1,32}))!/u.exec('Abé!'));
out.push(/(?=)([a-z]+)\1/i.exec('aBaB'));
var sticky = /(?=)([A-Z0-9]{0,32}?)(?=!)/iy;
sticky.lastIndex = 2;
var match = sticky.exec('xxaB09!');
out.push([match[0], match.index, sticky.lastIndex]);
sticky.lastIndex = 1;
out.push(sticky.exec('! aB09!')); out.push(sticky.lastIndex);
console.log(JSON.stringify(out));
"#,
        r#"[["Ab9_é日","Ab9_é日"],["abc12","abc12"],["KKſs","KKſs"],["09😀","09😀"],["!","Abé"],["aBaB","aB"],["aB09",2,6],null,0]"#,
    );
}
