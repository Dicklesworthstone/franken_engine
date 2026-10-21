//! Counted captured repetitions through the public native pipeline.

use frankenengine_engine::HybridRouter;

#[test]
fn counted_captures_public_fixed() {
    let source = r#"var out = [];
function sample(pattern, flags, text) {
  var m = new RegExp(pattern, flags).exec(text);
  return m === null ? null : [m.index, Array.from(m)];
}
var block = 'ab'.repeat(17) + '!';
out.push(sample('((ab)){17}(?=!)', '', 'ab' + block));
out.push(sample('((ab)){17}\\2!', '', 'ab' + block));
out.push(sample('(?<=((ab)){17})!', '', block));
out.push(sample('(?=((ab)){17})z|ab', '', block));
out.push(sample('((ab)){17}!', '', 'ab'.repeat(16) + '!'));
var text = 'x' + block + 'y' + block;
var re = /((ab)){17}(?=!)/g, m, matches = [];
while ((m = re.exec(text)) !== null) matches.push([m.index, re.lastIndex, m[1], m[2]]);
out.push(matches);
out.push(text.replace(/((ab)){17}(?=!)/g, '[$1:$2]'));
out.push(text.split(/((ab)){17}(?=!)/));
var sticky = /((ab)){17}(?=!)/y;
sticky.lastIndex = 1;
var hit = sticky.exec(text);
out.push([hit.index, hit[1], hit[2], sticky.lastIndex, sticky.exec(text), sticky.lastIndex]);
console.log(JSON.stringify(out));
"#;
    let outcome = HybridRouter::default().eval(source).expect("native evaluation");
    let lines: Vec<_> = outcome.console_output.iter().map(|entry| entry.message.as_str()).collect();
    assert_eq!(lines, [r#"[[2,["ababababababababababababababababab","ab","ab"]],[0,["abababababababababababababababababab!","ab","ab"]],[34,["!","ab","ab"]],[0,["ab",null,null]],null,[[1,35,"ab","ab"],[37,71,"ab","ab"]],"x[ab:ab]!y[ab:ab]!",["x","ab","ab","!y","ab","ab","!"],[1,"ab","ab",35,null,0]]"#]);
}

#[test]
fn counted_captures_public_fixed_unicode() {
    let source = r#"var out = [];
function sample(pattern, flags, text) {
  var m = new RegExp(pattern, flags).exec(text);
  return m === null ? null : [m.index, m[0].length, m[1], m[2]];
}
out.push(sample('((kſ)){17}(?=!)', 'iu', 'Ks'.repeat(17) + '!'));
out.push(sample('((kſ)){17}(?=!)', 'i', 'Ks'.repeat(17) + '!'));
out.push(sample('((😀é)){17}(?=!)', 'u', '😀é'.repeat(17) + '!'));
out.push(sample('(?<=((😀é)){17})!', 'u', '😀é'.repeat(17) + '!'));
out.push(sample('(([a-c])){17}(?=!)', 'i', 'AbcAbcAbcAbcAbcAbc!'));
out.push(sample('((.)){17}(?=!)', 's', 'x'.repeat(8) + '\n' + 'x'.repeat(8) + '!'));
out.push(sample('((.)){17}(?=!)', '', 'x'.repeat(8) + '\n' + 'x'.repeat(8) + '!'));
console.log(JSON.stringify(out));
"#;
    let outcome = HybridRouter::default().eval(source).expect("native evaluation");
    let lines: Vec<_> = outcome.console_output.iter().map(|entry| entry.message.as_str()).collect();
    assert_eq!(lines, [r#"[[0,34,"Ks","Ks"],null,[0,51,"😀é","😀é"],[51,1,"😀é","😀é"],[1,17,"c","c"],[0,17,"x","x"],null]"#]);
}

#[test]
fn optional_counted_greedy_captures_preserve_public_protocol_results() {
    let source = r#"var out = [];
function sample(pattern, flags, text) {
  var m = new RegExp(pattern, flags).exec(text);
  return m === null ? null : [m.index, Array.from(m)];
}
out.push(sample('((ab)){0,32}ab(?=!)', '', 'ababab!'));
out.push(sample('((ab)){17,20}\\2!', '', 'ab'.repeat(19) + '!'));
out.push(sample('((ab)){17,}(?=!)', '', 'ab'.repeat(18) + '!'));
out.push(sample('(?<=((ab)){0,32})!', '', 'abab!'));
out.push(sample('(?=((ab)){0,32})z|ab', '', 'abab!'));
out.push(sample('((ab)){0,32}(?=!)', '', '!'));
out.push(sample('((kſ)){0,32}(?=!)', 'iu', 'Ksks!'));
out.push(sample('((😀é)){0,32}😀é(?=!)', 'u', '😀é😀é😀é!'));
var re = /((ab)){0,32}!(?=x|$)/g, m, hits = [];
while ((m = re.exec('abab!x!xab!')) !== null) hits.push([m.index, re.lastIndex, m[1], m[2]]);
out.push(hits);
out.push('abab!x!xab!'.replace(/((ab)){0,32}!(?=x|$)/g, '[$1:$2]'));
out.push('xabab!yab!z'.split(/((ab)){0,32}!(?=y|z)/));
out.push(Array.from('abab!x!xab!'.matchAll(/((ab)){0,32}!(?=x|$)/g), function (m) { return [m.index, m[1], m[2]]; }));
var sticky = /((ab)){0,32}!(?=$)/y;
sticky.lastIndex = 1;
var hit = sticky.exec('xabab!');
out.push([hit.index, hit[1], sticky.lastIndex, sticky.exec('xabab!'), sticky.lastIndex]);
console.log(JSON.stringify(out));
"#;
    let outcome = HybridRouter::default().eval(source).expect("native evaluation");
    let lines: Vec<_> = outcome.console_output.iter().map(|entry| entry.message.as_str()).collect();
    assert_eq!(lines, [r#"[[0,["ababab","ab","ab"]],[0,["ababababababababababababababababababab!","ab","ab"]],[0,["abababababababababababababababababab","ab","ab"]],[4,["!","ab","ab"]],[0,["ab",null,null]],[0,["",null,null]],[0,["Ksks","ks","ks"]],[0,["😀é😀é😀é","😀é","😀é"]],[[0,5,"ab","ab"],[6,7,null,null],[8,11,"ab","ab"]],"[ab:ab]x[:]x[ab:ab]",["x","ab","ab","y","ab","ab","z"],[[0,"ab","ab"],[6,null,null],[8,"ab","ab"]],[1,"ab",6,null,0]]"#]);
}

#[test]
fn optional_counted_lazy_captures_preserve_public_protocol_results() {
    let source = r#"var out = [];
function sample(pattern, flags, text) {
  var m = new RegExp(pattern, flags).exec(text);
  return m === null ? null : [m.index, Array.from(m)];
}
out.push(sample('((ab)){0,32}?(?=)', '', 'ababab'));
out.push(sample('((ab)){0,32}?ab(?=!)', '', 'ababab!'));
out.push(sample('((ab)){17,20}?\\2!', '', 'ab'.repeat(19) + '!'));
out.push(sample('((ab)){17,}?(?=!)', '', 'ab'.repeat(18) + '!'));
out.push(sample('((ab)){0,17}?x|ab', '', 'ab'.repeat(17) + '?'));
out.push(sample('(?<=((ab)){0,32}?)!', '', 'abab!'));
out.push(sample('(?<=((ab)){17,32}?)!', '', 'ab'.repeat(18) + '!'));
out.push(sample('(?=((ab)){0,32}?)ab', '', 'abab!'));
out.push(sample('((kſ)){0,32}?(?=!)', 'iu', 'Ksks!'));
out.push(sample('((😀é)){0,32}?😀é(?=!)', 'u', '😀é😀é😀é!'));
out.push(sample('((.)){0,32}?(?=!)', 's', 'a\nb!'));
var re = /((ab)){0,32}?!(?=x|$)/g, m, hits = [];
while ((m = re.exec('abab!x!xab!')) !== null) hits.push([m.index, re.lastIndex, m[1], m[2]]);
out.push(hits);
out.push('abab!x!xab!'.replace(/((ab)){0,32}?!(?=x|$)/g, '[$1:$2]'));
out.push('xabab!yab!z'.split(/((ab)){0,32}?!(?=y|z)/));
out.push(Array.from('abab!x!xab!'.matchAll(/((ab)){0,32}?!(?=x|$)/g), function (m) { return [m.index, m[1], m[2]]; }));
var sticky = /((ab)){0,32}?!(?=$)/y;
sticky.lastIndex = 1;
var hit = sticky.exec('xabab!');
out.push([hit.index, hit[1], sticky.lastIndex, sticky.exec('xabab!'), sticky.lastIndex]);
console.log(JSON.stringify(out));
"#;
    let outcome = HybridRouter::default().eval(source).expect("native evaluation");
    let lines: Vec<_> = outcome.console_output.iter().map(|entry| entry.message.as_str()).collect();
    assert_eq!(lines, [r#"[[0,["",null,null]],[0,["ababab","ab","ab"]],[0,["ababababababababababababababababababab!","ab","ab"]],[0,["abababababababababababababababababab","ab","ab"]],[0,["ab",null,null]],[4,["!",null,null]],[36,["!","ab","ab"]],[0,["ab",null,null]],[0,["Ksks","ks","ks"]],[0,["😀é😀é😀é","😀é","😀é"]],[0,["a\nb","b","b"]],[[0,5,"ab","ab"],[6,7,null,null],[8,11,"ab","ab"]],"[ab:ab]x[:]x[ab:ab]",["x","ab","ab","y","ab","ab","z"],[[0,"ab","ab"],[6,null,null],[8,"ab","ab"]],[1,"ab",6,null,0]]"#]);
}
