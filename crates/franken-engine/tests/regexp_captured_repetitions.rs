//! Captured repetition behavior through the public native execution pipeline.

use frankenengine_engine::HybridRouter;

#[test]
fn captured_greedy_repetitions_preserve_public_results() {
    let source = r#"var out = [];
function sample(pattern, flags, text) {
  var m = new RegExp(pattern, flags).exec(text);
  return m === null ? null : [m.index, Array.from(m)];
}
out.push(sample('((ab))*ab', '', 'ababab'));
out.push(sample('((ab))*\\1x', '', 'abababx'));
out.push(sample('(?<=((ab))*)x', '', 'ababx'));
out.push(sample('(?=((ab))*)z|a', '', 'a'));
out.push(sample('((ab))*', '', 'x'));
var re = /((ab))*!/g;
var matches = [], m;
while ((m = re.exec('abab!x!ab!')) !== null) matches.push([m.index, re.lastIndex, m[1], m[2]]);
out.push(matches);
out.push('abab!x!ab!'.replace(/((ab))*!/g, '[$1:$2]'));
out.push('xabab!yab!z'.split(/((ab))*!/));
out.push(Array.from('abab!x!ab!'.matchAll(/((ab))*!/g), function (m) { return [m.index, m[0], m[1], m[2]]; }));
var sticky = /((ab))*!/y;
sticky.lastIndex = 1;
var hit = sticky.exec('xabab!');
out.push([hit.index, hit[1], hit[2], sticky.lastIndex, sticky.exec('xabab!'), sticky.lastIndex]);
console.log(JSON.stringify(out));
"#;
    let outcome = HybridRouter::default().eval(source).expect("native evaluation");
    let lines: Vec<_> = outcome.console_output.iter().map(|entry| entry.message.as_str()).collect();
    assert_eq!(lines, [r#"[[0,["ababab","ab","ab"]],[0,["abababx","ab","ab"]],[4,["x","ab","ab"]],[0,["a",null,null]],[0,["",null,null]],[[0,5,"ab","ab"],[6,7,null,null],[7,10,"ab","ab"]],"[ab:ab]x[:][ab:ab]",["x","ab","ab","y","ab","ab","z"],[[0,"abab!","ab","ab"],[6,"!",null,null],[7,"ab!","ab","ab"]],[1,"ab","ab",6,null,0]]"#]);
}

#[test]
fn captured_greedy_unicode_repetitions_preserve_public_results() {
    let source = r#"var out = [];
function sample(pattern, flags, text) {
  var m = new RegExp(pattern, flags).exec(text);
  return m === null ? null : [m.index, Array.from(m)];
}
out.push(sample('((kſ))*!', 'iu', 'Ksks!'));
out.push(sample('((kſ))*!', 'i', 'Ksks!'));
out.push(sample('((😀é))*😀é!', 'u', '😀é😀é😀é!'));
out.push(sample('(?<=((😀é))*)!', 'u', '😀é😀é!'));
out.push(sample('((.))*!', 's', 'a\nb!'));
out.push(sample('((.))*!', '', 'a\nb!'));
out.push(sample('(([a-c]))*!', 'i', 'ABc!'));
console.log(JSON.stringify(out));
"#;
    let outcome = HybridRouter::default().eval(source).expect("native evaluation");
    let lines: Vec<_> = outcome.console_output.iter().map(|entry| entry.message.as_str()).collect();
    assert_eq!(lines, [r#"[[0,["Ksks!","ks","ks"]],[4,["!",null,null]],[0,["😀é😀é😀é!","😀é","😀é"]],[6,["!","😀é","😀é"]],[0,["a\nb!","b","b"]],[2,["b!","b","b"]],[0,["ABc!","c","c"]]]"#]);
}

#[test]
fn captured_lazy_repetitions_preserve_public_results() {
    let source = r#"var out = [];
function sample(pattern, flags, text) {
  var m = new RegExp(pattern, flags).exec(text);
  return m === null ? null : [m.index, Array.from(m)];
}
out.push(sample('((ab))*?ab', '', 'ababab'));
out.push(sample('((ab))+?ab', '', 'ababab'));
out.push(sample('((ab))*?\\1x', '', 'abababx'));
out.push(sample('(?<=x((ab))*?)!', '', 'xabab!'));
out.push(sample('(?=((ab))*?)\\1x|a', '', 'ababx'));
out.push(sample('((ab))*?', '', 'abab'));
var re = /((ab))*?!/g;
var matches = [], m;
while ((m = re.exec('abab!x!ab!')) !== null) matches.push([m.index, re.lastIndex, m[1], m[2]]);
out.push(matches);
out.push('abab!x!ab!'.replace(/((ab))*?!/g, '[$1:$2]'));
out.push('xabab!yab!z'.split(/((ab))*?!/));
out.push(Array.from('abab!x!ab!'.matchAll(/((ab))*?!/g), function (m) { return [m.index, m[0], m[1], m[2]]; }));
var sticky = /((ab))*?!/y;
sticky.lastIndex = 1;
var hit = sticky.exec('xabab!');
out.push([hit.index, hit[1], hit[2], sticky.lastIndex, sticky.exec('xabab!'), sticky.lastIndex]);
console.log(JSON.stringify(out));
"#;
    let outcome = HybridRouter::default().eval(source).expect("native evaluation");
    let lines: Vec<_> = outcome.console_output.iter().map(|entry| entry.message.as_str()).collect();
    assert_eq!(lines, [r#"[[0,["ab",null,null]],[0,["abab","ab","ab"]],[0,["abababx","ab","ab"]],[5,["!","ab","ab"]],[0,["a",null,null]],[0,["",null,null]],[[0,5,"ab","ab"],[6,7,null,null],[7,10,"ab","ab"]],"[ab:ab]x[:][ab:ab]",["x","ab","ab","y","ab","ab","z"],[[0,"abab!","ab","ab"],[6,"!",null,null],[7,"ab!","ab","ab"]],[1,"ab","ab",6,null,0]]"#]);
}

#[test]
fn captured_lazy_unicode_repetitions_preserve_public_results() {
    let source = r#"var out = [];
function sample(pattern, flags, text) {
  var m = new RegExp(pattern, flags).exec(text);
  return m === null ? null : [m.index, Array.from(m)];
}
out.push(sample('((kſ))*?!', 'iu', 'Ksks!'));
out.push(sample('((kſ))*?!', 'i', 'Ksks!'));
out.push(sample('((😀é))*?😀é!', 'u', '😀é😀é😀é!'));
out.push(sample('(?<=x((😀é))*?)!', 'u', 'x😀é😀é!'));
out.push(sample('((.))*?!', 's', 'a\nb!'));
out.push(sample('((.))*?!', '', 'a\nb!'));
out.push(sample('(([a-c]))*?!', 'i', 'ABc!'));
out.push(sample('(?!(?:((ab))*?)x)(ab)*?y', '', 'ababy'));
console.log(JSON.stringify(out));
"#;
    let outcome = HybridRouter::default().eval(source).expect("native evaluation");
    let lines: Vec<_> = outcome.console_output.iter().map(|entry| entry.message.as_str()).collect();
    assert_eq!(lines, [r#"[[0,["Ksks!","ks","ks"]],[4,["!",null,null]],[0,["😀é😀é😀é!","😀é","😀é"]],[7,["!","😀é","😀é"]],[0,["a\nb!","b","b"]],[2,["b!","b","b"]],[0,["ABc!","c","c"]],[0,["ababy",null,null,"ab"]]]"#]);
}
