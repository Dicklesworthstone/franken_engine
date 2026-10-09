//! bd-9vouw.340: encodeURI and encodeURIComponent leave the uriMark
//! characters `- _ . ! ~ * ' ( )` as written (ES2020 18.2.6.1 uriUnescaped)
//! and throw a URIError for a lone surrogate (18.2.6.1.1 step 3.e). The
//! engine used RFC 3986's unreserved set, so `!'()*` were escaped
//! (`encodeURIComponent("it's")` was `it%27s`), and encoded a lone surrogate
//! as U+FFFD. The decoders' escape handling already matched Node and is
//! checked alongside; they too replaced a lone surrogate outside an escape
//! with U+FFFD, where Decode appends every code unit but `%` unchanged
//! (ES2020 18.2.6.1.2). Node v22.2.0 gives these lines.

use frankenengine_engine::HybridRouter;

#[test]
fn uri_encoders_keep_marks_and_refuse_lone_surrogates() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + '=' + f()); } catch (e) { out.push(name + ':' + e.name); } }
t('loneHigh', function () { return encodeURI('\uD800'); });
t('loneLow', function () { return encodeURI('\uDC00'); });
t('highThenA', function () { return encodeURI('\uD800a'); });
t('pair', function () { return encodeURI('😀'); });
t('compLoneHigh', function () { return encodeURIComponent('\uDBFF'); });
t('compLoneLow', function () { return encodeURIComponent('x\uDFFF'); });
t('unescaped', function () { return encodeURI("!'()*-._~"); });
t('reserved', function () { return encodeURI(';/?:@&=+$,#'); });
t('compReserved', function () { return encodeURIComponent(';/?:@&=+$,#!'); });
t('decD800', function () { return decodeURI('%ED%A0%80'); });
t('decCompD800', function () { return decodeURIComponent('%ED%A0%80'); });
t('decOverlong', function () { return decodeURI('%C0%80'); });
t('decGood', function () { return decodeURI('%F0%9F%98%80') === '😀'; });
t('decReserved', function () { return decodeURI('%3B%2F%3F%3A%40%26%3D%2B%24%2C%23'); });
t('decCompReserved', function () { return decodeURIComponent('%3B%2F%23'); });
t('dec4byteMax', function () { return decodeURI('%F4%8F%BF%BF').length; });
t('dec4byteOver', function () { return decodeURI('%F4%90%80%80'); });
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
            "loneHigh:URIError loneLow:URIError highThenA:URIError pair=%F0%9F%98%80 \
             compLoneHigh:URIError compLoneLow:URIError unescaped=!'()*-._~ \
             reserved=;/?:@&=+$,# compReserved=%3B%2F%3F%3A%40%26%3D%2B%24%2C%23! \
             decD800:URIError decCompD800:URIError decOverlong:URIError decGood=true \
             decReserved=%3B%2F%3F%3A%40%26%3D%2B%24%2C%23 decCompReserved=;/# \
             dec4byteMax=2 dec4byteOver:URIError"
        ]
    );
}

#[test]
fn uri_decoders_keep_lone_surrogates_outside_escapes() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + '=' + f()); } catch (e) { out.push(name + ':' + e.name); } }
function units(s) { var r = []; for (var i = 0; i < s.length; i++) r.push(s.charCodeAt(i).toString(16)); return r.join('.'); }
t('lone', function () { return units(decodeURI('\uD800')); });
t('loneComp', function () { return units(decodeURIComponent('a\uDFFFb')); });
t('loneEsc', function () { return units(decodeURI('%41\uDC00%C3%A9')); });
t('pairKept', function () { return units(decodeURI('😀%20')); });
t('interrupted', function () { return units(decodeURI('%C3\uD800%A9')); });
t('loneReserved', function () { return units(decodeURI('\uDBFF%2F')); });
var all = true;
for (var i = 0xD800; i <= 0xDFFF; i += 0x37) { var s = String.fromCharCode(i); if (decodeURI(s) !== s || decodeURIComponent(s) !== s) all = false; }
out.push('sweep=' + all);
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
            "lone=d800 loneComp=61.dfff.62 loneEsc=41.dc00.e9 pairKept=d83d.de00.20 \
             interrupted:URIError loneReserved=dbff.25.32.46 sweep=true"
        ]
    );
}
