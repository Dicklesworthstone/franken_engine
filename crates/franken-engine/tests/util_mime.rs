//! MIME records through the real parser/lowerer/interpreter, not a host preload.
//! Host differential results do not establish that these native tests pass.
#![forbid(unsafe_code)]
use frankenengine_engine::HybridRouter;

fn run(source: &str) -> Vec<String> {
    HybridRouter::default().eval(source).expect("native MIME execution")
        .console_output.into_iter().map(|entry| entry.message).collect()
}

#[test]
fn mime_constructor_and_live_parameter_iterators_keep_complete_content_type() {
    let lines = run(r#"
const {MIMEType,MIMEParams}=require('node:util');
const mime=new MIMEType('Application/Vnd.test+JSON; Charset=UTF-8; charset=ignored');
console.log(mime.essence,mime.params.get('charset'),mime.params instanceof MIMEParams);
const cursor=mime.params.entries();console.log(JSON.stringify(cursor.next().value));
mime.params.set('profile','urn:example;a="b"');
console.log(JSON.stringify(cursor.next().value));
console.log(mime.toString());
console.log('MIME_COMPLETE',cursor.next().done);
"#);
    assert_eq!(lines, [
        "application/vnd.test+json UTF-8 true",
        r#"["charset","UTF-8"]"#,
        r#"["profile","urn:example;a=\"b\""]"#,
        r#"application/vnd.test+json;charset=UTF-8;profile="urn:example;a=\"b\"""#,
        "MIME_COMPLETE true",
    ]);
}

#[test]
fn invalid_parameter_mutations_do_not_publish_header_injection_or_replace_state() {
    let lines = run(r#"
const {MIMEType}=require('util');const mime=new MIMEType('text/plain;charset=utf-8');
for(const value of ['bad\r\nInjected: yes','\0','\u0100']){
  try{mime.params.set('charset',value);console.log('UNEXPECTED');}
  catch(error){console.log(error.code,mime.toString());}
}
const retained=mime.params;mime.type='APPLICATION';mime.subtype='JSON';
console.log(retained===mime.params,JSON.stringify(mime));
console.log('MIME_VALIDATION_COMPLETE');
"#);
    assert_eq!(lines, [
        "ERR_INVALID_MIME_SYNTAX text/plain;charset=utf-8",
        "ERR_INVALID_MIME_SYNTAX text/plain;charset=utf-8",
        "ERR_INVALID_MIME_SYNTAX text/plain;charset=utf-8",
        r#"true "application/json;charset=utf-8""#,
        "MIME_VALIDATION_COMPLETE",
    ]);
}

#[test]
fn mime_aliases_and_shadowed_realm_globals_use_the_shared_private_installer() {
    let lines = run(r#"
const one=require('util');const two=require('node:util');
const WeakMap='guest',Map='guest',Array='guest',String='guest';
const mime=new one.MIMEType('x/y;__proto__=first;constructor=second');
console.log(one===two,one.MIMEType===two.MIMEType);
console.log(mime.params.get('__proto__'),mime.params.get('constructor'));
mime.params.toString=()=>{throw new Error('public replacement');};
console.log(mime.toString());console.log('MIME_IDENTITY_COMPLETE');
"#);
    assert_eq!(lines, [
        "true true", "first second", "x/y;__proto__=first;constructor=second",
        "MIME_IDENTITY_COMPLETE",
    ]);
}
