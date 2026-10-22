//! Byte validation through the actual parser, module lowerer and interpreter.
//! Host-JavaScript results do not establish that these native tests pass.
#![forbid(unsafe_code)]
use frankenengine_engine::HybridRouter;

fn run(source: &str) -> Vec<String> {
    HybridRouter::default().eval(source).expect("native buffer validation")
        .console_output.into_iter().map(|entry| entry.message).collect()
}

#[test]
fn utf8_and_ascii_validate_scalar_boundaries_without_decoding_text() {
    let lines = run(r#"
const {isUtf8,isAscii}=require('node:buffer');
const cases=[[],[65,66],[194,128],[224,160,128],[237,159,191],
  [240,144,128,128],[244,143,191,191],[192,175],[237,160,128],
  [244,144,128,128],[226,130],[240,159,152],[255]];
console.log(cases.map(bytes=>isUtf8(Buffer.from(bytes))?1:0).join(''));
console.log(cases.map(bytes=>isAscii(Buffer.from(bytes))?1:0).join(''));
const text=Buffer.from('café 😀');
TextDecoder.prototype.decode=()=>{throw new Error('validation decoded');};
console.log(isUtf8(text),isAscii(text),isUtf8(Buffer.from([255])));
console.log('BYTE_VALIDATION_COMPLETE');
"#);
    assert_eq!(lines, ["1111111000000", "1100000000000", "true false false", "BYTE_VALIDATION_COMPLETE"]);
}

#[test]
fn input_metadata_cannot_change_which_bytes_are_validated() {
    let lines = run(r#"
const buffer=require('buffer');
const invalid=Buffer.from([192,175]),decoy=Buffer.from('OK');
Object.defineProperty(invalid,'buffer',{value:decoy.buffer});
Object.defineProperty(invalid,'byteOffset',{value:decoy.byteOffset});
Object.defineProperty(invalid,'byteLength',{value:2});
console.log(buffer.isUtf8(invalid),buffer.isAscii(invalid));
const bytes=new Uint8Array([255,65,66,255]);
const view=new Uint8Array(bytes.buffer,1,2);let calls=0;
for(const name of ['buffer','byteOffset','byteLength','length']){
  Object.defineProperty(view,name,{get(){calls++;throw new Error('metadata read');}});
}
console.log(buffer.isUtf8(view),buffer.isAscii(view),calls);
try{buffer.isUtf8(new DataView(new ArrayBuffer(2)));console.log('UNEXPECTED');}
catch(error){console.log(error.code);}
console.log('BYTE_WINDOW_COMPLETE');
"#);
    assert_eq!(lines, ["false false", "true true 0", "ERR_INVALID_ARG_TYPE", "BYTE_WINDOW_COMPLETE"]);
}

#[test]
fn buffer_aliases_keep_the_canonical_validator_with_guest_globals_shadowed() {
    let lines = run(r#"
const first=require('node:buffer'),second=require('buffer');
const {isUtf8:valid}=first;
const ArrayBuffer='guest',Uint8Array='guest',Reflect='guest';
console.log(first===second,first.isUtf8===second.isUtf8);
const ascii=first.Buffer.alloc(4096,65);console.log(valid(ascii),first.isAscii(ascii));
ascii[4095]=255;console.log(valid(ascii),first.isAscii(ascii));
console.log('BUFFER_ALIAS_COMPLETE');
"#);
    assert_eq!(lines, ["true true", "true true", "false false", "BUFFER_ALIAS_COMPLETE"]);
}

#[test]
fn long_ascii_runs_keep_exact_unaligned_windows_and_utf8_boundaries() {
    let lines = run(r#"
const {isUtf8,isAscii}=require('node:buffer');
const backing=Buffer.alloc(1041,255);backing.fill(65,3,1034);
const view=new Uint8Array(backing.buffer,backing.byteOffset+3,1031);
console.log(isUtf8(view),isAscii(view));
let rejected=0;
for(let at=32;at<96;at++){
  view[at]=255;
  if(!isUtf8(view)&&!isAscii(view))rejected++;
  view[at]=65;
}
console.log(rejected);
view[64]=240;view[65]=159;view[66]=152;view[67]=128;
console.log(isUtf8(view),isAscii(view));
console.log(isUtf8(new Uint8Array(view.buffer,view.byteOffset,67)));
console.log('WORD_BOUNDARIES_COMPLETE');
"#);
    assert_eq!(lines, ["true true", "64", "true false", "false", "WORD_BOUNDARIES_COMPLETE"]);
}

#[test]
fn long_validation_keeps_captured_word_operations_and_protected_globals() {
    let lines = run(r#"
const buffer=require('node:buffer');
const DataView='guest',Object='guest';
const bytes=buffer.Buffer.alloc(8192,65);
console.log(buffer.isUtf8(bytes),buffer.isAscii(bytes));
const saved=globalThis.DataView.prototype.getUint32;
globalThis.DataView.prototype.getUint32=function(){return 0;};
bytes[4097]=255;
console.log(buffer.isUtf8(bytes),buffer.isAscii(bytes));
globalThis.DataView.prototype.getUint32=saved;
console.log('WORD_INTRINSICS_COMPLETE');
"#);
    assert_eq!(lines, ["true true", "false false", "WORD_INTRINSICS_COMPLETE"]);
}
