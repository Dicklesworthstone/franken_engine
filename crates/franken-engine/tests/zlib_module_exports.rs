//! First-class zlib exports through native lowering and native codec ownership.
//! The JavaScript host suite does not establish that these Rust tests pass.
use frankenengine_engine::HybridRouter;

fn run(source: &str) -> String {
    let output = HybridRouter::default().eval(source).expect("native zlib execution");
    output.console_output.iter().map(|entry| entry.message.clone())
        .collect::<Vec<_>>().join("\n")
}

#[test]
fn detached_destructured_and_computed_codecs_share_the_existing_native_implementation() {
    assert_eq!(run(r#"
const api=require('node:zlib');
const {gzipSync:pack,gunzipSync:unpack}=api;
const encoded=pack('café 😀');
console.log(unpack(encoded).toString());
console.log(api['inflateRawSync'](api['deflateRawSync']('raw')).toString());
const algorithms=[api.deflateSync,api.inflateSync];
console.log(algorithms[1](algorithms[0]('array')).toString());
console.log(api.brotliDecompressSync(api.brotliCompressSync('brotli')).toString());
console.log(api.unzipSync(encoded).toString());
console.log('ZLIB_EXPORTS_COMPLETE');
"#), "café 😀\nraw\narray\nbrotli\ncafé 😀\nZLIB_EXPORTS_COMPLETE");
}

#[test]
fn first_class_callbacks_compose_with_native_util_promisify_and_original_errors() {
    assert_eq!(run(r#"
const api=require('zlib');const {promisify}=require('util');
const pack=promisify(api.gzip);const unpack=promisify(api.gunzip);
(async function(){
  console.log((await unpack(await pack('promised',{level:9}))).toString());
  try{await unpack(Buffer.from('invalid compressed input'));}
  catch(error){console.log(error instanceof Error,error.code);}
  const encode=api.deflate,decode=api.inflate;
  encode('callback',function(error,bytes){
    if(error)throw error;
    decode(bytes,undefined,function(error,result){
      if(error)throw error;
      console.log(result.toString());console.log('ZLIB_CALLBACKS_COMPLETE');
    });
  });
})();
"#), "promised\ntrue Z_DATA_ERROR\ncallback\nZLIB_CALLBACKS_COMPLETE");
}

#[test]
fn observable_aliases_share_one_module_and_do_not_bypass_public_replacements() {
    assert_eq!(run(r#"
const a=require('zlib');const b=require('node:zlib');
const captured=a.gzipSync;
console.log(a===b,a.constants===b.constants);
b.gzipSync=function(){return Buffer.from('replacement');};
console.log(a.gzipSync('x').toString());
console.log(a.gunzipSync(captured('original')).toString());
const c=require('zlib');console.log(c===a,c.gzipSync===b.gzipSync);
console.log('ZLIB_IDENTITY_COMPLETE');
"#), "true true\nreplacement\noriginal\ntrue true\nZLIB_IDENTITY_COMPLETE");
}

#[test]
fn formerly_refused_module_values_are_ordinary_objects_without_ambient_loading() {
    assert_eq!(run(r#"
'use strict';
const z=require('zlib');const Object='guest';
function select(api){return api.gzipSync;}
console.log(typeof z,typeof select(z));
{const z={gzipSync:function(x){return x;}};console.log(z.gzipSync('shadow'));}
let local=require('zlib');local={gzipSync:function(x){return x;}};
console.log(local.gzipSync('reassigned'));
try{z.constants={};}catch(error){console.log(error instanceof TypeError);}
try{z.constants.Z_BEST_COMPRESSION=1;}catch(error){console.log(error instanceof TypeError);}
try{z.unsupportedMethod('x');}catch(error){console.log(error instanceof TypeError);}
console.log(z.constants.Z_BEST_COMPRESSION);
console.log('ZLIB_VALUES_COMPLETE');
"#), "object function\nshadow\nreassigned\ntrue\ntrue\ntrue\n9\nZLIB_VALUES_COMPLETE");
}

#[test]
fn checksum_exports_preserve_unsigned_values_and_chunked_seed_state() {
    assert_eq!(run(r#"
const {crc32}=require('node:zlib');
const Buffer='guest',Object='guest',Reflect='guest',Uint32Array='guest';
console.log(crc32('123456789'));
console.log(crc32('world',crc32('hello')));
let value=0;
for(const chunk of ['archive: ','café ','😀','\n'])value=crc32(chunk,value);
console.log(value===crc32('archive: café 😀\n'));
console.log(crc32('',4294967295));
for(const seed of [-1,4294967296,1.5]){
  try{crc32('x',seed);}catch(error){console.log(error.code);}
}
console.log('CRC32_SEED_COMPLETE');
"#), "3421780262\n4192936109\ntrue\n4294967295\nERR_OUT_OF_RANGE\nERR_OUT_OF_RANGE\nERR_OUT_OF_RANGE\nCRC32_SEED_COMPLETE");
}

#[test]
fn checksum_uses_authentic_byte_windows_instead_of_public_view_metadata() {
    assert_eq!(run(r#"
const {crc32}=require('zlib');
const bytes=new Uint8Array([88,82,69,65,76,89]);
const data=new DataView(bytes.buffer,1,4);
const view=bytes.subarray(1,5);
Object.defineProperty(view,'buffer',{get:function(){throw Error('decoy buffer');}});
Object.defineProperty(view,'byteOffset',{get:function(){throw Error('decoy offset');}});
Object.defineProperty(view,'byteLength',{get:function(){throw Error('decoy length');}});
console.log(crc32(data),crc32(view),crc32('REAL'));
console.log(bytes[0],bytes[5]);
const captured=crc32;const api=require('node:zlib');api.crc32=function(){return 1;};
console.log(captured('123456789'),api.crc32('123456789'));
console.log('CRC32_WINDOW_COMPLETE');
"#), "2686002401 2686002401 2686002401\n88 89\n3421780262 1\nCRC32_WINDOW_COMPLETE");
}

#[test]
fn checksum_encodes_utf16_directly_and_keeps_calls_independent() {
    assert_eq!(run(r#"
const {crc32}=require('node:zlib');
const String='guest',Uint32Array='guest',Reflect='guest';
const pieces=['A\0\x7f\x80\u07ff\u0800','\ud7ff\ud800','\udc00\udfff','\udbff\udfff','café 東京 😀'];
let rolling=4294967295;
for(const piece of pieces)rolling=crc32(piece,rolling);
console.log('UTF8_DIRECT',crc32(pieces.join('')),rolling,crc32(pieces.join(''),4294967295));
"#), "UTF8_DIRECT 1826171974 244545859 4255863571");
}
