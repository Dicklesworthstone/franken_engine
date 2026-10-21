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
