//! bd-305gi.3: `require('buffer')` / `require('node:buffer')` in the
//! script goal is Node's buffer module over the realm's Buffer, atob, btoa
//! and Blob, with Node v22's keys, limits, isUtf8 / isAscii / transcode /
//! SlowBuffer. Every form (member read, safer-buffer's key copy, a
//! destructure, a require inside a function or a try) was refused at
//! lowering as a file read, failing the whole program. A `require` the
//! program declares itself is still called as written. The line is Node
//! v22.2.0's (Bun 1.4.2 differs only in its engine limits and
//! SlowBuffer.length).

use frankenengine_engine::HybridRouter;

#[test]
fn require_buffer_is_the_buffer_module_in_the_script_goal() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + '=' + f()); } catch (e) { out.push(name + '!' + e.constructor.name + ':' + (e.code || '')); } }
t('member', function () { return [require('buffer').Buffer === Buffer, require('node:buffer') === require('buffer')].join(); });
t('keys', function () { var b = require('buffer'); return ['Buffer', 'SlowBuffer', 'transcode', 'isUtf8', 'isAscii', 'kMaxLength', 'kStringMaxLength', 'btoa', 'atob', 'constants', 'INSPECT_MAX_BYTES', 'Blob', 'resolveObjectURL'].map(function (k) { return k + ':' + typeof b[k]; }).join(','); });
t('constants', function () { var b = require('buffer'); var d = Object.getOwnPropertyDescriptor(b.constants, 'MAX_LENGTH'); return [b.kMaxLength, b.kStringMaxLength, b.constants.MAX_LENGTH, b.constants.MAX_STRING_LENGTH, b.INSPECT_MAX_BYTES, d.writable, d.configurable].join(); });
t('safer-buffer', function () { var buffer = require('buffer'); var safer = {}; for (var key in buffer) { if (!buffer.hasOwnProperty(key)) continue; if (key === 'SlowBuffer' || key === 'Buffer' || key === 'File') continue; safer[key] = buffer[key]; } safer.Buffer = {}; for (key in buffer.Buffer) { if (!buffer.Buffer.hasOwnProperty(key)) continue; safer.Buffer[key] = buffer.Buffer[key]; } return Object.keys(safer).filter(function (k) { return k !== 'Buffer'; }).sort().join(); });
t('destructure', function () { var { Buffer: B, atob: a } = require('buffer'); return [B.from([1, 2]).length, a('aGk=')].join(); });
t('in-function', function () { function load() { return require('buffer').Buffer.byteLength('héllo'); } return load(); });
t('bnjs-style', function () { var Buf; try { if (typeof window !== 'undefined' && typeof window.Buffer !== 'undefined') { Buf = window.Buffer; } else { Buf = require('buffer').Buffer; } } catch (e) { Buf = null; } return typeof Buf.from; });
t('isUtf8', function () { var b = require('buffer'); return [b.isUtf8(Buffer.from([0xc3, 0xa9])), b.isUtf8(Buffer.from([0xff])), b.isUtf8(new Uint8Array([0x41]).buffer), b.isAscii(Buffer.from('abc')), b.isAscii(Buffer.from([0x80]))].join(); });
t('isUtf8-bad', function () { return require('buffer').isUtf8('x'); });
t('transcode', function () { var b = require('buffer'); return [b.transcode(Buffer.from('hé€'), 'utf8', 'latin1').toString('latin1'), b.transcode(Buffer.from('hi'), 'utf8', 'ucs2').toString('hex')].join(); });
t('slowbuffer', function () { var b = require('buffer'); return [b.SlowBuffer.length, b.SlowBuffer(3).length, b.SlowBuffer(2) instanceof Buffer].join(); });
t('shadowed-require', function () { function f(require) { return require('buffer'); } return f(function (s) { return 'own:' + s; }); });
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
            "member=true,true | keys=Buffer:function,SlowBuffer:function,transcode:function,isUtf8:function,isAscii:function,kMaxLength:number,kStringMaxLength:number,btoa:function,atob:function,constants:object,INSPECT_MAX_BYTES:number,Blob:function,resolveObjectURL:function | constants=9007199254740991,536870888,9007199254740991,536870888,50,false,false | safer-buffer=Blob,INSPECT_MAX_BYTES,atob,btoa,constants,isAscii,isUtf8,kMaxLength,kStringMaxLength,resolveObjectURL,transcode | destructure=2,hi | in-function=6 | bnjs-style=function | isUtf8=true,false,true,true,false | isUtf8-bad!TypeError:ERR_INVALID_ARG_TYPE | transcode=hé?,68006900 | slowbuffer=1,3,true | shadowed-require=own:buffer",
        ]
    );
}
