//! bd-9vouw.437: Node's Buffer numeric accessors beyond the 8/16/32-bit
//! unsigned and 32-bit signed ones, and `buf.write(string)`. readInt8,
//! readInt16LE/BE, the variable-width readIntLE/readUIntBE family, float,
//! double, BigInt64 and the lowercase `Uint` aliases (readUint16BE ==
//! readUInt16BE), each with its write, were missing: calling one threw
//! "expected function, got undefined". Binary protocol code uses them all.
//! Expected lines are Node v22.2.0's for the same program, values, return
//! offsets and Node's error codes and messages included.

use std::process::Command;

const PROGRAM: &str = r#"import { Buffer } from 'node:buffer';
const out = [];
const t = (name, f) => {
  try { out.push(name + ' = ' + f()); } catch (e) { out.push(name + ' ! ' + e.name + ' ' + (e.code || '') + ' ' + e.message); }
};
const b = Buffer.alloc(16);
t('writeInt8', () => [b.writeInt8(-5, 0), b.readInt8(0), b.readUInt8(0), b.readUint8(0)].join());
t('writeUint8', () => [b.writeUint8(250, 1), b.readUint8(1), b.readInt8(1)].join());
t('writeInt16LE', () => [b.writeInt16LE(-2, 2), b.readInt16LE(2), b.readUInt16LE(2), b.readUint16LE(2), b[2], b[3]].join());
t('writeInt16BE', () => [b.writeInt16BE(-300, 4), b.readInt16BE(4), b.readUint16BE(4), b[4], b[5]].join());
t('writeUint16LE', () => [b.writeUint16LE(0xabcd, 6), b.readUInt16LE(6), b.readUint16BE(6)].join());
t('writeUint32BE', () => [b.writeUint32BE(0xdeadbeef, 8), b.readUint32BE(8), b.readUint32LE(8), b.readInt32BE(8)].join());
t('writeUint32LE', () => [b.writeUint32LE(4000000000, 12), b.readUInt32LE(12)].join());
t('IntLE', () => [b.writeIntLE(-123456789, 0, 6), b.readIntLE(0, 6), b.readUIntLE(0, 6), b.readIntLE(0, 3)].join());
t('IntBE', () => [b.writeIntBE(-2, 0, 5), b.readIntBE(0, 5), b.readUIntBE(0, 5), b.readUintBE(0, 2)].join());
t('UIntLE', () => [b.writeUIntLE(0x123456789a, 0, 5), b.readUIntLE(0, 5), b.readUintLE(0, 5), b.writeUintLE(1, 0, 1)].join());
t('UIntBE', () => [b.writeUIntBE(0xffffff, 3, 3), b.readUIntBE(3, 3), b.writeUintBE(258, 0, 2), b.readUInt16BE(0)].join());
t('Float', () => [b.writeFloatLE(1.5, 0), b.readFloatLE(0), b.writeFloatBE(-0.1, 4), b.readFloatBE(4), b.readFloatLE(4)].join());
t('Double', () => [b.writeDoubleLE(Math.PI, 0), b.readDoubleLE(0), b.writeDoubleBE(-1e300, 8), b.readDoubleBE(8)].join());
t('Double nan', () => [b.writeDoubleLE(NaN, 0), b.readDoubleLE(0), b.writeFloatLE(Infinity, 0), b.readFloatLE(0)].join());
t('BigInt64', () => [b.writeBigInt64LE(-5n, 0), b.readBigInt64LE(0), b.readBigUInt64LE(0), b.readBigUint64LE(0)].join());
t('BigInt64BE', () => [b.writeBigInt64BE(1n << 62n, 8), b.readBigInt64BE(8), b.readBigUInt64BE(8)].join());
t('BigUInt64', () => [b.writeBigUInt64LE(18446744073709551615n, 0), b.readBigUInt64LE(0), b.readBigInt64LE(0), b.writeBigUint64BE(7n, 8), b.readBigUint64BE(8)].join());
t('err int8 range', () => b.writeInt8(200, 0));
t('err int16 range', () => b.writeInt16LE(-40000, 0));
t('err uint32 range', () => b.writeUint32BE(4294967296, 0));
t('err intLE range', () => b.writeIntLE(2 ** 47, 0, 6));
t('err uintBE range', () => b.writeUIntBE(-1, 0, 5));
t('err byteLength', () => b.readIntLE(0, 7));
t('err byteLength missing', () => b.readUIntBE(0));
t('err read offset', () => b.readInt16LE(15));
t('err write offset', () => b.writeDoubleLE(1, 9));
t('err bigint type', () => b.writeBigInt64LE(5, 0));
t('err bigint range', () => b.writeBigInt64LE(1n << 63n, 0));
t('err biguint range', () => b.writeBigUInt64BE(-1n, 0));
const w = Buffer.alloc(8);
t('write', () => [w.write('hi'), w.toString('utf8', 0, 2)].join());
t('write offset', () => [w.write('xyz', 5), w.toString('latin1')].join('|'));
t('write offset length', () => [w.write('abcdef', 1, 3), w.toString('latin1', 0, 5)].join('|'));
t('write encoding', () => [w.write('ff00', 'hex'), w[0], w[1]].join());
t('write offset encoding', () => [w.write('ffee', 2, 'hex'), w[2], w[3]].join());
t('write partial utf8', () => [Buffer.alloc(2).write('€'), Buffer.alloc(4).write('a€'), Buffer.alloc(4).write('a€x')].join());
t('write ucs2', () => { const u = Buffer.alloc(3); return [u.write('ab', 'ucs2'), u[0], u[1], u[2]].join(); });
t('write base64', () => { const u = Buffer.alloc(4); return [u.write('aGk=', 'base64'), u.toString('latin1', 0, 2)].join(); });
t('write return chain', () => { const c = Buffer.alloc(8); let o = c.writeInt8(1, 0); o = c.writeInt16BE(2, o); o = c.writeFloatLE(3, o); return [o, c.readInt8(0), c.readInt16BE(1), c.readFloatLE(3)].join(); });
console.log(out.join('\n'));
"#;

const EXPECTED: &[&str] = &[
    "writeInt8 = 1,-5,251,251",
    "writeUint8 = 2,250,-6",
    "writeInt16LE = 4,-2,65534,65534,254,255",
    "writeInt16BE = 6,-300,65236,254,212",
    "writeUint16LE = 8,43981,52651",
    "writeUint32BE = 12,3735928559,4022250974,-559038737",
    "writeUint32LE = 16,4000000000",
    "IntLE = 6,-123456789,281474853253867,-6016277",
    "IntBE = 5,-2,1099511627774,65535",
    "UIntLE = 5,78187493530,78187493530,1",
    "UIntBE = 6,16777215,2,258",
    "Float = 4,1.5,8,-0.10000000149011612,-429496224",
    "Double = 8,3.141592653589793,16,-1e+300",
    "Double nan = 8,NaN,4,Infinity",
    "BigInt64 = 8,-5,18446744073709551611,18446744073709551611",
    "BigInt64BE = 16,4611686018427387904,4611686018427387904",
    "BigUInt64 = 8,18446744073709551615,-1,16,7",
    "err int8 range ! RangeError ERR_OUT_OF_RANGE The value of \"value\" is out of range. It must be >= -128 and <= 127. Received 200",
    "err int16 range ! RangeError ERR_OUT_OF_RANGE The value of \"value\" is out of range. It must be >= -32768 and <= 32767. Received -40000",
    "err uint32 range ! RangeError ERR_OUT_OF_RANGE The value of \"value\" is out of range. It must be >= 0 and <= 4294967295. Received 4294967296",
    "err intLE range ! RangeError ERR_OUT_OF_RANGE The value of \"value\" is out of range. It must be >= -(2 ** 47) and < 2 ** 47. Received 140_737_488_355_328",
    "err uintBE range ! RangeError ERR_OUT_OF_RANGE The value of \"value\" is out of range. It must be >= 0 and < 2 ** 40. Received -1",
    "err byteLength ! RangeError ERR_OUT_OF_RANGE The value of \"byteLength\" is out of range. It must be >= 1 and <= 6. Received 7",
    "err byteLength missing ! TypeError ERR_INVALID_ARG_TYPE The \"byteLength\" argument must be of type number. Received undefined",
    "err read offset ! RangeError ERR_OUT_OF_RANGE The value of \"offset\" is out of range. It must be >= 0 and <= 14. Received 15",
    "err write offset ! RangeError ERR_OUT_OF_RANGE The value of \"offset\" is out of range. It must be >= 0 and <= 8. Received 9",
    "err bigint type ! TypeError  Cannot mix BigInt and other types, use explicit conversions",
    "err bigint range ! RangeError ERR_OUT_OF_RANGE The value of \"value\" is out of range. It must be >= -(2n ** 63n) and < 2n ** 63n. Received 9_223_372_036_854_775_808n",
    "err biguint range ! RangeError ERR_OUT_OF_RANGE The value of \"value\" is out of range. It must be >= 0n and < 2n ** 64n. Received -1n",
    "write = 2,hi",
    "write offset = 3|hi\0\0\0xyz",
    "write offset length = 3|habc\0",
    "write encoding = 2,255,0",
    "write offset encoding = 2,255,238",
    "write partial utf8 = 0,4,4",
    "write ucs2 = 2,97,0,0",
    "write base64 = 2,hi",
    "write return chain = 7,1,2,3",
];

#[test]
fn buffer_numeric_accessors_and_write_match_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("buffer_numeric.mjs");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--goal",
            "module",
            "--extension-id",
            "buffer-numeric-accessors",
            "--out",
            report.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("frankenctl should execute");
    assert!(
        output.status.success(),
        "frankenctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("read report")).expect("json");
    let printed: Vec<String> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .flat_map(|message| message.split('\n').map(str::to_string))
        .collect();
    assert_eq!(printed, EXPECTED);
}
