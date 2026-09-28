//! ES2020 24.3.4: DataView.prototype get/set for Int8, Int16, Uint16,
//! Float32, Float64, BigInt64 and BigUint64 (the engine only had the Uint8,
//! Int32 and Uint32 accessors; `dv.setFloat64` was undefined, which failed the
//! probe corpus's typed-array case and 5 Test262 sample tests). Covers both
//! byte orders, sign handling, ToBigInt (a Number is a TypeError) and the
//! out-of-range RangeError. Expected string is Node v22.2.0's output.

use frankenengine_engine::HybridRouter;

#[test]
fn data_view_accessors_cover_every_element_type() {
    let source = "const b = new ArrayBuffer(16); const dv = new DataView(b); const u = new Uint8Array(b);\n\
                  dv.setFloat64(0, Math.PI); const pi = [u[0], u[7], dv.getFloat64(0), dv.getFloat64(0, true) !== Math.PI];\n\
                  dv.setFloat32(8, 1.1, true); const f32 = [dv.getFloat32(8, true), u[8], u[11]];\n\
                  dv.setInt16(0, -2); dv.setUint16(2, 65535, true); \
                  const i16 = [dv.getInt16(0), dv.getUint16(0), dv.getUint16(2, true), dv.getInt16(2, true), u[0], u[1]];\n\
                  dv.setInt8(4, -1); dv.setInt8(5, 200); const i8 = [dv.getInt8(4), dv.getUint8(4), dv.getInt8(5)];\n\
                  dv.setBigInt64(8, -2n); dv.setBigUint64(0, 18446744073709551615n, true); \
                  const big = [String(dv.getBigInt64(8)), String(dv.getBigUint64(8)), \
                  String(dv.getBigUint64(0, true)), String(dv.getBigInt64(0))];\n\
                  let errs = []; for (const f of [() => dv.setBigInt64(0, 1), () => dv.getFloat64(12), \
                  () => dv.setInt16(15, 1)]) { try { f(); errs.push('ok'); } catch (e) { errs.push(e.constructor.name); } }\n\
                  [pi.join(' '), f32.join(' '), i16.join(' '), i8.join(' '), big.join(' '), errs.join(' '), \
                  DataView.prototype.getFloat64.name, DataView.prototype.setBigInt64.length].join('|');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "64 24 3.141592653589793 true|1.100000023841858 205 63|-2 65534 65535 -1 255 254|\
         -1 255 -56|-2 18446744073709551614 18446744073709551615 -1|TypeError RangeError RangeError|\
         getFloat64|2"
    );
}
