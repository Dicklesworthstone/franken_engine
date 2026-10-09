//! bd-9vouw.308: `Buffer.isEncoding(encoding)` answers whether `encoding`
//! is a string naming one of Buffer's encodings, ignoring case; it was
//! missing (`typeof Buffer.isEncoding` was "undefined"). Node v22.2.0 gives
//! this value; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn buffer_is_encoding_matches_node() {
    let source = "[Buffer.isEncoding('utf8'), Buffer.isEncoding('UTF-8'), Buffer.isEncoding('hex'), \
                  Buffer.isEncoding('Base64url'), Buffer.isEncoding('binary'), Buffer.isEncoding('nope'), \
                  Buffer.isEncoding(''), Buffer.isEncoding(1), Buffer.isEncoding(), typeof Buffer.isEncoding, \
                  Buffer.isEncoding.length, Buffer.isEncoding.name].join(' ');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "true true true true true false false false false function 1 isEncoding"
    );
}
