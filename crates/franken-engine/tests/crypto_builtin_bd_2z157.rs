//! bd-2z157: deterministic Node `crypto` compute builtins.
//!
//! Entropy and key-generation operations deliberately remain outside this
//! surface. The lowering sentinel accepts only the bounded deterministic API
//! and keeps every unsupported/escaped/dynamic use on the ambient-authority
//! denial path.

use frankenengine_engine::HybridRouter;

fn eval_console(source: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(source)
        .unwrap_or_else(|error| panic!("eval failed for {source:?}: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn eval_error(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => panic!("expected eval failure for {source:?}, got {outcome:?}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn hash_algorithms_encodings_copy_and_invalid_algorithm_match_node() {
    let algorithms = eval_console(
        r#"
        const crypto = require('crypto');
        console.log(crypto.createHash('sha256').update('abc').digest('hex'));
        console.log(crypto.createHash('sha1').update('The quick brown fox jumps over the lazy dog').digest('hex'));
        console.log(crypto.createHash('sha512').update('abc').digest('hex').length);
        console.log(crypto.createHash('md5').update('hello world').digest('hex'));
        console.log(crypto.createHash('sha256').update('hello').digest('base64'));
        console.log(crypto.createHash('sha256').update('hello').digest('base64url'));
        "#,
    );
    let lifecycle = eval_console(
        r#"
        const crypto = require('crypto');
        console.log(crypto.createHash('sha256').update('616263', 'hex').digest('hex'));
        const hash = crypto.createHash('sha256').update('partial');
        const copy = hash.copy().update('-more');
        console.log(hash.digest('hex'));
        console.log(copy.digest('hex'));
        const raw = crypto.createHash('sha256').update('x').digest();
        console.log(Buffer.isBuffer(raw), raw.length, raw.toString('hex'));
        "#,
    );
    let invalid_inputs = eval_console(
        r#"
        const crypto = require('crypto');
        console.log(Buffer.isBuffer(crypto.createHash('sha256').update('x').digest('bogus')));
        console.log(Buffer.isBuffer(crypto.createHash('sha256').update('x').digest(7)));
        try { crypto.createHash('not-a-real-hash'); } catch (error) {
          console.log(error instanceof Error, typeof error.message);
        }
        "#,
    );
    let output = format!("{algorithms}\n{lifecycle}\n{invalid_inputs}");
    assert_eq!(
        output,
        concat!(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n",
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\n",
            "128\n",
            "5eb63bbbe01eeed093cb22bb8f5acdc3\n",
            "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=\n",
            "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ\n",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n",
            "9834a14ab9bcaa0f6a8da71073617eac8f004e596a3fa11d807b84631b825d9d\n",
            "a34ce16c09e919d5f545eac79e0e4dd2195a898e2ed131de71ab10618c129365\n",
            "true 32 2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881\n",
            "true\n",
            "true\n",
            "true string",
        )
    );
}

#[test]
fn hmac_algorithms_chaining_and_encodings_match_node() {
    let output = eval_console(
        r#"
        const crypto = require('node:crypto');
        console.log(crypto.createHmac('sha256', 'key').update('The quick brown fox jumps over the lazy dog').digest('hex'));
        console.log(crypto.createHmac('sha512', 'k2').update('part1').update('part2').digest('hex'));
        console.log(crypto.createHmac('sha256', Buffer.from('key1')).update('msg').digest('hex'));
        console.log(crypto.createHmac('sha256', 'abc').update('xyz').digest('base64'));
        const exhausted = crypto.createHmac('sha256', 'k').update('x');
        exhausted.digest('hex');
        console.log('[' + exhausted.digest('hex') + ']');
        "#,
    );
    assert_eq!(
        output,
        concat!(
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8\n",
            "e28bca2595fe7206a0973f874fb20bdbc581b9cdbd91403446b491bae0253cc1076ff827a12fd7e37dc73cc60deae699f7a0f717e2e92ee64d3c122104b3d096\n",
            "9feb8bc6c45130de39f391dd20c0f55054c55b22ce7e476cc41f6c21bc034a31\n",
            "wD0ImLdnMRMPPiE0s5uCTFPE5ipVs8AgpL5tWtpgYQI=\n",
            "[]",
        )
    );
}

#[test]
fn bound_hash_and_hmac_aliases_support_fluent_identity_chains() {
    let output = eval_console(
        r#"
        const crypto = require('crypto');
        const hash = crypto.createHash('sha256');
        console.log(hash.update('abc').digest('hex'));
        const copied = crypto.createHash('sha256');
        console.log(copied.copy().update('def').digest('hex'));
        const hmac = crypto.createHmac('sha256', 'public-key');
        console.log(hmac.update('ghi').digest('hex'));
        "#,
    );
    assert_eq!(
        output,
        concat!(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n",
            "cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34\n",
            "dff6cc07c467ff666087aa96ad09f909610a018378bac23758b62a20fbfb634c",
        )
    );
}

#[test]
fn hmac_secret_literal_remains_fail_closed_pending_authenticator_egress_contract() {
    let error = eval_error(
        r#"
        const crypto = require('crypto');
        console.log(crypto.createHmac('sha1', 'secret').update('message').digest('hex'));
        "#,
    );
    assert!(error.contains("unauthorized flow detected"));
    assert!(error.contains("Secret -> Internal"));
}

#[test]
fn timing_safe_equal_and_length_error_match_node() {
    let output = eval_console(
        r#"
        const crypto = require('crypto');
        console.log(crypto.timingSafeEqual(Buffer.from('same'), Buffer.from('same')));
        console.log(crypto.timingSafeEqual(Buffer.from('same'), Buffer.from('diff')));
        try { crypto.timingSafeEqual(Buffer.from('ab'), Buffer.from('abc')); } catch (error) { console.log(error instanceof RangeError, error.code); }
        try { crypto.timingSafeEqual('same', 'same'); } catch (error) { console.log(error instanceof TypeError, error.code); }
        console.log(crypto.timingSafeEqual(new Uint32Array([1, 2]), new Uint32Array([1, 2])));
        const leftBuffer = new ArrayBuffer(4), rightBuffer = new ArrayBuffer(4);
        console.log(crypto.timingSafeEqual(leftBuffer, rightBuffer));
        console.log(crypto.timingSafeEqual(new DataView(leftBuffer), new DataView(rightBuffer)));
        "#,
    );
    assert_eq!(
        output,
        concat!(
            "true\nfalse\ntrue ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH\n",
            "true ERR_INVALID_ARG_TYPE\ntrue\ntrue\ntrue",
        )
    );
}

#[test]
fn typed_array_view_and_binary_like_input_domains_match_node() {
    let words_hash = eval_console(
        r#"
        const crypto = require('crypto');
        const words = new Uint32Array([0x64636261]);
        console.log(crypto.createHash('sha256').update(words).digest('hex'));
        "#,
    );
    let data_view_hash = eval_console(
        r#"
        const crypto = require('crypto');
        const binary = new ArrayBuffer(4);
        const view = new DataView(binary, 1, 2);
        console.log(crypto.createHash('sha256').update(view).digest('hex'));
        "#,
    );
    let raw_array_buffer = eval_console(
        r#"
        const crypto = require('crypto');
        const binary = new ArrayBuffer(4);
        try {
          const arrayBufferHash = crypto.createHash('sha256');
          arrayBufferHash.update(binary);
        } catch (error) {
          console.log(error instanceof TypeError);
        }
        "#,
    );
    let hmac = eval_console(
        r#"
        const crypto = require('crypto');
        const binary = new ArrayBuffer(4);
        console.log(crypto.createHmac('sha256', binary).update(new Uint32Array([0x64636261])).digest('hex'));
        "#,
    );
    let pbkdf2 = eval_console(
        r#"
        const crypto = require('crypto');
        const binary = new ArrayBuffer(4);
        const view = new DataView(binary, 1, 2);
        console.log(crypto.pbkdf2Sync(binary, view, 1, 8, 'sha256').toString('hex'));
        "#,
    );
    let cipher = eval_console(
        r#"
        const crypto = require('crypto');
        const words = new Uint32Array([0x64636261]);
        const key = new ArrayBuffer(16), iv = new ArrayBuffer(16);
        console.log(crypto.createCipheriv('aes-128-ctr', key, iv).update(words).toString('hex'));
        "#,
    );
    let output =
        format!("{words_hash}\n{data_view_hash}\n{raw_array_buffer}\n{hmac}\n{pbkdf2}\n{cipher}");
    assert_eq!(
        output,
        concat!(
            "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589\n",
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7\n",
            "true\n",
            "527ff4c28c22a090fe39908139363e81b8fb10d0695a135518006abfa21cf5a2\n",
            "daeeaa96898b01b2\n",
            "078b28b0",
        )
    );
}

#[test]
fn deterministic_kdfs_and_deferred_pbkdf2_callback_match_node() {
    let sync_output = eval_console(
        r#"
        const crypto = require('crypto');
        console.log(crypto.pbkdf2Sync('public-input', 'salt', 1000, 32, 'sha256').toString('hex'));
        console.log(crypto.pbkdf2Sync('public-input', 'salt', 1, 16, 'md5').toString('hex'));
        console.log(crypto.scryptSync('public-input', 'salt', 24).toString('hex'));
        console.log(crypto.scryptSync('public', 'na', 16, { N: 1024, r: 8, p: 1 }).toString('hex'));
        "#,
    );
    let callback_output = eval_console(
        r#"
        const crypto = require('crypto');
        crypto.pbkdf2('public', 's', 100, 8, 'sha256', (error, key) => {
          console.log(error === null, key.toString('hex'));
        });
        console.log('sync');
        "#,
    );
    let output = format!("{sync_output}\n{callback_output}");
    assert_eq!(
        output,
        concat!(
            "affdbc2c4fc47057c7278bd62bb1c15ed6bca26f05280c54b3d173345fc9c1f1\n",
            "1b6e1bf14f036ef158d04dfa027b3141\n",
            "37cf38cf02b5aa9a8c50dad1a7414d099b00adca7e92b1ef\n",
            "44765af2861d2c8109d1905367567d32\n",
            "sync\n",
            "true 276926b235f3d05b",
        )
    );
}

#[test]
fn aes_cbc_ctr_gcm_and_bad_padding_match_node() {
    let cbc_roundtrip = eval_console(
        r#"
        const crypto = require('crypto');
        const cbcKey = Buffer.alloc(32, 1), cbcIv = Buffer.alloc(16, 2);
        const cbc = crypto.createCipheriv('aes-256-cbc', cbcKey, cbcIv);
        const cbcText = Buffer.concat([cbc.update('plain message', 'utf8'), cbc.final()]);
        console.log(cbcText.toString('hex'), cbcText.length);
        const cbcDec = crypto.createDecipheriv('aes-256-cbc', cbcKey, cbcIv);
        console.log(Buffer.concat([cbcDec.update(cbcText), cbcDec.final()]).toString());
        "#,
    );
    let bad_padding = eval_console(
        r#"
        const crypto = require('crypto');
        const cbcText = Buffer.from('0c276227d7db10379bfbb334ea96a5fc', 'hex');
        const bad = crypto.createDecipheriv('aes-256-cbc', Buffer.alloc(32, 2), Buffer.alloc(16, 2));
        try {
          bad.update(cbcText);
          bad.final();
        } catch (error) { console.log(error instanceof Error); }
        "#,
    );
    let finalized_final = eval_console(
        r#"
        const crypto = require('crypto');
        const cbcText = Buffer.from('0c276227d7db10379bfbb334ea96a5fc', 'hex');
        const bad = crypto.createDecipheriv('aes-256-cbc', Buffer.alloc(32, 2), Buffer.alloc(16, 2));
        try { bad.update(cbcText); bad.final(); } catch (error) {}
        try { bad.final(); } catch (error) { console.log(error.code); }
        "#,
    );
    let finalized_update = eval_console(
        r#"
        const crypto = require('crypto');
        const cbcText = Buffer.from('0c276227d7db10379bfbb334ea96a5fc', 'hex');
        const bad = crypto.createDecipheriv('aes-256-cbc', Buffer.alloc(32, 2), Buffer.alloc(16, 2));
        try { bad.update(cbcText); bad.final(); } catch (error) {}
        try { bad.update('retry'); } catch (error) { console.log(error instanceof Error); }
        "#,
    );
    let wrong_final_length = eval_console(
        r#"
        const crypto = require('crypto');
        const empty = crypto.createDecipheriv('aes-256-cbc', Buffer.alloc(32, 1), Buffer.alloc(16, 2));
        try { empty.final(); } catch (error) { console.log(error.code); }
        "#,
    );
    let cbc_blocks = eval_console(
        r#"
        const crypto = require('crypto');
        const cbcKey = Buffer.alloc(32, 1), cbcIv = Buffer.alloc(16, 2);
        const blocks = crypto.createCipheriv('aes-256-cbc', cbcKey, cbcIv);
        const block1 = blocks.update('1234567890123456');
        const block2 = blocks.update('x');
        const block3 = blocks.final();
        console.log(block1.length, block2.length, block3.length);
        const blockText = Buffer.concat([block1, block2, block3]);
        const blockDec = crypto.createDecipheriv('aes-256-cbc', cbcKey, cbcIv);
        const plain1 = blockDec.update(blockText);
        const plain2 = blockDec.final();
        console.log(plain1.length, plain2.length);
        "#,
    );
    let cbc_output = format!(
        "{cbc_roundtrip}\n{bad_padding}\n{finalized_final}\n{finalized_update}\n{wrong_final_length}\n{cbc_blocks}"
    );
    let ctr_output = eval_console(
        r#"
        const crypto = require('crypto');
        const key = Buffer.alloc(16, 3), iv = Buffer.alloc(16, 4);
        const cipher = crypto.createCipheriv('aes-128-ctr', key, iv);
        const encrypted = Buffer.concat([cipher.update('stream mode'), cipher.final()]);
        console.log(encrypted.toString('hex'));
        const decipher = crypto.createDecipheriv('aes-128-ctr', key, iv);
        console.log(Buffer.concat([decipher.update(encrypted), decipher.final()]).toString());
        const encoded = crypto.createCipheriv('aes-128-ctr', key, iv);
        console.log('[' + encoded.update('a', 'utf8', 'base64') + ']');
        console.log('[' + encoded.update('b', 'utf8', 'base64') + ']');
        console.log(encoded.update('c', 'utf8', 'base64'));
        console.log('[' + encoded.final('base64') + ']');
        const invalidEncoding = crypto.createCipheriv('aes-128-ctr', key, iv);
        try { invalidEncoding.update('a', 'utf8', 'bogus'); } catch (error) { console.log(error.code); }
        console.log(invalidEncoding.update('b').toString('hex'));
        const nonStringEncoding = crypto.createCipheriv('aes-128-ctr', key, iv);
        try { nonStringEncoding.update('a', 'utf8', 7); } catch (error) { console.log(error.code); }
        const utf8Carry = crypto.createCipheriv('aes-128-ctr', key, iv);
        console.log('[' + utf8Carry.update('.', 'latin1', 'utf8') + ']');
        console.log('[' + utf8Carry.final('utf8') + ']');
        "#,
    );
    let gcm_output = eval_console(
        r#"
        const crypto = require('crypto');
        const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.alloc(32, 5), Buffer.alloc(12, 6));
        const encrypted = Buffer.concat([cipher.update('gcm data'), cipher.final()]);
        const tag = cipher.getAuthTag();
        console.log(encrypted.toString('hex'), tag.toString('hex'));
        const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.alloc(32, 5), Buffer.alloc(12, 6));
        const unauthenticated = decipher.update(encrypted);
        console.log(unauthenticated.length);
        decipher.setAuthTag(tag);
        console.log(Buffer.concat([unauthenticated, decipher.final()]).toString());
        const tampered = crypto.createDecipheriv('aes-256-gcm', Buffer.alloc(32, 5), Buffer.alloc(12, 6));
        tampered.update(encrypted);
        tampered.setAuthTag(Buffer.alloc(16));
        try { tampered.final(); } catch (error) { console.log(error instanceof Error); }
        try { tampered.final(); } catch (error) { console.log(error.code); }
        const missing = crypto.createDecipheriv('aes-256-gcm', Buffer.alloc(32, 5), Buffer.alloc(12, 6));
        missing.update(encrypted);
        try { missing.final(); } catch (error) { console.log(error instanceof Error); }
        try { missing.final(); } catch (error) { console.log(error.code); }
        "#,
    );
    assert_eq!(
        cbc_output,
        concat!(
            "0c276227d7db10379bfbb334ea96a5fc 16\n",
            "plain message\n",
            "true\n",
            "ERR_CRYPTO_INVALID_STATE\n",
            "true\n",
            "ERR_OSSL_WRONG_FINAL_BLOCK_LENGTH\n",
            "16 0 16\n",
            "16 1",
        )
    );
    assert_eq!(
        ctr_output,
        concat!(
            "9d19f8e0ce7d836ac08c67\n",
            "stream mode\n",
            "[]\n",
            "[]\n",
            "jw/p\n",
            "[]\n",
            "ERR_UNKNOWN_ENCODING\n",
            "0f\n",
            "ERR_UNKNOWN_ENCODING\n",
            "[]\n",
            "[�]",
        )
    );
    assert_eq!(
        gcm_output,
        concat!(
            "fdd817513de8966c ed2b3196299afe4fb77be4c29a0eb87f\n",
            "0\n",
            "gcm data\n",
            "true\n",
            "ERR_CRYPTO_INVALID_STATE\n",
            "true\n",
            "ERR_CRYPTO_INVALID_STATE",
        )
    );
}

#[test]
fn secret_markers_remain_fail_closed_across_kdf_and_cipher_egress() {
    for source in [
        "const c=require('crypto'); console.log(c.pbkdf2Sync('password','salt',10,8,'sha256').toString('hex'));",
        "const c=require('crypto'); console.log(c.scryptSync('password','salt',8).toString('hex'));",
        "const c=require('crypto'); const x=c.createCipheriv('aes-256-cbc',Buffer.alloc(32,1),Buffer.alloc(16,2)); console.log(Buffer.concat([x.update('secret message'),x.final()]).toString('hex'));",
        "const c=require('crypto'); const x=c.createCipheriv('aes-256-gcm',Buffer.alloc(32,1),Buffer.alloc(12,2)); x.update('secret payload'); x.final(); console.log(x.getAuthTag().toString('hex'));",
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("unauthorized flow detected"),
            "secret-bearing crypto output must remain fail closed for {source:?}: {error}"
        );
    }
}

#[test]
fn metadata_constants_and_static_invalid_random_int_match_node() {
    let output = eval_console(
        r#"
        const crypto = require('crypto');
        console.log(crypto.constants.RSA_PKCS1_PADDING);
        console.log(crypto.getHashes().includes('sha256'), crypto.getHashes().includes('sha512'));
        console.log(crypto.getCiphers().includes('aes-256-cbc'), crypto.getCiphers().includes('aes-128-ctr'));
        try { crypto.randomInt(5, 5); } catch (error) { console.log(error instanceof RangeError, error.code); }
        "#,
    );
    assert_eq!(output, "1\ntrue true\ntrue true\ntrue ERR_OUT_OF_RANGE");
}

#[test]
fn entropy_asymmetric_dynamic_and_escaped_uses_remain_fail_closed() {
    for source in [
        "const crypto = require('crypto'); crypto.randomBytes(8);",
        "const crypto = require('crypto'); crypto.randomUUID();",
        "const crypto = require('crypto'); crypto.randomFillSync(Buffer.alloc(8));",
        "const crypto = require('crypto'); crypto.randomInt(10);",
        "const crypto = require('crypto'); const lo = 5, hi = 5; crypto.randomInt(lo, hi);",
        "const crypto = require('crypto'); crypto.generateKeyPairSync('ed25519');",
        "const crypto = require('crypto'); crypto.createSign('sha256');",
        "const crypto = require('crypto'); crypto;",
        "const crypto = require('crypto'); crypto['createHash']('sha256');",
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("require")
                || error.contains("ambient")
                || error.contains("capability")
                || error.contains("module"),
            "unexpected fail-closed error for {source:?}: {error}"
        );
    }
}

#[test]
fn computed_escaped_and_excluded_fluent_crypto_objects_cannot_dynamic_dispatch() {
    for source in [
        "const c=require('crypto'); const h=c.createHash('sha256'); h['update']('x');",
        "const c=require('crypto'); const h=c.createHash('sha256'); function id(x){return x} const e=id(h); e.update('x');",
        "const c=require('crypto'); const d=c.createDecipheriv('aes-256-gcm',Buffer.alloc(32),Buffer.alloc(12)); d.setAuthTag(Buffer.alloc(16)).final();",
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("call")
                || error.contains("function")
                || error.contains("undefined")
                || error.contains("ambient")
                || error.contains("capability"),
            "rejected crypto-object use unexpectedly escaped the finite dispatch boundary for {source:?}: {error}"
        );
    }
}
