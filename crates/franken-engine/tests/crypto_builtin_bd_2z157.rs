//! bd-2z157 / bd-opsnv: bounded Node `crypto` builtins.
//!
//! Deterministic operations stay compute-only. Authenticated entropy operations
//! require the separate `random_read` capability and cross the typed host-I/O
//! journal; asymmetric, unsupported, escaped, mutated, computed, and inline
//! require uses remain on the ambient-authority denial path.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use frankenengine_engine::HybridRouter;
use frankenengine_engine::baseline_interpreter::InterpreterError;
use frankenengine_engine::declassification_pipeline::{
    AuthenticationPolicy, CryptographicCipherAlgorithm, CryptographicCipherMode,
    CryptographicKeyPurpose, CryptographicReleaseSink, CryptographicTransformOutputClass,
    CryptographicTransformReleaseContext, CryptographicTransformReleaseError,
    CryptographicTransformReleaseGuard, CryptographicTransformReleaseRequest,
    DeclassificationPipeline, LossAssessment,
};
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt as _,
    OrchestratorConfig, OrchestratorError, OrchestratorResult,
};
use frankenengine_engine::ifc_artifacts::{
    DeclassificationRoute, FlowPolicy, FlowPolicyEnforcement, IfcSchemaVersion, Label,
};
use frankenengine_engine::lowering_pipeline::LoweringPipelineError;
use frankenengine_engine::signature_preimage::{SIGNATURE_SENTINEL, Signature, SigningKey};
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoError, HostIoOutcome, HostIoProvider, HostIoRecorder, HostIoRequest,
    HostIoResponse, InMemoryHostIoTranscript,
};

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

#[derive(Debug)]
struct ScriptedRandomHostIo {
    outcomes: Mutex<VecDeque<HostIoOutcome>>,
    calls: AtomicUsize,
    panic_on_call: bool,
}

impl ScriptedRandomHostIo {
    fn bytes(responses: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            outcomes: Mutex::new(
                responses
                    .into_iter()
                    .map(|bytes| Ok(HostIoResponse::RandomRead { bytes }))
                    .collect(),
            ),
            calls: AtomicUsize::new(0),
            panic_on_call: false,
        }
    }

    fn denying(count: usize) -> Self {
        Self {
            outcomes: Mutex::new(
                (0..count)
                    .map(|_| {
                        Err(HostIoError::Denied {
                            reason: "test entropy source denied".to_string(),
                        })
                    })
                    .collect(),
            ),
            calls: AtomicUsize::new(0),
            panic_on_call: false,
        }
    }

    fn never() -> Self {
        Self {
            outcomes: Mutex::new(VecDeque::new()),
            calls: AtomicUsize::new(0),
            panic_on_call: true,
        }
    }
}

impl HostIoProvider for ScriptedRandomHostIo {
    fn name(&self) -> &str {
        "scripted-random-host-io"
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        assert!(!self.panic_on_call, "replay must not consult live entropy");
        self.calls.fetch_add(1, Ordering::AcqRel);
        assert_eq!(granted, &[HostIoCapability::RandomRead]);
        assert!(matches!(request, HostIoRequest::RandomRead { .. }));
        self.outcomes
            .lock()
            .expect("scripted entropy queue")
            .pop_front()
            .unwrap_or_else(|| {
                Err(HostIoError::Denied {
                    reason: "scripted entropy exhausted".to_string(),
                })
            })
    }
}

fn crypto_package(source: &str, grant_random_read: bool) -> ExtensionPackage {
    let mut capabilities = vec!["builtin".to_string(), "timer".to_string()];
    if grant_random_read {
        capabilities.push("random_read".to_string());
    }
    ExtensionPackage {
        extension_id: "bd-opsnv-crypto-entropy".to_string(),
        source: source.to_string(),
        source_file: None,
        module_root: None,
        capabilities,
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn execute_crypto(
    source: &str,
    provider: Arc<dyn HostIoProvider>,
    recorder: Arc<dyn HostIoRecorder>,
) -> OrchestratorResult {
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_host_io(provider, Some(recorder));
    orchestrator
        .execute(&crypto_package(source, true))
        .unwrap_or_else(|error| panic!("orchestrated crypto eval failed for {source:?}: {error}"))
}

fn orchestrated_console(result: &OrchestratorResult) -> String {
    result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

const CRYPTO_RELEASE_TIME_MS: u64 = 1_700_000_000_000;

fn crypto_release_policy() -> FlowPolicy {
    FlowPolicy {
        policy_id: "crypto-release-policy".to_string(),
        extension_id: "crypto-release-extension".to_string(),
        label_classes: [Label::Public, Label::Secret].into_iter().collect(),
        clearance_classes: [Label::Public, Label::Secret].into_iter().collect(),
        allowed_flows: vec![],
        prohibited_flows: vec![],
        declassification_routes: vec![DeclassificationRoute {
            route_id: "crypto.ciphertext.release".to_string(),
            source_label: Label::Secret,
            target_clearance: Label::Public,
            conditions: vec!["authenticated_ciphertext_only".to_string()],
        }],
        enforcement_mode: FlowPolicyEnforcement::LatticeOpen,
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    }
}

fn low_crypto_release_loss() -> LossAssessment {
    LossAssessment {
        expected_loss_milli: 1_000,
        data_sensitivity_bps: 8_000,
        sink_exposure_bps: 2_000,
        historical_abuse_detected: false,
        summary: "authenticated ciphertext only".to_string(),
    }
}

fn gcm_release_request() -> CryptographicTransformReleaseRequest {
    CryptographicTransformReleaseRequest {
        request_id: "crypto-release-1".to_string(),
        extension_id: "crypto-release-extension".to_string(),
        output_class: CryptographicTransformOutputClass::Ciphertext,
        output_bytes: vec![0xfd, 0xd8, 0x17, 0x51, 0x3d, 0xe8, 0x96, 0x6c],
        source_labels: vec![Label::Secret],
        sink_clearance: Label::Public,
        requested_route_id: "crypto.ciphertext.release".to_string(),
        decision_contract_id: "crypto-release-contract".to_string(),
        algorithm: CryptographicCipherAlgorithm::Aes,
        mode: CryptographicCipherMode::Gcm,
        key_purpose: CryptographicKeyPurpose::DataEncryption,
        key_strength_bits: 256,
        iv_nonce_policy:
            frankenengine_engine::declassification_pipeline::IvNoncePolicy::UniquePerKey,
        iv_or_nonce: vec![2; 12],
        authentication_policy: AuthenticationPolicy::AeadTag128,
        authentication_tag: vec![3; 16],
        sink: CryptographicReleaseSink::Console,
        site: "crypto_builtin_bd_2z157::console.log".to_string(),
        replay_identity: "eval-crypto-release-1".to_string(),
        timestamp_ms: CRYPTO_RELEASE_TIME_MS,
    }
}

fn release_context(
    request: &CryptographicTransformReleaseRequest,
) -> CryptographicTransformReleaseContext {
    CryptographicTransformReleaseContext {
        extension_id: request.extension_id.clone(),
        source_labels: request.source_labels.clone(),
        sink_clearance: request.sink_clearance.clone(),
        declassification_route_ref: request.requested_route_id.clone(),
        decision_contract_id: request.decision_contract_id.clone(),
        algorithm: request.algorithm,
        mode: request.mode,
        key_purpose: request.key_purpose,
        key_strength_bits: request.key_strength_bits,
        iv_nonce_policy: request.iv_nonce_policy,
        iv_or_nonce: request.iv_or_nonce.clone(),
        authentication_policy: request.authentication_policy,
        authentication_tag: request.authentication_tag.clone(),
        sink: request.sink.clone(),
        site: request.site.clone(),
        replay_identity: request.replay_identity.clone(),
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
fn plaintext_raw_kdf_and_unauthenticated_ciphertext_cannot_obtain_release_receipts() {
    let signing_key = SigningKey::from_bytes([73; 32]).expect("valid signing key");
    let policy = crypto_release_policy();
    let loss = low_crypto_release_loss();
    let mut pipeline = DeclassificationPipeline::default();

    let mut plaintext_request = gcm_release_request();
    plaintext_request.output_class = CryptographicTransformOutputClass::Plaintext;
    assert_eq!(
        pipeline.process_cryptographic_transform_release(
            &plaintext_request,
            &policy,
            &loss,
            &signing_key,
        ),
        Err(CryptographicTransformReleaseError::PlaintextReleaseDenied)
    );

    let mut kdf_request = gcm_release_request();
    kdf_request.output_class = CryptographicTransformOutputClass::DerivedKeyMaterial;
    kdf_request.key_purpose = CryptographicKeyPurpose::KeyDerivation;
    assert_eq!(
        pipeline.process_cryptographic_transform_release(
            &kdf_request,
            &policy,
            &loss,
            &signing_key,
        ),
        Err(CryptographicTransformReleaseError::DerivedKeyMaterialReleaseDenied)
    );

    let mut cbc_request = gcm_release_request();
    cbc_request.mode = CryptographicCipherMode::Cbc;
    cbc_request.iv_nonce_policy =
        frankenengine_engine::declassification_pipeline::IvNoncePolicy::Fixed;
    cbc_request.iv_or_nonce = vec![2; 16];
    cbc_request.authentication_policy = AuthenticationPolicy::None;
    cbc_request.authentication_tag.clear();
    assert_eq!(
        pipeline.process_cryptographic_transform_release(
            &cbc_request,
            &policy,
            &loss,
            &signing_key,
        ),
        Err(CryptographicTransformReleaseError::UnauthenticatedCiphertextReleaseDenied)
    );
    assert!(pipeline.cryptographic_transform_receipts().is_empty());
}

#[test]
fn exact_authenticated_ciphertext_receipt_is_sink_bound_and_one_use() {
    let signing_key = SigningKey::from_bytes([74; 32]).expect("valid signing key");
    let request = gcm_release_request();
    let mut pipeline = DeclassificationPipeline::default();
    let receipt = pipeline
        .process_cryptographic_transform_release(
            &request,
            &crypto_release_policy(),
            &low_crypto_release_loss(),
            &signing_key,
        )
        .expect("valid AES-256-GCM ciphertext should receive exact release authorization");
    assert_eq!(
        pipeline.cryptographic_transform_receipts(),
        std::slice::from_ref(&receipt)
    );
    receipt
        .verify(&signing_key.verification_key())
        .expect("receipt signature must cover the transform contract");

    let mut guard = CryptographicTransformReleaseGuard::default();
    guard.trust_authorizer_for_contract(
        request.decision_contract_id.clone(),
        signing_key.verification_key(),
    );
    let context = release_context(&request);

    let mut wrong_site = context.clone();
    wrong_site.site = "different::network_sink".to_string();
    assert_eq!(
        guard.release_ciphertext(
            &receipt,
            &request.output_bytes,
            &wrong_site,
            CRYPTO_RELEASE_TIME_MS,
        ),
        Err(CryptographicTransformReleaseError::ContextMismatch { field: "site" })
    );
    let mut wrong_route = context.clone();
    wrong_route.declassification_route_ref = "different.route".to_string();
    assert_eq!(
        guard.release_ciphertext(
            &receipt,
            &request.output_bytes,
            &wrong_route,
            CRYPTO_RELEASE_TIME_MS,
        ),
        Err(CryptographicTransformReleaseError::ContextMismatch {
            field: "declassification_route_ref"
        })
    );
    assert_eq!(
        guard.release_ciphertext(
            &receipt,
            b"tampered ciphertext",
            &context,
            CRYPTO_RELEASE_TIME_MS,
        ),
        Err(CryptographicTransformReleaseError::OutputMismatch)
    );

    let released = guard
        .release_ciphertext(
            &receipt,
            &request.output_bytes,
            &context,
            CRYPTO_RELEASE_TIME_MS,
        )
        .expect("exact receipt should release only its bound ciphertext");
    assert_eq!(released, request.output_bytes);
    assert_eq!(
        guard.release_ciphertext(&receipt, &released, &context, CRYPTO_RELEASE_TIME_MS,),
        Err(CryptographicTransformReleaseError::ReplayDetected)
    );

    let mut second_request = request.clone();
    second_request.request_id = "crypto-release-2".to_string();
    let second_receipt = pipeline
        .process_cryptographic_transform_release(
            &second_request,
            &crypto_release_policy(),
            &low_crypto_release_loss(),
            &signing_key,
        )
        .expect("a distinct receipt can be issued for replay rejection coverage");
    assert_eq!(
        guard.release_ciphertext(
            &second_receipt,
            &second_request.output_bytes,
            &release_context(&second_request),
            CRYPTO_RELEASE_TIME_MS,
        ),
        Err(CryptographicTransformReleaseError::ReplayDetected),
        "a new receipt ID must not bypass one-use replay identity consumption"
    );
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
fn asymmetric_inline_and_escaped_uses_remain_fail_closed() {
    for source in [
        "require('crypto').randomBytes(8);",
        "require('crypto').randomUUID();",
        "require('crypto').randomFillSync(Buffer.alloc(8));",
        "require('crypto').randomInt(10);",
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
fn authenticated_entropy_apis_use_typed_ordered_host_effects_bd_opsnv() {
    let source = r#"
        const crypto = require('crypto');
        crypto.randomBytes(16);
        crypto.randomBytes(0);
        crypto.randomUUID();
        crypto.randomInt(10);
        crypto.randomInt(5, 8);
        crypto.randomFillSync(Buffer.alloc(8));
    "#;
    let provider = Arc::new(ScriptedRandomHostIo::bytes([
        vec![0x11; 16],
        vec![0; 16],
        vec![0; 6],
        vec![0; 6],
        vec![0x5a; 8],
    ]));
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    let result = execute_crypto(source, provider.clone(), recorder_dyn);

    assert_eq!(orchestrated_console(&result), "");
    assert_eq!(provider.calls.load(Ordering::Acquire), 5);
    assert_eq!(result.host_effect_transcript, recorder.recorded_entries());
    let lengths = result
        .host_effect_transcript
        .iter()
        .map(|(request, outcome)| match (request, outcome) {
            (HostIoRequest::RandomRead { byte_len }, Ok(HostIoResponse::RandomRead { bytes })) => {
                assert_eq!(*byte_len as usize, bytes.len());
                *byte_len
            }
            other => panic!("unexpected entropy transcript entry: {other:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(lengths, vec![16, 16, 6, 6, 8]);
}

#[test]
fn entropy_egress_requires_declassification_before_host_effect_bd_z1peg() {
    let provider = Arc::new(ScriptedRandomHostIo::never());
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_host_io(provider.clone(), Some(recorder_dyn));

    let error = orchestrator
        .execute(&crypto_package(
            "const crypto = require('crypto'); console.log(crypto.randomUUID());",
            true,
        ))
        .expect_err("Secret entropy must not flow directly to an Internal console sink");
    let primary_error = error.primary_error();
    assert!(
        matches!(
            primary_error,
            OrchestratorError::Lowering(lowering_error)
                if matches!(
                    lowering_error.as_ref(),
                    LoweringPipelineError::UnauthorizedFlow {
                        source_label: Label::Secret,
                        sink_clearance: Label::Internal,
                        ..
                    }
                )
        ),
        "entropy egress must retain its typed IFC denial, got {primary_error:?}"
    );
    assert_eq!(provider.calls.load(Ordering::Acquire), 0);
    assert!(
        recorder.recorded_entries().is_empty(),
        "static IFC denial must happen before a host entropy request exists"
    );
}

#[test]
fn random_int_rejection_sampling_discards_biased_tail_bd_opsnv() {
    let source = "const crypto = require('crypto'); crypto.randomInt(10);";
    let provider = Arc::new(ScriptedRandomHostIo::bytes([vec![0xff; 6], vec![0; 6]]));
    let recorder: Arc<dyn HostIoRecorder> = Arc::new(InMemoryHostIoTranscript::recording());
    let result = execute_crypto(source, provider.clone(), recorder);
    assert_eq!(orchestrated_console(&result), "");
    assert_eq!(provider.calls.load(Ordering::Acquire), 2);
    assert_eq!(result.host_effect_transcript.len(), 2);
}

#[test]
fn entropy_callbacks_are_err_first_and_deferred_bd_opsnv() {
    let source = r#"
        const crypto = require('crypto');
        const order = [];
        crypto.randomBytes(4, (error, bytes) => {
          if (error !== null || !Buffer.isBuffer(bytes) || bytes.length !== 4) {
            throw new Error('invalid randomBytes callback');
          }
          order.push('bytes');
        });
        crypto.randomInt(3, (error, value) => {
          if (error !== null || !Number.isInteger(value) || value < 0 || value >= 3) {
            throw new Error('invalid randomInt callback');
          }
          order.push('int');
        });
        order.push('sync');
        crypto.randomBytes(0, (error, bytes) => {
          if (error !== null || !Buffer.isBuffer(bytes) || bytes.length !== 0) {
            throw new Error('invalid zero-length randomBytes callback');
          }
          if (order.join(',') !== 'sync,bytes,int') {
            throw new Error(`unexpected callback order: ${order.join(',')}`);
          }
          throw new Error('bd-z1peg entropy callbacks completed in order');
        });
    "#;
    let provider = Arc::new(ScriptedRandomHostIo::bytes([vec![1, 2, 3, 4], vec![0; 6]]));
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_host_io(provider.clone(), Some(recorder_dyn));
    let error = orchestrator
        .execute(&crypto_package(source, true))
        .expect_err("the final I/O callback must publish its success sentinel");
    assert!(matches!(
        error.primary_error(),
        OrchestratorError::Interpreter(InterpreterError::UncaughtException { value })
            if value == "Error: bd-z1peg entropy callbacks completed in order"
    ));
    assert_eq!(provider.calls.load(Ordering::Acquire), 2);
    assert_eq!(recorder.recorded_entries().len(), 2);
}

#[test]
fn entropy_provider_failures_are_redacted_and_err_first_bd_opsnv() {
    let provider = Arc::new(ScriptedRandomHostIo::denying(2));

    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    let synchronous_recorder: Arc<dyn HostIoRecorder> =
        Arc::new(InMemoryHostIoTranscript::recording());
    orchestrator.set_host_io(provider.clone(), Some(synchronous_recorder));
    let error = orchestrator
        .execute(&crypto_package(
            "const crypto = require('crypto'); crypto.randomUUID();",
            true,
        ))
        .expect_err("a denied synchronous entropy request must throw");
    assert!(matches!(
        error.primary_error(),
        OrchestratorError::Interpreter(InterpreterError::UncaughtException { value })
            if value == "Error: Cryptographic random source unavailable"
    ));
    assert!(
        !error.to_string().contains("test entropy source denied"),
        "the provider's private denial reason must not cross the guest boundary"
    );

    let callback_source = r#"
        const crypto = require('crypto');
        crypto.randomBytes(4, (error, bytes) => {
          console.log(error.code, error.message, bytes === undefined);
        });
    "#;
    let recorder: Arc<dyn HostIoRecorder> = Arc::new(InMemoryHostIoTranscript::recording());
    let result = execute_crypto(callback_source, provider.clone(), recorder);
    assert_eq!(
        orchestrated_console(&result),
        "ERR_CRYPTO_OPERATION_FAILED Cryptographic random source unavailable true"
    );
    assert_eq!(provider.calls.load(Ordering::Acquire), 2);
    assert!(
        result
            .host_effect_transcript
            .iter()
            .all(|(_, outcome)| outcome.is_err())
    );
}

#[test]
fn entropy_recording_replays_exact_bytes_without_live_provider_bd_opsnv() {
    let source = r#"
        const crypto = require('crypto');
        crypto.randomBytes(4);
        crypto.randomInt(100);
    "#;
    let provider = Arc::new(ScriptedRandomHostIo::bytes([
        vec![0xde, 0xad, 0xbe, 0xef],
        vec![0, 0, 0, 0, 0, 42],
    ]));
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    let recorded = execute_crypto(source, provider.clone(), recorder_dyn);
    assert_eq!(orchestrated_console(&recorded), "");
    assert_eq!(provider.calls.load(Ordering::Acquire), 2);
    assert_eq!(
        recorded.host_effect_transcript,
        vec![
            (
                HostIoRequest::RandomRead { byte_len: 4 },
                Ok(HostIoResponse::RandomRead {
                    bytes: vec![0xde, 0xad, 0xbe, 0xef],
                }),
            ),
            (
                HostIoRequest::RandomRead { byte_len: 6 },
                Ok(HostIoResponse::RandomRead {
                    bytes: vec![0, 0, 0, 0, 0, 42],
                }),
            ),
        ]
    );

    let replay = Arc::new(InMemoryHostIoTranscript::replaying(
        recorded.host_effect_transcript.clone(),
    ));
    let replay_dyn: Arc<dyn HostIoRecorder> = replay.clone();
    let never_provider = Arc::new(ScriptedRandomHostIo::never());
    let replayed = execute_crypto(source, never_provider.clone(), replay_dyn);
    assert_eq!(orchestrated_console(&replayed), "");
    assert_eq!(never_provider.calls.load(Ordering::Acquire), 0);
    assert_eq!(
        replayed.host_effect_transcript,
        recorded.host_effect_transcript
    );
}

#[test]
fn entropy_replay_rejects_request_divergence_and_unused_suffix_bd_opsnv() {
    let transcript = vec![
        (
            HostIoRequest::RandomRead { byte_len: 4 },
            Ok(HostIoResponse::RandomRead {
                bytes: vec![1, 2, 3, 4],
            }),
        ),
        (
            HostIoRequest::RandomRead { byte_len: 6 },
            Ok(HostIoResponse::RandomRead { bytes: vec![0; 6] }),
        ),
    ];

    let divergent = Arc::new(InMemoryHostIoTranscript::replaying(transcript.clone()));
    let divergent_dyn: Arc<dyn HostIoRecorder> = divergent.clone();
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_host_io(Arc::new(ScriptedRandomHostIo::never()), Some(divergent_dyn));
    let error = orchestrator
        .execute(&crypto_package(
            "const crypto = require('crypto'); crypto.randomBytes(5);",
            true,
        ))
        .expect_err("a changed entropy byte count must diverge before live dispatch");
    assert!(matches!(
        error.primary_error(),
        OrchestratorError::Interpreter(InterpreterError::UncaughtException { value })
            if value == "Error: Cryptographic random source unavailable"
    ));
    assert!(matches!(
        divergent.finish_execution(),
        Err(HostIoError::SandboxViolation { detail })
            if detail.contains("host I/O replay divergence at index 0")
    ));

    let suffix: Arc<dyn HostIoRecorder> = Arc::new(InMemoryHostIoTranscript::replaying(transcript));
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_host_io(Arc::new(ScriptedRandomHostIo::never()), Some(suffix));
    let error = orchestrator
        .execute(&crypto_package(
            "const crypto = require('crypto'); crypto.randomBytes(4);",
            true,
        ))
        .expect_err("unused entropy replay suffix must fail finalization");
    assert!(error.to_string().contains("unused transcript entries"));
}

#[test]
fn missing_random_read_capability_prevents_provider_dispatch_bd_opsnv() {
    for byte_len in [0, 4] {
        let provider = Arc::new(ScriptedRandomHostIo::bytes([vec![0; byte_len]]));
        let recorder: Arc<dyn HostIoRecorder> = Arc::new(InMemoryHostIoTranscript::recording());
        let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
        orchestrator.set_host_io(provider.clone(), Some(recorder));
        let error = orchestrator
            .execute(&crypto_package(
                &format!("const crypto = require('crypto'); crypto.randomBytes({byte_len});"),
                false,
            ))
            .expect_err("random_read must be an explicit package grant");
        assert_eq!(provider.calls.load(Ordering::Acquire), 0);
        match error.primary_error() {
            OrchestratorError::Interpreter(InterpreterError::CapabilityDenied { capability })
                if capability == "random_read" => {}
            other => panic!(
                "missing random_read authority returned an unexpected error for {byte_len} bytes: {other:?}"
            ),
        }
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

