use super::*;

const NODE_SIGNATURE_HEX: &str = "3046022100e7071918b99cdc6d8b09d91f9d1ef17be50837488dc693153112fd7a0a7c3868022100de9c7b812b566195d990e8947a56590cc5be41aef821b405038c95f16b1f7d3a";

fn fixture() -> (InterpreterCore, ObjectId, ObjectId) {
    let mut core = quickjs_test_core();
    let scalar = [0x42; 32];
    let public_key = p256::ecdsa::SigningKey::from_slice(&scalar)
        .unwrap()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let Value::Object(private) = core
        .crypto_alloc_object(CryptoObjectState::PrivateKey {
            algorithm: CryptoKeyPairAlgorithm::EcP256,
            private_key: Zeroizing::new(scalar.to_vec()),
            public_key: public_key.clone(),
            lifecycle_label: Label::Secret,
        })
        .unwrap()
    else {
        panic!("private key object")
    };
    let Value::Object(public) = core
        .crypto_alloc_object(CryptoObjectState::PublicKey {
            algorithm: CryptoKeyPairAlgorithm::EcP256,
            public_key,
            lifecycle_label: Label::Secret,
        })
        .unwrap()
    else {
        panic!("public key object")
    };
    core.clear_pending_hostcall_result_label();
    (core, private, public)
}

fn context(core: &mut InterpreterCore, direction: CryptoSignatureDirection) -> ObjectId {
    core.write_reg_with_label(0, Value::str("sha256"), Label::Public)
        .unwrap();
    let Value::Object(id) = core
        .crypto_create_signature(RegRange { start: 0, count: 1 }, direction)
        .unwrap()
    else {
        panic!("signature context object")
    };
    core.clear_pending_hostcall_result_label();
    id
}

fn update(
    core: &mut InterpreterCore,
    id: ObjectId,
    data: Value,
    encoding: Option<Value>,
) -> Result<Value, InterpreterError> {
    core.write_reg_with_label(0, data, Label::Public).unwrap();
    let count = if let Some(encoding) = encoding {
        core.write_reg_with_label(1, encoding, Label::Public)
            .unwrap();
        2
    } else {
        1
    };
    let method = core.crypto_test_method(id, "update").unwrap();
    core.crypto_update(
        Some(Value::Object(id)),
        &method,
        RegRange { start: 0, count },
    )
}

fn finish(
    core: &mut InterpreterCore,
    id: ObjectId,
    direction: CryptoSignatureDirection,
    args: &[Value],
) -> Result<Value, InterpreterError> {
    for (index, value) in args.iter().enumerate() {
        // Deliberately lower register labels: private key and receiver state
        // must independently contribute their authenticated provenance.
        core.write_reg_with_label(index as u32, value.clone(), Label::Public)
            .unwrap();
    }
    let name = if direction == CryptoSignatureDirection::Sign {
        "sign"
    } else {
        "verify"
    };
    let method = core.crypto_test_method(id, name).unwrap();
    core.crypto_signature_final(
        Some(Value::Object(id)),
        &method,
        RegRange {
            start: 0,
            count: args.len() as u32,
        },
        direction,
    )
}

fn assert_code(core: &mut InterpreterCore, error: InterpreterError, code: &str) {
    assert!(
        matches!(error, InterpreterError::UncaughtException { .. }),
        "{error:?}"
    );
    let Some(Value::Object(thrown)) = core.pending_exception.clone() else {
        panic!("Node error object")
    };
    assert_eq!(
        core.prototype_chain_get(thrown, "code").unwrap(),
        Value::str(code)
    );
}

#[test]
fn streaming_p256_native_signatures_interoperate_and_retain_labels() {
    let (mut core, private, public) = fixture();
    let signer = context(&mut core, CryptoSignatureDirection::Sign);
    assert_eq!(
        update(&mut core, signer, Value::str("61"), Some(Value::str("hex"))).unwrap(),
        Value::Object(signer)
    );
    let suffix = core.alloc_buffer_from_bytes(b"bc").unwrap();
    update(
        &mut core,
        signer,
        Value::Object(suffix),
        Some(Value::str("ignored-on-buffer")),
    )
    .unwrap();
    let signature = finish(
        &mut core,
        signer,
        CryptoSignatureDirection::Sign,
        &[Value::Object(private), Value::str("base64")],
    )
    .unwrap();
    assert!(matches!(signature, Value::Str(_)));
    assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
    let bytes = core
        .crypto_input_bytes(&signature, Some(&Value::str("base64")))
        .unwrap();
    let (_, public_bytes, _) = core.crypto_key_pair_public(&Value::Object(public)).unwrap();
    assert_eq!(
        InterpreterCore::p256_verify_detached_der(&public_bytes, b"abc", &bytes),
        Ok(true)
    );
    assert_eq!(
        InterpreterCore::p256_verify_detached_der(&public_bytes, b"abd", &bytes),
        Ok(false)
    );
    assert_eq!(
        bytes,
        InterpreterCore::p256_sign_detached_der(&[0x42; 32], b"abc"),
        "streaming and one-shot share deterministic RFC6979 output"
    );
    assert!(matches!(
        core.crypto_objects[&signer],
        CryptoObjectState::SignatureFinalized {
            lifecycle_label: Label::Secret,
            ..
        }
    ));

    // Independent Node v24.22.3/OpenSSL DER signature for scalar 0x42*32
    // and UTF-8 "abc". This includes both DER INTEGER sign-padding bytes.
    for (message, expected) in [("abc", true), ("abd", false)] {
        let verifier = context(&mut core, CryptoSignatureDirection::Verify);
        update(&mut core, verifier, Value::str(message), None).unwrap();
        assert_eq!(
            finish(
                &mut core,
                verifier,
                CryptoSignatureDirection::Verify,
                &[
                    Value::Object(public),
                    Value::str(NODE_SIGNATURE_HEX),
                    Value::str("hex")
                ]
            )
            .unwrap(),
            Value::Bool(expected)
        );
        assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
    }
    let verifier = context(&mut core, CryptoSignatureDirection::Verify);
    update(&mut core, verifier, Value::str("abc"), None).unwrap();
    assert_eq!(
        finish(
            &mut core,
            verifier,
            CryptoSignatureDirection::Verify,
            &[Value::Object(private), signature, Value::str("base64")]
        )
        .unwrap(),
        Value::Bool(true),
        "private handles may verify through their public material"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn streaming_p256_argument_errors_preserve_state_and_secret_key_labels() {
    let (mut core, private, public) = fixture();
    let signer = context(&mut core, CryptoSignatureDirection::Sign);
    update(&mut core, signer, Value::str("abc"), None).unwrap();
    let before = core.crypto_objects[&signer].clone();
    let error = finish(
        &mut core,
        signer,
        CryptoSignatureDirection::Sign,
        &[Value::Object(public)],
    )
    .unwrap_err();
    assert!(matches!(error, InterpreterError::UncaughtException { .. }));
    assert_eq!(
        core.pending_exception_label,
        Label::Secret,
        "wrong key kind cannot reveal authenticated Secret state through Public registers"
    );
    assert_eq!(core.crypto_objects[&signer], before);
    core.clear_pending_exception_slot();

    let error = finish(&mut core, signer, CryptoSignatureDirection::Sign, &[]).unwrap_err();
    assert_code(&mut core, error, "ERR_CRYPTO_SIGN_KEY_REQUIRED");
    assert_eq!(core.crypto_objects[&signer], before);
    core.clear_pending_exception_slot();

    let Value::Object(ed_key) = core
        .crypto_alloc_object(CryptoObjectState::PrivateKey {
            algorithm: CryptoKeyPairAlgorithm::Ed25519,
            private_key: Zeroizing::new(vec![0x42; 32]),
            public_key: ed25519_dalek::SigningKey::from_bytes(&[0x42; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
            lifecycle_label: Label::Secret,
        })
        .unwrap()
    else {
        panic!("Ed25519 key")
    };
    let error = finish(
        &mut core,
        signer,
        CryptoSignatureDirection::Sign,
        &[Value::Object(ed_key)],
    )
    .unwrap_err();
    assert_code(&mut core, error, "ERR_CRYPTO_UNSUPPORTED_OPERATION");
    assert_eq!(core.crypto_objects[&signer], before);
    assert_eq!(core.pending_exception_label, Label::Secret);
    core.clear_pending_exception_slot();
    finish(
        &mut core,
        signer,
        CryptoSignatureDirection::Sign,
        &[Value::Object(private)],
    )
    .unwrap();

    let verifier = context(&mut core, CryptoSignatureDirection::Verify);
    update(&mut core, verifier, Value::str("abc"), None).unwrap();
    let before = core.crypto_objects[&verifier].clone();
    let error = finish(
        &mut core,
        verifier,
        CryptoSignatureDirection::Verify,
        &[
            Value::Object(public),
            Value::str("abc"),
            Value::str("unknown"),
        ],
    )
    .unwrap_err();
    assert_code(&mut core, error, "ERR_UNKNOWN_ENCODING");
    assert_eq!(core.crypto_objects[&verifier], before);
    core.clear_pending_exception_slot();
    assert_eq!(
        finish(
            &mut core,
            verifier,
            CryptoSignatureDirection::Verify,
            &[
                Value::Object(public),
                Value::str(NODE_SIGNATURE_HEX),
                Value::str("hex")
            ]
        )
        .unwrap(),
        Value::Bool(true)
    );
}

#[test]
fn streaming_p256_finalization_and_receiver_brand_are_not_forgeable() {
    let (mut core, private, public) = fixture();
    let signer = context(&mut core, CryptoSignatureDirection::Sign);
    update(&mut core, signer, Value::str("abc"), None).unwrap();
    let error = finish(
        &mut core,
        signer,
        CryptoSignatureDirection::Sign,
        &[Value::Object(private), Value::str("unknown")],
    )
    .unwrap_err();
    assert_code(&mut core, error, "ERR_UNKNOWN_ENCODING");
    assert_eq!(core.pending_exception_label, Label::Secret);
    assert!(matches!(
        core.crypto_objects[&signer],
        CryptoObjectState::SignatureFinalized { .. }
    ));
    core.clear_pending_exception_slot();
    let error = update(&mut core, signer, Value::str("late"), None).unwrap_err();
    assert_code(&mut core, error, "ERR_CRYPTO_INVALID_STATE");
    assert_eq!(core.pending_exception_label, Label::Secret);
    core.clear_pending_exception_slot();

    let verifier = context(&mut core, CryptoSignatureDirection::Verify);
    update(&mut core, verifier, Value::str("abc"), None).unwrap();
    let malformed = core.alloc_buffer_from_bytes(b"not DER").unwrap();
    assert_eq!(
        finish(
            &mut core,
            verifier,
            CryptoSignatureDirection::Verify,
            &[Value::Object(public), Value::Object(malformed)]
        )
        .unwrap(),
        Value::Bool(false)
    );
    let error = finish(
        &mut core,
        verifier,
        CryptoSignatureDirection::Verify,
        &[Value::Object(public), Value::Object(malformed)],
    )
    .unwrap_err();
    assert_code(&mut core, error, "ERR_CRYPTO_INVALID_STATE");
    core.clear_pending_exception_slot();

    let forged = core
        .alloc_object_with_properties(&[
            ("__type", Value::str("Sign")),
            ("privateKey", Value::Object(private)),
        ])
        .unwrap();
    core.write_reg_with_label(0, Value::Object(forged), Label::Public)
        .unwrap();
    core.write_reg_with_label(1, Value::Object(private), Label::Public)
        .unwrap();
    assert!(
        core.crypto_object_hostcall("builtin:CryptoObjectSign", RegRange { start: 0, count: 2 })
            .is_err()
    );
    assert_eq!(core.pending_exception_label, Label::TopSecret);
    core.clear_pending_exception_slot();
    core.write_reg_with_label(0, Value::Object(verifier), Label::Public)
        .unwrap();
    assert!(
        core.crypto_object_hostcall("builtin:CryptoObjectSign", RegRange { start: 0, count: 2 })
            .is_err(),
        "Verify cannot acquire signing authority"
    );
    assert_eq!(core.pending_exception_label, Label::TopSecret);
    core.clear_pending_exception_slot();
    let method = core.crypto_test_method(signer, "sign").unwrap();
    assert!(
        core.crypto_signature_final(
            Some(Value::Object(forged)),
            &method,
            RegRange { start: 1, count: 1 },
            CryptoSignatureDirection::Sign
        )
        .is_err(),
        "a copied method retains its exact receiver brand"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn streaming_p256_budget_refusals_are_atomic_and_message_storage_is_bounded() {
    let (mut core, private, _) = fixture();
    let signer = context(&mut core, CryptoSignatureDirection::Sign);
    update(&mut core, signer, Value::str("retained message"), None).unwrap();
    core.clear_pending_hostcall_result_label();
    core.write_reg_with_label(0, Value::Object(private), Label::Public)
        .unwrap();
    let before = core.crypto_objects[&signer].clone();
    let memory_before = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = memory_before + 1;
    let method = core.crypto_test_method(signer, "sign").unwrap();
    assert!(matches!(
        core.crypto_signature_final(
            Some(Value::Object(signer)),
            &method,
            RegRange { start: 0, count: 1 },
            CryptoSignatureDirection::Sign
        ),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.crypto_objects[&signer], before);
    assert_eq!(core.estimated_memory_bytes(), memory_before);
    core.config.max_total_memory_bytes = u64::MAX;
    core.config.instruction_budget = core.instructions_executed;
    assert!(matches!(
        core.crypto_signature_final(
            Some(Value::Object(signer)),
            &method,
            RegRange { start: 0, count: 1 },
            CryptoSignatureDirection::Sign
        ),
        Err(InterpreterError::BudgetExhausted { .. })
    ));
    assert_eq!(core.crypto_objects[&signer], before);
    core.config.instruction_budget = u64::MAX;
    core.crypto_signature_final(
        Some(Value::Object(signer)),
        &method,
        RegRange { start: 0, count: 1 },
        CryptoSignatureDirection::Sign,
    )
    .unwrap();
    assert!(
        InterpreterCore::estimate_crypto_object_state_bytes(&core.crypto_objects[&signer])
            < InterpreterCore::estimate_crypto_object_state_bytes(&before),
        "finalization discards retained message capacity"
    );

    let incremental = context(&mut core, CryptoSignatureDirection::Sign);
    update(&mut core, incremental, Value::str("x".repeat(4096)), None).unwrap();
    let prefix = core.crypto_objects[&incremental].clone();
    core.config.instruction_budget = core.instructions_executed + 1;
    assert!(
        matches!(
            update(&mut core, incremental, Value::str("x"), None),
            Err(InterpreterError::BudgetExhausted { .. })
        ),
        "one-byte chunks must account for copying their retained prefix"
    );
    assert_eq!(core.crypto_objects[&incremental], prefix);
    core.config.instruction_budget = u64::MAX;

    let Value::Object(full) = core
        .crypto_alloc_object(CryptoObjectState::SignatureActive {
            direction: CryptoSignatureDirection::Verify,
            input: Zeroizing::new(vec![0; CRYPTO_MAX_INPUT_BYTES]),
            lifecycle_label: Label::Secret,
        })
        .unwrap()
    else {
        panic!("full context")
    };
    let error = update(&mut core, full, Value::str("x"), None).unwrap_err();
    assert!(matches!(error, InterpreterError::UncaughtException { .. }));
    assert_eq!(core.pending_exception_label, Label::Secret);
    assert!(
        matches!(&core.crypto_objects[&full], CryptoObjectState::SignatureActive { input, .. } if input.len() == CRYPTO_MAX_INPUT_BYTES)
    );
    core.clear_pending_exception_slot();
    let error = update(&mut core, full, Value::Int(1), None).unwrap_err();
    assert!(matches!(error, InterpreterError::UncaughtException { .. }));
    assert_eq!(
        core.pending_exception_label,
        Label::Secret,
        "invalid direct update input retains private lifecycle provenance"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}
