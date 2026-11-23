//! Bounded Node Sign/Verify contexts over authenticated P-256 key objects.
//! Message chunks live only in the accounted, zeroizing crypto side table.
//! Finalization uses the same SHA-256/RFC6979 primitives as one-shot signing.

use super::*;

impl InterpreterCore {
    fn crypto_signature_key_clone_preflight(
        &self,
        key: &Value,
        invocation_label: &Label,
        private: bool,
    ) -> Result<(), InterpreterError> {
        let Some(state) = (match key {
            Value::Object(object_id) => self.crypto_objects.get(object_id),
            _ => None,
        }) else {
            return Ok(());
        };
        let material_bytes = match state {
            CryptoObjectState::PrivateKey { private_key, .. } if private => private_key.len(),
            CryptoObjectState::PrivateKey { public_key, .. }
            | CryptoObjectState::PublicKey { public_key, .. }
                if !private =>
            {
                public_key.len()
            }
            _ => 0,
        };
        self.check_temporary_memory_budget(
            u64::try_from(material_bytes)
                .unwrap_or(u64::MAX)
                .saturating_add(Self::estimate_label_bytes(invocation_label))
                .saturating_add(Self::estimate_label_bytes(state.lifecycle_label())),
        )
    }

    pub(super) fn crypto_create_signature(
        &mut self,
        args: RegRange,
        direction: CryptoSignatureDirection,
    ) -> Result<Value, InterpreterError> {
        let label = self.crypto_invocation_label(args)?;
        let algorithm = self.crypto_required_string_arg(args, 0, "crypto signature digest")?;
        if !["sha256", "sha-256", "rsa-sha256"]
            .iter()
            .any(|name| algorithm.eq_ignore_ascii_case(name))
        {
            return Err(self.crypto_throw_node_error(
                "TypeError",
                "ERR_CRYPTO_INVALID_DIGEST",
                "Invalid digest: streaming signatures support SHA-256".to_string(),
                &label,
            ));
        }
        self.crypto_alloc_object(CryptoObjectState::SignatureActive {
            direction,
            input: Zeroizing::new(Vec::new()),
            lifecycle_label: label,
        })
    }

    /// Validate the key before inspecting finalization, matching Node's
    /// retryable argument errors. A failed guest argument never consumes the
    /// message; successful signing/verification does, including false verdicts.
    fn crypto_signature_snapshot(
        &mut self,
        object_id: ObjectId,
        direction: CryptoSignatureDirection,
        key_algorithm: CryptoKeyPairAlgorithm,
        invocation_label: &Label,
        key_label: &Label,
        already_owned_temporary_bytes: u64,
    ) -> Result<(CryptoObjectState, Label), InterpreterError> {
        let retained = self
            .crypto_objects
            .get(&object_id)
            .expect("authenticated crypto receiver has state");
        let state_bytes = Self::estimate_crypto_object_state_bytes(retained);
        let labels_bound = Self::estimate_label_bytes(invocation_label)
            .saturating_add(Self::estimate_label_bytes(key_label))
            .saturating_add(Self::estimate_label_bytes(retained.lifecycle_label()))
            .saturating_mul(4);
        self.check_temporary_memory_budget(
            already_owned_temporary_bytes
                .saturating_add(state_bytes)
                .saturating_add(labels_bound),
        )?;
        let label = invocation_label
            .join(key_label)
            .join(retained.lifecycle_label());
        if key_algorithm != CryptoKeyPairAlgorithm::EcP256 {
            return Err(self.crypto_throw_node_error_with_temporary_budget(
                "Error",
                "ERR_CRYPTO_UNSUPPORTED_OPERATION",
                "Unsupported crypto operation: streaming signatures require a P-256 key"
                    .to_string(),
                &label,
                already_owned_temporary_bytes.saturating_add(Self::estimate_label_bytes(&label)),
            ));
        }
        match retained {
            CryptoObjectState::SignatureActive {
                direction: actual, ..
            } if *actual == direction => {}
            CryptoObjectState::SignatureFinalized {
                direction: actual, ..
            } if *actual == direction => {
                return Err(self.crypto_throw_node_error_with_temporary_budget(
                    "Error",
                    "ERR_CRYPTO_INVALID_STATE",
                    "Not initialised".to_string(),
                    &label,
                    already_owned_temporary_bytes
                        .saturating_add(Self::estimate_label_bytes(&label)),
                ));
            }
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "matching authenticated Sign or Verify receiver".to_string(),
                    got: "incompatible crypto receiver".to_string(),
                });
            }
        }
        Ok((self.crypto_state_snapshot(object_id)?, label))
    }

    pub(super) fn crypto_signature_final(
        &mut self,
        receiver: Option<Value>,
        builtin: &BuiltinFunction,
        args: RegRange,
        direction: CryptoSignatureDirection,
    ) -> Result<Value, InterpreterError> {
        let (method, capability) = match direction {
            CryptoSignatureDirection::Sign => ("sign", "builtin:CryptoObjectSign"),
            CryptoSignatureDirection::Verify => ("verify", "builtin:CryptoObjectVerify"),
        };
        let object_id = self.crypto_receiver_id(receiver, builtin, method)?;
        let result = match direction {
            CryptoSignatureDirection::Sign => self.crypto_sign_final(object_id, args),
            CryptoSignatureDirection::Verify => self.crypto_verify_final(object_id, args),
        };
        match result {
            Err(error)
                if !matches!(error, InterpreterError::UncaughtException { .. })
                    && Self::js_catchable_error_name(&error).is_some() =>
            {
                // This also protects first-class module methods, whose calls
                // do not pass through the script facade's lifecycle wrapper.
                Err(self.crypto_rethrow_lifecycle_error(&error, object_id, capability, args)?)
            }
            result => result,
        }
    }

    fn crypto_sign_final(
        &mut self,
        object_id: ObjectId,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let invocation_label = self.crypto_invocation_label(args)?;
        let key = self.builtin_arg(args, 0)?;
        if matches!(key, None | Some(Value::Undefined) | Some(Value::Null)) {
            let state = self
                .crypto_objects
                .get(&object_id)
                .expect("authenticated crypto receiver has state");
            let label = self.clone_dominant_label_with_temporary_budget(
                state.lifecycle_label(),
                &invocation_label,
                Self::estimate_label_bytes(&invocation_label),
            )?;
            return Err(self.crypto_throw_node_error_with_temporary_budget(
                "Error",
                "ERR_CRYPTO_SIGN_KEY_REQUIRED",
                "No key provided to sign".to_string(),
                &label,
                Self::estimate_label_bytes(&invocation_label),
            ));
        }
        let key = key.expect("missing signing key was rejected");
        self.crypto_signature_key_clone_preflight(&key, &invocation_label, true)?;
        let (algorithm, private_key, key_label) = self.crypto_key_pair_private(&key)?;
        let key_scratch = u64::try_from(private_key.capacity())
            .unwrap_or(u64::MAX)
            .saturating_add(Self::estimate_label_bytes(&key_label))
            .saturating_add(Self::estimate_label_bytes(&invocation_label));
        let (previous, label) = self.crypto_signature_snapshot(
            object_id,
            CryptoSignatureDirection::Sign,
            algorithm,
            &invocation_label,
            &key_label,
            key_scratch,
        )?;
        let CryptoObjectState::SignatureActive { input, .. } = &previous else {
            unreachable!("signature snapshot validates active state")
        };
        let previous_bytes = Self::estimate_crypto_object_state_bytes(&previous);
        let caller_scratch = key_scratch
            .saturating_add(previous_bytes)
            .saturating_add(Self::estimate_label_bytes(&label));
        self.check_temporary_memory_budget(
            caller_scratch
                .saturating_add(160)
                .saturating_add(CRYPTO_STATE_BASE_BYTES)
                .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
                .saturating_add(Self::estimate_label_bytes(&label))
                .saturating_add(Self::crypto_output_publication_peak_bytes(72, &label, true)),
        )?;
        self.charge_crypto_work(Self::crypto_byte_work(input.len().saturating_add(144)))?;
        let scalar = <&[u8; 32]>::try_from(private_key.as_slice()).map_err(|_| {
            InterpreterError::InternalError {
                details: "P-256 signing scalar must be exactly 32 bytes".to_string(),
            }
        })?;
        let signature = Zeroizing::new(Self::p256_sign_detached_der(scalar, input));
        let next = CryptoObjectState::SignatureFinalized {
            direction: CryptoSignatureDirection::Sign,
            lifecycle_label: label.clone(),
        };
        let output_encoding = self.builtin_arg(args, 1)?.filter(Value::is_truthy);
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let result = (|| {
            self.apply_memory_component_delta(
                previous_bytes,
                Self::estimate_crypto_object_state_bytes(&next),
            )?;
            self.crypto_objects.insert(object_id, next);
            // Node consumes Sign before converting its output encoding, even
            // when that conversion throws ERR_UNKNOWN_ENCODING.
            self.crypto_output_value_with_temporary_budget(
                &signature,
                output_encoding,
                &label,
                true,
                caller_scratch
                    .saturating_add(u64::try_from(signature.capacity()).unwrap_or(u64::MAX)),
            )
        })();
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, InterpreterError::UncaughtException { .. }))
        {
            self.crypto_objects.insert(object_id, previous);
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result
    }

    fn crypto_verify_final(
        &mut self,
        object_id: ObjectId,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let invocation_label = self.crypto_invocation_label(args)?;
        // Signature validation precedes key preparation in Node. Binary views
        // ignore the string encoding, whereas strings reject unknown encodings.
        let signature_value = self.crypto_required_arg(args, 1, "signature")?;
        let encoding = self
            .builtin_arg(args, 2)?
            .filter(|value| matches!(value, Value::Str(name) if !name.is_empty()));
        if let (Value::Str(_), Some(Value::Str(name))) = (&signature_value, &encoding)
            && Self::crypto_canonical_buffer_encoding(name).is_none()
        {
            let state = self
                .crypto_objects
                .get(&object_id)
                .expect("authenticated crypto receiver has state");
            let label = self.clone_dominant_label_with_temporary_budget(
                state.lifecycle_label(),
                &invocation_label,
                Self::estimate_label_bytes(&invocation_label),
            )?;
            return Err(self.crypto_throw_node_error_with_temporary_budget(
                "TypeError",
                "ERR_UNKNOWN_ENCODING",
                format!(
                    "Unknown encoding: {}",
                    Self::crypto_diagnostic_fragment(name)
                ),
                &label,
                Self::estimate_label_bytes(&invocation_label),
            ));
        }
        let signature_bound =
            self.crypto_input_allocation_bound(&signature_value, encoding.as_ref())?;
        if signature_bound > CRYPTO_MAX_INPUT_BYTES as u64 {
            return Err(InterpreterError::RangeError {
                message: "crypto signature exceeds engine input limit".to_string(),
            });
        }
        let key = self.crypto_required_arg(args, 0, "key handle")?;
        self.crypto_signature_key_clone_preflight(&key, &invocation_label, false)?;
        let (algorithm, public_key, key_label) = self.crypto_key_pair_public(&key)?;
        let key_scratch = u64::try_from(public_key.capacity())
            .unwrap_or(u64::MAX)
            .saturating_add(Self::estimate_label_bytes(&key_label))
            .saturating_add(Self::estimate_label_bytes(&invocation_label));
        let (previous, label) = self.crypto_signature_snapshot(
            object_id,
            CryptoSignatureDirection::Verify,
            algorithm,
            &invocation_label,
            &key_label,
            key_scratch,
        )?;
        let CryptoObjectState::SignatureActive { input, .. } = &previous else {
            unreachable!("signature snapshot validates active state")
        };
        let previous_bytes = Self::estimate_crypto_object_state_bytes(&previous);
        self.check_temporary_memory_budget(
            key_scratch
                .saturating_add(previous_bytes)
                .saturating_add(signature_bound)
                .saturating_add(CRYPTO_STATE_BASE_BYTES)
                .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
                .saturating_add(Self::estimate_label_bytes(&label).saturating_mul(3))
                .saturating_add(160),
        )?;
        let signature =
            Zeroizing::new(self.crypto_input_bytes(&signature_value, encoding.as_ref())?);
        self.charge_crypto_work(Self::crypto_byte_work(
            input
                .len()
                .saturating_add(signature.len())
                .saturating_add(144),
        ))?;
        let verified = match Self::p256_verify_detached_der(&public_key, input, &signature) {
            Ok(verified) => verified,
            // Node Verify returns false for invalid DER and consumes its
            // context, just as it does for a well-formed but wrong signature.
            Err("ERR_CRYPTO_INVALID_SIGNATURE") => false,
            Err(error) => {
                return Err(InterpreterError::InternalError {
                    details: error.to_string(),
                });
            }
        };
        let next = CryptoObjectState::SignatureFinalized {
            direction: CryptoSignatureDirection::Verify,
            lifecycle_label: label.clone(),
        };
        let previous_estimated_bytes = self.estimated_memory_bytes;
        self.apply_memory_component_delta(
            previous_bytes,
            Self::estimate_crypto_object_state_bytes(&next),
        )?;
        self.crypto_objects.insert(object_id, next);
        if let Err(error) = self.replace_pending_hostcall_result_label(Some(label)) {
            self.crypto_objects.insert(object_id, previous);
            self.estimated_memory_bytes = previous_estimated_bytes;
            return Err(error);
        }
        Ok(Value::Bool(verified))
    }
}
