#![no_main]

use frankenengine_extension_host::{
    verify_manifest_signature, ExtensionManifest, Capability, compute_content_hash,
    ManifestValidationError, validate_manifest,
};
use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

/// Maximum input size to prevent OOM during fuzzing
const MAX_INPUT_SIZE: usize = 1024 * 1024; // 1MB

/// Fuzz input structure covering all Ed25519 verification attack vectors
#[derive(Debug)]
struct FuzzInput {
    // Manifest content - can be mutated to test content hash verification
    manifest_name: Vec<u8>,
    manifest_version: Vec<u8>,
    manifest_entrypoint: Vec<u8>,
    capabilities: u8, // Use as bitmask for capability selection

    // Trust chain ref - can be malformed public key encoding
    trust_chain_ref: Vec<u8>,

    // Publisher signature - primary attack vector
    publisher_signature: Vec<u8>,

    // Attack type selector
    attack_mode: u8,
}

impl FuzzInput {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }

        let mut pos = 0;

        // Read attack mode first
        let attack_mode = data[pos];
        pos += 1;

        // Parse manifest name (1-128 bytes)
        let name_len = (data.get(pos)? % 128).max(1) as usize;
        pos += 1;
        if pos + name_len > data.len() { return None; }
        let manifest_name = data[pos..pos + name_len].to_vec();
        pos += name_len;

        // Parse version (1-32 bytes)
        let version_len = (data.get(pos)? % 32).max(1) as usize;
        pos += 1;
        if pos + version_len > data.len() { return None; }
        let manifest_version = data[pos..pos + version_len].to_vec();
        pos += version_len;

        // Parse entrypoint (1-64 bytes)
        let entry_len = (data.get(pos)? % 64).max(1) as usize;
        pos += 1;
        if pos + entry_len > data.len() { return None; }
        let manifest_entrypoint = data[pos..pos + entry_len].to_vec();
        pos += entry_len;

        // Capabilities selector
        let capabilities = *data.get(pos)?;
        pos += 1;

        // Trust chain ref (0-256 bytes) - can be malformed
        let trust_len = (*data.get(pos)? as usize).min(256);
        pos += 1;
        if pos + trust_len > data.len() { return None; }
        let trust_chain_ref = data[pos..pos + trust_len].to_vec();
        pos += trust_len;

        // Publisher signature - remaining bytes
        let publisher_signature = data[pos..].to_vec();

        Some(FuzzInput {
            manifest_name,
            manifest_version,
            manifest_entrypoint,
            capabilities,
            trust_chain_ref,
            publisher_signature,
            attack_mode,
        })
    }

    fn to_manifest(&self) -> ExtensionManifest {
        // Convert bytes to valid UTF-8 strings for manifest fields
        let name = String::from_utf8_lossy(&self.manifest_name);
        let version = String::from_utf8_lossy(&self.manifest_version);
        let entrypoint = String::from_utf8_lossy(&self.manifest_entrypoint);

        // Convert capability bitmask to capability set
        let mut caps = BTreeSet::new();
        if self.capabilities & 0x01 != 0 { caps.insert(Capability::FsRead); }
        if self.capabilities & 0x02 != 0 { caps.insert(Capability::FsWrite); }
        if self.capabilities & 0x04 != 0 { caps.insert(Capability::NetClient); }
        if self.capabilities & 0x08 != 0 { caps.insert(Capability::HostCall); }
        if self.capabilities & 0x10 != 0 { caps.insert(Capability::ProcessSpawn); }

        let mut manifest = ExtensionManifest {
            name: name.to_string(),
            version: version.to_string(),
            entrypoint: entrypoint.to_string(),
            capabilities: caps,
            publisher_signature: if self.publisher_signature.is_empty() {
                None
            } else {
                Some(self.publisher_signature.clone())
            },
            content_hash: [0; 32],
            trust_chain_ref: if self.trust_chain_ref.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&self.trust_chain_ref).to_string())
            },
            min_engine_version: "0.1.0".to_string(),
        };

        // Compute content hash based on manifest contents
        manifest.content_hash = compute_content_hash(&manifest).unwrap_or([0; 32]);
        manifest
    }
}

/// Apply attack-specific mutations to test different vulnerability classes
fn apply_attack_mutations(input: &mut FuzzInput) {
    match input.attack_mode % 8 {
        0 => {
            // Attack 1: Tampered signatures - flip random bits in signature
            if !input.publisher_signature.is_empty() {
                let idx = (input.attack_mode as usize) % input.publisher_signature.len();
                input.publisher_signature[idx] ^= 0xFF;
            }
        },
        1 => {
            // Attack 2: Wrong-length signatures
            match (input.attack_mode >> 3) % 4 {
                0 => input.publisher_signature = vec![0; 0],     // Empty
                1 => input.publisher_signature = vec![0; 32],    // Too short
                2 => input.publisher_signature = vec![0; 128],   // Too long
                3 => input.publisher_signature = vec![0xFF; 64], // Valid length, invalid content
                _ => {}
            }
        },
        2 => {
            // Attack 3: Malformed public key encodings
            match (input.attack_mode >> 3) % 5 {
                0 => input.trust_chain_ref = b"not_hex".to_vec(),
                1 => input.trust_chain_ref = b"deadbeef".to_vec(), // Valid hex, wrong length
                2 => input.trust_chain_ref = vec![0; 128],  // Too long when hex-decoded
                3 => input.trust_chain_ref = b"gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg".to_vec(), // Invalid hex
                4 => input.trust_chain_ref = vec![], // Empty
                _ => {}
            }
        },
        3 => {
            // Attack 4: Edge sizes - zero and maximum payloads
            if (input.attack_mode >> 3) % 2 == 0 {
                // Zero-size components
                input.manifest_name = vec![b'a']; // Keep minimal valid
                input.trust_chain_ref = vec![];
                input.publisher_signature = vec![];
            } else {
                // Maximum size components
                input.manifest_name = vec![b'a'; 128];
                input.trust_chain_ref = vec![b'f'; 64]; // 64 hex chars = 32 bytes when decoded
                input.publisher_signature = vec![0xFF; 64];
            }
        },
        4 => {
            // Attack 5: Valid signature for different content (cross-manifest replay)
            // Generate a valid Ed25519 signature, but for different manifest content
            let signing_key = SigningKey::from_bytes(&[0x42; 32]);
            let different_content = b"different manifest content";
            let signature = signing_key.sign(different_content);
            input.publisher_signature = signature.to_bytes().to_vec();

            let verifying_key = signing_key.verifying_key();
            input.trust_chain_ref = hex::encode(verifying_key.to_bytes()).into_bytes();
        },
        5 => {
            // Attack 6: Signature malleability attempts
            // Ed25519 should be malleability-resistant, but test edge cases
            if input.publisher_signature.len() >= 64 {
                // Try to manipulate S component of signature (second 32 bytes)
                for i in 32..64 {
                    if i < input.publisher_signature.len() {
                        input.publisher_signature[i] = input.publisher_signature[i].wrapping_add(1);
                    }
                }
            }
        },
        6 => {
            // Attack 7: Domain separation bypass attempts
            // Try to create signatures that might bypass domain separation
            let fake_domain = b"wrong-domain-tag:";
            let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
            let mut fake_payload = Vec::new();
            fake_payload.extend_from_slice(fake_domain);
            fake_payload.extend_from_slice(&[0; 32]); // Fake content hash
            let signature = signing_key.sign(&fake_payload);
            input.publisher_signature = signature.to_bytes().to_vec();

            let verifying_key = signing_key.verifying_key();
            input.trust_chain_ref = hex::encode(verifying_key.to_bytes()).into_bytes();
        },
        7 => {
            // Attack 8: High-entropy random mutations (catch unexpected edge cases)
            // Let libfuzzer's mutation engine handle this case
        },
        _ => {}
    }
}

/// Oracle: Check that verification results are deterministic and consistent
fn check_verification_oracle(manifest: &ExtensionManifest) {
    // Oracle 1: Verification should be deterministic
    let result1 = validate_manifest(manifest);
    let result2 = validate_manifest(manifest);
    assert_eq!(result1.is_ok(), result2.is_ok(),
               "Ed25519 verification non-deterministic");

    // Oracle 2: If signature is present, trust chain must be consistent
    if manifest.publisher_signature.is_some() && manifest.trust_chain_ref.is_some() {
        // Should either both succeed or both fail in the same way
        match result1 {
            Ok(_) => {
                // If verification passes, re-verification must also pass
                assert!(result2.is_ok(), "Verification success not reproducible");
            },
            Err(ref e) => {
                // Error should be the same type
                if let Err(ref e2) = result2 {
                    assert_eq!(
                        std::mem::discriminant(e),
                        std::mem::discriminant(e2),
                        "Error type changed between verification attempts"
                    );
                }
            }
        }
    }

    // Oracle 3: Invalid signature lengths should fail predictably
    if let Some(ref sig) = manifest.publisher_signature {
        if sig.len() != 64 {
            assert!(result1.is_err(), "Non-64-byte signature should be rejected");
            if let Err(ManifestValidationError::InvalidPublisherSignature) = result1 {
                // Expected error type
            } else {
                panic!("Wrong error type for invalid signature length");
            }
        }
    }

    // Oracle 4: Missing components should fail appropriately
    if manifest.publisher_signature.is_none() && manifest.trust_chain_ref.is_some() {
        // Trust chain without signature should be rejected for signed trust level
        // (This is checked in validate_provenance, not validate_manifest)
    }
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input sizes that could cause OOM
    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    // Parse fuzz input structure
    let mut fuzz_input = match FuzzInput::from_bytes(data) {
        Some(input) => input,
        None => return, // Invalid input structure, skip
    };

    // Apply attack-specific mutations based on attack mode
    apply_attack_mutations(&mut fuzz_input);

    // Convert to manifest and test verification
    let manifest = fuzz_input.to_manifest();

    // Primary fuzz target: validate_manifest should never panic or crash
    let _result = validate_manifest(&manifest);

    // Secondary oracle checks for consistency and determinism
    check_verification_oracle(&manifest);

    // If we have what looks like a valid signature, test round-trip property
    if let (Some(signature), Some(trust_chain)) =
           (&manifest.publisher_signature, &manifest.trust_chain_ref) {
        if signature.len() == 64 && trust_chain.len() == 64 {
            // This might be a valid signature - test that verification is stable
            let result = validate_manifest(&manifest);

            // Re-compute content hash and verify it's stable
            if let Ok(recomputed_hash) = compute_content_hash(&manifest) {
                let manifest_with_recomputed = ExtensionManifest {
                    content_hash: recomputed_hash,
                    ..manifest
                };
                let result2 = validate_manifest(&manifest_with_recomputed);

                // Verification result should be consistent with recomputed hash
                assert_eq!(result.is_ok(), result2.is_ok(),
                          "Verification inconsistent with recomputed content hash");
            }
        }
    }
});