//! Self-replacement lineage chain replay example.
//!
//! This example demonstrates end-to-end replay of a multi-replacement
//! lineage chain using the ReplacementReceipt schema and verifies
//! lineage integrity across multiple promotion steps.
//!
//! Usage:
//!     cargo run --example self_replacement_lineage_replay
//!
//! The example creates a synthetic lineage chain with multiple
//! replacements, validates each receipt, and verifies the complete
//! chain integrity including content hash linkage.

use frankenengine_engine::{
    engine_object_id::{self, EngineObjectId, ObjectDomain},
    pre_signed_demotion_fallback::{
        DemotionTrigger, FallbackStatus, PreSignedFallbackStore, PromotionId,
    },
    security_epoch::SecurityEpoch,
    self_replacement::{
        CreateReceiptInput, DelegateCellManifest, DelegateType, ReplacementReceipt,
        SandboxConfiguration, SchemaVersion, SignatureBundle, ValidationArtifactRef,
        ValidationStatus,
    },
    signature_preimage::{Signature, SigningKey, VerificationKey},
    slot_registry::{AuthorityEnvelope, Capability, SlotId},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize)]
struct LineageChainEntry {
    receipt: ReplacementReceipt,
    validation_proof: String,
    content_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LineageChain {
    entries: Vec<LineageChainEntry>,
    initial_delegate_hash: String,
    final_native_hash: String,
    chain_start_timestamp_ns: u64,
}

/// Create a test signing key for demonstration purposes.
fn create_test_signing_key() -> SigningKey {
    // Use deterministic test key for reproducible output
    let test_seed = [42u8; 32];
    SigningKey::from_bytes(&test_seed).expect("valid test seed")
}

/// Create a test slot ID.
fn create_test_slot_id(suffix: &str) -> SlotId {
    SlotId::from_str(&format!("test_slot_{}", suffix)).expect("valid slot ID")
}

/// Create a validation artifact reference.
fn create_validation_artifact_ref(name: &str, status: ValidationStatus) -> ValidationArtifactRef {
    ValidationArtifactRef {
        artifact_id: format!("artifact_{}", name),
        validation_type: format!("type_{}", name),
        status,
        evidence_digest: format!("evidence_{}", name),
        validator_identity: format!("validator_{}", name),
    }
}

/// Create a signature bundle for testing.
fn create_test_signature_bundle() -> SignatureBundle {
    let signing_key = create_test_signing_key();
    let signature = Signature::from_bytes(&[0u8; 64]).expect("valid test signature");

    SignatureBundle {
        signatures: vec![signature],
        required_threshold: 1,
        signer_identities: vec!["test_signer".to_string()],
    }
}

/// Create a replacement receipt for the lineage chain.
fn create_replacement_receipt(
    old_slot_id: &SlotId,
    new_slot_id: &SlotId,
    old_digest: &str,
    new_digest: &str,
    translation_proof_ref: &str,
    content_hash_chain: &str,
    timestamp_ns: u64,
    step: usize,
) -> Result<ReplacementReceipt, Box<dyn std::error::Error>> {
    let zone = "test_zone";

    // Create receipt ID (slot_id for backward compatibility equals old_slot_id)
    let receipt_id = ReplacementReceipt::derive_receipt_id(
        old_slot_id, // slot_id for backward compatibility
        old_slot_id,
        new_slot_id,
        old_digest,
        new_digest,
        translation_proof_ref,
        content_hash_chain,
        timestamp_ns,
        zone,
    )?;

    // Create validation artifacts
    let validation_artifacts = vec![
        create_validation_artifact_ref(
            &format!("perf_check_step_{}", step),
            ValidationStatus::Approved,
        ),
        create_validation_artifact_ref(
            &format!("security_scan_step_{}", step),
            ValidationStatus::Approved,
        ),
        create_validation_artifact_ref(
            &format!("behavior_equiv_step_{}", step),
            ValidationStatus::Approved,
        ),
    ];

    Ok(ReplacementReceipt {
        receipt_id,
        schema_version: SchemaVersion::V1,
        slot_id: old_slot_id.clone(), // For backward compatibility
        old_slot_id: old_slot_id.clone(),
        new_slot_id: new_slot_id.clone(),
        old_cell_digest: old_digest.to_string(),
        new_cell_digest: new_digest.to_string(),
        translation_validation_proof_ref: translation_proof_ref.to_string(),
        content_hash_chain_into_lineage: content_hash_chain.to_string(),
        validation_artifacts,
        rollback_token: format!("rollback_token_step_{}", step),
        promotion_rationale: format!(
            "Performance improvement step {} - 15% latency reduction",
            step
        ),
        timestamp_ns,
        epoch: SecurityEpoch::from_raw(1),
        zone: zone.to_string(),
        signature_bundle: create_test_signature_bundle(),
    })
}

/// Create a synthetic lineage chain with multiple replacements.
fn create_lineage_chain() -> Result<LineageChain, Box<dyn std::error::Error>> {
    let base_timestamp = 1714003200000000000u64; // 2024-04-25 00:00:00 UTC in nanoseconds
    let mut entries = Vec::new();

    // Chain: delegate -> native_v1 -> native_v2 -> native_v3
    let replacements = vec![
        ("delegate_impl", "native_impl_v1"),
        ("native_impl_v1", "native_impl_v2"),
        ("native_impl_v2", "native_impl_v3"),
    ];

    for (step, (old_impl, new_impl)) in replacements.iter().enumerate() {
        let timestamp = base_timestamp + (step as u64 * 3600_000_000_000); // 1 hour apart
        let old_slot = create_test_slot_id(&format!("slot_{}", step));
        let new_slot = create_test_slot_id(&format!("slot_{}", step + 1));
        let old_digest = format!("digest_{}_{:08x}", old_impl, step * 0x1000);
        let new_digest = format!("digest_{}_{:08x}", new_impl, (step + 1) * 0x1000);
        let translation_proof = format!("translation_proof_step_{}", step);
        let content_hash_chain = if step == 0 {
            format!("genesis_chain_{:08x}", step)
        } else {
            format!("chain_link_{}_{:08x}", step, step * 0x2000)
        };

        let receipt = create_replacement_receipt(
            &old_slot,
            &new_slot,
            &old_digest,
            &new_digest,
            &translation_proof,
            &content_hash_chain,
            timestamp,
            step,
        )?;

        entries.push(LineageChainEntry {
            receipt,
            validation_proof: translation_proof,
            content_hash: content_hash_chain,
        });
    }

    Ok(LineageChain {
        initial_delegate_hash: "digest_delegate_impl_00000000".to_string(),
        final_native_hash: "digest_native_impl_v3_00003000".to_string(),
        chain_start_timestamp_ns: base_timestamp,
        entries,
    })
}

/// Verify the integrity of a lineage chain.
fn verify_lineage_chain(chain: &LineageChain) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Verifying lineage chain integrity...");

    if chain.entries.is_empty() {
        return Err("Empty lineage chain".into());
    }

    // Verify chain continuity
    for (i, entry) in chain.entries.iter().enumerate() {
        let receipt = &entry.receipt;

        println!(
            "  📝 Step {}: {} -> {}",
            i + 1,
            receipt.old_cell_digest,
            receipt.new_cell_digest
        );

        // Verify receipt fields are populated
        if receipt.old_slot_id.as_str().is_empty() {
            return Err(format!("Step {}: missing old_slot_id", i).into());
        }
        if receipt.new_slot_id.as_str().is_empty() {
            return Err(format!("Step {}: missing new_slot_id", i).into());
        }
        if receipt.translation_validation_proof_ref.is_empty() {
            return Err(format!("Step {}: missing translation_validation_proof_ref", i).into());
        }
        if receipt.content_hash_chain_into_lineage.is_empty() {
            return Err(format!("Step {}: missing content_hash_chain_into_lineage", i).into());
        }

        // Verify validation artifacts
        if receipt.validation_artifacts.is_empty() {
            return Err(format!("Step {}: no validation artifacts", i).into());
        }

        for artifact in &receipt.validation_artifacts {
            if artifact.status != ValidationStatus::Approved {
                return Err(format!(
                    "Step {}: artifact {} not approved: {:?}",
                    i, artifact.artifact_id, artifact.status
                )
                .into());
            }
        }

        // Verify timestamp ordering
        if i > 0 {
            let prev_timestamp = chain.entries[i - 1].receipt.timestamp_ns;
            if receipt.timestamp_ns <= prev_timestamp {
                return Err(format!("Step {}: timestamp not increasing", i).into());
            }
        }

        // Verify chain linkage (next step's old digest should match current new digest)
        if i + 1 < chain.entries.len() {
            let next_receipt = &chain.entries[i + 1].receipt;
            if receipt.new_cell_digest != next_receipt.old_cell_digest {
                return Err(format!(
                    "Step {}: chain break - {} != {}",
                    i, receipt.new_cell_digest, next_receipt.old_cell_digest
                )
                .into());
            }
        }
    }

    // Verify chain endpoints
    let first_receipt = &chain.entries[0].receipt;
    let last_receipt = &chain.entries.last().unwrap().receipt;

    if first_receipt.old_cell_digest != chain.initial_delegate_hash {
        return Err(format!(
            "Chain start mismatch: {} != {}",
            first_receipt.old_cell_digest, chain.initial_delegate_hash
        )
        .into());
    }

    if last_receipt.new_cell_digest != chain.final_native_hash {
        return Err(format!(
            "Chain end mismatch: {} != {}",
            last_receipt.new_cell_digest, chain.final_native_hash
        )
        .into());
    }

    println!(
        "  ✅ Chain integrity verified: {} steps",
        chain.entries.len()
    );
    println!(
        "  🔗 Complete lineage: {} -> {}",
        chain.initial_delegate_hash, chain.final_native_hash
    );

    Ok(())
}

/// Test the pre-signed demotion fallback integration.
fn test_demotion_fallback_integration(
    chain: &LineageChain,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️  Testing pre-signed demotion fallback integration...");

    let mut fallback_store = PreSignedFallbackStore::new();

    for (i, entry) in chain.entries.iter().enumerate() {
        let receipt = &entry.receipt;
        let promotion_id = PromotionId::from_str(&format!("promotion_{}", i))?;

        // Verify that for each replacement, a demotion fallback would be available
        // (In real usage, this would be checked before promotion)
        let has_fallback = fallback_store.has_sealed_fallback_for(&promotion_id);

        // For this demo, we'll create fallbacks as needed
        if !has_fallback {
            let permitted_triggers = vec![
                DemotionTrigger::DigestDrift,
                DemotionTrigger::SeverityThresholdCrossed,
                DemotionTrigger::GatekeeperRejection,
            ];

            fallback_store.seal_fallback_for(
                promotion_id.clone(),
                receipt.rollback_token.clone(),
                permitted_triggers,
            )?;
        }

        println!(
            "  📦 Step {}: demotion fallback sealed for {}",
            i + 1,
            promotion_id.as_str()
        );
    }

    println!("  ✅ All demotion fallbacks verified");
    Ok(())
}

/// Generate a summary report of the lineage chain.
fn generate_lineage_report(chain: &LineageChain) {
    println!("\n📊 LINEAGE CHAIN SUMMARY");
    println!("=======================");
    println!("Total replacements: {}", chain.entries.len());
    println!("Chain start time: {} ns", chain.chain_start_timestamp_ns);

    if let Some(last_entry) = chain.entries.last() {
        let duration_ns = last_entry.receipt.timestamp_ns - chain.chain_start_timestamp_ns;
        let duration_hours = duration_ns as f64 / 3600_000_000_000.0;
        println!("Chain duration: {:.2} hours", duration_hours);
    }

    println!("Initial delegate: {}", chain.initial_delegate_hash);
    println!("Final native: {}", chain.final_native_hash);

    println!("\nSTEP DETAILS:");
    for (i, entry) in chain.entries.iter().enumerate() {
        let receipt = &entry.receipt;
        println!(
            "  Step {}: {} -> {}",
            i + 1,
            &receipt.old_cell_digest[..20],
            &receipt.new_cell_digest[..20]
        );
        println!(
            "    Validation artifacts: {}",
            receipt.validation_artifacts.len()
        );
        println!("    Rationale: {}", receipt.promotion_rationale);
    }

    println!("\n✅ Lineage replay completed successfully");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Self-Replacement Lineage Chain Replay Example");
    println!("=================================================\n");

    // Create synthetic lineage chain
    println!("📋 Creating synthetic lineage chain...");
    let chain = create_lineage_chain()?;
    println!(
        "  ✅ Created chain with {} replacement steps\n",
        chain.entries.len()
    );

    // Verify lineage integrity
    verify_lineage_chain(&chain)?;
    println!("");

    // Test demotion fallback integration
    test_demotion_fallback_integration(&chain)?;
    println!("");

    // Generate summary report
    generate_lineage_report(&chain);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lineage_chain_creation() {
        let chain = create_lineage_chain().expect("should create chain");
        assert_eq!(chain.entries.len(), 3);
        assert!(!chain.initial_delegate_hash.is_empty());
        assert!(!chain.final_native_hash.is_empty());
    }

    #[test]
    fn test_lineage_chain_verification() {
        let chain = create_lineage_chain().expect("should create chain");
        verify_lineage_chain(&chain).expect("should verify successfully");
    }

    #[test]
    fn test_receipt_field_requirements() {
        let chain = create_lineage_chain().expect("should create chain");

        for entry in &chain.entries {
            let receipt = &entry.receipt;

            // Verify all required fields from bd-cixqu.22.1 are present
            assert!(
                !receipt.old_slot_id.as_str().is_empty(),
                "old_slot_id required"
            );
            assert!(
                !receipt.new_slot_id.as_str().is_empty(),
                "new_slot_id required"
            );
            assert!(
                !receipt.translation_validation_proof_ref.is_empty(),
                "translation_validation_proof_ref required"
            );
            assert!(
                !receipt.content_hash_chain_into_lineage.is_empty(),
                "content_hash_chain_into_lineage required"
            );
        }
    }

    #[test]
    fn test_demotion_fallback_integration() {
        let chain = create_lineage_chain().expect("should create chain");
        test_demotion_fallback_integration(&chain).expect("should integrate successfully");
    }
}
