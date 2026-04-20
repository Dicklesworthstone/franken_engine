// Regression test for bd-ldm0f: Decision receipt extension_id propagation
// Tests that extension_id is correctly propagated through the DecisionReceipt pipeline

use frankenengine_core::baseline_interpreter::{EvidenceLog, DecisionReceipt, ExtensionId};
use serde_json;

#[test]
fn test_decision_receipt_extension_id_propagation() {
    // Create a test evidence log
    let test_key = [42u8; 32];
    let mut log = EvidenceLog::with_key(test_key);

    // Create a test extension ID
    let test_extension_id = ExtensionId::from("test-extension-123");

    // Add a receipt with the extension ID
    let receipt = log.add_receipt(
        test_extension_id.clone(),
        "memory_access".to_string(),
        750, // risk_score
        "quarantine".to_string(),
        0x1000, // instruction_pointer
        &[], // empty register_state to avoid Value type dependency
    );

    // Regression test: verify extension_id propagates correctly through receipt pipeline
    assert_eq!(
        receipt.extension_id,
        test_extension_id,
        "extension_id must propagate correctly through DecisionReceipt creation"
    );

    // Verify the receipt is properly formed with other expected fields
    assert_eq!(receipt.operation_type, "memory_access");
    assert_eq!(receipt.risk_score, 750);
    assert_eq!(receipt.action_taken, "quarantine");
    assert_eq!(receipt.instruction_pointer, 0x1000);
    assert!(!receipt.signature.is_empty(), "Receipt must be signed");

    // Test with different extension ID to ensure no cross-contamination
    let second_extension_id = ExtensionId::from("different-extension-456");
    let second_receipt = log.add_receipt(
        second_extension_id.clone(),
        "syscall".to_string(),
        200,
        "allow".to_string(),
        0x2000,
        &[Value::String("test".to_string())],
    );

    assert_eq!(
        second_receipt.extension_id,
        second_extension_id,
        "Each receipt must maintain its own extension_id"
    );
    assert_ne!(
        second_receipt.extension_id,
        test_extension_id,
        "Different receipts must have different extension_ids when created with different inputs"
    );
}

#[test]
fn test_receipt_chaining_preserves_extension_id() {
    // Test that extension_id is preserved in receipt chains
    let mut log = EvidenceLog::with_key([1u8; 32]);

    let ext_id_1 = ExtensionId::from("chain-test-1");
    let ext_id_2 = ExtensionId::from("chain-test-2");

    // Add first receipt
    let receipt1 = log.add_receipt(
        ext_id_1.clone(),
        "operation1".to_string(),
        100,
        "allow".to_string(),
        0x100,
        &[], // empty register_state
    );

    // Add second receipt
    let receipt2 = log.add_receipt(
        ext_id_2.clone(),
        "operation2".to_string(),
        200,
        "allow".to_string(),
        0x200,
        &[], // empty register_state
    );

    // Verify both receipts maintain their distinct extension_ids
    assert_eq!(receipt1.extension_id, ext_id_1);
    assert_eq!(receipt2.extension_id, ext_id_2);

    // Verify receipt chaining doesn't affect extension_id
    assert!(receipt2.previous_receipt_hash.is_some(), "Second receipt should reference first");
    // SAFETY: Just asserted that previous_receipt_hash is Some, so unwrap cannot fail.
    assert_eq!(receipt2.previous_receipt_hash.as_ref().unwrap(), &receipt1.signature);
}

#[test]
fn test_extension_id_serialization_roundtrip() {
    // Test that extension_id survives serialization/deserialization in receipts
    use serde_json;

    let mut log = EvidenceLog::with_key([255u8; 32]);
    let test_extension_id = ExtensionId::from("serialization-test-ext");

    let receipt = log.add_receipt(
        test_extension_id.clone(),
        "test_op".to_string(),
        500,
        "monitor".to_string(),
        0xDEAD,
        &[], // empty register_state
    );

    // Serialize the receipt
    let serialized = serde_json::to_string(receipt).expect("Receipt should serialize");

    // Deserialize the receipt
    let deserialized: frankenengine_core::baseline_interpreter::DecisionReceipt =
        serde_json::from_str(&serialized).expect("Receipt should deserialize");

    // Verify extension_id is preserved through serialization roundtrip
    assert_eq!(
        deserialized.extension_id,
        test_extension_id,
        "extension_id must survive serialization roundtrip"
    );

    // Verify all other fields are also preserved
    assert_eq!(deserialized.operation_type, receipt.operation_type);
    assert_eq!(deserialized.risk_score, receipt.risk_score);
    assert_eq!(deserialized.action_taken, receipt.action_taken);
    assert_eq!(deserialized.instruction_pointer, receipt.instruction_pointer);
    assert_eq!(deserialized.signature, receipt.signature);
}