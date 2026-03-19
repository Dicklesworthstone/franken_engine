//! Enrichment integration tests for the `simd_morsel_kernel` module.
//!
//! Covers enum serde roundtrips, as_str uniqueness, boundary values,
//! struct serde roundtrips, partitioning, kill switch semantics,
//! callback fence interactions, catalog operations, engine execution,
//! diagnostics, and edge cases.
use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::simd_morsel_kernel::*;
use frankenengine_engine::vectorized_lane_contract::{BuiltinFamily, LaneWidth, SelectionVector};

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ---------------------------------------------------------------
// 1. Schema version constant
// ---------------------------------------------------------------

#[test]
fn enrichment_constant_schema_version_value() {
    assert_eq!(
        SIMD_MORSEL_KERNEL_SCHEMA_VERSION,
        "franken-engine.simd-morsel-kernel.v1"
    );
    assert!(!SIMD_MORSEL_KERNEL_SCHEMA_VERSION.is_empty());
}

// ---------------------------------------------------------------
// 2. MorselSize enum — element_count, for_input_length, as_str, serde
// ---------------------------------------------------------------

#[test]
fn enrichment_morsel_size_element_count_all_variants() {
    assert_eq!(MorselSize::Small.element_count(), 64);
    assert_eq!(MorselSize::Medium.element_count(), 256);
    assert_eq!(MorselSize::Large.element_count(), 1024);
    assert_eq!(MorselSize::Huge.element_count(), 4096);
}

#[test]
fn enrichment_morsel_size_for_input_length_boundary_values() {
    // Zero
    assert_eq!(MorselSize::for_input_length(0), MorselSize::Small);
    // At boundary 128
    assert_eq!(MorselSize::for_input_length(128), MorselSize::Small);
    // Just past boundary
    assert_eq!(MorselSize::for_input_length(129), MorselSize::Medium);
    // At boundary 512
    assert_eq!(MorselSize::for_input_length(512), MorselSize::Medium);
    assert_eq!(MorselSize::for_input_length(513), MorselSize::Large);
    // At boundary 2048
    assert_eq!(MorselSize::for_input_length(2048), MorselSize::Large);
    assert_eq!(MorselSize::for_input_length(2049), MorselSize::Huge);
    // Max u64
    assert_eq!(MorselSize::for_input_length(u64::MAX), MorselSize::Huge);
}

#[test]
fn enrichment_morsel_size_as_str_uniqueness() {
    let variants = [
        MorselSize::Small,
        MorselSize::Medium,
        MorselSize::Large,
        MorselSize::Huge,
    ];
    let strings: BTreeSet<&str> = variants.iter().map(|v| v.as_str()).collect();
    assert_eq!(
        strings.len(),
        variants.len(),
        "as_str values must be unique"
    );
    assert!(strings.contains("small"));
    assert!(strings.contains("medium"));
    assert!(strings.contains("large"));
    assert!(strings.contains("huge"));
}

#[test]
fn enrichment_morsel_size_serde_roundtrip_all_variants() {
    for size in [
        MorselSize::Small,
        MorselSize::Medium,
        MorselSize::Large,
        MorselSize::Huge,
    ] {
        let json = serde_json::to_string(&size).unwrap();
        let decoded: MorselSize = serde_json::from_str(&json).unwrap();
        assert_eq!(size, decoded);
    }
}

#[test]
fn enrichment_morsel_size_ordering() {
    assert!(MorselSize::Small < MorselSize::Medium);
    assert!(MorselSize::Medium < MorselSize::Large);
    assert!(MorselSize::Large < MorselSize::Huge);
}

// ---------------------------------------------------------------
// 3. CallbackFenceKind — allows_vectorization, requires_ordering, as_str, serde
// ---------------------------------------------------------------

#[test]
fn enrichment_callback_fence_kind_allows_vectorization_all() {
    assert!(CallbackFenceKind::NoCallback.allows_vectorization());
    assert!(CallbackFenceKind::PureCallback.allows_vectorization());
    assert!(!CallbackFenceKind::SideEffectCallback.allows_vectorization());
    assert!(!CallbackFenceKind::ThrowingCallback.allows_vectorization());
    assert!(!CallbackFenceKind::MutatingCallback.allows_vectorization());
}

#[test]
fn enrichment_callback_fence_kind_requires_ordering_all() {
    assert!(!CallbackFenceKind::NoCallback.requires_ordering());
    assert!(!CallbackFenceKind::PureCallback.requires_ordering());
    assert!(CallbackFenceKind::SideEffectCallback.requires_ordering());
    assert!(CallbackFenceKind::ThrowingCallback.requires_ordering());
    assert!(CallbackFenceKind::MutatingCallback.requires_ordering());
}

#[test]
fn enrichment_callback_fence_kind_vectorization_ordering_mutual_exclusion() {
    // allows_vectorization and requires_ordering are mutually exclusive
    // for all variants
    let all_kinds = [
        CallbackFenceKind::NoCallback,
        CallbackFenceKind::PureCallback,
        CallbackFenceKind::SideEffectCallback,
        CallbackFenceKind::ThrowingCallback,
        CallbackFenceKind::MutatingCallback,
    ];
    for kind in all_kinds {
        assert_ne!(
            kind.allows_vectorization(),
            kind.requires_ordering(),
            "{:?} must be either vectorizable or ordering-required, not both/neither",
            kind
        );
    }
}

#[test]
fn enrichment_callback_fence_kind_as_str_uniqueness() {
    let all_kinds = [
        CallbackFenceKind::NoCallback,
        CallbackFenceKind::PureCallback,
        CallbackFenceKind::SideEffectCallback,
        CallbackFenceKind::ThrowingCallback,
        CallbackFenceKind::MutatingCallback,
    ];
    let strings: BTreeSet<&str> = all_kinds.iter().map(|k| k.as_str()).collect();
    assert_eq!(strings.len(), all_kinds.len());
    assert!(strings.contains("no_callback"));
    assert!(strings.contains("pure_callback"));
    assert!(strings.contains("side_effect_callback"));
    assert!(strings.contains("throwing_callback"));
    assert!(strings.contains("mutating_callback"));
}

#[test]
fn enrichment_callback_fence_kind_serde_roundtrip_all() {
    for kind in [
        CallbackFenceKind::NoCallback,
        CallbackFenceKind::PureCallback,
        CallbackFenceKind::SideEffectCallback,
        CallbackFenceKind::ThrowingCallback,
        CallbackFenceKind::MutatingCallback,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let decoded: CallbackFenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, decoded);
    }
}

// ---------------------------------------------------------------
// 4. CliffBehavior — as_str, serde
// ---------------------------------------------------------------

#[test]
fn enrichment_cliff_behavior_as_str_uniqueness() {
    let all = [
        CliffBehavior::ScalarFallback,
        CliffBehavior::NarrowLane,
        CliffBehavior::PaddedLane,
    ];
    let strings: BTreeSet<&str> = all.iter().map(|b| b.as_str()).collect();
    assert_eq!(strings.len(), all.len());
    assert!(strings.contains("scalar_fallback"));
    assert!(strings.contains("narrow_lane"));
    assert!(strings.contains("padded_lane"));
}

#[test]
fn enrichment_cliff_behavior_serde_roundtrip_all() {
    for behavior in [
        CliffBehavior::ScalarFallback,
        CliffBehavior::NarrowLane,
        CliffBehavior::PaddedLane,
    ] {
        let json = serde_json::to_string(&behavior).unwrap();
        let decoded: CliffBehavior = serde_json::from_str(&json).unwrap();
        assert_eq!(behavior, decoded);
    }
}

// ---------------------------------------------------------------
// 5. MorselOutcome — as_str, serde, ordering
// ---------------------------------------------------------------

#[test]
fn enrichment_morsel_outcome_as_str_all_variants() {
    assert_eq!(MorselOutcome::Vectorized.as_str(), "vectorized");
    assert_eq!(MorselOutcome::ScalarFallback.as_str(), "scalar_fallback");
    assert_eq!(MorselOutcome::AbortedMutation.as_str(), "aborted_mutation");
    assert_eq!(
        MorselOutcome::AbortedKillSwitch.as_str(),
        "aborted_kill_switch"
    );
    assert_eq!(MorselOutcome::Skipped.as_str(), "skipped");
}

#[test]
fn enrichment_morsel_outcome_serde_roundtrip_all() {
    for outcome in [
        MorselOutcome::Vectorized,
        MorselOutcome::ScalarFallback,
        MorselOutcome::AbortedMutation,
        MorselOutcome::AbortedKillSwitch,
        MorselOutcome::Skipped,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let decoded: MorselOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, decoded);
    }
}

#[test]
fn enrichment_morsel_outcome_as_str_uniqueness() {
    let all = [
        MorselOutcome::Vectorized,
        MorselOutcome::ScalarFallback,
        MorselOutcome::AbortedMutation,
        MorselOutcome::AbortedKillSwitch,
        MorselOutcome::Skipped,
    ];
    let strings: BTreeSet<&str> = all.iter().map(|o| o.as_str()).collect();
    assert_eq!(strings.len(), all.len());
}

// ---------------------------------------------------------------
// 6. MorselPartition — element_count, serde, edge cases
// ---------------------------------------------------------------

#[test]
fn enrichment_morsel_partition_element_count_normal() {
    let part = MorselPartition {
        index: 0,
        start: 100,
        end: 356,
        lane_width: LaneWidth::Lane8,
        is_tail: false,
    };
    assert_eq!(part.element_count(), 256);
}

#[test]
fn enrichment_morsel_partition_element_count_zero_when_start_equals_end() {
    let part = MorselPartition {
        index: 0,
        start: 500,
        end: 500,
        lane_width: LaneWidth::Lane4,
        is_tail: true,
    };
    assert_eq!(part.element_count(), 0);
}

#[test]
fn enrichment_morsel_partition_element_count_saturating_when_start_exceeds_end() {
    let part = MorselPartition {
        index: 0,
        start: 200,
        end: 50,
        lane_width: LaneWidth::Scalar,
        is_tail: false,
    };
    assert_eq!(part.element_count(), 0);
}

#[test]
fn enrichment_morsel_partition_serde_roundtrip() {
    let part = MorselPartition {
        index: 7,
        start: 1792,
        end: 2048,
        lane_width: LaneWidth::Lane16,
        is_tail: true,
    };
    let json = serde_json::to_string(&part).unwrap();
    let decoded: MorselPartition = serde_json::from_str(&json).unwrap();
    assert_eq!(part, decoded);
}

#[test]
fn enrichment_morsel_partition_max_values() {
    let part = MorselPartition {
        index: u32::MAX,
        start: u64::MAX - 1,
        end: u64::MAX,
        lane_width: LaneWidth::Lane32,
        is_tail: true,
    };
    assert_eq!(part.element_count(), 1);
    let json = serde_json::to_string(&part).unwrap();
    let decoded: MorselPartition = serde_json::from_str(&json).unwrap();
    assert_eq!(part, decoded);
}

// ---------------------------------------------------------------
// 7. CallbackFence — serde
// ---------------------------------------------------------------

#[test]
fn enrichment_callback_fence_serde_roundtrip() {
    let fence = CallbackFence {
        kind: CallbackFenceKind::SideEffectCallback,
        after_morsel: 42,
        flushed_effects: true,
        callback_invocations: 999,
    };
    let json = serde_json::to_string(&fence).unwrap();
    let decoded: CallbackFence = serde_json::from_str(&json).unwrap();
    assert_eq!(fence, decoded);
}

#[test]
fn enrichment_callback_fence_zero_invocations() {
    let fence = CallbackFence {
        kind: CallbackFenceKind::NoCallback,
        after_morsel: 0,
        flushed_effects: false,
        callback_invocations: 0,
    };
    let json = serde_json::to_string(&fence).unwrap();
    let decoded: CallbackFence = serde_json::from_str(&json).unwrap();
    assert_eq!(fence, decoded);
}

// ---------------------------------------------------------------
// 8. CliffPolicy — Default values, serde
// ---------------------------------------------------------------

#[test]
fn enrichment_cliff_policy_default_values() {
    let policy = CliffPolicy::default();
    assert_eq!(policy.min_vectorize_length, 8);
    assert_eq!(policy.behavior, CliffBehavior::ScalarFallback);
    assert_eq!(policy.min_parallel_length, 256);
}

#[test]
fn enrichment_cliff_policy_serde_roundtrip() {
    let policy = CliffPolicy {
        min_vectorize_length: 32,
        behavior: CliffBehavior::PaddedLane,
        min_parallel_length: 1024,
    };
    let json = serde_json::to_string(&policy).unwrap();
    let decoded: CliffPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, decoded);
}

// ---------------------------------------------------------------
// 9. KillSwitch — lifecycle, targeted families, epoch tracking
// ---------------------------------------------------------------

#[test]
fn enrichment_kill_switch_new_is_disengaged() {
    let ks = KillSwitch::new(epoch(1));
    assert!(!ks.engaged);
    assert!(ks.reason.is_none());
    assert!(ks.affected_families.is_empty());
    assert_eq!(ks.last_toggled_epoch, epoch(1));
}

#[test]
fn enrichment_kill_switch_engage_disengage_lifecycle() {
    let mut ks = KillSwitch::new(epoch(1));
    ks.engage("test reason", epoch(5));
    assert!(ks.engaged);
    assert_eq!(ks.reason, Some("test reason".to_string()));
    assert_eq!(ks.last_toggled_epoch, epoch(5));

    ks.disengage(epoch(10));
    assert!(!ks.engaged);
    assert!(ks.reason.is_none());
    assert_eq!(ks.last_toggled_epoch, epoch(10));
}

#[test]
fn enrichment_kill_switch_is_killed_all_families_when_empty_set() {
    let mut ks = KillSwitch::new(epoch(1));
    ks.engage("global kill", epoch(2));
    // Empty affected_families means all families killed
    assert!(ks.is_killed(BuiltinFamily::ArrayMap));
    assert!(ks.is_killed(BuiltinFamily::JsonParse));
    assert!(ks.is_killed(BuiltinFamily::TypedArraySort));
    assert!(ks.is_killed(BuiltinFamily::StringSplit));
}

#[test]
fn enrichment_kill_switch_targeted_families() {
    let mut ks = KillSwitch::new(epoch(1));
    ks.add_family(BuiltinFamily::ArrayMap);
    ks.add_family(BuiltinFamily::ArrayFilter);
    ks.engage("targeted", epoch(2));

    assert!(ks.is_killed(BuiltinFamily::ArrayMap));
    assert!(ks.is_killed(BuiltinFamily::ArrayFilter));
    assert!(!ks.is_killed(BuiltinFamily::JsonParse));
    assert!(!ks.is_killed(BuiltinFamily::TypedArrayFill));
}

#[test]
fn enrichment_kill_switch_not_engaged_never_kills() {
    let mut ks = KillSwitch::new(epoch(1));
    ks.add_family(BuiltinFamily::ArrayMap);
    // Not engaged — families added but nothing killed
    assert!(!ks.is_killed(BuiltinFamily::ArrayMap));
    assert!(!ks.is_killed(BuiltinFamily::JsonParse));
}

#[test]
fn enrichment_kill_switch_serde_roundtrip() {
    let mut ks = KillSwitch::new(epoch(3));
    ks.add_family(BuiltinFamily::ArrayMap);
    ks.add_family(BuiltinFamily::JsonParse);
    ks.engage("serde test", epoch(7));

    let json = serde_json::to_string(&ks).unwrap();
    let decoded: KillSwitch = serde_json::from_str(&json).unwrap();
    assert_eq!(ks.engaged, decoded.engaged);
    assert_eq!(ks.reason, decoded.reason);
    assert_eq!(ks.last_toggled_epoch, decoded.last_toggled_epoch);
    assert_eq!(ks.affected_families, decoded.affected_families);
}

// ---------------------------------------------------------------
// 10. MorselKernelDescriptor — new, supports_callback, is_suitable_length, serde
// ---------------------------------------------------------------

#[test]
fn enrichment_kernel_descriptor_new_populates_fields() {
    let k = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane8,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    assert_eq!(k.family, BuiltinFamily::ArrayMap);
    assert_eq!(k.lane_width, LaneWidth::Lane8);
    assert_eq!(k.morsel_size, MorselSize::Medium);
    assert_eq!(k.callback_fence, CallbackFenceKind::PureCallback);
    assert!(k.kernel_id.starts_with("mk-"));
    assert!(k.requires_homogeneous);
    assert_eq!(k.max_input_length, 0);
    // Default cliff policy
    assert_eq!(k.cliff_policy.min_vectorize_length, 8);
}

#[test]
fn enrichment_kernel_descriptor_supports_callback_no_callback_kernel() {
    let k = MorselKernelDescriptor::new(
        BuiltinFamily::StringSplit,
        LaneWidth::Lane4,
        MorselSize::Small,
        CallbackFenceKind::NoCallback,
    );
    assert!(k.supports_callback(CallbackFenceKind::NoCallback));
    assert!(!k.supports_callback(CallbackFenceKind::PureCallback));
    assert!(!k.supports_callback(CallbackFenceKind::SideEffectCallback));
    assert!(!k.supports_callback(CallbackFenceKind::MutatingCallback));
}

#[test]
fn enrichment_kernel_descriptor_supports_callback_pure_callback_kernel() {
    let k = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane8,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    assert!(k.supports_callback(CallbackFenceKind::NoCallback));
    assert!(k.supports_callback(CallbackFenceKind::PureCallback));
    assert!(!k.supports_callback(CallbackFenceKind::SideEffectCallback));
    assert!(!k.supports_callback(CallbackFenceKind::ThrowingCallback));
    assert!(!k.supports_callback(CallbackFenceKind::MutatingCallback));
}

#[test]
fn enrichment_kernel_descriptor_supports_callback_side_effect_kernel() {
    let k = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayReduce,
        LaneWidth::Lane4,
        MorselSize::Medium,
        CallbackFenceKind::SideEffectCallback,
    );
    // Side-effect-aware kernels handle everything
    assert!(k.supports_callback(CallbackFenceKind::NoCallback));
    assert!(k.supports_callback(CallbackFenceKind::PureCallback));
    assert!(k.supports_callback(CallbackFenceKind::SideEffectCallback));
    assert!(k.supports_callback(CallbackFenceKind::ThrowingCallback));
    assert!(k.supports_callback(CallbackFenceKind::MutatingCallback));
}

#[test]
fn enrichment_kernel_descriptor_is_suitable_length_below_cliff() {
    let k = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane8,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    // Default min_vectorize_length = 8
    assert!(!k.is_suitable_length(0));
    assert!(!k.is_suitable_length(7));
    assert!(k.is_suitable_length(8));
    assert!(k.is_suitable_length(10_000));
}

#[test]
fn enrichment_kernel_descriptor_is_suitable_length_with_max() {
    let mut k = MorselKernelDescriptor::new(
        BuiltinFamily::StringReplace,
        LaneWidth::Lane4,
        MorselSize::Small,
        CallbackFenceKind::NoCallback,
    );
    k.max_input_length = 500;
    assert!(k.is_suitable_length(500));
    assert!(!k.is_suitable_length(501));
    assert!(!k.is_suitable_length(u64::MAX));
    // Zero max_input_length means unlimited
    k.max_input_length = 0;
    assert!(k.is_suitable_length(u64::MAX));
}

#[test]
fn enrichment_kernel_descriptor_serde_roundtrip() {
    let k = MorselKernelDescriptor::new(
        BuiltinFamily::JsonParse,
        LaneWidth::Lane8,
        MorselSize::Large,
        CallbackFenceKind::NoCallback,
    );
    let json = serde_json::to_string(&k).unwrap();
    let decoded: MorselKernelDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(k, decoded);
}

#[test]
fn enrichment_kernel_descriptor_content_hash_deterministic() {
    let k1 = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane8,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    let k2 = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane8,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    assert_eq!(k1.content_hash, k2.content_hash);
}

#[test]
fn enrichment_kernel_descriptor_content_hash_differs_by_family() {
    let k1 = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane8,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    let k2 = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayFilter,
        LaneWidth::Lane8,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    assert_ne!(k1.content_hash, k2.content_hash);
}

#[test]
fn enrichment_kernel_descriptor_content_hash_differs_by_lane_width() {
    let k1 = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane4,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    let k2 = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane16,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    assert_ne!(k1.content_hash, k2.content_hash);
}

#[test]
fn enrichment_kernel_descriptor_content_hash_differs_by_morsel_size() {
    let k1 = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane8,
        MorselSize::Small,
        CallbackFenceKind::PureCallback,
    );
    let k2 = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane8,
        MorselSize::Huge,
        CallbackFenceKind::PureCallback,
    );
    assert_ne!(k1.content_hash, k2.content_hash);
}

// ---------------------------------------------------------------
// 11. MorselExecutionRecord — serde
// ---------------------------------------------------------------

#[test]
fn enrichment_morsel_execution_record_serde_roundtrip() {
    let record = MorselExecutionRecord {
        partition: MorselPartition {
            index: 2,
            start: 512,
            end: 768,
            lane_width: LaneWidth::Lane8,
            is_tail: false,
        },
        outcome: MorselOutcome::Vectorized,
        elements_processed: 256,
        elements_masked: 0,
        fences: vec![CallbackFence {
            kind: CallbackFenceKind::PureCallback,
            after_morsel: 2,
            flushed_effects: false,
            callback_invocations: 100,
        }],
        epoch: epoch(5),
    };
    let json = serde_json::to_string(&record).unwrap();
    let decoded: MorselExecutionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, decoded);
}

#[test]
fn enrichment_morsel_execution_record_empty_fences() {
    let record = MorselExecutionRecord {
        partition: MorselPartition {
            index: 0,
            start: 0,
            end: 64,
            lane_width: LaneWidth::Lane4,
            is_tail: true,
        },
        outcome: MorselOutcome::ScalarFallback,
        elements_processed: 64,
        elements_masked: 0,
        fences: Vec::new(),
        epoch: epoch(1),
    };
    let json = serde_json::to_string(&record).unwrap();
    let decoded: MorselExecutionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, decoded);
    assert!(decoded.fences.is_empty());
}

// ---------------------------------------------------------------
// 12. KernelExecutionReceipt — vectorization_rate_millionths, serde
// ---------------------------------------------------------------

#[test]
fn enrichment_receipt_vectorization_rate_full() {
    let receipt = KernelExecutionReceipt {
        receipt_id: "test-full".to_string(),
        kernel_id: "mk-test".to_string(),
        family: BuiltinFamily::ArrayMap,
        input_length: 1000,
        morsel_count: 4,
        vectorized_count: 4,
        scalar_count: 0,
        aborted_count: 0,
        total_elements: 1000,
        total_fences: 0,
        kill_switch_active: false,
        receipt_hash: ContentHash::compute(b"full"),
        epoch: epoch(1),
    };
    assert_eq!(receipt.vectorization_rate_millionths(), 1_000_000);
}

#[test]
fn enrichment_receipt_vectorization_rate_partial() {
    let receipt = KernelExecutionReceipt {
        receipt_id: "test-partial".to_string(),
        kernel_id: "mk-test".to_string(),
        family: BuiltinFamily::ArrayMap,
        input_length: 500,
        morsel_count: 4,
        vectorized_count: 1,
        scalar_count: 3,
        aborted_count: 0,
        total_elements: 500,
        total_fences: 0,
        kill_switch_active: false,
        receipt_hash: ContentHash::compute(b"partial"),
        epoch: epoch(1),
    };
    // 1/4 = 250_000 millionths
    assert_eq!(receipt.vectorization_rate_millionths(), 250_000);
}

#[test]
fn enrichment_receipt_vectorization_rate_zero_morsels() {
    let receipt = KernelExecutionReceipt {
        receipt_id: "test-zero".to_string(),
        kernel_id: "mk-test".to_string(),
        family: BuiltinFamily::ArrayMap,
        input_length: 0,
        morsel_count: 0,
        vectorized_count: 0,
        scalar_count: 0,
        aborted_count: 0,
        total_elements: 0,
        total_fences: 0,
        kill_switch_active: false,
        receipt_hash: ContentHash::compute(b"zero"),
        epoch: epoch(1),
    };
    assert_eq!(receipt.vectorization_rate_millionths(), 0);
}

#[test]
fn enrichment_receipt_vectorization_rate_half() {
    let receipt = KernelExecutionReceipt {
        receipt_id: "test-half".to_string(),
        kernel_id: "mk-test".to_string(),
        family: BuiltinFamily::ArrayMap,
        input_length: 200,
        morsel_count: 2,
        vectorized_count: 1,
        scalar_count: 1,
        aborted_count: 0,
        total_elements: 200,
        total_fences: 0,
        kill_switch_active: false,
        receipt_hash: ContentHash::compute(b"half"),
        epoch: epoch(1),
    };
    assert_eq!(receipt.vectorization_rate_millionths(), 500_000);
}

#[test]
fn enrichment_receipt_serde_roundtrip() {
    let mut engine = MorselKernelEngine::new(epoch(42));
    let receipt = engine
        .execute(
            BuiltinFamily::ArrayFilter,
            500,
            CallbackFenceKind::PureCallback,
            None,
        )
        .unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    let decoded: KernelExecutionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.receipt_id, decoded.receipt_id);
    assert_eq!(receipt.receipt_hash, decoded.receipt_hash);
    assert_eq!(receipt.family, decoded.family);
    assert_eq!(receipt.morsel_count, decoded.morsel_count);
    assert_eq!(receipt.total_elements, decoded.total_elements);
}

// ---------------------------------------------------------------
// 13. MorselKernelCatalog — new, with_defaults, register, lookup
// ---------------------------------------------------------------

#[test]
fn enrichment_catalog_new_is_empty() {
    let cat = MorselKernelCatalog::new();
    assert_eq!(cat.kernel_count(), 0);
    assert!(cat.lookup(BuiltinFamily::ArrayMap).is_none());
    assert!(cat.registered_families().is_empty());
}

#[test]
fn enrichment_catalog_with_defaults_has_15_families() {
    let cat = MorselKernelCatalog::with_defaults();
    assert_eq!(cat.kernel_count(), 15);
    let families = cat.registered_families();
    assert_eq!(families.len(), 15);
    // All BuiltinFamily::ALL entries should be registered
    for family in BuiltinFamily::ALL {
        assert!(
            cat.lookup(*family).is_some(),
            "Missing kernel for {:?}",
            family
        );
    }
}

#[test]
fn enrichment_catalog_default_trait_matches_with_defaults() {
    let cat1 = MorselKernelCatalog::with_defaults();
    let cat2: MorselKernelCatalog = Default::default();
    assert_eq!(cat1.kernel_count(), cat2.kernel_count());
}

#[test]
fn enrichment_catalog_register_and_lookup() {
    let mut cat = MorselKernelCatalog::new();
    let k = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane8,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    let kid = k.kernel_id.clone();
    cat.register(k);
    assert_eq!(cat.kernel_count(), 1);

    let looked_up = cat.lookup(BuiltinFamily::ArrayMap).unwrap();
    assert_eq!(looked_up.kernel_id, kid);
    assert_eq!(looked_up.family, BuiltinFamily::ArrayMap);
}

#[test]
fn enrichment_catalog_register_overwrites_family_map() {
    let mut cat = MorselKernelCatalog::new();
    let k1 = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane4,
        MorselSize::Small,
        CallbackFenceKind::NoCallback,
    );
    cat.register(k1);

    let k2 = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane16,
        MorselSize::Huge,
        CallbackFenceKind::PureCallback,
    );
    cat.register(k2);

    // family_map points to latest registration
    let looked_up = cat.lookup(BuiltinFamily::ArrayMap).unwrap();
    assert_eq!(looked_up.lane_width, LaneWidth::Lane16);
    assert_eq!(looked_up.morsel_size, MorselSize::Huge);
    // Both kernel_ids remain since they differ (different lane widths)
    assert_eq!(cat.kernel_count(), 2);
}

#[test]
fn enrichment_catalog_serde_roundtrip() {
    let cat = MorselKernelCatalog::with_defaults();
    let json = serde_json::to_string(&cat).unwrap();
    let decoded: MorselKernelCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(cat.kernel_count(), decoded.kernel_count());
    // Verify lookup still works after deserialization
    let k = decoded.lookup(BuiltinFamily::TypedArrayFill).unwrap();
    assert_eq!(k.family, BuiltinFamily::TypedArrayFill);
    assert_eq!(k.lane_width, LaneWidth::Lane16);
}

#[test]
fn enrichment_catalog_default_array_kernels_lane8() {
    let cat = MorselKernelCatalog::with_defaults();
    for family in [
        BuiltinFamily::ArrayMap,
        BuiltinFamily::ArrayFilter,
        BuiltinFamily::ArrayForEach,
        BuiltinFamily::ArrayEvery,
        BuiltinFamily::ArraySome,
        BuiltinFamily::ArrayFind,
    ] {
        let k = cat.lookup(family).unwrap();
        assert_eq!(
            k.lane_width,
            LaneWidth::Lane8,
            "Expected Lane8 for {:?}",
            family
        );
        assert_eq!(k.morsel_size, MorselSize::Medium);
        assert_eq!(k.callback_fence, CallbackFenceKind::PureCallback);
    }
}

#[test]
fn enrichment_catalog_default_string_kernels_lane4() {
    let cat = MorselKernelCatalog::with_defaults();
    for family in [
        BuiltinFamily::StringReplace,
        BuiltinFamily::StringSplit,
        BuiltinFamily::StringMatch,
    ] {
        let k = cat.lookup(family).unwrap();
        assert_eq!(
            k.lane_width,
            LaneWidth::Lane4,
            "Expected Lane4 for {:?}",
            family
        );
        assert_eq!(k.morsel_size, MorselSize::Small);
        assert_eq!(k.callback_fence, CallbackFenceKind::NoCallback);
    }
}

#[test]
fn enrichment_catalog_default_json_kernels_lane8() {
    let cat = MorselKernelCatalog::with_defaults();
    for family in [BuiltinFamily::JsonParse, BuiltinFamily::JsonStringify] {
        let k = cat.lookup(family).unwrap();
        assert_eq!(
            k.lane_width,
            LaneWidth::Lane8,
            "Expected Lane8 for {:?}",
            family
        );
        assert_eq!(k.morsel_size, MorselSize::Large);
        assert_eq!(k.callback_fence, CallbackFenceKind::NoCallback);
    }
}

#[test]
fn enrichment_catalog_default_typed_array_kernels_lane16() {
    let cat = MorselKernelCatalog::with_defaults();
    for family in [
        BuiltinFamily::TypedArraySort,
        BuiltinFamily::TypedArrayCopy,
        BuiltinFamily::TypedArrayFill,
    ] {
        let k = cat.lookup(family).unwrap();
        assert_eq!(
            k.lane_width,
            LaneWidth::Lane16,
            "Expected Lane16 for {:?}",
            family
        );
        assert_eq!(k.morsel_size, MorselSize::Large);
        assert_eq!(k.callback_fence, CallbackFenceKind::NoCallback);
        assert!(k.requires_homogeneous);
    }
}

#[test]
fn enrichment_catalog_default_array_reduce_side_effect() {
    let cat = MorselKernelCatalog::with_defaults();
    let k = cat.lookup(BuiltinFamily::ArrayReduce).unwrap();
    assert_eq!(k.lane_width, LaneWidth::Lane4);
    assert_eq!(k.morsel_size, MorselSize::Medium);
    assert_eq!(k.callback_fence, CallbackFenceKind::SideEffectCallback);
}

// ---------------------------------------------------------------
// 14. MorselKernelEngine — creation, partition, execute, kill switch
// ---------------------------------------------------------------

#[test]
fn enrichment_engine_new_initial_state() {
    let engine = MorselKernelEngine::new(epoch(1));
    assert_eq!(engine.total_morsels_executed, 0);
    assert_eq!(engine.total_elements_processed, 0);
    assert_eq!(engine.total_scalar_fallbacks, 0);
    assert!(!engine.kill_switch.engaged);
    assert_eq!(engine.receipt_count(), 0);
    assert!(engine.receipts.is_empty());
    assert!(engine.family_execution_counts.is_empty());
    assert!(engine.family_vectorization_rates.is_empty());
    assert_eq!(engine.epoch, epoch(1));
}

#[test]
fn enrichment_engine_with_catalog_custom() {
    let mut cat = MorselKernelCatalog::new();
    cat.register(MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane4,
        MorselSize::Small,
        CallbackFenceKind::NoCallback,
    ));
    let engine = MorselKernelEngine::with_catalog(cat, epoch(99));
    assert_eq!(engine.catalog.kernel_count(), 1);
    assert_eq!(engine.epoch, epoch(99));
}

#[test]
fn enrichment_engine_partition_empty_input() {
    let engine = MorselKernelEngine::new(epoch(1));
    let parts = engine.partition(BuiltinFamily::ArrayMap, 0);
    assert!(parts.is_empty());
}

#[test]
fn enrichment_engine_partition_single_element() {
    let engine = MorselKernelEngine::new(epoch(1));
    let parts = engine.partition(BuiltinFamily::ArrayMap, 1);
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].start, 0);
    assert_eq!(parts[0].end, 1);
    assert_eq!(parts[0].element_count(), 1);
    assert!(parts[0].is_tail);
    assert_eq!(parts[0].index, 0);
}

#[test]
fn enrichment_engine_partition_exact_morsel_size() {
    let engine = MorselKernelEngine::new(epoch(1));
    // ArrayMap uses Medium (256)
    let parts = engine.partition(BuiltinFamily::ArrayMap, 256);
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].element_count(), 256);
    assert!(parts[0].is_tail);
}

#[test]
fn enrichment_engine_partition_contiguous_no_gaps() {
    let engine = MorselKernelEngine::new(epoch(1));
    let parts = engine.partition(BuiltinFamily::ArrayFilter, 999);
    assert!(!parts.is_empty());
    // Verify contiguity
    assert_eq!(parts[0].start, 0);
    for i in 1..parts.len() {
        assert_eq!(parts[i].start, parts[i - 1].end);
    }
    assert_eq!(parts.last().unwrap().end, 999);
    // Only last is tail
    for p in &parts[..parts.len() - 1] {
        assert!(!p.is_tail);
    }
    assert!(parts.last().unwrap().is_tail);
}

#[test]
fn enrichment_engine_partition_unknown_family_empty_catalog() {
    let engine = MorselKernelEngine::with_catalog(MorselKernelCatalog::new(), epoch(1));
    let parts = engine.partition(BuiltinFamily::ArrayMap, 500);
    assert!(parts.is_empty());
}

#[test]
fn enrichment_engine_partition_uses_correct_lane_width() {
    let engine = MorselKernelEngine::new(epoch(1));
    // TypedArray uses Lane16
    let parts = engine.partition(BuiltinFamily::TypedArraySort, 2048);
    for p in &parts {
        assert_eq!(p.lane_width, LaneWidth::Lane16);
    }
    // String uses Lane4
    let parts = engine.partition(BuiltinFamily::StringReplace, 100);
    for p in &parts {
        assert_eq!(p.lane_width, LaneWidth::Lane4);
    }
}

#[test]
fn enrichment_engine_execute_pure_callback_vectorized() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    let receipt = engine
        .execute(
            BuiltinFamily::ArrayMap,
            500,
            CallbackFenceKind::PureCallback,
            None,
        )
        .unwrap();
    assert_eq!(receipt.family, BuiltinFamily::ArrayMap);
    assert_eq!(receipt.input_length, 500);
    assert!(receipt.vectorized_count > 0);
    assert!(receipt.receipt_id.starts_with("mkr-"));
    assert_eq!(receipt.receipt_id.len(), 20); // "mkr-" + 16 hex chars
    assert_eq!(receipt.total_fences, 0);
    assert!(!receipt.kill_switch_active);
}

#[test]
fn enrichment_engine_execute_zero_length_returns_none() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    let receipt = engine.execute(
        BuiltinFamily::ArrayMap,
        0,
        CallbackFenceKind::PureCallback,
        None,
    );
    assert!(receipt.is_none());
}

#[test]
fn enrichment_engine_execute_unsupported_callback_returns_none() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    // ArrayMap PureCallback kernel rejects MutatingCallback
    let receipt = engine.execute(
        BuiltinFamily::ArrayMap,
        100,
        CallbackFenceKind::MutatingCallback,
        None,
    );
    assert!(receipt.is_none());
}

#[test]
fn enrichment_engine_execute_mutating_aborts_all_morsels() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    // ArrayReduce (SideEffectCallback kernel) accepts MutatingCallback
    let receipt = engine
        .execute(
            BuiltinFamily::ArrayReduce,
            500,
            CallbackFenceKind::MutatingCallback,
            None,
        )
        .unwrap();
    assert_eq!(receipt.vectorized_count, 0);
    assert_eq!(receipt.scalar_count, 0);
    assert!(receipt.aborted_count > 0);
    assert_eq!(receipt.aborted_count, receipt.morsel_count);
}

#[test]
fn enrichment_engine_execute_side_effect_produces_fences() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    let receipt = engine
        .execute(
            BuiltinFamily::ArrayReduce,
            600,
            CallbackFenceKind::SideEffectCallback,
            None,
        )
        .unwrap();
    assert!(receipt.total_fences > 0);
    assert_eq!(receipt.total_fences, receipt.morsel_count);
}

#[test]
fn enrichment_engine_execute_no_callback_zero_fences() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    let receipt = engine
        .execute(
            BuiltinFamily::TypedArrayFill,
            2000,
            CallbackFenceKind::NoCallback,
            None,
        )
        .unwrap();
    assert_eq!(receipt.total_fences, 0);
    assert!(receipt.vectorized_count > 0);
}

#[test]
fn enrichment_engine_execute_below_cliff_scalar_fallback() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    // Default cliff min_vectorize_length = 8. Single morsel with 5 < 8 elements.
    let receipt = engine
        .execute(
            BuiltinFamily::ArrayMap,
            5,
            CallbackFenceKind::PureCallback,
            None,
        )
        .unwrap();
    assert_eq!(receipt.vectorized_count, 0);
    assert_eq!(receipt.scalar_count, 1);
    assert_eq!(engine.total_scalar_fallbacks, 1);
}

#[test]
fn enrichment_engine_kill_switch_blocks_all() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    engine.engage_kill_switch("emergency");
    let receipt = engine.execute(
        BuiltinFamily::ArrayMap,
        100,
        CallbackFenceKind::PureCallback,
        None,
    );
    assert!(receipt.is_none());
}

#[test]
fn enrichment_engine_targeted_kill_switch_selective() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    engine.engage_family_kill(BuiltinFamily::ArrayMap, "map broken");

    // ArrayMap is killed
    assert!(
        engine
            .execute(
                BuiltinFamily::ArrayMap,
                100,
                CallbackFenceKind::PureCallback,
                None
            )
            .is_none()
    );

    // JsonParse still alive
    assert!(
        engine
            .execute(
                BuiltinFamily::JsonParse,
                100,
                CallbackFenceKind::NoCallback,
                None
            )
            .is_some()
    );
}

#[test]
fn enrichment_engine_disengage_kill_switch_resumes() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    engine.engage_kill_switch("temp");
    engine.disengage_kill_switch();
    let receipt = engine.execute(
        BuiltinFamily::ArrayMap,
        100,
        CallbackFenceKind::PureCallback,
        None,
    );
    assert!(receipt.is_some());
}

#[test]
fn enrichment_engine_cumulative_stats() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    engine.execute(
        BuiltinFamily::ArrayMap,
        256,
        CallbackFenceKind::PureCallback,
        None,
    );
    let m1 = engine.total_morsels_executed;
    let e1 = engine.total_elements_processed;
    assert!(m1 > 0);
    assert!(e1 > 0);

    engine.execute(
        BuiltinFamily::JsonParse,
        2000,
        CallbackFenceKind::NoCallback,
        None,
    );
    assert!(engine.total_morsels_executed > m1);
    assert!(engine.total_elements_processed > e1);
    assert_eq!(engine.receipt_count(), 2);
}

#[test]
fn enrichment_engine_selection_vector_all_active() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    let sel = SelectionVector::new(100);
    let receipt = engine
        .execute(
            BuiltinFamily::ArrayMap,
            100,
            CallbackFenceKind::PureCallback,
            Some(&sel),
        )
        .unwrap();
    assert_eq!(receipt.total_elements, 100);
}

#[test]
fn enrichment_engine_selection_vector_partial_mask() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    let mut sel = SelectionVector::new(100);
    for i in 0..30 {
        sel.mask(i);
    }
    let receipt = engine
        .execute(
            BuiltinFamily::ArrayMap,
            100,
            CallbackFenceKind::PureCallback,
            Some(&sel),
        )
        .unwrap();
    assert_eq!(receipt.total_elements, 70);
}

#[test]
fn enrichment_engine_selection_vector_all_masked() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    let mut sel = SelectionVector::new(50);
    for i in 0..50 {
        sel.mask(i);
    }
    let receipt = engine
        .execute(
            BuiltinFamily::ArrayMap,
            50,
            CallbackFenceKind::PureCallback,
            Some(&sel),
        )
        .unwrap();
    assert_eq!(receipt.total_elements, 0);
}

// ---------------------------------------------------------------
// 15. MorselKernelDiagnostics — diagnostics snapshot, serde
// ---------------------------------------------------------------

#[test]
fn enrichment_diagnostics_initial_state() {
    let engine = MorselKernelEngine::new(epoch(1));
    let diag = engine.diagnostics();
    assert_eq!(diag.kernel_count, 15);
    assert_eq!(diag.total_morsels_executed, 0);
    assert_eq!(diag.total_elements_processed, 0);
    assert_eq!(diag.total_scalar_fallbacks, 0);
    assert_eq!(diag.total_receipts, 0);
    assert!(!diag.kill_switch_engaged);
    assert!(diag.family_execution_counts.is_empty());
    assert!(diag.family_vectorization_rates.is_empty());
}

#[test]
fn enrichment_diagnostics_after_executions() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    engine.execute(
        BuiltinFamily::ArrayMap,
        500,
        CallbackFenceKind::PureCallback,
        None,
    );
    engine.execute(
        BuiltinFamily::JsonParse,
        2000,
        CallbackFenceKind::NoCallback,
        None,
    );
    let diag = engine.diagnostics();
    assert!(diag.total_morsels_executed > 0);
    assert!(diag.total_elements_processed > 0);
    assert_eq!(diag.total_receipts, 2);
    assert_eq!(diag.family_execution_counts.get("array_map"), Some(&1));
    assert_eq!(diag.family_execution_counts.get("json_parse"), Some(&1));
}

#[test]
fn enrichment_diagnostics_reflects_kill_switch() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    assert!(!engine.diagnostics().kill_switch_engaged);

    engine.engage_kill_switch("test");
    assert!(engine.diagnostics().kill_switch_engaged);

    engine.disengage_kill_switch();
    assert!(!engine.diagnostics().kill_switch_engaged);
}

#[test]
fn enrichment_diagnostics_serde_roundtrip() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    engine.execute(
        BuiltinFamily::ArrayMap,
        256,
        CallbackFenceKind::PureCallback,
        None,
    );
    let diag = engine.diagnostics();
    let json = serde_json::to_string(&diag).unwrap();
    let decoded: MorselKernelDiagnostics = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, decoded);
}

// ---------------------------------------------------------------
// 16. Receipt determinism and uniqueness
// ---------------------------------------------------------------

#[test]
fn enrichment_receipt_hash_deterministic_same_inputs() {
    let mut e1 = MorselKernelEngine::new(epoch(1));
    let mut e2 = MorselKernelEngine::new(epoch(1));
    let r1 = e1
        .execute(
            BuiltinFamily::ArrayMap,
            100,
            CallbackFenceKind::PureCallback,
            None,
        )
        .unwrap();
    let r2 = e2
        .execute(
            BuiltinFamily::ArrayMap,
            100,
            CallbackFenceKind::PureCallback,
            None,
        )
        .unwrap();
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
    assert_eq!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn enrichment_receipt_hash_differs_by_epoch() {
    let mut e1 = MorselKernelEngine::new(epoch(1));
    let mut e2 = MorselKernelEngine::new(epoch(99));
    let r1 = e1
        .execute(
            BuiltinFamily::ArrayMap,
            100,
            CallbackFenceKind::PureCallback,
            None,
        )
        .unwrap();
    let r2 = e2
        .execute(
            BuiltinFamily::ArrayMap,
            100,
            CallbackFenceKind::PureCallback,
            None,
        )
        .unwrap();
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_receipt_hash_differs_by_input_length() {
    let mut e1 = MorselKernelEngine::new(epoch(1));
    let mut e2 = MorselKernelEngine::new(epoch(1));
    let r1 = e1
        .execute(
            BuiltinFamily::ArrayMap,
            100,
            CallbackFenceKind::PureCallback,
            None,
        )
        .unwrap();
    let r2 = e2
        .execute(
            BuiltinFamily::ArrayMap,
            200,
            CallbackFenceKind::PureCallback,
            None,
        )
        .unwrap();
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

// ---------------------------------------------------------------
// 17. Engine serde roundtrip
// ---------------------------------------------------------------

#[test]
fn enrichment_engine_serde_roundtrip() {
    let mut engine = MorselKernelEngine::new(epoch(5));
    engine.execute(
        BuiltinFamily::ArrayMap,
        300,
        CallbackFenceKind::PureCallback,
        None,
    );
    let json = serde_json::to_string(&engine).unwrap();
    let decoded: MorselKernelEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(
        engine.total_morsels_executed,
        decoded.total_morsels_executed
    );
    assert_eq!(
        engine.total_elements_processed,
        decoded.total_elements_processed
    );
    assert_eq!(engine.receipt_count(), decoded.receipt_count());
    assert_eq!(engine.epoch, decoded.epoch);
}

// ---------------------------------------------------------------
// 18. Large input stress
// ---------------------------------------------------------------

#[test]
fn enrichment_engine_partition_large_input_many_morsels() {
    let engine = MorselKernelEngine::new(epoch(1));
    // JsonParse uses Large morsel (1024). 10000 / 1024 = 9 full + 1 tail (784)
    let parts = engine.partition(BuiltinFamily::JsonParse, 10_000);
    assert_eq!(parts.len(), 10);
    // Verify indices
    for (i, p) in parts.iter().enumerate() {
        assert_eq!(p.index, i as u32);
    }
    // First 9 are full-sized
    for p in &parts[..9] {
        assert_eq!(p.element_count(), 1024);
        assert!(!p.is_tail);
    }
    // Last is the tail
    assert_eq!(parts[9].element_count(), 10_000 - 9 * 1024);
    assert!(parts[9].is_tail);
}

// ---------------------------------------------------------------
// 19. Throwing callback scalar fallback
// ---------------------------------------------------------------

#[test]
fn enrichment_engine_throwing_callback_produces_scalar_fallback() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    let receipt = engine
        .execute(
            BuiltinFamily::ArrayReduce,
            300,
            CallbackFenceKind::ThrowingCallback,
            None,
        )
        .unwrap();
    // ThrowingCallback does not allow vectorization
    assert_eq!(receipt.vectorized_count, 0);
    assert!(receipt.scalar_count > 0);
    assert!(receipt.total_fences > 0); // requires_ordering
}

// ---------------------------------------------------------------
// 20. Family vectorization rate tracking
// ---------------------------------------------------------------

#[test]
fn enrichment_engine_family_vectorization_rate_tracked() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    engine.execute(
        BuiltinFamily::TypedArrayFill,
        2000,
        CallbackFenceKind::NoCallback,
        None,
    );
    // Full vectorization -> rate should be 1_000_000
    let rate = engine.family_vectorization_rates.get("typed_array_fill");
    assert!(rate.is_some());
    assert_eq!(*rate.unwrap(), 1_000_000);
}

#[test]
fn enrichment_engine_family_execution_count_increments() {
    let mut engine = MorselKernelEngine::new(epoch(1));
    engine.execute(
        BuiltinFamily::ArrayMap,
        100,
        CallbackFenceKind::PureCallback,
        None,
    );
    engine.execute(
        BuiltinFamily::ArrayMap,
        200,
        CallbackFenceKind::PureCallback,
        None,
    );
    engine.execute(
        BuiltinFamily::ArrayMap,
        300,
        CallbackFenceKind::PureCallback,
        None,
    );
    assert_eq!(engine.family_execution_counts.get("array_map"), Some(&3));
}
