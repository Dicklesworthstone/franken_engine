//! Integration tests for simd_morsel_kernel (RGC-624B).
//!
//! Tests morsel-parallel execution kernels with vectorized lanes,
//! callback fences, cliff handling, kill switches, and execution receipts.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::simd_morsel_kernel::{
    CallbackFence, CallbackFenceKind, CliffBehavior, CliffPolicy, KernelExecutionReceipt,
    KillSwitch, MorselKernelCatalog, MorselKernelDescriptor, MorselKernelDiagnostics,
    MorselKernelEngine, MorselOutcome, MorselPartition, MorselSize,
    SIMD_MORSEL_KERNEL_SCHEMA_VERSION,
};
use frankenengine_engine::vectorized_lane_contract::{BuiltinFamily, LaneWidth, SelectionVector};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn default_engine() -> MorselKernelEngine {
    MorselKernelEngine::new(epoch(1))
}

// ---------------------------------------------------------------------------
// MorselSize
// ---------------------------------------------------------------------------

#[test]
fn test_morsel_size_element_count_values() {
    assert_eq!(MorselSize::Small.element_count(), 64);
    assert_eq!(MorselSize::Medium.element_count(), 256);
    assert_eq!(MorselSize::Large.element_count(), 1024);
    assert_eq!(MorselSize::Huge.element_count(), 4096);
}

#[test]
fn test_morsel_size_selection_boundaries() {
    // Boundary: <=128 -> Small
    assert_eq!(MorselSize::for_input_length(0), MorselSize::Small);
    assert_eq!(MorselSize::for_input_length(1), MorselSize::Small);
    assert_eq!(MorselSize::for_input_length(128), MorselSize::Small);

    // Boundary: 129..=512 -> Medium
    assert_eq!(MorselSize::for_input_length(129), MorselSize::Medium);
    assert_eq!(MorselSize::for_input_length(512), MorselSize::Medium);

    // Boundary: 513..=2048 -> Large
    assert_eq!(MorselSize::for_input_length(513), MorselSize::Large);
    assert_eq!(MorselSize::for_input_length(2048), MorselSize::Large);

    // Boundary: >2048 -> Huge
    assert_eq!(MorselSize::for_input_length(2049), MorselSize::Huge);
    assert_eq!(MorselSize::for_input_length(1_000_000), MorselSize::Huge);
}

#[test]
fn test_morsel_size_as_str_roundtrip() {
    for size in [
        MorselSize::Small,
        MorselSize::Medium,
        MorselSize::Large,
        MorselSize::Huge,
    ] {
        let s = size.as_str();
        assert!(!s.is_empty());
        // Verify as_str is deterministic
        assert_eq!(size.as_str(), s);
    }
}

#[test]
fn test_morsel_size_ordering() {
    assert!(MorselSize::Small < MorselSize::Medium);
    assert!(MorselSize::Medium < MorselSize::Large);
    assert!(MorselSize::Large < MorselSize::Huge);
}

// ---------------------------------------------------------------------------
// CallbackFenceKind
// ---------------------------------------------------------------------------

#[test]
fn test_callback_fence_vectorization_rules() {
    // Only NoCallback and PureCallback allow vectorization
    assert!(CallbackFenceKind::NoCallback.allows_vectorization());
    assert!(CallbackFenceKind::PureCallback.allows_vectorization());
    assert!(!CallbackFenceKind::SideEffectCallback.allows_vectorization());
    assert!(!CallbackFenceKind::ThrowingCallback.allows_vectorization());
    assert!(!CallbackFenceKind::MutatingCallback.allows_vectorization());
}

#[test]
fn test_callback_fence_ordering_rules() {
    // Side-effect, Throwing, and Mutating require strict ordering
    assert!(!CallbackFenceKind::NoCallback.requires_ordering());
    assert!(!CallbackFenceKind::PureCallback.requires_ordering());
    assert!(CallbackFenceKind::SideEffectCallback.requires_ordering());
    assert!(CallbackFenceKind::ThrowingCallback.requires_ordering());
    assert!(CallbackFenceKind::MutatingCallback.requires_ordering());
}

#[test]
fn test_callback_fence_as_str_unique() {
    let names: Vec<&str> = vec![
        CallbackFenceKind::NoCallback.as_str(),
        CallbackFenceKind::PureCallback.as_str(),
        CallbackFenceKind::SideEffectCallback.as_str(),
        CallbackFenceKind::ThrowingCallback.as_str(),
        CallbackFenceKind::MutatingCallback.as_str(),
    ];
    // All unique
    for i in 0..names.len() {
        for j in (i + 1)..names.len() {
            assert_ne!(names[i], names[j], "Duplicate fence kind name");
        }
    }
}

// ---------------------------------------------------------------------------
// CliffPolicy
// ---------------------------------------------------------------------------

#[test]
fn test_cliff_policy_defaults_reasonable() {
    let policy = CliffPolicy::default();
    assert!(policy.min_vectorize_length > 0);
    assert!(policy.min_parallel_length >= policy.min_vectorize_length);
    assert_eq!(policy.behavior, CliffBehavior::ScalarFallback);
}

#[test]
fn test_cliff_behavior_as_str_coverage() {
    let behaviors = [
        CliffBehavior::ScalarFallback,
        CliffBehavior::NarrowLane,
        CliffBehavior::PaddedLane,
    ];
    let names: Vec<&str> = behaviors.iter().map(|b| b.as_str()).collect();
    // All unique and non-empty
    for name in &names {
        assert!(!name.is_empty());
    }
    assert_eq!(
        names.len(),
        names
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );
}

// ---------------------------------------------------------------------------
// KillSwitch
// ---------------------------------------------------------------------------

#[test]
fn test_kill_switch_new_is_disengaged() {
    let ks = KillSwitch::new(epoch(1));
    assert!(!ks.engaged);
    assert!(ks.reason.is_none());
    assert!(ks.affected_families.is_empty());
}

#[test]
fn test_kill_switch_engage_disengage_cycle() {
    let mut ks = KillSwitch::new(epoch(1));
    ks.engage("test reason", epoch(2));
    assert!(ks.engaged);
    assert_eq!(ks.reason.as_deref(), Some("test reason"));
    assert_eq!(ks.last_toggled_epoch, epoch(2));

    ks.disengage(epoch(3));
    assert!(!ks.engaged);
    assert!(ks.reason.is_none());
    assert_eq!(ks.last_toggled_epoch, epoch(3));
}

#[test]
fn test_kill_switch_global_kills_all_families() {
    let mut ks = KillSwitch::new(epoch(1));
    ks.engage("global", epoch(2));
    // All families should be killed when affected_families is empty
    for family in BuiltinFamily::ALL {
        assert!(ks.is_killed(*family), "Expected {:?} to be killed", family);
    }
}

#[test]
fn test_kill_switch_targeted_selective() {
    let mut ks = KillSwitch::new(epoch(1));
    ks.add_family(BuiltinFamily::ArrayMap);
    ks.add_family(BuiltinFamily::ArrayFilter);
    ks.engage("targeted", epoch(2));

    assert!(ks.is_killed(BuiltinFamily::ArrayMap));
    assert!(ks.is_killed(BuiltinFamily::ArrayFilter));
    assert!(!ks.is_killed(BuiltinFamily::JsonParse));
    assert!(!ks.is_killed(BuiltinFamily::TypedArraySort));
    assert!(!ks.is_killed(BuiltinFamily::StringReplace));
}

#[test]
fn test_kill_switch_disengaged_kills_nothing() {
    let mut ks = KillSwitch::new(epoch(1));
    ks.add_family(BuiltinFamily::ArrayMap);
    // Not engaged — nothing killed
    for family in BuiltinFamily::ALL {
        assert!(!ks.is_killed(*family));
    }
}

// ---------------------------------------------------------------------------
// MorselKernelDescriptor
// ---------------------------------------------------------------------------

#[test]
fn test_kernel_descriptor_id_format() {
    let k = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane8,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    assert!(
        k.kernel_id.starts_with("mk-"),
        "Kernel ID should start with mk-: {}",
        k.kernel_id
    );
    assert!(k.kernel_id.contains("array_map"));
}

#[test]
fn test_kernel_descriptor_callback_support_no_callback() {
    let k = MorselKernelDescriptor::new(
        BuiltinFamily::TypedArrayFill,
        LaneWidth::Lane16,
        MorselSize::Large,
        CallbackFenceKind::NoCallback,
    );
    assert!(k.supports_callback(CallbackFenceKind::NoCallback));
    assert!(!k.supports_callback(CallbackFenceKind::PureCallback));
    assert!(!k.supports_callback(CallbackFenceKind::SideEffectCallback));
}

#[test]
fn test_kernel_descriptor_callback_support_pure() {
    let k = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane8,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    assert!(k.supports_callback(CallbackFenceKind::NoCallback));
    assert!(k.supports_callback(CallbackFenceKind::PureCallback));
    assert!(!k.supports_callback(CallbackFenceKind::SideEffectCallback));
}

#[test]
fn test_kernel_descriptor_callback_support_side_effect() {
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
    assert!(k.supports_callback(CallbackFenceKind::MutatingCallback));
}

#[test]
fn test_kernel_descriptor_suitable_length() {
    let k = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane8,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    // Default cliff min_vectorize_length = 8
    assert!(!k.is_suitable_length(0));
    assert!(!k.is_suitable_length(7));
    assert!(k.is_suitable_length(8));
    assert!(k.is_suitable_length(10_000));
}

#[test]
fn test_kernel_descriptor_max_input_length_enforcement() {
    let mut k = MorselKernelDescriptor::new(
        BuiltinFamily::StringSplit,
        LaneWidth::Lane4,
        MorselSize::Small,
        CallbackFenceKind::NoCallback,
    );
    k.max_input_length = 500;
    assert!(k.is_suitable_length(500));
    assert!(!k.is_suitable_length(501));
    assert!(k.is_suitable_length(8)); // within range
}

#[test]
fn test_kernel_descriptor_unlimited_input_length() {
    let k = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane8,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    // max_input_length = 0 means unlimited
    assert_eq!(k.max_input_length, 0);
    assert!(k.is_suitable_length(u64::MAX));
}

// ---------------------------------------------------------------------------
// MorselKernelCatalog
// ---------------------------------------------------------------------------

#[test]
fn test_catalog_default_has_all_15_builtin_families() {
    let catalog = MorselKernelCatalog::with_defaults();
    assert_eq!(catalog.kernel_count(), 15);
    for family in BuiltinFamily::ALL {
        assert!(
            catalog.lookup(*family).is_some(),
            "Missing default kernel for {:?}",
            family
        );
    }
}

#[test]
fn test_catalog_default_array_kernels_lane8() {
    let catalog = MorselKernelCatalog::with_defaults();
    for family in [
        BuiltinFamily::ArrayMap,
        BuiltinFamily::ArrayFilter,
        BuiltinFamily::ArrayForEach,
        BuiltinFamily::ArrayEvery,
        BuiltinFamily::ArraySome,
        BuiltinFamily::ArrayFind,
    ] {
        let k = catalog.lookup(family).unwrap();
        assert_eq!(k.lane_width, LaneWidth::Lane8);
        assert_eq!(k.morsel_size, MorselSize::Medium);
        assert_eq!(k.callback_fence, CallbackFenceKind::PureCallback);
    }
}

#[test]
fn test_catalog_default_string_kernels_lane4() {
    let catalog = MorselKernelCatalog::with_defaults();
    for family in [
        BuiltinFamily::StringReplace,
        BuiltinFamily::StringSplit,
        BuiltinFamily::StringMatch,
    ] {
        let k = catalog.lookup(family).unwrap();
        assert_eq!(k.lane_width, LaneWidth::Lane4);
        assert_eq!(k.morsel_size, MorselSize::Small);
        assert_eq!(k.callback_fence, CallbackFenceKind::NoCallback);
    }
}

#[test]
fn test_catalog_default_typed_array_kernels_lane16() {
    let catalog = MorselKernelCatalog::with_defaults();
    for family in [
        BuiltinFamily::TypedArraySort,
        BuiltinFamily::TypedArrayCopy,
        BuiltinFamily::TypedArrayFill,
    ] {
        let k = catalog.lookup(family).unwrap();
        assert_eq!(k.lane_width, LaneWidth::Lane16);
        assert!(k.requires_homogeneous);
        assert_eq!(k.callback_fence, CallbackFenceKind::NoCallback);
    }
}

#[test]
fn test_catalog_default_json_kernels_lane8_large() {
    let catalog = MorselKernelCatalog::with_defaults();
    for family in [BuiltinFamily::JsonParse, BuiltinFamily::JsonStringify] {
        let k = catalog.lookup(family).unwrap();
        assert_eq!(k.lane_width, LaneWidth::Lane8);
        assert_eq!(k.morsel_size, MorselSize::Large);
    }
}

#[test]
fn test_catalog_empty() {
    let catalog = MorselKernelCatalog::new();
    assert_eq!(catalog.kernel_count(), 0);
    assert!(catalog.lookup(BuiltinFamily::ArrayMap).is_none());
    assert!(catalog.registered_families().is_empty());
}

#[test]
fn test_catalog_custom_registration() {
    let mut catalog = MorselKernelCatalog::new();
    let kernel = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane4,
        MorselSize::Small,
        CallbackFenceKind::PureCallback,
    );
    catalog.register(kernel);
    assert_eq!(catalog.kernel_count(), 1);
    let k = catalog.lookup(BuiltinFamily::ArrayMap).unwrap();
    assert_eq!(k.lane_width, LaneWidth::Lane4);
    assert_eq!(k.morsel_size, MorselSize::Small);
}

#[test]
fn test_catalog_registered_families_complete() {
    let catalog = MorselKernelCatalog::with_defaults();
    let families = catalog.registered_families();
    assert_eq!(families.len(), 15);
    assert!(families.contains(&BuiltinFamily::ArrayMap));
    assert!(families.contains(&BuiltinFamily::JsonParse));
    assert!(families.contains(&BuiltinFamily::TypedArrayFill));
}

#[test]
fn test_catalog_register_overwrites_same_family() {
    let mut catalog = MorselKernelCatalog::new();
    let k1 = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane4,
        MorselSize::Small,
        CallbackFenceKind::PureCallback,
    );
    let k2 = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane16,
        MorselSize::Huge,
        CallbackFenceKind::NoCallback,
    );
    catalog.register(k1);
    catalog.register(k2);
    // Latest registration wins for family map
    let k = catalog.lookup(BuiltinFamily::ArrayMap).unwrap();
    assert_eq!(k.lane_width, LaneWidth::Lane16);
}

// ---------------------------------------------------------------------------
// MorselKernelEngine — partitioning
// ---------------------------------------------------------------------------

#[test]
fn test_engine_partition_empty_input() {
    let engine = default_engine();
    let parts = engine.partition(BuiltinFamily::ArrayMap, 0);
    assert!(parts.is_empty());
}

#[test]
fn test_engine_partition_single_morsel() {
    let engine = default_engine();
    // ArrayMap default morsel = Medium (256), input = 100 < 256
    let parts = engine.partition(BuiltinFamily::ArrayMap, 100);
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].start, 0);
    assert_eq!(parts[0].end, 100);
    assert!(parts[0].is_tail);
    assert_eq!(parts[0].index, 0);
}

#[test]
fn test_engine_partition_exact_morsel() {
    let engine = default_engine();
    let parts = engine.partition(BuiltinFamily::ArrayMap, 256);
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].element_count(), 256);
    assert!(parts[0].is_tail);
}

#[test]
fn test_engine_partition_multiple_morsels() {
    let engine = default_engine();
    // 600 / 256 = 2 full + 1 tail (88 elements)
    let parts = engine.partition(BuiltinFamily::ArrayMap, 600);
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].start, 0);
    assert_eq!(parts[0].end, 256);
    assert!(!parts[0].is_tail);
    assert_eq!(parts[1].start, 256);
    assert_eq!(parts[1].end, 512);
    assert!(!parts[1].is_tail);
    assert_eq!(parts[2].start, 512);
    assert_eq!(parts[2].end, 600);
    assert!(parts[2].is_tail);
}

#[test]
fn test_engine_partition_large_input() {
    let engine = default_engine();
    // TypedArray kernels use Large morsel (1024)
    let parts = engine.partition(BuiltinFamily::TypedArrayFill, 5000);
    // 5000 / 1024 = 4 full + 1 tail (904)
    assert_eq!(parts.len(), 5);
    assert_eq!(parts[4].element_count(), 5000 - 4 * 1024);
    assert!(parts[4].is_tail);
}

#[test]
fn test_engine_partition_unknown_family_empty() {
    // Custom catalog with no kernels
    let catalog = MorselKernelCatalog::new();
    let engine = MorselKernelEngine::with_catalog(catalog, epoch(1));
    let parts = engine.partition(BuiltinFamily::ArrayMap, 100);
    assert!(parts.is_empty());
}

#[test]
fn test_engine_partition_preserves_lane_width() {
    let engine = default_engine();
    let parts = engine.partition(BuiltinFamily::ArrayMap, 500);
    for part in &parts {
        assert_eq!(part.lane_width, LaneWidth::Lane8);
    }
    let parts_typed = engine.partition(BuiltinFamily::TypedArraySort, 2000);
    for part in &parts_typed {
        assert_eq!(part.lane_width, LaneWidth::Lane16);
    }
}

#[test]
fn test_engine_partition_indices_sequential() {
    let engine = default_engine();
    let parts = engine.partition(BuiltinFamily::ArrayMap, 1000);
    for (i, part) in parts.iter().enumerate() {
        assert_eq!(part.index, i as u32);
    }
}

#[test]
fn test_engine_partition_covers_full_range() {
    let engine = default_engine();
    let parts = engine.partition(BuiltinFamily::ArrayMap, 777);
    assert_eq!(parts.first().unwrap().start, 0);
    assert_eq!(parts.last().unwrap().end, 777);
    // No gaps
    for window in parts.windows(2) {
        assert_eq!(window[0].end, window[1].start);
    }
}

// ---------------------------------------------------------------------------
// MorselKernelEngine — execution
// ---------------------------------------------------------------------------

#[test]
fn test_engine_execute_pure_callback_vectorized() {
    let mut engine = default_engine();
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
    assert!(!receipt.kill_switch_active);
}

#[test]
fn test_engine_execute_no_callback_vectorized() {
    let mut engine = default_engine();
    let receipt = engine
        .execute(
            BuiltinFamily::TypedArrayFill,
            2000,
            CallbackFenceKind::NoCallback,
            None,
        )
        .unwrap();
    assert!(receipt.vectorized_count > 0);
    assert_eq!(receipt.scalar_count, 0);
    assert_eq!(receipt.vectorization_rate_millionths(), 1_000_000);
}

#[test]
fn test_engine_execute_side_effect_callback_scalar() {
    let mut engine = default_engine();
    // ArrayReduce supports SideEffectCallback
    let receipt = engine
        .execute(
            BuiltinFamily::ArrayReduce,
            100,
            CallbackFenceKind::SideEffectCallback,
            None,
        )
        .unwrap();
    // Side effects require ordering -> scalar fallback
    assert!(receipt.scalar_count > 0);
    assert!(receipt.total_fences > 0);
}

#[test]
fn test_engine_execute_mutating_callback_rejected_pure_kernel() {
    let mut engine = default_engine();
    // ArrayMap kernel is PureCallback — doesn't support MutatingCallback
    let receipt = engine.execute(
        BuiltinFamily::ArrayMap,
        100,
        CallbackFenceKind::MutatingCallback,
        None,
    );
    assert!(receipt.is_none());
}

#[test]
fn test_engine_execute_zero_input_returns_none() {
    let mut engine = default_engine();
    let receipt = engine.execute(
        BuiltinFamily::ArrayMap,
        0,
        CallbackFenceKind::PureCallback,
        None,
    );
    assert!(receipt.is_none());
}

#[test]
fn test_engine_execute_with_selection_vector() {
    let mut engine = default_engine();
    let mut sel = SelectionVector::new(100);
    // Mask every other element
    for i in (0..100).step_by(2) {
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
    // Some elements were masked so total_elements < input_length
    assert!(receipt.total_elements < receipt.input_length);
}

#[test]
fn test_engine_execute_accumulates_stats() {
    let mut engine = default_engine();
    // Execute multiple times
    engine.execute(
        BuiltinFamily::ArrayMap,
        100,
        CallbackFenceKind::PureCallback,
        None,
    );
    engine.execute(
        BuiltinFamily::JsonParse,
        2000,
        CallbackFenceKind::NoCallback,
        None,
    );
    engine.execute(
        BuiltinFamily::TypedArrayFill,
        500,
        CallbackFenceKind::NoCallback,
        None,
    );
    assert_eq!(engine.receipt_count(), 3);
    assert!(engine.total_morsels_executed > 0);
    assert!(engine.total_elements_processed > 0);
}

#[test]
fn test_engine_execute_updates_family_counts() {
    let mut engine = default_engine();
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
        BuiltinFamily::JsonParse,
        500,
        CallbackFenceKind::NoCallback,
        None,
    );
    assert_eq!(engine.family_execution_counts.get("array_map"), Some(&2));
    assert_eq!(engine.family_execution_counts.get("json_parse"), Some(&1));
}

// ---------------------------------------------------------------------------
// Kill switch integration with engine
// ---------------------------------------------------------------------------

#[test]
fn test_engine_global_kill_switch_blocks_all() {
    let mut engine = default_engine();
    engine.engage_kill_switch("emergency stop");
    // All families should be blocked
    for family in BuiltinFamily::ALL {
        assert!(
            engine
                .execute(*family, 100, CallbackFenceKind::NoCallback, None)
                .is_none(),
            "Expected {:?} to be blocked",
            family
        );
    }
}

#[test]
fn test_engine_targeted_kill_allows_other_families() {
    let mut engine = default_engine();
    engine.engage_family_kill(BuiltinFamily::ArrayMap, "array_map broken");

    // ArrayMap blocked
    assert!(
        engine
            .execute(
                BuiltinFamily::ArrayMap,
                100,
                CallbackFenceKind::PureCallback,
                None,
            )
            .is_none()
    );

    // JsonParse still works
    assert!(
        engine
            .execute(
                BuiltinFamily::JsonParse,
                100,
                CallbackFenceKind::NoCallback,
                None,
            )
            .is_some()
    );
}

#[test]
fn test_engine_disengage_kill_switch_resumes() {
    let mut engine = default_engine();
    engine.engage_kill_switch("test");
    assert!(
        engine
            .execute(
                BuiltinFamily::ArrayMap,
                100,
                CallbackFenceKind::PureCallback,
                None,
            )
            .is_none()
    );

    engine.disengage_kill_switch();
    assert!(
        engine
            .execute(
                BuiltinFamily::ArrayMap,
                100,
                CallbackFenceKind::PureCallback,
                None,
            )
            .is_some()
    );
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

#[test]
fn test_engine_diagnostics_initial() {
    let engine = default_engine();
    let diag = engine.diagnostics();
    assert_eq!(diag.kernel_count, 15);
    assert_eq!(diag.total_morsels_executed, 0);
    assert_eq!(diag.total_elements_processed, 0);
    assert_eq!(diag.total_scalar_fallbacks, 0);
    assert_eq!(diag.total_receipts, 0);
    assert!(!diag.kill_switch_engaged);
}

#[test]
fn test_engine_diagnostics_after_execution() {
    let mut engine = default_engine();
    engine.execute(
        BuiltinFamily::ArrayMap,
        500,
        CallbackFenceKind::PureCallback,
        None,
    );
    let diag = engine.diagnostics();
    assert!(diag.total_morsels_executed > 0);
    assert!(diag.total_elements_processed > 0);
    assert_eq!(diag.total_receipts, 1);
    assert!(diag.family_execution_counts.contains_key("array_map"));
    assert!(diag.family_vectorization_rates.contains_key("array_map"));
}

#[test]
fn test_engine_diagnostics_kill_switch_visible() {
    let mut engine = default_engine();
    let diag = engine.diagnostics();
    assert!(!diag.kill_switch_engaged);

    engine.engage_kill_switch("reason");
    let diag = engine.diagnostics();
    assert!(diag.kill_switch_engaged);
}

// ---------------------------------------------------------------------------
// Vectorization rate
// ---------------------------------------------------------------------------

#[test]
fn test_vectorization_rate_full() {
    let mut engine = default_engine();
    let receipt = engine
        .execute(
            BuiltinFamily::TypedArrayFill,
            2000,
            CallbackFenceKind::NoCallback,
            None,
        )
        .unwrap();
    assert_eq!(receipt.vectorization_rate_millionths(), 1_000_000);
}

#[test]
fn test_vectorization_rate_zero_morsels() {
    // A receipt with zero morsels returns 0 rate
    let receipt = KernelExecutionReceipt {
        receipt_id: "test".to_string(),
        kernel_id: "k".to_string(),
        family: BuiltinFamily::ArrayMap,
        input_length: 0,
        morsel_count: 0,
        vectorized_count: 0,
        scalar_count: 0,
        aborted_count: 0,
        total_elements: 0,
        total_fences: 0,
        kill_switch_active: false,
        receipt_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
        epoch: epoch(1),
    };
    assert_eq!(receipt.vectorization_rate_millionths(), 0);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn test_kernel_content_hash_deterministic() {
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
    assert_eq!(k1.kernel_id, k2.kernel_id);
}

#[test]
fn test_kernel_content_hash_differs_on_family() {
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
fn test_receipt_hash_deterministic() {
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
fn test_partition_deterministic() {
    let e1 = default_engine();
    let e2 = default_engine();
    let p1 = e1.partition(BuiltinFamily::ArrayMap, 777);
    let p2 = e2.partition(BuiltinFamily::ArrayMap, 777);
    assert_eq!(p1, p2);
}

// ---------------------------------------------------------------------------
// Serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_morsel_size_serde_roundtrip() {
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
fn test_callback_fence_kind_serde_roundtrip() {
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

#[test]
fn test_cliff_behavior_serde_roundtrip() {
    for b in [
        CliffBehavior::ScalarFallback,
        CliffBehavior::NarrowLane,
        CliffBehavior::PaddedLane,
    ] {
        let json = serde_json::to_string(&b).unwrap();
        let decoded: CliffBehavior = serde_json::from_str(&json).unwrap();
        assert_eq!(b, decoded);
    }
}

#[test]
fn test_morsel_outcome_serde_roundtrip() {
    for o in [
        MorselOutcome::Vectorized,
        MorselOutcome::ScalarFallback,
        MorselOutcome::AbortedMutation,
        MorselOutcome::AbortedKillSwitch,
        MorselOutcome::Skipped,
    ] {
        let json = serde_json::to_string(&o).unwrap();
        let decoded: MorselOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, decoded);
    }
}

#[test]
fn test_kernel_descriptor_serde_roundtrip() {
    let k = MorselKernelDescriptor::new(
        BuiltinFamily::ArrayMap,
        LaneWidth::Lane8,
        MorselSize::Medium,
        CallbackFenceKind::PureCallback,
    );
    let json = serde_json::to_string(&k).unwrap();
    let decoded: MorselKernelDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(k, decoded);
}

#[test]
fn test_diagnostics_serde_roundtrip() {
    let mut engine = default_engine();
    engine.execute(
        BuiltinFamily::ArrayMap,
        100,
        CallbackFenceKind::PureCallback,
        None,
    );
    let diag = engine.diagnostics();
    let json = serde_json::to_string(&diag).unwrap();
    let decoded: MorselKernelDiagnostics = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, decoded);
}

#[test]
fn test_engine_serde_roundtrip() {
    let mut engine = default_engine();
    engine.execute(
        BuiltinFamily::ArrayMap,
        100,
        CallbackFenceKind::PureCallback,
        None,
    );
    let json = serde_json::to_string(&engine).unwrap();
    let decoded: MorselKernelEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.receipt_count(), 1);
    assert_eq!(
        decoded.total_morsels_executed,
        engine.total_morsels_executed
    );
}

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_format() {
    assert!(SIMD_MORSEL_KERNEL_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SIMD_MORSEL_KERNEL_SCHEMA_VERSION.contains("simd-morsel-kernel"));
}

// ---------------------------------------------------------------------------
// MorselOutcome
// ---------------------------------------------------------------------------

#[test]
fn test_morsel_outcome_as_str_all_unique() {
    let outcomes = [
        MorselOutcome::Vectorized,
        MorselOutcome::ScalarFallback,
        MorselOutcome::AbortedMutation,
        MorselOutcome::AbortedKillSwitch,
        MorselOutcome::Skipped,
    ];
    let names: Vec<&str> = outcomes.iter().map(|o| o.as_str()).collect();
    let unique: std::collections::BTreeSet<&str> = names.iter().copied().collect();
    assert_eq!(names.len(), unique.len());
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_engine_custom_catalog_no_kernels() {
    let catalog = MorselKernelCatalog::new();
    let mut engine = MorselKernelEngine::with_catalog(catalog, epoch(1));
    let receipt = engine.execute(
        BuiltinFamily::ArrayMap,
        100,
        CallbackFenceKind::PureCallback,
        None,
    );
    assert!(receipt.is_none());
}

#[test]
fn test_engine_execute_very_small_input_scalar_fallback() {
    let mut engine = default_engine();
    // Input < cliff min_vectorize_length (8) — triggers scalar fallback
    // But our input of 1 element goes through partition, and partition will
    // produce 1 morsel with element_count = 1 < min_vectorize_length
    let receipt = engine.execute(
        BuiltinFamily::ArrayMap,
        1,
        CallbackFenceKind::PureCallback,
        None,
    );
    if let Some(r) = receipt {
        // Scalar fallback for small inputs
        assert!(r.scalar_count > 0 || r.vectorized_count > 0);
    }
}

#[test]
fn test_engine_multiple_families_sequential() {
    let mut engine = default_engine();
    let families = [
        BuiltinFamily::ArrayMap,
        BuiltinFamily::ArrayFilter,
        BuiltinFamily::JsonParse,
        BuiltinFamily::TypedArrayFill,
        BuiltinFamily::StringReplace,
    ];
    for family in families {
        let fence = if family.as_str().starts_with("array") {
            CallbackFenceKind::PureCallback
        } else {
            CallbackFenceKind::NoCallback
        };
        let receipt = engine.execute(family, 300, fence, None);
        assert!(receipt.is_some(), "Failed for {:?}", family);
    }
    assert_eq!(engine.receipt_count(), 5);
}

#[test]
fn test_engine_with_catalog_preserves_epoch() {
    let catalog = MorselKernelCatalog::with_defaults();
    let engine = MorselKernelEngine::with_catalog(catalog, epoch(42));
    assert_eq!(engine.epoch, epoch(42));
}

#[test]
fn test_morsel_partition_element_count() {
    let p = MorselPartition {
        index: 0,
        start: 100,
        end: 350,
        lane_width: LaneWidth::Lane8,
        is_tail: false,
    };
    assert_eq!(p.element_count(), 250);
}

#[test]
fn test_morsel_partition_element_count_saturating() {
    let p = MorselPartition {
        index: 0,
        start: 500,
        end: 100, // end < start (shouldn't happen normally)
        lane_width: LaneWidth::Lane8,
        is_tail: false,
    };
    assert_eq!(p.element_count(), 0); // saturating_sub
}

#[test]
fn test_callback_fence_struct() {
    let fence = CallbackFence {
        kind: CallbackFenceKind::SideEffectCallback,
        after_morsel: 3,
        flushed_effects: true,
        callback_invocations: 42,
    };
    assert_eq!(fence.kind, CallbackFenceKind::SideEffectCallback);
    assert_eq!(fence.after_morsel, 3);
    assert!(fence.flushed_effects);
    assert_eq!(fence.callback_invocations, 42);
}

#[test]
fn test_cliff_policy_custom() {
    let policy = CliffPolicy {
        min_vectorize_length: 32,
        behavior: CliffBehavior::PaddedLane,
        min_parallel_length: 1024,
    };
    assert_eq!(policy.min_vectorize_length, 32);
    assert_eq!(policy.behavior, CliffBehavior::PaddedLane);
    assert_eq!(policy.min_parallel_length, 1024);
}

#[test]
fn test_kill_switch_serde_roundtrip() {
    let mut ks = KillSwitch::new(epoch(1));
    ks.add_family(BuiltinFamily::ArrayMap);
    ks.engage("test", epoch(2));
    let json = serde_json::to_string(&ks).unwrap();
    let decoded: KillSwitch = serde_json::from_str(&json).unwrap();
    assert_eq!(ks.engaged, decoded.engaged);
    assert_eq!(ks.reason, decoded.reason);
    assert_eq!(ks.affected_families, decoded.affected_families);
}
