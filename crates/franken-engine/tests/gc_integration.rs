#![forbid(unsafe_code)]

//! Integration tests for the `gc` module.
//!
//! Exercises the public API from outside the crate, covering:
//! - GcObjectId construction, Display, serde round-trip
//! - GcObject construction, field access, serde round-trip
//! - GcPhase enum variants, Display, serde round-trip
//! - GcEvent construction, serde round-trip
//! - GcConfig construction, Default, deterministic(), pressure_ratio, serde round-trip
//! - GcError variants, Display formatting, std::error::Error, From<AllocDomainError>, serde round-trip
//! - CollectionStats field access
//! - ExtensionHeap lifecycle (allocate, reference, root/unroot, collect, contains, get)
//! - GcCollector lifecycle (register/remove/get heaps, allocate, collect, events, pressure)
//! - GC collection cycles: mark-sweep, circular references, dangling references
//! - Domain registry integration (allocate_tracked, collect_tracked)
//! - Determinism: identical inputs produce identical outputs
//! - Cross-concern integration scenarios

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

use std::collections::BTreeSet;

use frankenengine_engine::alloc_domain::{AllocationDomain, DomainRegistry, LifetimeClass};
use frankenengine_engine::gc::{
    CollectionStats, ExtensionHeap, GcCollector, GcConfig, GcError, GcEvent, GcObjectId, GcPhase,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn det_collector() -> GcCollector {
    GcCollector::new(GcConfig::deterministic())
}

fn make_registry(max_bytes: u64) -> DomainRegistry {
    let mut reg = DomainRegistry::new();
    reg.register(
        AllocationDomain::ExtensionHeap,
        LifetimeClass::SessionScoped,
        max_bytes,
    )
    .unwrap();
    reg
}

// ===========================================================================
// 1. GcObjectId — construction, Display, Ord, serde round-trip
// ===========================================================================

#[test]
fn gc_object_id_display_format() {
    let mut heap = ExtensionHeap::new("ext-a".into());
    let id = heap.allocate(10);
    assert_eq!(id.to_string(), "obj-0");
    assert_eq!(id.as_u64(), 0);
}

#[test]
fn gc_object_id_display_large_value() {
    // Allocate many objects to get a high ID
    let mut heap = ExtensionHeap::new("ext".into());
    let mut last = heap.allocate(1);
    for _ in 0..99 {
        last = heap.allocate(1);
    }
    assert_eq!(last.as_u64(), 99);
    assert_eq!(last.to_string(), "obj-99");
}

#[test]
fn gc_object_id_ordering_is_deterministic() {
    let mut heap = ExtensionHeap::new("ext".into());
    let a = heap.allocate(1);
    let b = heap.allocate(1);
    let c = heap.allocate(1);
    assert!(a < b);
    assert!(b < c);
}

#[test]
fn gc_object_id_serde_round_trip() {
    let mut heap = ExtensionHeap::new("ext".into());
    let id = heap.allocate(10);
    let json = serde_json::to_string(&id).expect("serialize");
    let decoded: GcObjectId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, id);
    assert_eq!(decoded.as_u64(), 0);
}

#[test]
fn gc_object_id_clone_eq() {
    let mut heap = ExtensionHeap::new("ext".into());
    let id = heap.allocate(5);
    let id2 = id;
    assert_eq!(id, id2);
}

// ===========================================================================
// 2. GcObject — construction, field access, serde round-trip
// ===========================================================================

#[test]
fn gc_object_fields_accessible() {
    let mut heap = ExtensionHeap::new("ext".into());
    let id = heap.allocate(256);
    let obj = heap.get(id).expect("object exists");
    assert_eq!(obj.id, id);
    assert_eq!(obj.size_bytes, 256);
    assert!(obj.references.is_empty());
    assert!(obj.rooted);
}

#[test]
fn gc_object_references_are_btreeset() {
    let mut heap = ExtensionHeap::new("ext".into());
    let a = heap.allocate(10);
    let b = heap.allocate(20);
    let c = heap.allocate(30);
    heap.add_reference(a, b).unwrap();
    heap.add_reference(a, c).unwrap();
    let obj = heap.get(a).unwrap();
    let refs: Vec<GcObjectId> = obj.references.iter().copied().collect();
    assert_eq!(refs.len(), 2);
    // BTreeSet guarantees ordering
    assert!(refs[0] < refs[1]);
}

#[test]
fn gc_object_serde_round_trip() {
    let mut heap = ExtensionHeap::new("ext".into());
    let id = heap.allocate(128);
    let obj = heap.get(id).unwrap().clone();
    let json = serde_json::to_string(&obj).expect("serialize");
    let decoded: frankenengine_engine::gc::GcObject =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.id, obj.id);
    assert_eq!(decoded.size_bytes, obj.size_bytes);
    assert_eq!(decoded.rooted, obj.rooted);
    assert_eq!(decoded.references, obj.references);
}

// ===========================================================================
// 3. GcPhase — enum variants, Display, serde round-trip
// ===========================================================================

#[test]
fn gc_phase_display_all_variants() {
    assert_eq!(GcPhase::Mark.to_string(), "mark");
    assert_eq!(GcPhase::Sweep.to_string(), "sweep");
    assert_eq!(GcPhase::Complete.to_string(), "complete");
}

#[test]
fn gc_phase_serde_round_trip_all_variants() {
    for phase in [GcPhase::Mark, GcPhase::Sweep, GcPhase::Complete] {
        let json = serde_json::to_string(&phase).expect("serialize");
        let decoded: GcPhase = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, phase);
    }
}

#[test]
fn gc_phase_clone_and_copy() {
    let phase = GcPhase::Mark;
    let phase2 = phase;
    assert_eq!(phase, phase2);
}

#[test]
fn gc_phase_debug_format() {
    let dbg = format!("{:?}", GcPhase::Sweep);
    assert!(dbg.contains("Sweep"));
}

// ===========================================================================
// 4. GcEvent — construction, serde round-trip
// ===========================================================================

#[test]
fn gc_event_from_collection() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.allocate("ext-a", 50).unwrap();
    let event = gc.collect("ext-a").unwrap();

    assert_eq!(event.extension_id, "ext-a");
    assert_eq!(event.phase, GcPhase::Complete);
    assert_eq!(event.sequence, 1);
    assert_eq!(event.marked_count, 1);
    assert_eq!(event.swept_count, 0);
    assert_eq!(event.bytes_reclaimed, 0);
    assert_eq!(event.pause_ns, 1000); // deterministic mode
}

#[test]
fn gc_event_serde_round_trip() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let obj = gc.allocate("ext-a", 100).unwrap();
    gc.unroot("ext-a", obj).unwrap();
    let event = gc.collect("ext-a").unwrap();

    let json = serde_json::to_string(&event).expect("serialize");
    let decoded: GcEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded, event);
}

#[test]
fn gc_event_clone_eq() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let event = gc.collect("ext").unwrap();
    let event2 = event.clone();
    assert_eq!(event, event2);
}

// ===========================================================================
// 5. GcConfig — construction, Default, deterministic, pressure_ratio, serde
// ===========================================================================

#[test]
fn gc_config_default_values() {
    let config = GcConfig::default();
    assert!(!config.deterministic);
    assert_eq!(config.pressure_threshold_percent, 75);
}

#[test]
fn gc_config_deterministic_values() {
    let config = GcConfig::deterministic();
    assert!(config.deterministic);
    assert_eq!(config.pressure_threshold_percent, 75);
}

#[test]
fn gc_config_pressure_ratio() {
    let config = GcConfig {
        deterministic: false,
        pressure_threshold_percent: 50,
    };
    assert!((config.pressure_ratio() - 0.5).abs() < f64::EPSILON);
}

#[test]
fn gc_config_pressure_ratio_zero() {
    let config = GcConfig {
        deterministic: false,
        pressure_threshold_percent: 0,
    };
    assert!((config.pressure_ratio()).abs() < f64::EPSILON);
}

#[test]
fn gc_config_pressure_ratio_100() {
    let config = GcConfig {
        deterministic: false,
        pressure_threshold_percent: 100,
    };
    assert!((config.pressure_ratio() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn gc_config_serde_round_trip() {
    let config = GcConfig {
        deterministic: true,
        pressure_threshold_percent: 42,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let decoded: GcConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.deterministic, config.deterministic);
    assert_eq!(
        decoded.pressure_threshold_percent,
        config.pressure_threshold_percent
    );
}

// ===========================================================================
// 6. GcError — all variants, Display, std::error::Error, From, serde
// ===========================================================================

#[test]
fn gc_error_heap_not_found_display() {
    let err = GcError::HeapNotFound {
        extension_id: "missing-ext".into(),
    };
    let display = err.to_string();
    assert!(display.contains("missing-ext"));
    assert!(display.contains("not found"));
}

#[test]
fn gc_error_duplicate_heap_display() {
    let err = GcError::DuplicateHeap {
        extension_id: "dup-ext".into(),
    };
    let display = err.to_string();
    assert!(display.contains("dup-ext"));
    assert!(display.contains("already registered"));
}

#[test]
fn gc_error_object_not_found_display() {
    let mut heap = ExtensionHeap::new("ext-a".into());
    let id = heap.allocate(10);
    let err = GcError::ObjectNotFound {
        extension_id: "ext-a".into(),
        object_id: id,
    };
    let display = err.to_string();
    assert!(display.contains("obj-0"));
    assert!(display.contains("ext-a"));
}

#[test]
fn gc_error_domain_error_display() {
    let domain_err = frankenengine_engine::alloc_domain::AllocDomainError::BudgetExceeded {
        requested: 500,
        remaining: 100,
        domain: Some(AllocationDomain::ExtensionHeap),
    };
    let gc_err = GcError::DomainError(domain_err);
    let display = gc_err.to_string();
    assert!(display.contains("domain error"));
}

#[test]
fn gc_error_is_std_error() {
    let err = GcError::HeapNotFound {
        extension_id: "ext".into(),
    };
    // Verify std::error::Error is implemented
    let _: &dyn std::error::Error = &err;
}

#[test]
fn gc_error_from_alloc_domain_error() {
    let domain_err = frankenengine_engine::alloc_domain::AllocDomainError::BudgetOverflow;
    let gc_err: GcError = domain_err.into();
    assert!(matches!(gc_err, GcError::DomainError(_)));
}

#[test]
fn gc_error_serde_round_trip_all_variants() {
    let mut heap = ExtensionHeap::new("ext".into());
    let id = heap.allocate(10);

    let errors: Vec<GcError> = vec![
        GcError::HeapNotFound {
            extension_id: "ext".into(),
        },
        GcError::DuplicateHeap {
            extension_id: "ext".into(),
        },
        GcError::ObjectNotFound {
            extension_id: "ext".into(),
            object_id: id,
        },
        GcError::DomainError(frankenengine_engine::alloc_domain::AllocDomainError::BudgetOverflow),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let decoded: GcError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&decoded, err);
    }
}

#[test]
fn gc_error_debug_format() {
    let err = GcError::HeapNotFound {
        extension_id: "ext".into(),
    };
    let dbg = format!("{:?}", err);
    assert!(dbg.contains("HeapNotFound"));
}

// ===========================================================================
// 7. CollectionStats — field access
// ===========================================================================

#[test]
fn collection_stats_fields() {
    let stats = CollectionStats {
        marked_count: 10,
        swept_count: 5,
        bytes_reclaimed: 1024,
    };
    assert_eq!(stats.marked_count, 10);
    assert_eq!(stats.swept_count, 5);
    assert_eq!(stats.bytes_reclaimed, 1024);
}

#[test]
fn collection_stats_clone_copy_eq() {
    let stats = CollectionStats {
        marked_count: 3,
        swept_count: 2,
        bytes_reclaimed: 512,
    };
    let stats2 = stats;
    assert_eq!(stats, stats2);
}

// ===========================================================================
// 8. ExtensionHeap — lifecycle
// ===========================================================================

#[test]
fn extension_heap_new() {
    let heap = ExtensionHeap::new("ext-a".into());
    assert_eq!(heap.extension_id(), "ext-a");
    assert_eq!(heap.object_count(), 0);
    assert_eq!(heap.total_bytes(), 0);
    assert_eq!(heap.collection_count(), 0);
    assert_eq!(heap.total_reclaimed(), 0);
}

#[test]
fn extension_heap_allocate_increments_stats() {
    let mut heap = ExtensionHeap::new("ext".into());
    let id1 = heap.allocate(100);
    assert_eq!(heap.object_count(), 1);
    assert_eq!(heap.total_bytes(), 100);
    assert!(heap.contains(id1));
    assert!(heap.get(id1).is_some());

    let id2 = heap.allocate(200);
    assert_eq!(heap.object_count(), 2);
    assert_eq!(heap.total_bytes(), 300);
    assert!(heap.contains(id2));
}

#[test]
fn extension_heap_allocate_assigns_monotonic_ids() {
    let mut heap = ExtensionHeap::new("ext".into());
    let id1 = heap.allocate(10);
    let id2 = heap.allocate(20);
    let id3 = heap.allocate(30);
    assert_eq!(id1.as_u64(), 0);
    assert_eq!(id2.as_u64(), 1);
    assert_eq!(id3.as_u64(), 2);
}

#[test]
fn extension_heap_allocate_zero_size() {
    let mut heap = ExtensionHeap::new("ext".into());
    let id = heap.allocate(0);
    assert_eq!(heap.object_count(), 1);
    assert_eq!(heap.total_bytes(), 0);
    assert!(heap.contains(id));
}

#[test]
fn extension_heap_add_reference_ok() {
    let mut heap = ExtensionHeap::new("ext".into());
    let a = heap.allocate(10);
    let b = heap.allocate(20);
    heap.add_reference(a, b).unwrap();
    let obj = heap.get(a).unwrap();
    assert!(obj.references.contains(&b));
}

#[test]
fn extension_heap_add_reference_nonexistent_from() {
    let mut heap = ExtensionHeap::new("ext".into());
    let _a = heap.allocate(10);
    let b = heap.allocate(20);
    // Create a fake ID that doesn't exist in this heap
    let mut other = ExtensionHeap::new("other".into());
    for _ in 0..5 {
        other.allocate(1);
    }
    let fake_from = other.allocate(1); // obj-5, doesn't exist in "ext" which only has obj-0, obj-1
    let result = heap.add_reference(fake_from, b);
    assert!(matches!(result, Err(GcError::ObjectNotFound { .. })));
}

#[test]
fn extension_heap_unroot_and_root() {
    let mut heap = ExtensionHeap::new("ext".into());
    let id = heap.allocate(50);
    assert!(heap.get(id).unwrap().rooted);

    heap.unroot(id).unwrap();
    assert!(!heap.get(id).unwrap().rooted);

    heap.root(id).unwrap();
    assert!(heap.get(id).unwrap().rooted);
}

#[test]
fn extension_heap_unroot_nonexistent() {
    let mut heap = ExtensionHeap::new("ext".into());
    let _ = heap.allocate(10);
    let _ = heap.allocate(10);
    let mut other = ExtensionHeap::new("other".into());
    let _ = other.allocate(1);
    let _ = other.allocate(1);
    let nonexistent = other.allocate(1);
    let result = heap.unroot(nonexistent);
    assert!(matches!(result, Err(GcError::ObjectNotFound { .. })));
}

#[test]
fn extension_heap_root_nonexistent() {
    let mut heap = ExtensionHeap::new("ext".into());
    let _ = heap.allocate(10);
    let _ = heap.allocate(10);
    let mut other = ExtensionHeap::new("other".into());
    let _ = other.allocate(1);
    let _ = other.allocate(1);
    let nonexistent = other.allocate(1);
    let result = heap.root(nonexistent);
    assert!(matches!(result, Err(GcError::ObjectNotFound { .. })));
}

#[test]
fn extension_heap_contains_false_for_missing() {
    let heap = ExtensionHeap::new("ext".into());
    let mut other = ExtensionHeap::new("other".into());
    let id = other.allocate(10);
    assert!(!heap.contains(id));
}

#[test]
fn extension_heap_get_none_for_missing() {
    let heap = ExtensionHeap::new("ext".into());
    let mut other = ExtensionHeap::new("other".into());
    let id = other.allocate(10);
    assert!(heap.get(id).is_none());
}

#[test]
fn extension_heap_serde_round_trip() {
    let mut heap = ExtensionHeap::new("ext-a".into());
    let a = heap.allocate(100);
    let b = heap.allocate(200);
    heap.add_reference(a, b).unwrap();

    let json = serde_json::to_string(&heap).expect("serialize");
    let decoded: ExtensionHeap = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.extension_id(), "ext-a");
    assert_eq!(decoded.object_count(), 2);
    assert_eq!(decoded.total_bytes(), 300);
}

// ===========================================================================
// 9. GcCollector — heap management
// ===========================================================================

#[test]
fn gc_collector_new() {
    let gc = det_collector();
    assert_eq!(gc.heap_count(), 0);
    assert_eq!(gc.event_sequence(), 0);
    assert!(gc.events().is_empty());
}

#[test]
fn gc_collector_default() {
    let gc = GcCollector::default();
    assert!(!gc.config().deterministic);
    assert_eq!(gc.heap_count(), 0);
}

#[test]
fn gc_collector_register_heap() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    assert_eq!(gc.heap_count(), 1);
    assert!(gc.get_heap("ext-a").is_some());
}

#[test]
fn gc_collector_register_duplicate_heap() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let result = gc.register_heap("ext-a".into());
    assert!(matches!(result, Err(GcError::DuplicateHeap { .. })));
}

#[test]
fn gc_collector_remove_heap() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.allocate("ext-a", 100).unwrap();

    let heap = gc.remove_heap("ext-a").unwrap();
    assert_eq!(heap.extension_id(), "ext-a");
    assert_eq!(heap.object_count(), 1);
    assert_eq!(gc.heap_count(), 0);
    assert!(gc.get_heap("ext-a").is_none());
}

#[test]
fn gc_collector_remove_nonexistent_heap() {
    let mut gc = det_collector();
    let result = gc.remove_heap("nonexistent");
    assert!(matches!(result, Err(GcError::HeapNotFound { .. })));
}

#[test]
fn gc_collector_get_heap_none() {
    let gc = det_collector();
    assert!(gc.get_heap("nonexistent").is_none());
}

#[test]
fn gc_collector_get_heap_mut() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let heap = gc.get_heap_mut("ext-a").unwrap();
    let id = heap.allocate(50);
    assert!(heap.contains(id));
}

#[test]
fn gc_collector_get_heap_mut_none() {
    let mut gc = det_collector();
    assert!(gc.get_heap_mut("nonexistent").is_none());
}

// ===========================================================================
// 10. GcCollector — allocate
// ===========================================================================

#[test]
fn gc_collector_allocate() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let id = gc.allocate("ext-a", 200).unwrap();
    assert_eq!(id.as_u64(), 0);
    let heap = gc.get_heap("ext-a").unwrap();
    assert_eq!(heap.object_count(), 1);
    assert_eq!(heap.total_bytes(), 200);
}

#[test]
fn gc_collector_allocate_nonexistent_heap() {
    let mut gc = det_collector();
    let result = gc.allocate("nonexistent", 100);
    assert!(matches!(result, Err(GcError::HeapNotFound { .. })));
}

#[test]
fn gc_collector_allocate_multiple_objects() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let id1 = gc.allocate("ext-a", 100).unwrap();
    let id2 = gc.allocate("ext-a", 200).unwrap();
    let id3 = gc.allocate("ext-a", 300).unwrap();
    assert_eq!(id1.as_u64(), 0);
    assert_eq!(id2.as_u64(), 1);
    assert_eq!(id3.as_u64(), 2);
    let heap = gc.get_heap("ext-a").unwrap();
    assert_eq!(heap.object_count(), 3);
    assert_eq!(heap.total_bytes(), 600);
}

// ===========================================================================
// 11. GcCollector — add_reference
// ===========================================================================

#[test]
fn gc_collector_add_reference() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let a = gc.allocate("ext-a", 10).unwrap();
    let b = gc.allocate("ext-a", 20).unwrap();
    gc.add_reference("ext-a", a, b).unwrap();
    let heap = gc.get_heap("ext-a").unwrap();
    let obj = heap.get(a).unwrap();
    assert!(obj.references.contains(&b));
}

#[test]
fn gc_collector_add_reference_nonexistent_heap() {
    let mut gc = det_collector();
    let mut other_heap = ExtensionHeap::new("tmp".into());
    let a = other_heap.allocate(10);
    let b = other_heap.allocate(20);
    let result = gc.add_reference("nonexistent", a, b);
    assert!(matches!(result, Err(GcError::HeapNotFound { .. })));
}

#[test]
fn gc_collector_add_reference_nonexistent_from_object() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let b = gc.allocate("ext-a", 20).unwrap();
    // Create a fake "from" ID that doesn't exist in the heap
    let mut other_heap = ExtensionHeap::new("tmp".into());
    for _ in 0..5 {
        other_heap.allocate(1);
    }
    let fake_from = other_heap.allocate(1); // obj-5, doesn't exist in ext-a
    let result = gc.add_reference("ext-a", fake_from, b);
    assert!(matches!(result, Err(GcError::ObjectNotFound { .. })));
}

// ===========================================================================
// 12. GcCollector — unroot
// ===========================================================================

#[test]
fn gc_collector_unroot() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let id = gc.allocate("ext-a", 50).unwrap();
    gc.unroot("ext-a", id).unwrap();
    let heap = gc.get_heap("ext-a").unwrap();
    assert!(!heap.get(id).unwrap().rooted);
}

#[test]
fn gc_collector_unroot_nonexistent_heap() {
    let mut gc = det_collector();
    let mut other_heap = ExtensionHeap::new("tmp".into());
    let id = other_heap.allocate(10);
    let result = gc.unroot("nonexistent", id);
    assert!(matches!(result, Err(GcError::HeapNotFound { .. })));
}

// ===========================================================================
// 13. GcCollector — collect (mark-sweep)
// ===========================================================================

#[test]
fn collect_empty_heap() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let event = gc.collect("ext-a").unwrap();
    assert_eq!(event.marked_count, 0);
    assert_eq!(event.swept_count, 0);
    assert_eq!(event.bytes_reclaimed, 0);
}

#[test]
fn collect_all_rooted_survives() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.allocate("ext-a", 100).unwrap();
    gc.allocate("ext-a", 200).unwrap();
    let event = gc.collect("ext-a").unwrap();
    assert_eq!(event.marked_count, 2);
    assert_eq!(event.swept_count, 0);
    assert_eq!(event.bytes_reclaimed, 0);
}

#[test]
fn collect_all_unrooted_collected() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let a = gc.allocate("ext-a", 100).unwrap();
    let b = gc.allocate("ext-a", 200).unwrap();
    gc.unroot("ext-a", a).unwrap();
    gc.unroot("ext-a", b).unwrap();
    let event = gc.collect("ext-a").unwrap();
    assert_eq!(event.marked_count, 0);
    assert_eq!(event.swept_count, 2);
    assert_eq!(event.bytes_reclaimed, 300);
    assert_eq!(gc.get_heap("ext-a").unwrap().object_count(), 0);
    assert_eq!(gc.get_heap("ext-a").unwrap().total_bytes(), 0);
}

#[test]
fn collect_mixed_rooted_and_unrooted() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let a = gc.allocate("ext-a", 100).unwrap();
    let _b = gc.allocate("ext-a", 200).unwrap();
    gc.unroot("ext-a", a).unwrap();
    let event = gc.collect("ext-a").unwrap();
    assert_eq!(event.marked_count, 1);
    assert_eq!(event.swept_count, 1);
    assert_eq!(event.bytes_reclaimed, 100);
}

#[test]
fn collect_referenced_objects_survive() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let root = gc.allocate("ext-a", 50).unwrap();
    let child = gc.allocate("ext-a", 80).unwrap();
    let grandchild = gc.allocate("ext-a", 120).unwrap();
    gc.add_reference("ext-a", root, child).unwrap();
    gc.add_reference("ext-a", child, grandchild).unwrap();
    gc.unroot("ext-a", child).unwrap();
    gc.unroot("ext-a", grandchild).unwrap();

    let event = gc.collect("ext-a").unwrap();
    assert_eq!(event.marked_count, 3);
    assert_eq!(event.swept_count, 0);
    assert_eq!(gc.get_heap("ext-a").unwrap().object_count(), 3);
}

#[test]
fn collect_unreachable_despite_outgoing_refs() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let a = gc.allocate("ext-a", 100).unwrap();
    let b = gc.allocate("ext-a", 200).unwrap();
    gc.add_reference("ext-a", a, b).unwrap();
    // Both are rooted; unroot both
    gc.unroot("ext-a", a).unwrap();
    gc.unroot("ext-a", b).unwrap();
    let event = gc.collect("ext-a").unwrap();
    assert_eq!(event.swept_count, 2);
    assert_eq!(event.bytes_reclaimed, 300);
}

#[test]
fn collect_nonexistent_heap() {
    let mut gc = det_collector();
    let result = gc.collect("nonexistent");
    assert!(matches!(result, Err(GcError::HeapNotFound { .. })));
}

// ===========================================================================
// 14. Circular references
// ===========================================================================

#[test]
fn circular_ref_two_nodes_unreachable() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let a = gc.allocate("ext", 64).unwrap();
    let b = gc.allocate("ext", 64).unwrap();
    gc.add_reference("ext", a, b).unwrap();
    gc.add_reference("ext", b, a).unwrap();
    gc.unroot("ext", a).unwrap();
    gc.unroot("ext", b).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.swept_count, 2);
    assert_eq!(event.bytes_reclaimed, 128);
}

#[test]
fn circular_ref_three_nodes_unreachable() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let a = gc.allocate("ext", 64).unwrap();
    let b = gc.allocate("ext", 64).unwrap();
    let c = gc.allocate("ext", 64).unwrap();
    gc.add_reference("ext", a, b).unwrap();
    gc.add_reference("ext", b, c).unwrap();
    gc.add_reference("ext", c, a).unwrap();
    gc.unroot("ext", a).unwrap();
    gc.unroot("ext", b).unwrap();
    gc.unroot("ext", c).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.swept_count, 3);
    assert_eq!(event.bytes_reclaimed, 192);
}

#[test]
fn circular_ref_survives_when_one_rooted() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let a = gc.allocate("ext", 100).unwrap();
    let b = gc.allocate("ext", 100).unwrap();
    gc.add_reference("ext", a, b).unwrap();
    gc.add_reference("ext", b, a).unwrap();
    // Only unroot b; a remains rooted, so both survive
    gc.unroot("ext", b).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.marked_count, 2);
    assert_eq!(event.swept_count, 0);
}

#[test]
fn self_referencing_object_unreachable() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let a = gc.allocate("ext", 100).unwrap();
    gc.add_reference("ext", a, a).unwrap();
    gc.unroot("ext", a).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.swept_count, 1);
    assert_eq!(event.bytes_reclaimed, 100);
}

#[test]
fn self_referencing_object_rooted_survives() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let a = gc.allocate("ext", 100).unwrap();
    gc.add_reference("ext", a, a).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.marked_count, 1);
    assert_eq!(event.swept_count, 0);
}

// ===========================================================================
// 15. Dangling references (safe-mode)
// ===========================================================================

#[test]
fn dangling_reference_does_not_crash() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let obj = gc.allocate("ext", 100).unwrap();
    // add_reference only checks 'from' exists; 'to' can be any ID
    let heap = gc.get_heap_mut("ext").unwrap();
    let mut other = ExtensionHeap::new("tmp".into());
    for _ in 0..100 {
        other.allocate(1);
    }
    let phantom_id = other.allocate(1); // obj-100, doesn't exist in "ext"
    heap.add_reference(obj, phantom_id).unwrap();

    let event = gc.collect("ext").unwrap();
    assert_eq!(event.marked_count, 1); // obj is rooted and marked
    assert_eq!(event.swept_count, 0);
}

#[test]
fn dangling_reference_in_chain_does_not_crash() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let a = gc.allocate("ext", 50).unwrap();
    let b = gc.allocate("ext", 50).unwrap();
    gc.add_reference("ext", a, b).unwrap();

    // Add dangling ref from b to a nonexistent ID
    let heap = gc.get_heap_mut("ext").unwrap();
    let mut other = ExtensionHeap::new("tmp".into());
    for _ in 0..100 {
        other.allocate(1);
    }
    let phantom_id = other.allocate(1);
    heap.add_reference(b, phantom_id).unwrap();

    gc.unroot("ext", b).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.marked_count, 2); // a (rooted) and b (reachable from a)
    assert_eq!(event.swept_count, 0);
}

// ===========================================================================
// 16. Per-extension isolation
// ===========================================================================

#[test]
fn collection_of_one_heap_does_not_affect_another() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.register_heap("ext-b".into()).unwrap();
    let a1 = gc.allocate("ext-a", 100).unwrap();
    let _b1 = gc.allocate("ext-b", 200).unwrap();

    gc.unroot("ext-a", a1).unwrap();
    let event = gc.collect("ext-a").unwrap();
    assert_eq!(event.swept_count, 1);
    assert_eq!(event.extension_id, "ext-a");

    let heap_b = gc.get_heap("ext-b").unwrap();
    assert_eq!(heap_b.object_count(), 1);
    assert_eq!(heap_b.total_bytes(), 200);
    assert_eq!(heap_b.collection_count(), 0);
}

#[test]
fn ids_are_per_heap_independent() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.register_heap("ext-b".into()).unwrap();
    let a1 = gc.allocate("ext-a", 100).unwrap();
    let b1 = gc.allocate("ext-b", 200).unwrap();
    // Both heaps start from 0
    assert_eq!(a1.as_u64(), 0);
    assert_eq!(b1.as_u64(), 0);
}

// ===========================================================================
// 17. collect_all
// ===========================================================================

#[test]
fn collect_all_deterministic_order() {
    let mut gc = det_collector();
    gc.register_heap("ext-z".into()).unwrap();
    gc.register_heap("ext-a".into()).unwrap();
    gc.register_heap("ext-m".into()).unwrap();

    let events = gc.collect_all();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].extension_id, "ext-a");
    assert_eq!(events[1].extension_id, "ext-m");
    assert_eq!(events[2].extension_id, "ext-z");
}

#[test]
fn collect_all_monotonic_sequences() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.register_heap("ext-b".into()).unwrap();
    let events = gc.collect_all();
    assert_eq!(events[0].sequence, 1);
    assert_eq!(events[1].sequence, 2);
}

#[test]
fn collect_all_empty_collector() {
    let mut gc = det_collector();
    let events = gc.collect_all();
    assert!(events.is_empty());
}

#[test]
fn collect_all_with_garbage() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.register_heap("ext-b".into()).unwrap();
    let a1 = gc.allocate("ext-a", 100).unwrap();
    gc.unroot("ext-a", a1).unwrap();
    let b1 = gc.allocate("ext-b", 200).unwrap();
    gc.unroot("ext-b", b1).unwrap();

    let events = gc.collect_all();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].bytes_reclaimed, 100);
    assert_eq!(events[1].bytes_reclaimed, 200);
}

// ===========================================================================
// 18. Pressure and should_collect
// ===========================================================================

#[test]
fn check_pressure_basic() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.allocate("ext-a", 500).unwrap();
    let pressure = gc.check_pressure("ext-a", 1000).unwrap();
    assert!((pressure - 0.5).abs() < f64::EPSILON);
}

#[test]
fn check_pressure_zero_budget() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.allocate("ext-a", 100).unwrap();
    let pressure = gc.check_pressure("ext-a", 0).unwrap();
    // Budget=0 with bytes>0 returns f64::MAX (infinite pressure)
    assert_eq!(pressure, f64::MAX);
}

#[test]
fn check_pressure_nonexistent_returns_none() {
    let gc = det_collector();
    assert!(gc.check_pressure("nonexistent", 1000).is_none());
}

#[test]
fn check_pressure_empty_heap() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let pressure = gc.check_pressure("ext-a", 1000).unwrap();
    assert!((pressure).abs() < f64::EPSILON);
}

#[test]
fn should_collect_below_threshold() {
    let mut gc = GcCollector::new(GcConfig {
        deterministic: true,
        pressure_threshold_percent: 75,
    });
    gc.register_heap("ext-a".into()).unwrap();
    gc.allocate("ext-a", 700).unwrap();
    // 700/1000 = 0.70 < 0.75
    assert!(!gc.should_collect("ext-a", 1000));
}

#[test]
fn should_collect_at_threshold() {
    let mut gc = GcCollector::new(GcConfig {
        deterministic: true,
        pressure_threshold_percent: 75,
    });
    gc.register_heap("ext-a".into()).unwrap();
    gc.allocate("ext-a", 750).unwrap();
    // 750/1000 = 0.75 >= 0.75
    assert!(gc.should_collect("ext-a", 1000));
}

#[test]
fn should_collect_above_threshold() {
    let mut gc = GcCollector::new(GcConfig {
        deterministic: true,
        pressure_threshold_percent: 50,
    });
    gc.register_heap("ext-a".into()).unwrap();
    gc.allocate("ext-a", 600).unwrap();
    // 600/1000 = 0.60 >= 0.50
    assert!(gc.should_collect("ext-a", 1000));
}

#[test]
fn should_collect_nonexistent_heap() {
    let gc = det_collector();
    assert!(!gc.should_collect("nonexistent", 1000));
}

// ===========================================================================
// 19. Domain registry integration (allocate_tracked, collect_tracked)
// ===========================================================================

#[test]
fn allocate_tracked_charges_registry() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let mut reg = make_registry(1000);

    let (id, seq) = gc.allocate_tracked("ext-a", 400, &mut reg).unwrap();
    assert_eq!(id.as_u64(), 0);
    assert_eq!(seq, 1);
    assert_eq!(
        reg.get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        400
    );
}

#[test]
fn allocate_tracked_nonexistent_heap() {
    let mut gc = det_collector();
    let mut reg = make_registry(1000);
    let result = gc.allocate_tracked("nonexistent", 100, &mut reg);
    assert!(matches!(result, Err(GcError::HeapNotFound { .. })));
}

#[test]
fn allocate_tracked_budget_exceeded() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let mut reg = make_registry(100);

    let result = gc.allocate_tracked("ext-a", 200, &mut reg);
    assert!(matches!(result, Err(GcError::DomainError(_))));
}

#[test]
fn allocate_tracked_multiple_charges() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let mut reg = make_registry(1000);

    let (_, seq1) = gc.allocate_tracked("ext-a", 100, &mut reg).unwrap();
    let (_, seq2) = gc.allocate_tracked("ext-a", 200, &mut reg).unwrap();
    let (_, seq3) = gc.allocate_tracked("ext-a", 300, &mut reg).unwrap();

    assert_eq!(seq1, 1);
    assert_eq!(seq2, 2);
    assert_eq!(seq3, 3);
    assert_eq!(
        reg.get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        600
    );
}

#[test]
fn collect_tracked_releases_to_registry() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let mut reg = make_registry(1000);

    let (id, _) = gc.allocate_tracked("ext-a", 400, &mut reg).unwrap();
    gc.unroot("ext-a", id).unwrap();

    let event = gc.collect_tracked("ext-a", &mut reg).unwrap();
    assert_eq!(event.bytes_reclaimed, 400);
    assert_eq!(
        reg.get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        0
    );
}

#[test]
fn collect_tracked_no_garbage_no_release() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let mut reg = make_registry(1000);

    gc.allocate_tracked("ext-a", 400, &mut reg).unwrap();
    let event = gc.collect_tracked("ext-a", &mut reg).unwrap();
    assert_eq!(event.bytes_reclaimed, 0);
    assert_eq!(
        reg.get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        400
    );
}

#[test]
fn collect_tracked_partial_release() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let mut reg = make_registry(1000);

    let (id1, _) = gc.allocate_tracked("ext-a", 100, &mut reg).unwrap();
    let (_id2, _) = gc.allocate_tracked("ext-a", 200, &mut reg).unwrap();
    gc.unroot("ext-a", id1).unwrap();

    let event = gc.collect_tracked("ext-a", &mut reg).unwrap();
    assert_eq!(event.bytes_reclaimed, 100);
    assert_eq!(
        reg.get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        200
    );
}

// ===========================================================================
// 20. Event recording
// ===========================================================================

#[test]
fn events_accumulate() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.register_heap("ext-b".into()).unwrap();

    gc.collect("ext-a").unwrap();
    gc.collect("ext-b").unwrap();
    gc.collect("ext-a").unwrap();

    assert_eq!(gc.events().len(), 3);
    assert_eq!(gc.event_sequence(), 3);
    assert_eq!(gc.events()[0].sequence, 1);
    assert_eq!(gc.events()[1].sequence, 2);
    assert_eq!(gc.events()[2].sequence, 3);
}

#[test]
fn events_include_collect_all() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.register_heap("ext-b".into()).unwrap();

    gc.collect_all();
    assert_eq!(gc.events().len(), 2);
    assert_eq!(gc.event_sequence(), 2);
}

#[test]
fn events_empty_initially() {
    let gc = det_collector();
    assert!(gc.events().is_empty());
    assert_eq!(gc.event_sequence(), 0);
}

// ===========================================================================
// 21. Deterministic mode
// ===========================================================================

#[test]
fn deterministic_mode_fixed_pause_ns() {
    let mut gc = GcCollector::new(GcConfig::deterministic());
    gc.register_heap("ext".into()).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.pause_ns, 1000);
}

#[test]
fn non_deterministic_mode_zero_pause_ns() {
    let mut gc = GcCollector::new(GcConfig::default());
    gc.register_heap("ext".into()).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.pause_ns, 0);
}

#[test]
fn deterministic_mode_produces_identical_event_sequences() {
    fn run_scenario() -> Vec<GcEvent> {
        let mut gc = GcCollector::new(GcConfig::deterministic());
        gc.register_heap("ext-a".into()).unwrap();

        let r = gc.allocate("ext-a", 50).unwrap();
        let a = gc.allocate("ext-a", 30).unwrap();
        let b = gc.allocate("ext-a", 20).unwrap();

        gc.add_reference("ext-a", r, a).unwrap();
        gc.add_reference("ext-a", a, b).unwrap();
        gc.unroot("ext-a", a).unwrap();
        gc.unroot("ext-a", b).unwrap();

        gc.collect("ext-a").unwrap();

        let c = gc.allocate("ext-a", 40).unwrap();
        gc.unroot("ext-a", c).unwrap();
        gc.unroot("ext-a", r).unwrap();

        gc.collect("ext-a").unwrap();
        gc.events().to_vec()
    }

    let run1 = run_scenario();
    let run2 = run_scenario();
    assert_eq!(run1, run2);
}

#[test]
fn deterministic_collect_all_same_across_runs() {
    fn run() -> Vec<GcEvent> {
        let mut gc = GcCollector::new(GcConfig::deterministic());
        gc.register_heap("ext-c".into()).unwrap();
        gc.register_heap("ext-a".into()).unwrap();
        gc.register_heap("ext-b".into()).unwrap();

        let a = gc.allocate("ext-a", 100).unwrap();
        gc.unroot("ext-a", a).unwrap();
        let b = gc.allocate("ext-b", 200).unwrap();
        gc.unroot("ext-b", b).unwrap();

        gc.collect_all();
        gc.events().to_vec()
    }

    assert_eq!(run(), run());
}

// ===========================================================================
// 22. Collection count and total_reclaimed tracking
// ===========================================================================

#[test]
fn collection_count_increments_per_heap() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.collect("ext-a").unwrap();
    gc.collect("ext-a").unwrap();
    gc.collect("ext-a").unwrap();
    assert_eq!(gc.get_heap("ext-a").unwrap().collection_count(), 3);
}

#[test]
fn total_reclaimed_accumulates_across_collections() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();

    let a = gc.allocate("ext-a", 100).unwrap();
    gc.unroot("ext-a", a).unwrap();
    gc.collect("ext-a").unwrap();

    let b = gc.allocate("ext-a", 200).unwrap();
    gc.unroot("ext-a", b).unwrap();
    gc.collect("ext-a").unwrap();

    assert_eq!(gc.get_heap("ext-a").unwrap().total_reclaimed(), 300);
}

#[test]
fn total_bytes_decreases_after_collection() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let a = gc.allocate("ext-a", 100).unwrap();
    gc.allocate("ext-a", 200).unwrap();
    assert_eq!(gc.get_heap("ext-a").unwrap().total_bytes(), 300);

    gc.unroot("ext-a", a).unwrap();
    gc.collect("ext-a").unwrap();
    assert_eq!(gc.get_heap("ext-a").unwrap().total_bytes(), 200);
}

// ===========================================================================
// 23. Re-rooting
// ===========================================================================

#[test]
fn reroot_prevents_collection() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let obj = gc.allocate("ext-a", 100).unwrap();
    gc.unroot("ext-a", obj).unwrap();

    // Re-root via heap
    gc.get_heap_mut("ext-a").unwrap().root(obj).unwrap();

    let event = gc.collect("ext-a").unwrap();
    assert_eq!(event.swept_count, 0);
    assert_eq!(event.marked_count, 1);
}

#[test]
fn double_unroot_is_idempotent() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let obj = gc.allocate("ext", 50).unwrap();
    gc.unroot("ext", obj).unwrap();
    gc.unroot("ext", obj).unwrap(); // second unroot is fine
    let heap = gc.get_heap("ext").unwrap();
    assert!(!heap.get(obj).unwrap().rooted);
}

#[test]
fn double_root_is_idempotent() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let obj = gc.allocate("ext", 50).unwrap();
    // Already rooted, rooting again is fine
    gc.get_heap_mut("ext").unwrap().root(obj).unwrap();
    let heap = gc.get_heap("ext").unwrap();
    assert!(heap.get(obj).unwrap().rooted);
}

// ===========================================================================
// 24. iter_heaps
// ===========================================================================

#[test]
fn iter_heaps_deterministic_order() {
    let mut gc = det_collector();
    gc.register_heap("ext-z".into()).unwrap();
    gc.register_heap("ext-a".into()).unwrap();
    gc.register_heap("ext-m".into()).unwrap();

    let ids: Vec<&str> = gc.iter_heaps().map(|(id, _)| id).collect();
    assert_eq!(ids, vec!["ext-a", "ext-m", "ext-z"]);
}

#[test]
fn iter_heaps_empty() {
    let gc = det_collector();
    assert_eq!(gc.iter_heaps().count(), 0);
}

#[test]
fn iter_heaps_gives_access_to_heap_data() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.allocate("ext-a", 100).unwrap();

    for (id, heap) in gc.iter_heaps() {
        assert_eq!(id, "ext-a");
        assert_eq!(heap.object_count(), 1);
    }
}

// ===========================================================================
// 25. config() accessor
// ===========================================================================

#[test]
fn config_accessor() {
    let gc = det_collector();
    assert!(gc.config().deterministic);
    assert_eq!(gc.config().pressure_threshold_percent, 75);
}

// ===========================================================================
// 26. GcCollector serde round-trip
// ===========================================================================

#[test]
fn gc_collector_serde_round_trip() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let obj = gc.allocate("ext-a", 100).unwrap();
    gc.unroot("ext-a", obj).unwrap();
    gc.collect("ext-a").unwrap();

    let json = serde_json::to_string(&gc).expect("serialize");
    let restored: GcCollector = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(gc.heap_count(), restored.heap_count());
    assert_eq!(gc.event_sequence(), restored.event_sequence());
    assert_eq!(gc.events().len(), restored.events().len());
    assert_eq!(
        gc.get_heap("ext-a").unwrap().object_count(),
        restored.get_heap("ext-a").unwrap().object_count()
    );
}

#[test]
fn gc_collector_serde_preserves_events() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.collect("ext-a").unwrap();
    gc.collect("ext-a").unwrap();

    let json = serde_json::to_string(&gc).expect("serialize");
    let restored: GcCollector = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored.events().len(), 2);
    assert_eq!(restored.events()[0].sequence, 1);
    assert_eq!(restored.events()[1].sequence, 2);
}

#[test]
fn gc_collector_serde_preserves_heap_state() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let a = gc.allocate("ext-a", 100).unwrap();
    let b = gc.allocate("ext-a", 200).unwrap();
    gc.add_reference("ext-a", a, b).unwrap();
    gc.unroot("ext-a", b).unwrap();

    let json = serde_json::to_string(&gc).expect("serialize");
    let restored: GcCollector = serde_json::from_str(&json).expect("deserialize");

    let heap = restored.get_heap("ext-a").unwrap();
    assert_eq!(heap.object_count(), 2);
    assert_eq!(heap.total_bytes(), 300);
    let obj_a = heap.get(a).unwrap();
    assert!(obj_a.references.contains(&b));
    assert!(obj_a.rooted);
    let obj_b = heap.get(b).unwrap();
    assert!(!obj_b.rooted);
}

// ===========================================================================
// 27. Complex cross-concern integration scenarios
// ===========================================================================

#[test]
fn full_lifecycle_allocate_reference_collect_reuse() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();

    // Phase 1: Allocate a graph
    let root = gc.allocate("ext-a", 50).unwrap();
    let child1 = gc.allocate("ext-a", 30).unwrap();
    let child2 = gc.allocate("ext-a", 40).unwrap();
    let leaf = gc.allocate("ext-a", 20).unwrap();
    gc.add_reference("ext-a", root, child1).unwrap();
    gc.add_reference("ext-a", root, child2).unwrap();
    gc.add_reference("ext-a", child1, leaf).unwrap();
    gc.unroot("ext-a", child1).unwrap();
    gc.unroot("ext-a", child2).unwrap();
    gc.unroot("ext-a", leaf).unwrap();

    // Phase 2: Collect — everything reachable from root
    let event1 = gc.collect("ext-a").unwrap();
    assert_eq!(event1.marked_count, 4);
    assert_eq!(event1.swept_count, 0);

    // Phase 3: Unroot root, everything is garbage
    gc.unroot("ext-a", root).unwrap();
    let event2 = gc.collect("ext-a").unwrap();
    assert_eq!(event2.swept_count, 4);
    assert_eq!(event2.bytes_reclaimed, 140);

    // Phase 4: Allocate new objects on the same heap
    let new_obj = gc.allocate("ext-a", 500).unwrap();
    assert_eq!(gc.get_heap("ext-a").unwrap().object_count(), 1);
    assert_eq!(gc.get_heap("ext-a").unwrap().total_bytes(), 500);
    assert!(gc.get_heap("ext-a").unwrap().contains(new_obj));
}

#[test]
fn multi_heap_tracked_lifecycle() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.register_heap("ext-b".into()).unwrap();
    let mut reg = make_registry(10000);

    // Allocate in both heaps via tracked API
    let (a1, _) = gc.allocate_tracked("ext-a", 100, &mut reg).unwrap();
    let (a2, _) = gc.allocate_tracked("ext-a", 200, &mut reg).unwrap();
    let (b1, _) = gc.allocate_tracked("ext-b", 300, &mut reg).unwrap();
    assert_eq!(
        reg.get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        600
    );

    // Reference a1 -> a2
    gc.add_reference("ext-a", a1, a2).unwrap();
    gc.unroot("ext-a", a2).unwrap();

    // Collect ext-a: a2 is reachable from a1, nothing collected
    let event_a = gc.collect_tracked("ext-a", &mut reg).unwrap();
    assert_eq!(event_a.bytes_reclaimed, 0);

    // Unroot a1: now a1 and a2 are garbage
    gc.unroot("ext-a", a1).unwrap();
    let event_a2 = gc.collect_tracked("ext-a", &mut reg).unwrap();
    assert_eq!(event_a2.bytes_reclaimed, 300);
    assert_eq!(
        reg.get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        300 // only b1 remains
    );

    // Unroot and collect ext-b
    gc.unroot("ext-b", b1).unwrap();
    let event_b = gc.collect_tracked("ext-b", &mut reg).unwrap();
    assert_eq!(event_b.bytes_reclaimed, 300);
    assert_eq!(
        reg.get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        0
    );
}

#[test]
fn pressure_driven_collection_workflow() {
    let mut gc = GcCollector::new(GcConfig {
        deterministic: true,
        pressure_threshold_percent: 50,
    });
    gc.register_heap("ext-a".into()).unwrap();

    let budget = 1000_u64;

    // Allocate below threshold
    gc.allocate("ext-a", 400).unwrap();
    assert!(!gc.should_collect("ext-a", budget)); // 40% < 50%

    // Allocate above threshold
    gc.allocate("ext-a", 200).unwrap();
    assert!(gc.should_collect("ext-a", budget)); // 60% >= 50%

    // After collection (objects are rooted, nothing reclaimed)
    let event = gc.collect("ext-a").unwrap();
    assert_eq!(event.bytes_reclaimed, 0);
    // Still above threshold because nothing was collected
    assert!(gc.should_collect("ext-a", budget));
}

#[test]
fn large_graph_with_diamond_pattern() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();

    //     root
    //    /    \
    //   a      b
    //    \    /
    //     leaf
    let root = gc.allocate("ext", 10).unwrap();
    let a = gc.allocate("ext", 20).unwrap();
    let b = gc.allocate("ext", 30).unwrap();
    let leaf = gc.allocate("ext", 40).unwrap();

    gc.add_reference("ext", root, a).unwrap();
    gc.add_reference("ext", root, b).unwrap();
    gc.add_reference("ext", a, leaf).unwrap();
    gc.add_reference("ext", b, leaf).unwrap();

    gc.unroot("ext", a).unwrap();
    gc.unroot("ext", b).unwrap();
    gc.unroot("ext", leaf).unwrap();

    let event = gc.collect("ext").unwrap();
    assert_eq!(event.marked_count, 4);
    assert_eq!(event.swept_count, 0);
}

#[test]
fn multiple_roots_keep_shared_subgraph_alive() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();

    let root1 = gc.allocate("ext", 10).unwrap();
    let root2 = gc.allocate("ext", 10).unwrap();
    let shared = gc.allocate("ext", 100).unwrap();

    gc.add_reference("ext", root1, shared).unwrap();
    gc.add_reference("ext", root2, shared).unwrap();
    gc.unroot("ext", shared).unwrap();

    // Unroot root1 — shared still reachable from root2
    gc.unroot("ext", root1).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.marked_count, 2); // root2 and shared
    assert_eq!(event.swept_count, 1); // root1

    // Unroot root2 — now shared is garbage too
    gc.unroot("ext", root2).unwrap();
    let event2 = gc.collect("ext").unwrap();
    assert_eq!(event2.marked_count, 0);
    assert_eq!(event2.swept_count, 2);
}

#[test]
fn serialize_and_continue_lifecycle() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    let obj = gc.allocate("ext-a", 100).unwrap();
    gc.collect("ext-a").unwrap();

    // Serialize
    let json = serde_json::to_string(&gc).expect("serialize");
    let mut restored: GcCollector = serde_json::from_str(&json).expect("deserialize");

    // Continue working with restored collector
    let obj2 = restored.allocate("ext-a", 200).unwrap();
    assert_eq!(obj2.as_u64(), 1); // continues from where we left off
    restored.unroot("ext-a", obj).unwrap();
    let event = restored.collect("ext-a").unwrap();
    assert_eq!(event.bytes_reclaimed, 100);
    assert_eq!(event.sequence, 2); // continues from sequence 1
}

#[test]
fn heap_removal_and_re_registration() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.allocate("ext-a", 100).unwrap();
    gc.collect("ext-a").unwrap();

    // Remove and verify
    let old_heap = gc.remove_heap("ext-a").unwrap();
    assert_eq!(old_heap.collection_count(), 1);
    assert_eq!(gc.heap_count(), 0);

    // Re-register
    gc.register_heap("ext-a".into()).unwrap();
    assert_eq!(gc.get_heap("ext-a").unwrap().object_count(), 0);
    assert_eq!(gc.get_heap("ext-a").unwrap().collection_count(), 0);
}

#[test]
fn many_objects_stress_test() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();

    let mut ids = Vec::new();
    for i in 0..100 {
        let id = gc.allocate("ext", (i + 1) * 10).unwrap();
        ids.push(id);
    }
    assert_eq!(gc.get_heap("ext").unwrap().object_count(), 100);

    // Chain references: 0 -> 1 -> 2 -> ... -> 99
    for i in 0..99 {
        gc.add_reference("ext", ids[i], ids[i + 1]).unwrap();
    }

    // Unroot all except first
    for id in ids.iter().skip(1) {
        gc.unroot("ext", *id).unwrap();
    }

    // All 100 should survive (reachable from root chain)
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.marked_count, 100);
    assert_eq!(event.swept_count, 0);

    // Now unroot the first
    gc.unroot("ext", ids[0]).unwrap();
    let event2 = gc.collect("ext").unwrap();
    assert_eq!(event2.swept_count, 100);
    let expected_bytes: u64 = (1..=100).map(|i: u64| i * 10).sum();
    assert_eq!(event2.bytes_reclaimed, expected_bytes);
}

#[test]
fn event_phase_is_always_complete() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    gc.allocate("ext", 100).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.phase, GcPhase::Complete);

    let events = gc.collect_all();
    for evt in events {
        assert_eq!(evt.phase, GcPhase::Complete);
    }
}

#[test]
fn references_in_btreeset_are_deterministic() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let root = gc.allocate("ext", 10).unwrap();
    let a = gc.allocate("ext", 10).unwrap();
    let b = gc.allocate("ext", 10).unwrap();
    let c = gc.allocate("ext", 10).unwrap();

    // Add in reverse order
    gc.add_reference("ext", root, c).unwrap();
    gc.add_reference("ext", root, a).unwrap();
    gc.add_reference("ext", root, b).unwrap();

    let heap = gc.get_heap("ext").unwrap();
    let refs: Vec<GcObjectId> = heap.get(root).unwrap().references.iter().copied().collect();
    // BTreeSet should yield in sorted order regardless of insertion order
    assert_eq!(refs, vec![a, b, c]);
}

#[test]
fn duplicate_reference_is_idempotent() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let a = gc.allocate("ext", 10).unwrap();
    let b = gc.allocate("ext", 20).unwrap();

    gc.add_reference("ext", a, b).unwrap();
    gc.add_reference("ext", a, b).unwrap(); // duplicate

    let heap = gc.get_heap("ext").unwrap();
    assert_eq!(heap.get(a).unwrap().references.len(), 1);
}

#[test]
fn collect_after_removing_reference_target_from_roots() {
    // Scenario: root -> child. Unroot child (still reachable). Then unroot root.
    // Both should be collected.
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let root = gc.allocate("ext", 10).unwrap();
    let child = gc.allocate("ext", 20).unwrap();
    gc.add_reference("ext", root, child).unwrap();
    gc.unroot("ext", child).unwrap();

    // Collect: child is reachable from root
    let event1 = gc.collect("ext").unwrap();
    assert_eq!(event1.marked_count, 2);
    assert_eq!(event1.swept_count, 0);

    // Unroot root
    gc.unroot("ext", root).unwrap();
    let event2 = gc.collect("ext").unwrap();
    assert_eq!(event2.marked_count, 0);
    assert_eq!(event2.swept_count, 2);
    assert_eq!(event2.bytes_reclaimed, 30);
}

#[test]
fn empty_extension_id_is_valid() {
    let mut gc = det_collector();
    gc.register_heap(String::new()).unwrap();
    let id = gc.allocate("", 10).unwrap();
    assert!(gc.get_heap("").unwrap().contains(id));
    let event = gc.collect("").unwrap();
    assert_eq!(event.extension_id, "");
}

#[test]
fn gc_config_custom_threshold() {
    let config = GcConfig {
        deterministic: true,
        pressure_threshold_percent: 1,
    };
    assert!((config.pressure_ratio() - 0.01).abs() < f64::EPSILON);

    let config2 = GcConfig {
        deterministic: false,
        pressure_threshold_percent: 99,
    };
    assert!((config2.pressure_ratio() - 0.99).abs() < f64::EPSILON);
}

#[test]
fn gc_object_zero_references_set() {
    let mut heap = ExtensionHeap::new("ext".into());
    let id = heap.allocate(10);
    let obj = heap.get(id).unwrap();
    let empty_set: BTreeSet<GcObjectId> = BTreeSet::new();
    assert_eq!(obj.references, empty_set);
}

#[test]
fn gc_collector_config_is_accessible() {
    let config = GcConfig {
        deterministic: false,
        pressure_threshold_percent: 42,
    };
    let gc = GcCollector::new(config);
    assert!(!gc.config().deterministic);
    assert_eq!(gc.config().pressure_threshold_percent, 42);
}

#[test]
fn collection_on_heap_with_only_unrooted_zero_size_objects() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let a = gc.allocate("ext", 0).unwrap();
    let b = gc.allocate("ext", 0).unwrap();
    gc.unroot("ext", a).unwrap();
    gc.unroot("ext", b).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.swept_count, 2);
    assert_eq!(event.bytes_reclaimed, 0);
    assert_eq!(gc.get_heap("ext").unwrap().object_count(), 0);
}

#[test]
fn allocate_tracked_then_collect_tracked_cycle() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let mut reg = make_registry(10000);

    // Allocate-collect-allocate-collect cycle
    for i in 0..5 {
        let (id, _) = gc.allocate_tracked("ext", (i + 1) * 100, &mut reg).unwrap();
        gc.unroot("ext", id).unwrap();
        let event = gc.collect_tracked("ext", &mut reg).unwrap();
        assert_eq!(event.bytes_reclaimed, (i + 1) * 100);
    }

    assert_eq!(
        reg.get(&AllocationDomain::ExtensionHeap)
            .unwrap()
            .budget
            .used_bytes,
        0
    );
    assert_eq!(gc.get_heap("ext").unwrap().collection_count(), 5);
}
