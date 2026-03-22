#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

//! Enrichment integration tests for the `gc` module.
//!
//! Covers: serde round-trips, GcHeap allocation and collection,
//! deterministic collection, reference graph handling, pressure
//! calculation, GcCollector lifecycle, error paths, Display formatting.
//!
//! NOTE: GcObjectId has a private constructor — all IDs must come from
//! allocation calls or serde deserialization.

use std::collections::BTreeSet;

use frankenengine_engine::alloc_domain::{AllocationDomain, DomainRegistry, LifetimeClass};
use frankenengine_engine::gc::{
    CollectionStats, ExtensionHeap, GcCollector, GcConfig, GcError, GcEvent, GcPhase,
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

/// Obtain a GcObjectId via deserialization (since constructor is private).
fn gc_object_id_from_u64(n: u64) -> frankenengine_engine::gc::GcObjectId {
    serde_json::from_str(&n.to_string()).unwrap()
}

// ===========================================================================
// GcObjectId (via allocation or serde)
// ===========================================================================

#[test]
fn enrichment_gc_object_id_display_from_allocation() {
    let mut heap = ExtensionHeap::new("ext".into());
    let id = heap.allocate(10);
    assert_eq!(id.to_string(), "obj-0");
    assert_eq!(id.as_u64(), 0);
}

#[test]
fn enrichment_gc_object_id_serde_roundtrip() {
    let id = gc_object_id_from_u64(7);
    let json = serde_json::to_string(&id).unwrap();
    let back: frankenengine_engine::gc::GcObjectId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn enrichment_gc_object_id_ordering_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(gc_object_id_from_u64(3));
    set.insert(gc_object_id_from_u64(1));
    set.insert(gc_object_id_from_u64(2));
    set.insert(gc_object_id_from_u64(1)); // duplicate
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_gc_object_id_display_various() {
    assert_eq!(gc_object_id_from_u64(0).to_string(), "obj-0");
    assert_eq!(gc_object_id_from_u64(42).to_string(), "obj-42");
    assert_eq!(gc_object_id_from_u64(999).to_string(), "obj-999");
}

// ===========================================================================
// GcPhase
// ===========================================================================

#[test]
fn enrichment_gc_phase_display_values() {
    assert_eq!(GcPhase::Mark.to_string(), "mark");
    assert_eq!(GcPhase::Sweep.to_string(), "sweep");
    assert_eq!(GcPhase::Complete.to_string(), "complete");
}

#[test]
fn enrichment_gc_phase_display_all_unique() {
    let set: BTreeSet<String> = [GcPhase::Mark, GcPhase::Sweep, GcPhase::Complete]
        .iter()
        .map(|p| p.to_string())
        .collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_gc_phase_serde_roundtrip() {
    for phase in [GcPhase::Mark, GcPhase::Sweep, GcPhase::Complete] {
        let json = serde_json::to_string(&phase).unwrap();
        let back: GcPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(phase, back);
    }
}

// ===========================================================================
// GcConfig
// ===========================================================================

#[test]
fn enrichment_gc_config_default() {
    let cfg = GcConfig::default();
    assert!(!cfg.deterministic);
    assert_eq!(cfg.pressure_threshold_percent, 75);
}

#[test]
fn enrichment_gc_config_deterministic() {
    let cfg = GcConfig::deterministic();
    assert!(cfg.deterministic);
    assert_eq!(cfg.pressure_threshold_percent, 75);
}

#[test]
fn enrichment_gc_config_pressure_ratio() {
    assert!((GcConfig::default().pressure_ratio() - 0.75).abs() < f64::EPSILON);
}

#[test]
fn enrichment_gc_config_pressure_ratio_boundaries() {
    let zero = GcConfig {
        deterministic: true,
        pressure_threshold_percent: 0,
    };
    assert!((zero.pressure_ratio() - 0.0).abs() < f64::EPSILON);
    let hundred = GcConfig {
        deterministic: true,
        pressure_threshold_percent: 100,
    };
    assert!((hundred.pressure_ratio() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn enrichment_gc_config_serde_roundtrip() {
    for cfg in [GcConfig::default(), GcConfig::deterministic()] {
        let json = serde_json::to_string(&cfg).unwrap();
        let back: GcConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg.deterministic, back.deterministic);
        assert_eq!(
            cfg.pressure_threshold_percent,
            back.pressure_threshold_percent
        );
    }
}

// ===========================================================================
// GcError (no direct GcObjectId construction — use serde or allocation IDs)
// ===========================================================================

#[test]
fn enrichment_gc_error_display_heap_not_found() {
    let err = GcError::HeapNotFound {
        extension_id: "ext-missing".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("ext-missing"));
    assert!(msg.contains("not found"));
}

#[test]
fn enrichment_gc_error_display_duplicate_heap() {
    let err = GcError::DuplicateHeap {
        extension_id: "ext-dup".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("ext-dup"));
    assert!(msg.contains("already registered"));
}

#[test]
fn enrichment_gc_error_display_object_not_found() {
    let err = GcError::ObjectNotFound {
        extension_id: "ext".into(),
        object_id: gc_object_id_from_u64(42),
    };
    let msg = err.to_string();
    assert!(msg.contains("obj-42"));
    assert!(msg.contains("ext"));
}

#[test]
fn enrichment_gc_error_display_all_unique() {
    let errors = vec![
        GcError::HeapNotFound {
            extension_id: "a".into(),
        },
        GcError::DuplicateHeap {
            extension_id: "b".into(),
        },
        GcError::ObjectNotFound {
            extension_id: "c".into(),
            object_id: gc_object_id_from_u64(1),
        },
    ];
    let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_gc_error_serde_roundtrip() {
    let errors = vec![
        GcError::HeapNotFound {
            extension_id: "ext".into(),
        },
        GcError::DuplicateHeap {
            extension_id: "ext".into(),
        },
        GcError::ObjectNotFound {
            extension_id: "ext".into(),
            object_id: gc_object_id_from_u64(5),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: GcError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_gc_error_implements_std_error() {
    let err = GcError::HeapNotFound {
        extension_id: "test".into(),
    };
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

// ===========================================================================
// GcEvent
// ===========================================================================

#[test]
fn enrichment_gc_event_serde_roundtrip() {
    let event = GcEvent {
        sequence: 1,
        extension_id: "ext-a".to_string(),
        phase: GcPhase::Complete,
        marked_count: 10,
        swept_count: 3,
        bytes_reclaimed: 300,
        pause_ns: 1000,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: GcEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// ExtensionHeap
// ===========================================================================

#[test]
fn enrichment_heap_allocate_and_count() {
    let mut heap = ExtensionHeap::new("ext".into());
    assert_eq!(heap.object_count(), 0);
    let id1 = heap.allocate(100);
    let id2 = heap.allocate(200);
    assert_eq!(heap.object_count(), 2);
    assert_eq!(heap.total_bytes(), 300);
    assert!(heap.contains(id1));
    assert!(heap.contains(id2));
}

#[test]
fn enrichment_heap_monotonic_ids() {
    let mut heap = ExtensionHeap::new("ext".into());
    let a = heap.allocate(10);
    let b = heap.allocate(20);
    let c = heap.allocate(30);
    assert_eq!(a.as_u64(), 0);
    assert_eq!(b.as_u64(), 1);
    assert_eq!(c.as_u64(), 2);
}

#[test]
fn enrichment_heap_add_reference_and_get() {
    let mut heap = ExtensionHeap::new("ext".into());
    let a = heap.allocate(10);
    let b = heap.allocate(20);
    heap.add_reference(a, b).unwrap();
    let obj = heap.get(a).unwrap();
    assert!(obj.references.contains(&b));
}

#[test]
fn enrichment_heap_add_reference_nonexistent_from() {
    let mut heap = ExtensionHeap::new("ext".into());
    let valid = heap.allocate(10);
    // Use a fake ID via serde for the 'from' param (which doesn't exist in heap)
    let fake = gc_object_id_from_u64(999);
    assert!(matches!(
        heap.add_reference(fake, valid),
        Err(GcError::ObjectNotFound { .. })
    ));
}

#[test]
fn enrichment_heap_serde_roundtrip() {
    let mut heap = ExtensionHeap::new("serde-ext".into());
    let a = heap.allocate(100);
    let b = heap.allocate(200);
    heap.add_reference(a, b).unwrap();
    heap.unroot(b).unwrap();
    let json = serde_json::to_string(&heap).unwrap();
    let back: ExtensionHeap = serde_json::from_str(&json).unwrap();
    assert_eq!(back.extension_id(), "serde-ext");
    assert_eq!(back.object_count(), 2);
    assert_eq!(back.total_bytes(), 300);
}

#[test]
fn enrichment_heap_extension_id_accessor() {
    let heap = ExtensionHeap::new("my-ext-42".into());
    assert_eq!(heap.extension_id(), "my-ext-42");
}

// ===========================================================================
// GcCollector — allocation, collection, references
// ===========================================================================

#[test]
fn enrichment_collector_register_and_allocate() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let id = gc.allocate("ext", 100).unwrap();
    assert_eq!(id.as_u64(), 0);
    assert_eq!(gc.get_heap("ext").unwrap().object_count(), 1);
}

#[test]
fn enrichment_collector_collect_dead_objects() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let a = gc.allocate("ext", 100).unwrap();
    let b = gc.allocate("ext", 200).unwrap();
    gc.unroot("ext", a).unwrap();
    gc.unroot("ext", b).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.swept_count, 2);
    assert_eq!(event.bytes_reclaimed, 300);
    assert_eq!(gc.get_heap("ext").unwrap().object_count(), 0);
}

#[test]
fn enrichment_collector_rooted_objects_survive() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let a = gc.allocate("ext", 100).unwrap();
    gc.allocate("ext", 200).unwrap();
    gc.unroot("ext", a).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.swept_count, 1);
    assert_eq!(event.marked_count, 1);
}

#[test]
fn enrichment_collector_referenced_survive() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let root = gc.allocate("ext", 50).unwrap();
    let child = gc.allocate("ext", 80).unwrap();
    gc.add_reference("ext", root, child).unwrap();
    gc.unroot("ext", child).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.marked_count, 2);
    assert_eq!(event.swept_count, 0);
}

#[test]
fn enrichment_collector_circular_refs_collected_when_unreachable() {
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
fn enrichment_collector_diamond_reference_graph() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let root = gc.allocate("ext", 10).unwrap();
    let left = gc.allocate("ext", 20).unwrap();
    let right = gc.allocate("ext", 30).unwrap();
    let bottom = gc.allocate("ext", 40).unwrap();
    gc.add_reference("ext", root, left).unwrap();
    gc.add_reference("ext", root, right).unwrap();
    gc.add_reference("ext", left, bottom).unwrap();
    gc.add_reference("ext", right, bottom).unwrap();
    gc.unroot("ext", left).unwrap();
    gc.unroot("ext", right).unwrap();
    gc.unroot("ext", bottom).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.marked_count, 4);
    assert_eq!(event.swept_count, 0);
}

#[test]
fn enrichment_collector_long_chain_survives() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let mut prev = gc.allocate("ext", 10).unwrap(); // root
    for _ in 0..20 {
        let next = gc.allocate("ext", 10).unwrap();
        gc.add_reference("ext", prev, next).unwrap();
        gc.unroot("ext", next).unwrap();
        prev = next;
    }
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.marked_count, 21);
    assert_eq!(event.swept_count, 0);
}

#[test]
fn enrichment_collector_collect_all_deterministic_order() {
    let mut gc = det_collector();
    gc.register_heap("ext-c".into()).unwrap();
    gc.register_heap("ext-a".into()).unwrap();
    gc.register_heap("ext-b".into()).unwrap();
    let events = gc.collect_all();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].extension_id, "ext-a");
    assert_eq!(events[1].extension_id, "ext-b");
    assert_eq!(events[2].extension_id, "ext-c");
}

#[test]
fn enrichment_collector_deterministic_fixed_pause() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.pause_ns, 1000);
}

#[test]
fn enrichment_collector_non_deterministic_zero_pause() {
    let mut gc = GcCollector::new(GcConfig::default());
    gc.register_heap("ext".into()).unwrap();
    assert_eq!(gc.collect("ext").unwrap().pause_ns, 0);
}

// ===========================================================================
// GcCollector — pressure
// ===========================================================================

#[test]
fn enrichment_collector_pressure_check() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    gc.allocate("ext", 750).unwrap();
    let p = gc.check_pressure("ext", 1000).unwrap();
    assert!((p - 0.75).abs() < f64::EPSILON);
}

#[test]
fn enrichment_collector_should_collect_respects_threshold() {
    let mut gc = GcCollector::new(GcConfig {
        deterministic: true,
        pressure_threshold_percent: 50,
    });
    gc.register_heap("ext".into()).unwrap();
    gc.allocate("ext", 400).unwrap();
    assert!(!gc.should_collect("ext", 1000));
    gc.allocate("ext", 200).unwrap();
    assert!(gc.should_collect("ext", 1000));
}

#[test]
fn enrichment_collector_pressure_zero_budget() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    gc.allocate("ext", 1).unwrap();
    assert_eq!(gc.check_pressure("ext", 0).unwrap(), f64::MAX);
}

// ===========================================================================
// GcCollector — lifecycle
// ===========================================================================

#[test]
fn enrichment_collector_remove_heap() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    gc.allocate("ext", 100).unwrap();
    let heap = gc.remove_heap("ext").unwrap();
    assert_eq!(heap.object_count(), 1);
    assert_eq!(gc.heap_count(), 0);
}

#[test]
fn enrichment_collector_events_accumulate() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    gc.collect("ext").unwrap();
    gc.collect("ext").unwrap();
    assert_eq!(gc.events().len(), 2);
    assert_eq!(gc.event_sequence(), 2);
}

#[test]
fn enrichment_collector_heap_count() {
    let mut gc = det_collector();
    assert_eq!(gc.heap_count(), 0);
    gc.register_heap("a".into()).unwrap();
    gc.register_heap("b".into()).unwrap();
    assert_eq!(gc.heap_count(), 2);
    gc.remove_heap("a").unwrap();
    assert_eq!(gc.heap_count(), 1);
}

#[test]
fn enrichment_collector_iter_heaps_alphabetical() {
    let mut gc = det_collector();
    gc.register_heap("z".into()).unwrap();
    gc.register_heap("a".into()).unwrap();
    gc.register_heap("m".into()).unwrap();
    let ids: Vec<&str> = gc.iter_heaps().map(|(id, _)| id).collect();
    assert_eq!(ids, vec!["a", "m", "z"]);
}

#[test]
fn enrichment_collector_serde_roundtrip() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let obj = gc.allocate("ext", 100).unwrap();
    gc.unroot("ext", obj).unwrap();
    gc.collect("ext").unwrap();
    let json = serde_json::to_string(&gc).unwrap();
    let back: GcCollector = serde_json::from_str(&json).unwrap();
    assert_eq!(gc.heap_count(), back.heap_count());
    assert_eq!(gc.event_sequence(), back.event_sequence());
}

#[test]
fn enrichment_collector_deterministic_replay() {
    fn scenario() -> Vec<GcEvent> {
        let mut gc = GcCollector::new(GcConfig::deterministic());
        gc.register_heap("ext".into()).unwrap();
        let a = gc.allocate("ext", 50).unwrap();
        let b = gc.allocate("ext", 30).unwrap();
        gc.add_reference("ext", a, b).unwrap();
        gc.unroot("ext", b).unwrap();
        gc.collect("ext").unwrap();
        gc.events().to_vec()
    }
    assert_eq!(scenario(), scenario());
}

#[test]
fn enrichment_collector_empty_heap_collect_noop() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.marked_count, 0);
    assert_eq!(event.swept_count, 0);
    assert_eq!(event.bytes_reclaimed, 0);
}

#[test]
fn enrichment_collector_many_objects() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let mut ids = Vec::new();
    for _ in 0..100 {
        ids.push(gc.allocate("ext", 10).unwrap());
    }
    assert_eq!(gc.get_heap("ext").unwrap().object_count(), 100);
    // Unroot odd-indexed objects
    for (i, id) in ids.iter().enumerate() {
        if i % 2 == 1 {
            gc.unroot("ext", *id).unwrap();
        }
    }
    let event = gc.collect("ext").unwrap();
    assert_eq!(event.marked_count, 50);
    assert_eq!(event.swept_count, 50);
}

#[test]
fn enrichment_collector_remove_and_reregister() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    gc.allocate("ext", 100).unwrap();
    gc.remove_heap("ext").unwrap();
    gc.register_heap("ext".into()).unwrap();
    assert_eq!(gc.get_heap("ext").unwrap().object_count(), 0);
    assert_eq!(gc.get_heap("ext").unwrap().total_bytes(), 0);
}

// ===========================================================================
// Error paths
// ===========================================================================

#[test]
fn enrichment_collector_duplicate_heap() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    assert!(matches!(
        gc.register_heap("ext".into()),
        Err(GcError::DuplicateHeap { .. })
    ));
}

#[test]
fn enrichment_collector_allocate_nonexistent_heap() {
    let mut gc = det_collector();
    assert!(matches!(
        gc.allocate("missing", 100),
        Err(GcError::HeapNotFound { .. })
    ));
}

#[test]
fn enrichment_collector_collect_nonexistent_heap() {
    let mut gc = det_collector();
    assert!(matches!(
        gc.collect("missing"),
        Err(GcError::HeapNotFound { .. })
    ));
}

#[test]
fn enrichment_collector_remove_nonexistent_heap() {
    let mut gc = det_collector();
    assert!(matches!(
        gc.remove_heap("missing"),
        Err(GcError::HeapNotFound { .. })
    ));
}

#[test]
fn enrichment_collector_unroot_nonexistent_heap() {
    let mut gc = det_collector();
    let fake_id = gc_object_id_from_u64(0);
    assert!(matches!(
        gc.unroot("missing", fake_id),
        Err(GcError::HeapNotFound { .. })
    ));
}

#[test]
fn enrichment_collector_add_reference_nonexistent_heap() {
    let mut gc = det_collector();
    let fake = gc_object_id_from_u64(0);
    assert!(matches!(
        gc.add_reference("missing", fake, fake),
        Err(GcError::HeapNotFound { .. })
    ));
}

// ===========================================================================
// Domain registry integration
// ===========================================================================

#[test]
fn enrichment_allocate_tracked_charges_registry() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let mut reg = make_registry(1000);
    let (id, seq) = gc.allocate_tracked("ext", 400, &mut reg).unwrap();
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
fn enrichment_collect_tracked_releases_budget() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let mut reg = make_registry(1000);
    let (id, _) = gc.allocate_tracked("ext", 400, &mut reg).unwrap();
    gc.unroot("ext", id).unwrap();
    let event = gc.collect_tracked("ext", &mut reg).unwrap();
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
fn enrichment_collect_tracked_missing_registry_domain_preserves_heap_state() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();

    let obj = gc.allocate("ext", 400).unwrap();
    gc.unroot("ext", obj).unwrap();

    let mut reg = DomainRegistry::new();
    assert!(matches!(
        gc.collect_tracked("ext", &mut reg),
        Err(GcError::DomainError(
            frankenengine_engine::alloc_domain::AllocDomainError::DomainNotFound {
                domain: AllocationDomain::ExtensionHeap
            }
        ))
    ));

    let heap = gc.get_heap("ext").unwrap();
    assert_eq!(heap.object_count(), 1);
    assert_eq!(heap.total_bytes(), 400);
    assert!(heap.contains(obj));
    assert_eq!(gc.events().len(), 0);
}

#[test]
fn enrichment_allocate_tracked_budget_exceeded() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let mut reg = make_registry(100);
    assert!(matches!(
        gc.allocate_tracked("ext", 200, &mut reg),
        Err(GcError::DomainError(_))
    ));
}

#[test]
fn enrichment_allocate_tracked_nonexistent_heap() {
    let mut gc = det_collector();
    let mut reg = make_registry(1000);
    assert!(matches!(
        gc.allocate_tracked("missing", 100, &mut reg),
        Err(GcError::HeapNotFound { .. })
    ));
}

// ===========================================================================
// CollectionStats
// ===========================================================================

#[test]
fn enrichment_collection_stats_equality() {
    let a = CollectionStats {
        marked_count: 5,
        swept_count: 3,
        bytes_reclaimed: 100,
    };
    let b = CollectionStats {
        marked_count: 5,
        swept_count: 3,
        bytes_reclaimed: 100,
    };
    let c = CollectionStats {
        marked_count: 5,
        swept_count: 2,
        bytes_reclaimed: 100,
    };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ===========================================================================
// Multi-heap interleaved operations
// ===========================================================================

#[test]
fn enrichment_multi_heap_interleaved_operations() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.register_heap("ext-b".into()).unwrap();

    let a1 = gc.allocate("ext-a", 100).unwrap();
    let b1 = gc.allocate("ext-b", 200).unwrap();
    let a2 = gc.allocate("ext-a", 150).unwrap();

    gc.unroot("ext-a", a1).unwrap();
    gc.unroot("ext-b", b1).unwrap();

    let ev_a = gc.collect("ext-a").unwrap();
    assert_eq!(ev_a.swept_count, 1);
    assert_eq!(ev_a.bytes_reclaimed, 100);

    // ext-b should be unaffected
    assert_eq!(gc.get_heap("ext-b").unwrap().object_count(), 1);

    let ev_b = gc.collect("ext-b").unwrap();
    assert_eq!(ev_b.swept_count, 1);

    // a2 should still be alive
    assert!(gc.get_heap("ext-a").unwrap().contains(a2));
}

#[test]
fn enrichment_event_sequence_monotonic_across_heaps() {
    let mut gc = det_collector();
    gc.register_heap("ext-a".into()).unwrap();
    gc.register_heap("ext-b".into()).unwrap();
    let e1 = gc.collect("ext-b").unwrap();
    let e2 = gc.collect("ext-a").unwrap();
    let e3 = gc.collect("ext-b").unwrap();
    assert!(e1.sequence < e2.sequence);
    assert!(e2.sequence < e3.sequence);
}

#[test]
fn enrichment_collector_config_accessor() {
    let cfg = GcConfig {
        deterministic: true,
        pressure_threshold_percent: 42,
    };
    let gc = GcCollector::new(cfg.clone());
    assert_eq!(*gc.config(), cfg);
}

#[test]
fn enrichment_collector_total_reclaimed_accumulates() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    let a = gc.allocate("ext", 100).unwrap();
    gc.unroot("ext", a).unwrap();
    gc.collect("ext").unwrap();
    let b = gc.allocate("ext", 200).unwrap();
    gc.unroot("ext", b).unwrap();
    gc.collect("ext").unwrap();
    assert_eq!(gc.get_heap("ext").unwrap().total_reclaimed(), 300);
}

#[test]
fn enrichment_collector_collection_count_increments() {
    let mut gc = det_collector();
    gc.register_heap("ext".into()).unwrap();
    gc.collect("ext").unwrap();
    gc.collect("ext").unwrap();
    gc.collect("ext").unwrap();
    assert_eq!(gc.get_heap("ext").unwrap().collection_count(), 3);
}
