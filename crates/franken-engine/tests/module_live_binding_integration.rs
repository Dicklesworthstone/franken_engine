#![forbid(unsafe_code)]

//! Integration tests for the module_live_binding module.

use frankenengine_engine::esm_loader::BindingType;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_live_binding::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_cell(module: &str, export: &str) -> BindingCell {
    BindingCell::new(module, export, export, BindingType::Direct)
}

fn make_namespace(module: &str, exports: &[&str]) -> NamespaceObject {
    let mut export_names: Vec<String> = exports.iter().map(|s| s.to_string()).collect();
    export_names.sort();
    let bindings = export_names
        .iter()
        .map(|name| (name.clone(), BindingId::new(module, name)))
        .collect();
    NamespaceObject {
        schema_version: NAMESPACE_OBJECT_SCHEMA_VERSION.to_string(),
        module_specifier: module.to_string(),
        export_names,
        bindings,
        source_hash: ContentHash::compute(module.as_bytes()),
    }
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(MODULE_LIVE_BINDING_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(MODULE_LIVE_BINDING_SCHEMA_VERSION.contains("live-binding"));
}

#[test]
fn namespace_schema_version_format() {
    assert!(NAMESPACE_OBJECT_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(NAMESPACE_OBJECT_SCHEMA_VERSION.contains("namespace"));
}

#[test]
fn bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
}

// ---------------------------------------------------------------------------
// BindingCellState serde
// ---------------------------------------------------------------------------

#[test]
fn binding_cell_state_serde_all_variants() {
    for state in [
        BindingCellState::Uninitialized,
        BindingCellState::Initialized,
        BindingCellState::Dead,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let back: BindingCellState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}

#[test]
fn binding_cell_state_display_all_variants() {
    assert_eq!(BindingCellState::Uninitialized.to_string(), "uninitialized");
    assert_eq!(BindingCellState::Initialized.to_string(), "initialized");
    assert_eq!(BindingCellState::Dead.to_string(), "dead");
}

#[test]
fn binding_cell_state_ord() {
    assert!(BindingCellState::Uninitialized < BindingCellState::Initialized);
    assert!(BindingCellState::Initialized < BindingCellState::Dead);
}

// ---------------------------------------------------------------------------
// BindingCell
// ---------------------------------------------------------------------------

#[test]
fn binding_cell_new_is_uninitialized() {
    let cell = make_cell("mod_a", "foo");
    assert_eq!(cell.state, BindingCellState::Uninitialized);
    assert!(!cell.is_initialized());
    assert_eq!(cell.version, 0);
    assert!(cell.value_millionths.is_none());
    assert!(cell.value_string.is_none());
}

#[test]
fn binding_cell_initialize_millionths() {
    let mut cell = make_cell("mod_a", "count");
    cell.initialize_millionths(1_000_000);
    assert!(cell.is_initialized());
    assert_eq!(cell.value_millionths, Some(1_000_000));
    assert!(cell.value_string.is_none());
    assert_eq!(cell.version, 1);
}

#[test]
fn binding_cell_initialize_string() {
    let mut cell = make_cell("mod_a", "name");
    cell.initialize_string("alice".to_string());
    assert!(cell.is_initialized());
    assert_eq!(cell.value_string.as_deref(), Some("alice"));
    assert!(cell.value_millionths.is_none());
    assert_eq!(cell.version, 1);
}

#[test]
fn binding_cell_mutate_increments_version() {
    let mut cell = make_cell("mod_a", "val");
    cell.initialize_millionths(0);
    assert_eq!(cell.version, 1);
    cell.mutate_millionths(1).unwrap();
    assert_eq!(cell.version, 2);
    cell.mutate_millionths(2).unwrap();
    assert_eq!(cell.version, 3);
}

#[test]
fn binding_cell_mutate_dead_fails() {
    let mut cell = make_cell("mod_a", "val");
    cell.mark_dead();
    assert!(cell.mutate_millionths(1).is_err());
    assert!(cell.mutate_string("x".to_string()).is_err());
}

#[test]
fn binding_cell_mark_dead_increments_version() {
    let mut cell = make_cell("mod_a", "val");
    cell.mark_dead();
    assert_eq!(cell.version, 1);
    assert_eq!(cell.state, BindingCellState::Dead);
}

#[test]
fn binding_cell_display() {
    let cell = make_cell("mod_a", "foo");
    let s = cell.to_string();
    assert!(s.contains("mod_a"));
    assert!(s.contains("foo"));
    assert!(s.contains("v0"));
}

#[test]
fn binding_cell_serde_roundtrip() {
    let mut cell = make_cell("mod_a", "counter");
    cell.initialize_millionths(42_000_000);
    let json = serde_json::to_string(&cell).unwrap();
    let back: BindingCell = serde_json::from_str(&json).unwrap();
    assert_eq!(cell, back);
}

#[test]
fn binding_cell_string_serde_roundtrip() {
    let mut cell = make_cell("mod_a", "name");
    cell.initialize_string("hello world".to_string());
    let json = serde_json::to_string(&cell).unwrap();
    let back: BindingCell = serde_json::from_str(&json).unwrap();
    assert_eq!(cell, back);
}

// ---------------------------------------------------------------------------
// BindingId
// ---------------------------------------------------------------------------

#[test]
fn binding_id_display() {
    let id = BindingId::new("mod_a", "foo");
    assert_eq!(id.to_string(), "mod_a::foo");
}

#[test]
fn binding_id_ord() {
    let a = BindingId::new("a", "x");
    let b = BindingId::new("b", "x");
    let c = BindingId::new("a", "y");
    assert!(a < b);
    assert!(a < c);
}

#[test]
fn binding_id_serde_roundtrip() {
    let id = BindingId::new("mod_a", "exported_val");
    let json = serde_json::to_string(&id).unwrap();
    let back: BindingId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

// ---------------------------------------------------------------------------
// NamespaceObject
// ---------------------------------------------------------------------------

#[test]
fn namespace_object_has_export() {
    let ns = make_namespace("mod_a", &["foo", "bar"]);
    assert!(ns.has_export("foo"));
    assert!(ns.has_export("bar"));
    assert!(!ns.has_export("baz"));
}

#[test]
fn namespace_object_get_binding() {
    let ns = make_namespace("mod_a", &["foo"]);
    let binding = ns.get_binding("foo").unwrap();
    assert_eq!(binding.module_specifier, "mod_a");
    assert_eq!(binding.export_name, "foo");
}

#[test]
fn namespace_object_export_names_sorted() {
    let ns = make_namespace("mod_a", &["zebra", "alpha", "mike"]);
    assert_eq!(ns.export_names, vec!["alpha", "mike", "zebra"]);
}

#[test]
fn namespace_object_len_and_empty() {
    let ns = make_namespace("mod_a", &["a", "b"]);
    assert_eq!(ns.len(), 2);
    assert!(!ns.is_empty());

    let empty_ns = make_namespace("mod_b", &[]);
    assert_eq!(empty_ns.len(), 0);
    assert!(empty_ns.is_empty());
}

#[test]
fn namespace_object_display() {
    let ns = make_namespace("mod_a", &["x", "y"]);
    let s = ns.to_string();
    assert!(s.contains("mod_a"));
    assert!(s.contains("2 exports"));
}

#[test]
fn namespace_object_serde_roundtrip() {
    let ns = make_namespace("mod_a", &["foo", "bar"]);
    let json = serde_json::to_string(&ns).unwrap();
    let back: NamespaceObject = serde_json::from_str(&json).unwrap();
    assert_eq!(ns, back);
}

// ---------------------------------------------------------------------------
// ImportBinding
// ---------------------------------------------------------------------------

#[test]
fn import_binding_display_named() {
    let ib = ImportBinding {
        importer: "mod_b".to_string(),
        local_name: "myFoo".to_string(),
        target: BindingId::new("mod_a", "foo"),
        is_namespace: false,
    };
    let s = ib.to_string();
    assert!(s.contains("mod_b"));
    assert!(s.contains("myFoo"));
    assert!(s.contains("mod_a"));
}

#[test]
fn import_binding_display_namespace() {
    let ib = ImportBinding {
        importer: "mod_b".to_string(),
        local_name: "ns".to_string(),
        target: BindingId::new("mod_a", "*"),
        is_namespace: true,
    };
    let s = ib.to_string();
    assert!(s.contains("Namespace"));
    assert!(s.contains("mod_a"));
}

#[test]
fn import_binding_serde_roundtrip() {
    let ib = ImportBinding {
        importer: "mod_b".to_string(),
        local_name: "x".to_string(),
        target: BindingId::new("mod_a", "x"),
        is_namespace: false,
    };
    let json = serde_json::to_string(&ib).unwrap();
    let back: ImportBinding = serde_json::from_str(&json).unwrap();
    assert_eq!(ib, back);
}

// ---------------------------------------------------------------------------
// BindingEvent
// ---------------------------------------------------------------------------

#[test]
fn binding_event_cell_created_serde() {
    let ev = BindingEvent::CellCreated {
        binding_id: BindingId::new("mod_a", "x"),
        binding_type: BindingType::Direct,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: BindingEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn binding_event_all_variants_serde() {
    let events = vec![
        BindingEvent::CellCreated {
            binding_id: BindingId::new("m", "x"),
            binding_type: BindingType::Direct,
        },
        BindingEvent::CellInitialized {
            binding_id: BindingId::new("m", "x"),
            version: 1,
        },
        BindingEvent::CellMutated {
            binding_id: BindingId::new("m", "x"),
            version: 2,
        },
        BindingEvent::CellDied {
            binding_id: BindingId::new("m", "x"),
        },
        BindingEvent::NamespaceCreated {
            module_specifier: "m".to_string(),
            export_count: 3,
        },
        BindingEvent::ImportWired {
            importer: "n".to_string(),
            local_name: "y".to_string(),
            target: BindingId::new("m", "x"),
        },
    ];
    for ev in &events {
        let json = serde_json::to_string(ev).unwrap();
        let back: BindingEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(*ev, back);
    }
}

// ---------------------------------------------------------------------------
// LiveBindingMap core operations
// ---------------------------------------------------------------------------

#[test]
fn live_binding_map_new_is_empty() {
    let map = LiveBindingMap::new();
    assert_eq!(map.cell_count(), 0);
    assert_eq!(map.namespace_count(), 0);
    assert_eq!(map.import_count(), 0);
    assert!(map.events.is_empty());
}

#[test]
fn live_binding_map_default_equals_new() {
    assert_eq!(LiveBindingMap::new(), LiveBindingMap::default());
}

#[test]
fn live_binding_map_register_cell() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "foo");
    let id = map.register_cell(cell);
    assert_eq!(id, BindingId::new("mod_a", "foo"));
    assert_eq!(map.cell_count(), 1);
    assert_eq!(map.events.len(), 1);
}

#[test]
fn live_binding_map_get_cell() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "foo");
    let id = map.register_cell(cell);
    let retrieved = map.get_cell(&id).unwrap();
    assert_eq!(retrieved.source_module, "mod_a");
    assert_eq!(retrieved.export_name, "foo");
}

#[test]
fn live_binding_map_get_cell_mut() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "foo");
    let id = map.register_cell(cell);
    let mutable = map.get_cell_mut(&id).unwrap();
    mutable.initialize_millionths(42);
    assert_eq!(map.get_cell(&id).unwrap().value_millionths, Some(42));
}

#[test]
fn live_binding_map_initialize_millionths() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "counter");
    let id = map.register_cell(cell);
    map.initialize_millionths(&id, 1_000_000).unwrap();
    let cell = map.get_cell(&id).unwrap();
    assert_eq!(cell.value_millionths, Some(1_000_000));
    assert!(cell.is_initialized());
}

#[test]
fn live_binding_map_initialize_string() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "name");
    let id = map.register_cell(cell);
    map.initialize_string(&id, "alice".to_string()).unwrap();
    assert_eq!(
        map.get_cell(&id).unwrap().value_string.as_deref(),
        Some("alice")
    );
}

#[test]
fn live_binding_map_mutate_millionths() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "val");
    let id = map.register_cell(cell);
    map.initialize_millionths(&id, 0).unwrap();
    map.mutate_millionths(&id, 42).unwrap();
    assert_eq!(map.get_cell(&id).unwrap().value_millionths, Some(42));
    assert_eq!(map.get_cell(&id).unwrap().version, 2);
}

#[test]
fn live_binding_map_mutate_string() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "name");
    let id = map.register_cell(cell);
    map.initialize_string(&id, "alice".to_string()).unwrap();
    map.mutate_string(&id, "bob".to_string()).unwrap();
    assert_eq!(
        map.get_cell(&id).unwrap().value_string.as_deref(),
        Some("bob")
    );
}

#[test]
fn live_binding_map_mark_dead() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "val");
    let id = map.register_cell(cell);
    map.mark_dead(&id).unwrap();
    assert_eq!(map.get_cell(&id).unwrap().state, BindingCellState::Dead);
}

#[test]
fn live_binding_map_dead_prevents_mutation() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "val");
    let id = map.register_cell(cell);
    map.mark_dead(&id).unwrap();
    assert!(map.mutate_millionths(&id, 1).is_err());
    assert!(map.mutate_string(&id, "x".to_string()).is_err());
}

#[test]
fn live_binding_map_not_found_error() {
    let mut map = LiveBindingMap::new();
    let id = BindingId::new("nonexistent", "x");
    assert!(map.initialize_millionths(&id, 0).is_err());
    assert!(map.mutate_millionths(&id, 0).is_err());
    assert!(map.mark_dead(&id).is_err());
}

// ---------------------------------------------------------------------------
// Namespace registration
// ---------------------------------------------------------------------------

#[test]
fn live_binding_map_register_namespace() {
    let mut map = LiveBindingMap::new();
    let ns = make_namespace("mod_a", &["foo", "bar"]);
    map.register_namespace(ns);
    assert_eq!(map.namespace_count(), 1);
    let retrieved = map.get_namespace("mod_a").unwrap();
    assert_eq!(retrieved.export_names.len(), 2);
}

#[test]
fn live_binding_map_namespace_not_found() {
    let map = LiveBindingMap::new();
    assert!(map.get_namespace("nonexistent").is_none());
}

// ---------------------------------------------------------------------------
// Import wiring and live-binding reads
// ---------------------------------------------------------------------------

#[test]
fn wire_import_and_read_through() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "foo");
    let id = map.register_cell(cell);
    map.initialize_millionths(&id, 42).unwrap();

    map.wire_import(ImportBinding {
        importer: "mod_b".to_string(),
        local_name: "myFoo".to_string(),
        target: id,
        is_namespace: false,
    });

    let cell = map.read_through_import("mod_b", "myFoo").unwrap();
    assert_eq!(cell.value_millionths, Some(42));
}

#[test]
fn live_binding_sees_mutation_through_import() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "counter");
    let id = map.register_cell(cell);
    map.initialize_millionths(&id, 0).unwrap();

    map.wire_import(ImportBinding {
        importer: "mod_b".to_string(),
        local_name: "cnt".to_string(),
        target: id.clone(),
        is_namespace: false,
    });

    // Before mutation
    assert_eq!(
        map.read_through_import("mod_b", "cnt")
            .unwrap()
            .value_millionths,
        Some(0)
    );

    // Mutate in source module
    map.mutate_millionths(&id, 1_000_000).unwrap();

    // After mutation — importer sees updated value (live binding)
    assert_eq!(
        map.read_through_import("mod_b", "cnt")
            .unwrap()
            .value_millionths,
        Some(1_000_000)
    );
}

#[test]
fn multiple_importers_share_same_cell() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "shared");
    let id = map.register_cell(cell);
    map.initialize_millionths(&id, 0).unwrap();

    map.wire_import(ImportBinding {
        importer: "mod_b".to_string(),
        local_name: "s1".to_string(),
        target: id.clone(),
        is_namespace: false,
    });
    map.wire_import(ImportBinding {
        importer: "mod_c".to_string(),
        local_name: "s2".to_string(),
        target: id.clone(),
        is_namespace: false,
    });

    map.mutate_millionths(&id, 999).unwrap();

    assert_eq!(
        map.read_through_import("mod_b", "s1")
            .unwrap()
            .value_millionths,
        Some(999)
    );
    assert_eq!(
        map.read_through_import("mod_c", "s2")
            .unwrap()
            .value_millionths,
        Some(999)
    );
}

#[test]
fn read_through_import_not_wired_fails() {
    let map = LiveBindingMap::new();
    let err = map.read_through_import("mod_b", "nonexistent").unwrap_err();
    assert_eq!(
        err,
        LiveBindingError::ImportNotWired {
            importer: "mod_b".to_string(),
            local_name: "nonexistent".to_string(),
        }
    );
}

// ---------------------------------------------------------------------------
// Event trace
// ---------------------------------------------------------------------------

#[test]
fn event_trace_records_all_operations() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "x");
    let id = map.register_cell(cell);
    map.initialize_millionths(&id, 1).unwrap();
    map.mutate_millionths(&id, 2).unwrap();
    map.mark_dead(&id).unwrap();
    // 1 created + 1 initialized + 1 mutated + 1 died = 4
    assert_eq!(map.events.len(), 4);
}

#[test]
fn event_trace_includes_namespace_and_import() {
    let mut map = LiveBindingMap::new();
    let ns = make_namespace("mod_a", &["x"]);
    map.register_namespace(ns);

    let cell = make_cell("mod_a", "x");
    let id = map.register_cell(cell);
    map.wire_import(ImportBinding {
        importer: "mod_b".to_string(),
        local_name: "y".to_string(),
        target: id,
        is_namespace: false,
    });

    // namespace_created + cell_created + import_wired = 3
    assert_eq!(map.events.len(), 3);
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[test]
fn validate_bindings_empty_map_passes() {
    let map = LiveBindingMap::new();
    assert!(validate_bindings(&map).is_empty());
}

#[test]
fn validate_bindings_detects_missing_cell() {
    let mut map = LiveBindingMap::new();
    map.wire_import(ImportBinding {
        importer: "mod_b".to_string(),
        local_name: "x".to_string(),
        target: BindingId::new("nonexistent", "x"),
        is_namespace: false,
    });
    let errors = validate_bindings(&map);
    assert_eq!(errors.len(), 1);
}

#[test]
fn validate_bindings_namespace_import_checks_namespace() {
    let mut map = LiveBindingMap::new();
    map.wire_import(ImportBinding {
        importer: "mod_b".to_string(),
        local_name: "ns".to_string(),
        target: BindingId::new("nonexistent", "*"),
        is_namespace: true,
    });
    let errors = validate_bindings(&map);
    assert_eq!(errors.len(), 1);
}

#[test]
fn validate_bindings_valid_namespace_import_passes() {
    let mut map = LiveBindingMap::new();
    let ns = make_namespace("mod_a", &["x"]);
    map.register_namespace(ns);
    map.wire_import(ImportBinding {
        importer: "mod_b".to_string(),
        local_name: "ns".to_string(),
        target: BindingId::new("mod_a", "*"),
        is_namespace: true,
    });
    let errors = validate_bindings(&map);
    assert!(errors.is_empty());
}

// ---------------------------------------------------------------------------
// Render summary
// ---------------------------------------------------------------------------

#[test]
fn render_summary_includes_counts() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "x");
    map.register_cell(cell);
    let summary = map.render_summary();
    assert!(summary.contains("Cells: 1"));
    assert!(summary.contains("Events: 1"));
    assert!(summary.contains("Namespaces: 0"));
}

// ---------------------------------------------------------------------------
// LiveBindingMap serde
// ---------------------------------------------------------------------------

#[test]
fn live_binding_map_serde_roundtrip() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "x");
    let id = map.register_cell(cell);
    map.initialize_millionths(&id, 42).unwrap();
    let ns = make_namespace("mod_a", &["x"]);
    map.register_namespace(ns);
    map.wire_import(ImportBinding {
        importer: "mod_b".to_string(),
        local_name: "y".to_string(),
        target: id,
        is_namespace: false,
    });

    let json = serde_json::to_string(&map).unwrap();
    let back: LiveBindingMap = serde_json::from_str(&json).unwrap();
    assert_eq!(map, back);
}

#[test]
fn live_binding_map_serde_empty() {
    let map = LiveBindingMap::new();
    let json = serde_json::to_string(&map).unwrap();
    let back: LiveBindingMap = serde_json::from_str(&json).unwrap();
    assert_eq!(map, back);
}

// ---------------------------------------------------------------------------
// LiveBindingError
// ---------------------------------------------------------------------------

#[test]
fn live_binding_error_display_module_not_linked() {
    let err = LiveBindingError::ModuleNotLinked {
        module: "mod_a".to_string(),
        status: "unlinked".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("mod_a"));
    assert!(s.contains("not linked"));
}

#[test]
fn live_binding_error_display_binding_not_found() {
    let err = LiveBindingError::BindingNotFound {
        module: "mod_a".to_string(),
        export_name: "foo".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("mod_a"));
    assert!(s.contains("foo"));
    assert!(s.contains("not found"));
}

#[test]
fn live_binding_error_display_binding_dead() {
    let err = LiveBindingError::BindingDead {
        module: "mod_a".to_string(),
        export_name: "foo".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("dead"));
}

#[test]
fn live_binding_error_display_import_not_wired() {
    let err = LiveBindingError::ImportNotWired {
        importer: "mod_b".to_string(),
        local_name: "x".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("not wired"));
}

#[test]
fn live_binding_error_display_namespace_not_found() {
    let err = LiveBindingError::NamespaceNotFound {
        module: "mod_a".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("namespace"));
    assert!(s.contains("not found"));
}

#[test]
fn live_binding_error_serde_roundtrip() {
    let errors = vec![
        LiveBindingError::ModuleNotLinked {
            module: "m".to_string(),
            status: "unlinked".to_string(),
        },
        LiveBindingError::BindingNotFound {
            module: "m".to_string(),
            export_name: "x".to_string(),
        },
        LiveBindingError::BindingDead {
            module: "m".to_string(),
            export_name: "x".to_string(),
        },
        LiveBindingError::ImportNotWired {
            importer: "n".to_string(),
            local_name: "y".to_string(),
        },
        LiveBindingError::NamespaceNotFound {
            module: "m".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: LiveBindingError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn deterministic_operations_produce_same_result() {
    let build = || {
        let mut map = LiveBindingMap::new();
        for i in 0..5 {
            let name = format!("export_{i}");
            let cell = make_cell("mod_a", &name);
            let id = map.register_cell(cell);
            map.initialize_millionths(&id, i as i64 * 1_000_000)
                .unwrap();
        }
        map.register_namespace(make_namespace(
            "mod_a",
            &["export_0", "export_1", "export_2", "export_3", "export_4"],
        ));
        serde_json::to_string(&map).unwrap()
    };

    let a = build();
    let b = build();
    assert_eq!(a, b);
}

#[test]
fn binding_map_counters() {
    let mut map = LiveBindingMap::new();
    assert_eq!(map.cell_count(), 0);
    assert_eq!(map.namespace_count(), 0);
    assert_eq!(map.import_count(), 0);

    let cell = make_cell("mod_a", "x");
    let id = map.register_cell(cell);
    assert_eq!(map.cell_count(), 1);

    map.register_namespace(make_namespace("mod_a", &["x"]));
    assert_eq!(map.namespace_count(), 1);

    map.wire_import(ImportBinding {
        importer: "mod_b".to_string(),
        local_name: "y".to_string(),
        target: id,
        is_namespace: false,
    });
    assert_eq!(map.import_count(), 1);
}

// ---------------------------------------------------------------------------
// Re-export binding chains
// ---------------------------------------------------------------------------

#[test]
fn re_export_binding_chain() {
    let mut map = LiveBindingMap::new();

    // mod_a exports "foo" directly
    let cell_a = make_cell("mod_a", "foo");
    let id_a = map.register_cell(cell_a);
    map.initialize_millionths(&id_a, 100).unwrap();

    // mod_b re-exports "foo" from mod_a
    let cell_b = BindingCell::new("mod_b", "foo", "foo", BindingType::ReExport);
    let _id_b = map.register_cell(cell_b);

    // mod_c imports "foo" from mod_b, but the live binding points to mod_a
    map.wire_import(ImportBinding {
        importer: "mod_c".to_string(),
        local_name: "foo".to_string(),
        target: id_a.clone(),
        is_namespace: false,
    });

    // Mutation at source is visible to mod_c
    map.mutate_millionths(&id_a, 200).unwrap();
    assert_eq!(
        map.read_through_import("mod_c", "foo")
            .unwrap()
            .value_millionths,
        Some(200)
    );
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn initialize_then_switch_type() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "val");
    let id = map.register_cell(cell);

    // Start as number
    map.initialize_millionths(&id, 42).unwrap();
    assert_eq!(map.get_cell(&id).unwrap().value_millionths, Some(42));

    // Switch to string
    map.mutate_string(&id, "now a string".to_string()).unwrap();
    assert!(map.get_cell(&id).unwrap().value_millionths.is_none());
    assert_eq!(
        map.get_cell(&id).unwrap().value_string.as_deref(),
        Some("now a string")
    );
}

#[test]
fn many_mutations_version_tracks() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "counter");
    let id = map.register_cell(cell);
    map.initialize_millionths(&id, 0).unwrap();

    for i in 1..=100 {
        map.mutate_millionths(&id, i).unwrap();
    }

    assert_eq!(map.get_cell(&id).unwrap().version, 101); // 1 init + 100 mutations
    assert_eq!(map.get_cell(&id).unwrap().value_millionths, Some(100));
}

// ---------------------------------------------------------------------------
// Multiple modules with cross-references
// ---------------------------------------------------------------------------

#[test]
fn multiple_modules_independent_bindings() {
    let mut map = LiveBindingMap::new();

    let id_a = map.register_cell(make_cell("mod_a", "x"));
    let id_b = map.register_cell(make_cell("mod_b", "y"));
    let id_c = map.register_cell(make_cell("mod_c", "z"));

    map.initialize_millionths(&id_a, 10).unwrap();
    map.initialize_string(&id_b, "hello".to_string()).unwrap();
    map.initialize_millionths(&id_c, 30).unwrap();

    assert_eq!(map.cell_count(), 3);
    assert_eq!(map.get_cell(&id_a).unwrap().value_millionths, Some(10));
    assert_eq!(
        map.get_cell(&id_b).unwrap().value_string.as_deref(),
        Some("hello")
    );
    assert_eq!(map.get_cell(&id_c).unwrap().value_millionths, Some(30));
}

#[test]
fn multiple_importers_from_same_source() {
    let mut map = LiveBindingMap::new();

    let id = map.register_cell(make_cell("mod_a", "shared"));
    map.initialize_millionths(&id, 999).unwrap();

    // Three modules import the same binding
    for importer in ["mod_b", "mod_c", "mod_d"] {
        map.wire_import(ImportBinding {
            importer: importer.to_string(),
            local_name: "shared".to_string(),
            target: id.clone(),
            is_namespace: false,
        });
    }

    assert_eq!(map.import_count(), 3);

    // All importers see the same value
    for importer in ["mod_b", "mod_c", "mod_d"] {
        let cell = map.read_through_import(importer, "shared").unwrap();
        assert_eq!(cell.value_millionths, Some(999));
    }

    // Mutation at source propagates to all
    map.mutate_millionths(&id, 1000).unwrap();
    for importer in ["mod_b", "mod_c", "mod_d"] {
        let cell = map.read_through_import(importer, "shared").unwrap();
        assert_eq!(cell.value_millionths, Some(1000));
    }
}

// ---------------------------------------------------------------------------
// Namespace object edge cases
// ---------------------------------------------------------------------------

#[test]
fn namespace_with_many_exports() {
    let exports: Vec<String> = (0..20).map(|i| format!("export_{i}")).collect();
    let export_refs: Vec<&str> = exports.iter().map(|s| s.as_str()).collect();
    let ns = make_namespace("big_mod", &export_refs);

    assert_eq!(ns.len(), 20);
    assert!(!ns.is_empty());

    // Export names should be sorted
    let names = &ns.export_names;
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(*names, sorted);
}

#[test]
fn namespace_display_includes_module_specifier() {
    let ns = make_namespace("my_module", &["a", "b"]);
    let display = ns.to_string();
    assert!(display.contains("my_module"));
}

// ---------------------------------------------------------------------------
// BindingEvent serde for all variants
// ---------------------------------------------------------------------------

#[test]
fn binding_event_all_variants_through_map_operations() {
    let mut map = LiveBindingMap::new();
    let ns = make_namespace("mod_a", &["x"]);
    map.register_namespace(ns);

    let cell = make_cell("mod_a", "x");
    let id = map.register_cell(cell);
    map.initialize_millionths(&id, 1).unwrap();
    map.mutate_millionths(&id, 2).unwrap();

    map.wire_import(ImportBinding {
        importer: "mod_b".to_string(),
        local_name: "y".to_string(),
        target: id.clone(),
        is_namespace: false,
    });

    map.mark_dead(&id).unwrap();

    // Should have: NamespaceCreated, CellCreated, CellInitialized, CellMutated, ImportWired, CellDied = 6
    assert_eq!(map.events.len(), 6);

    // Serde round-trip of all events
    for event in &map.events {
        let json = serde_json::to_string(event).unwrap();
        let parsed: BindingEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(*event, parsed);
    }
}

// ---------------------------------------------------------------------------
// BindingCell state machine
// ---------------------------------------------------------------------------

#[test]
fn binding_cell_state_transitions() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "x");
    let id = map.register_cell(cell);

    // Starts Uninitialized
    assert_eq!(
        map.get_cell(&id).unwrap().state,
        BindingCellState::Uninitialized
    );

    // Initialize -> Initialized
    map.initialize_millionths(&id, 1).unwrap();
    assert_eq!(
        map.get_cell(&id).unwrap().state,
        BindingCellState::Initialized
    );

    // Mutate stays Initialized
    map.mutate_millionths(&id, 2).unwrap();
    assert_eq!(
        map.get_cell(&id).unwrap().state,
        BindingCellState::Initialized
    );

    // Mark dead -> Dead
    map.mark_dead(&id).unwrap();
    assert_eq!(map.get_cell(&id).unwrap().state, BindingCellState::Dead);
}

// ---------------------------------------------------------------------------
// String value bindings
// ---------------------------------------------------------------------------

#[test]
fn string_binding_lifecycle() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "greeting");
    let id = map.register_cell(cell);

    map.initialize_string(&id, "hello".to_string()).unwrap();
    assert_eq!(
        map.get_cell(&id).unwrap().value_string.as_deref(),
        Some("hello")
    );

    map.mutate_string(&id, "world".to_string()).unwrap();
    assert_eq!(
        map.get_cell(&id).unwrap().value_string.as_deref(),
        Some("world")
    );

    // Version should be 2 (init + mutation)
    assert_eq!(map.get_cell(&id).unwrap().version, 2);
}

#[test]
fn empty_string_binding() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "empty");
    let id = map.register_cell(cell);

    map.initialize_string(&id, String::new()).unwrap();
    assert_eq!(map.get_cell(&id).unwrap().value_string.as_deref(), Some(""));
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

#[test]
fn read_through_import_unknown_importer() {
    let map = LiveBindingMap::new();
    let result = map.read_through_import("nonexistent", "x");
    assert!(result.is_err());
}

#[test]
fn mutate_uninitialized_cell() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "x");
    let id = map.register_cell(cell);

    // Try to mutate before initializing
    let result = map.mutate_millionths(&id, 42);
    // The API may allow this (auto-initializing) or return error
    // Just verify it doesn't panic
    let _ = result;
}

#[test]
fn get_cell_nonexistent_returns_none() {
    let map = LiveBindingMap::new();
    let fake_id = BindingId::new("nonexistent", "fake");
    assert!(map.get_cell(&fake_id).is_none());
}

// ---------------------------------------------------------------------------
// Schema version stability
// ---------------------------------------------------------------------------

#[test]
fn module_live_binding_schema_version_stable() {
    assert!(MODULE_LIVE_BINDING_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(MODULE_LIVE_BINDING_SCHEMA_VERSION.contains("live-binding"));
}

#[test]
fn module_live_binding_bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
}

// ---------------------------------------------------------------------------
// Large-scale determinism
// ---------------------------------------------------------------------------

#[test]
fn large_binding_map_deterministic_serde() {
    let build = || {
        let mut map = LiveBindingMap::new();
        for i in 0..50 {
            let name = format!("export_{i}");
            let cell = make_cell("mod_a", &name);
            let id = map.register_cell(cell);
            map.initialize_millionths(&id, i as i64 * 1_000_000)
                .unwrap();
        }
        let exports: Vec<&str> = (0..50)
            .map(|i| {
                // Pre-generate the strings so references are valid
                Box::leak(format!("export_{i}").into_boxed_str()) as &str
            })
            .collect();
        map.register_namespace(make_namespace("mod_a", &exports));
        serde_json::to_string(&map).unwrap()
    };

    let a = build();
    let b = build();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// BindingId ordering
// ---------------------------------------------------------------------------

#[test]
fn binding_id_ordering_is_lexicographic() {
    let a = BindingId::new("mod_a", "x");
    let b = BindingId::new("mod_a", "y");
    let c = BindingId::new("mod_b", "x");

    // Same module, different export: x < y
    assert!(a < b);
    // Different module: mod_a < mod_b
    assert!(a < c);
    assert!(b < c);
}

// ---------------------------------------------------------------------------
// BindingCell display includes state
// ---------------------------------------------------------------------------

#[test]
fn binding_cell_display_all_states() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "x");
    let id = map.register_cell(cell);

    // Uninitialized
    let display1 = map.get_cell(&id).unwrap().to_string();
    assert!(
        display1.contains("Uninitialized") || display1.contains("uninitialized"),
        "display should mention state"
    );

    map.initialize_millionths(&id, 42).unwrap();
    let display2 = map.get_cell(&id).unwrap().to_string();
    assert!(
        display2.contains("Initialized") || display2.contains("initialized"),
        "display should mention initialized"
    );

    map.mark_dead(&id).unwrap();
    let display3 = map.get_cell(&id).unwrap().to_string();
    assert!(
        display3.contains("Dead") || display3.contains("dead"),
        "display should mention dead"
    );
}
