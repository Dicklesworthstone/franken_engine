#![allow(clippy::too_many_arguments)]

//! Enrichment integration tests for `module_live_binding`.

use std::collections::BTreeMap;

use frankenengine_engine::esm_loader::BindingType;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_live_binding::*;

fn make_cell(module: &str, export: &str) -> BindingCell {
    BindingCell::new(module, export, export, BindingType::Direct)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_non_empty() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(!MODULE_LIVE_BINDING_SCHEMA_VERSION.is_empty());
    assert!(!NAMESPACE_OBJECT_SCHEMA_VERSION.is_empty());
}

// ---------------------------------------------------------------------------
// BindingCellState
// ---------------------------------------------------------------------------

#[test]
fn binding_cell_state_serde_roundtrip() {
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
fn binding_cell_state_display() {
    assert_eq!(BindingCellState::Uninitialized.to_string(), "uninitialized");
    assert_eq!(BindingCellState::Initialized.to_string(), "initialized");
    assert_eq!(BindingCellState::Dead.to_string(), "dead");
}

#[test]
fn binding_cell_state_ordering() {
    assert!(BindingCellState::Uninitialized < BindingCellState::Initialized);
    assert!(BindingCellState::Initialized < BindingCellState::Dead);
}

// ---------------------------------------------------------------------------
// BindingCell
// ---------------------------------------------------------------------------

#[test]
fn binding_cell_initial_state() {
    let cell = make_cell("mod_a", "foo");
    assert_eq!(cell.state, BindingCellState::Uninitialized);
    assert!(!cell.is_initialized());
    assert_eq!(cell.version, 0);
    assert!(cell.value_millionths.is_none());
    assert!(cell.value_string.is_none());
}

#[test]
fn binding_cell_initialize_millionths() {
    let mut cell = make_cell("mod_a", "counter");
    cell.initialize_millionths(1_000_000);
    assert_eq!(cell.state, BindingCellState::Initialized);
    assert!(cell.is_initialized());
    assert_eq!(cell.value_millionths, Some(1_000_000));
    assert_eq!(cell.version, 1);
}

#[test]
fn binding_cell_initialize_string() {
    let mut cell = make_cell("mod_a", "name");
    cell.initialize_string("hello".to_string());
    assert_eq!(cell.state, BindingCellState::Initialized);
    assert_eq!(cell.value_string.as_deref(), Some("hello"));
    assert!(cell.value_millionths.is_none());
    assert_eq!(cell.version, 1);
}

#[test]
fn binding_cell_mutate_increments_version() {
    let mut cell = make_cell("mod_a", "x");
    cell.initialize_millionths(0);
    assert_eq!(cell.version, 1);
    cell.mutate_millionths(42).unwrap();
    assert_eq!(cell.version, 2);
    assert_eq!(cell.value_millionths, Some(42));
}

#[test]
fn binding_cell_mutate_string_increments_version() {
    let mut cell = make_cell("mod_a", "greeting");
    cell.initialize_string("hello".into());
    cell.mutate_string("world".into()).unwrap();
    assert_eq!(cell.version, 2);
    assert_eq!(cell.value_string.as_deref(), Some("world"));
}

#[test]
fn binding_cell_mutate_dead_fails() {
    let mut cell = make_cell("mod_a", "x");
    cell.mark_dead();
    let err = cell.mutate_millionths(1).unwrap_err();
    assert!(matches!(err, LiveBindingError::BindingDead { .. }));
}

#[test]
fn binding_cell_mutate_string_dead_fails() {
    let mut cell = make_cell("mod_a", "x");
    cell.mark_dead();
    let err = cell.mutate_string("val".into()).unwrap_err();
    assert!(matches!(err, LiveBindingError::BindingDead { .. }));
}

#[test]
fn binding_cell_display() {
    let mut cell = make_cell("mod_a", "foo");
    cell.initialize_millionths(42);
    let s = cell.to_string();
    assert!(s.contains("mod_a"));
    assert!(s.contains("foo"));
    assert!(s.contains("v1"));
}

#[test]
fn binding_cell_serde_roundtrip() {
    let mut cell = make_cell("mod_a", "foo");
    cell.initialize_millionths(42);
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
fn binding_id_ordering() {
    let a = BindingId::new("a", "x");
    let b = BindingId::new("b", "x");
    let c = BindingId::new("a", "y");
    assert!(a < b);
    assert!(a < c);
}

#[test]
fn binding_id_serde_roundtrip() {
    let id = BindingId::new("mod_a", "foo");
    let json = serde_json::to_string(&id).unwrap();
    let back: BindingId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

// ---------------------------------------------------------------------------
// NamespaceObject
// ---------------------------------------------------------------------------

#[test]
fn namespace_accessors() {
    let ns = NamespaceObject {
        schema_version: NAMESPACE_OBJECT_SCHEMA_VERSION.to_string(),
        module_specifier: "mod_a".to_string(),
        export_names: vec!["bar".to_string(), "foo".to_string()],
        bindings: {
            let mut m = BTreeMap::new();
            m.insert("foo".to_string(), BindingId::new("mod_a", "foo"));
            m.insert("bar".to_string(), BindingId::new("mod_a", "bar"));
            m
        },
        source_hash: ContentHash::compute(b"source"),
    };
    assert_eq!(ns.len(), 2);
    assert!(!ns.is_empty());
    assert!(ns.has_export("foo"));
    assert!(!ns.has_export("baz"));
    assert_eq!(ns.get_binding("foo"), Some(&BindingId::new("mod_a", "foo")));
}

#[test]
fn namespace_empty() {
    let ns = NamespaceObject {
        schema_version: "v1".into(),
        module_specifier: "mod_empty".into(),
        export_names: vec![],
        bindings: BTreeMap::new(),
        source_hash: ContentHash::compute(b"empty"),
    };
    assert!(ns.is_empty());
    assert_eq!(ns.len(), 0);
}

#[test]
fn namespace_display() {
    let ns = NamespaceObject {
        schema_version: "v1".into(),
        module_specifier: "mod_a".into(),
        export_names: vec!["foo".into()],
        bindings: BTreeMap::new(),
        source_hash: ContentHash::compute(b"x"),
    };
    let s = ns.to_string();
    assert!(s.contains("mod_a"));
    assert!(s.contains("1 exports"));
}

#[test]
fn namespace_serde_roundtrip() {
    let ns = NamespaceObject {
        schema_version: NAMESPACE_OBJECT_SCHEMA_VERSION.to_string(),
        module_specifier: "mod_a".to_string(),
        export_names: vec!["foo".to_string()],
        bindings: {
            let mut m = BTreeMap::new();
            m.insert("foo".to_string(), BindingId::new("mod_a", "foo"));
            m
        },
        source_hash: ContentHash::compute(b"source"),
    };
    let json = serde_json::to_string(&ns).unwrap();
    let back: NamespaceObject = serde_json::from_str(&json).unwrap();
    assert_eq!(ns, back);
}

// ---------------------------------------------------------------------------
// ImportBinding
// ---------------------------------------------------------------------------

#[test]
fn import_binding_display_normal() {
    let ib = ImportBinding {
        importer: "mod_b".into(),
        local_name: "myFoo".into(),
        target: BindingId::new("mod_a", "foo"),
        is_namespace: false,
    };
    let s = ib.to_string();
    assert!(s.contains("mod_b"));
    assert!(s.contains("myFoo"));
}

#[test]
fn import_binding_display_namespace() {
    let ib = ImportBinding {
        importer: "mod_b".into(),
        local_name: "ns".into(),
        target: BindingId::new("mod_a", "*"),
        is_namespace: true,
    };
    let s = ib.to_string();
    assert!(s.contains("Namespace"));
}

#[test]
fn import_binding_serde_roundtrip() {
    let ib = ImportBinding {
        importer: "mod_b".into(),
        local_name: "x".into(),
        target: BindingId::new("mod_a", "x"),
        is_namespace: false,
    };
    let json = serde_json::to_string(&ib).unwrap();
    let back: ImportBinding = serde_json::from_str(&json).unwrap();
    assert_eq!(ib, back);
}

// ---------------------------------------------------------------------------
// LiveBindingMap
// ---------------------------------------------------------------------------

#[test]
fn live_binding_map_register_and_read() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "foo");
    let id = map.register_cell(cell);
    assert_eq!(id, BindingId::new("mod_a", "foo"));
    let retrieved = map.get_cell(&id).unwrap();
    assert_eq!(retrieved.source_module, "mod_a");
}

#[test]
fn live_binding_map_initialize_and_mutate() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "counter");
    let id = map.register_cell(cell);
    map.initialize_millionths(&id, 0).unwrap();
    assert_eq!(map.get_cell(&id).unwrap().value_millionths, Some(0));
    map.mutate_millionths(&id, 1_000_000).unwrap();
    assert_eq!(map.get_cell(&id).unwrap().value_millionths, Some(1_000_000));
    assert_eq!(map.get_cell(&id).unwrap().version, 2);
}

#[test]
fn live_binding_map_mark_dead_prevents_mutation() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "val");
    let id = map.register_cell(cell);
    map.mark_dead(&id).unwrap();
    assert!(map.mutate_millionths(&id, 1).is_err());
}

#[test]
fn live_binding_map_not_found() {
    let map = LiveBindingMap::new();
    let id = BindingId::new("nonexistent", "x");
    assert!(map.get_cell(&id).is_none());
}

#[test]
fn live_binding_map_initialize_not_found() {
    let mut map = LiveBindingMap::new();
    let id = BindingId::new("nonexistent", "x");
    let err = map.initialize_millionths(&id, 0).unwrap_err();
    assert!(matches!(err, LiveBindingError::BindingNotFound { .. }));
}

#[test]
fn live_binding_map_string_operations() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "name");
    let id = map.register_cell(cell);
    map.initialize_string(&id, "alice".into()).unwrap();
    assert_eq!(map.get_cell(&id).unwrap().value_string.as_deref(), Some("alice"));
    map.mutate_string(&id, "bob".into()).unwrap();
    assert_eq!(map.get_cell(&id).unwrap().value_string.as_deref(), Some("bob"));
}

#[test]
fn live_binding_map_counters() {
    let mut map = LiveBindingMap::new();
    assert_eq!(map.cell_count(), 0);
    assert_eq!(map.namespace_count(), 0);
    assert_eq!(map.import_count(), 0);

    map.register_cell(make_cell("mod_a", "x"));
    assert_eq!(map.cell_count(), 1);
}

#[test]
fn live_binding_map_default_is_empty() {
    let map = LiveBindingMap::default();
    assert_eq!(map.cell_count(), 0);
    assert_eq!(map.namespace_count(), 0);
    assert_eq!(map.import_count(), 0);
}

// ---------------------------------------------------------------------------
// Import wiring and read-through
// ---------------------------------------------------------------------------

#[test]
fn import_wire_and_read_through() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "foo");
    let id = map.register_cell(cell);
    map.initialize_millionths(&id, 42).unwrap();

    let import = ImportBinding {
        importer: "mod_b".into(),
        local_name: "myFoo".into(),
        target: id.clone(),
        is_namespace: false,
    };
    map.wire_import(import);

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
        importer: "mod_b".into(),
        local_name: "cnt".into(),
        target: id.clone(),
        is_namespace: false,
    });

    assert_eq!(
        map.read_through_import("mod_b", "cnt").unwrap().value_millionths,
        Some(0)
    );

    map.mutate_millionths(&id, 1_000_000).unwrap();

    assert_eq!(
        map.read_through_import("mod_b", "cnt").unwrap().value_millionths,
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
        importer: "mod_b".into(),
        local_name: "s1".into(),
        target: id.clone(),
        is_namespace: false,
    });
    map.wire_import(ImportBinding {
        importer: "mod_c".into(),
        local_name: "s2".into(),
        target: id.clone(),
        is_namespace: false,
    });

    map.mutate_millionths(&id, 999).unwrap();

    assert_eq!(
        map.read_through_import("mod_b", "s1").unwrap().value_millionths,
        Some(999)
    );
    assert_eq!(
        map.read_through_import("mod_c", "s2").unwrap().value_millionths,
        Some(999)
    );
}

#[test]
fn read_through_import_not_wired() {
    let map = LiveBindingMap::new();
    let err = map.read_through_import("nonexistent", "local_x").unwrap_err();
    assert!(matches!(err, LiveBindingError::ImportNotWired { .. }));
}

// ---------------------------------------------------------------------------
// Event trace
// ---------------------------------------------------------------------------

#[test]
fn event_trace_records_operations() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "x");
    let id = map.register_cell(cell);
    map.initialize_millionths(&id, 1).unwrap();
    map.mutate_millionths(&id, 2).unwrap();
    map.mark_dead(&id).unwrap();
    // CellCreated + CellInitialized + CellMutated + CellDied = 4
    assert_eq!(map.events.len(), 4);
}

#[test]
fn event_trace_has_died_event() {
    let mut map = LiveBindingMap::new();
    let id = BindingId::new("mod_a", "x");
    let cell = BindingCell::new("mod_a", "x", "x", BindingType::Direct);
    map.register_cell(cell);
    map.mark_dead(&id).unwrap();
    assert!(map.events.iter().any(|e| matches!(e, BindingEvent::CellDied { .. })));
}

// ---------------------------------------------------------------------------
// validate_bindings
// ---------------------------------------------------------------------------

#[test]
fn validate_bindings_empty_passes() {
    let map = LiveBindingMap::new();
    assert!(validate_bindings(&map).is_empty());
}

#[test]
fn validate_bindings_detects_missing_cell() {
    let mut map = LiveBindingMap::new();
    map.wire_import(ImportBinding {
        importer: "mod_b".into(),
        local_name: "x".into(),
        target: BindingId::new("nonexistent", "x"),
        is_namespace: false,
    });
    let errors = validate_bindings(&map);
    assert_eq!(errors.len(), 1);
}

#[test]
fn validate_bindings_detects_multiple_missing() {
    let mut map = LiveBindingMap::new();
    map.wire_import(ImportBinding {
        importer: "mod_a".into(),
        local_name: "x".into(),
        target: BindingId::new("nonexistent", "a"),
        is_namespace: false,
    });
    map.wire_import(ImportBinding {
        importer: "mod_b".into(),
        local_name: "y".into(),
        target: BindingId::new("nonexistent", "b"),
        is_namespace: false,
    });
    let errors = validate_bindings(&map);
    assert!(errors.len() >= 2);
}

// ---------------------------------------------------------------------------
// render_summary
// ---------------------------------------------------------------------------

#[test]
fn render_summary_includes_counts() {
    let mut map = LiveBindingMap::new();
    map.register_cell(make_cell("mod_a", "x"));
    let summary = map.render_summary();
    assert!(summary.contains("Cells: 1"));
}

#[test]
fn render_summary_empty() {
    let map = LiveBindingMap::new();
    let summary = map.render_summary();
    assert!(summary.contains("Cells: 0"));
}

// ---------------------------------------------------------------------------
// LiveBindingMap serde
// ---------------------------------------------------------------------------

#[test]
fn live_binding_map_serde_roundtrip() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "x");
    map.register_cell(cell);
    let json = serde_json::to_string(&map).unwrap();
    let back: LiveBindingMap = serde_json::from_str(&json).unwrap();
    assert_eq!(map, back);
}

#[test]
fn live_binding_map_serde_with_namespace() {
    let mut map = LiveBindingMap::new();
    let cell = make_cell("mod_a", "x");
    map.register_cell(cell);

    let ns = NamespaceObject {
        schema_version: NAMESPACE_OBJECT_SCHEMA_VERSION.to_string(),
        module_specifier: "mod_a".to_string(),
        export_names: vec!["x".to_string()],
        bindings: {
            let mut m = BTreeMap::new();
            m.insert("x".to_string(), BindingId::new("mod_a", "x"));
            m
        },
        source_hash: ContentHash::compute(b"source"),
    };
    map.register_namespace(ns);

    let json = serde_json::to_string(&map).unwrap();
    let back: LiveBindingMap = serde_json::from_str(&json).unwrap();
    assert_eq!(map, back);
}

// ---------------------------------------------------------------------------
// BindingEvent serde
// ---------------------------------------------------------------------------

#[test]
fn binding_event_all_variants_serde() {
    let events = [
        BindingEvent::CellCreated {
            binding_id: BindingId::new("m", "e"),
            binding_type: BindingType::Direct,
        },
        BindingEvent::CellInitialized {
            binding_id: BindingId::new("m", "e"),
            version: 1,
        },
        BindingEvent::CellMutated {
            binding_id: BindingId::new("m", "e"),
            version: 2,
        },
        BindingEvent::CellDied {
            binding_id: BindingId::new("m", "e"),
        },
        BindingEvent::NamespaceCreated {
            module_specifier: "m".into(),
            export_count: 5,
        },
        BindingEvent::ImportWired {
            importer: "mod_b".into(),
            local_name: "x".into(),
            target: BindingId::new("m", "e"),
        },
    ];
    for event in &events {
        let json = serde_json::to_string(event).unwrap();
        let back: BindingEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(*event, back);
    }
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

#[test]
fn live_binding_error_all_variants_display() {
    let errors: Vec<LiveBindingError> = vec![
        LiveBindingError::ModuleNotLinked {
            module: "mod_a".into(),
            status: "unlinked".into(),
        },
        LiveBindingError::BindingNotFound {
            module: "mod_a".into(),
            export_name: "x".into(),
        },
        LiveBindingError::BindingDead {
            module: "mod_a".into(),
            export_name: "x".into(),
        },
        LiveBindingError::ImportNotWired {
            importer: "mod_b".into(),
            local_name: "y".into(),
        },
        LiveBindingError::NamespaceNotFound {
            module: "mod_c".into(),
        },
    ];
    for err in &errors {
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn live_binding_error_serde_roundtrip() {
    let err = LiveBindingError::BindingNotFound {
        module: "mod_a".into(),
        export_name: "x".into(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: LiveBindingError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ---------------------------------------------------------------------------
// Namespace registration
// ---------------------------------------------------------------------------

#[test]
fn namespace_registration_and_lookup() {
    let mut map = LiveBindingMap::new();
    let ns = NamespaceObject {
        schema_version: NAMESPACE_OBJECT_SCHEMA_VERSION.to_string(),
        module_specifier: "mod_a".to_string(),
        export_names: vec!["foo".to_string()],
        bindings: BTreeMap::new(),
        source_hash: ContentHash::compute(b"src"),
    };
    map.register_namespace(ns);
    assert_eq!(map.namespace_count(), 1);
    assert!(map.get_namespace("mod_a").is_some());
    assert!(map.get_namespace("mod_b").is_none());
}

// ---------------------------------------------------------------------------
// Validate bindings with namespace imports
// ---------------------------------------------------------------------------

#[test]
fn validate_bindings_namespace_missing() {
    let mut map = LiveBindingMap::new();
    map.wire_import(ImportBinding {
        importer: "mod_b".into(),
        local_name: "ns".into(),
        target: BindingId::new("nonexistent", "*"),
        is_namespace: true,
    });
    let errors = validate_bindings(&map);
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| matches!(e, LiveBindingError::NamespaceNotFound { .. })));
}
