#![forbid(unsafe_code)]

//! Enrichment integration tests for the `esm_loader` module.
//!
//! Covers: Clone independence, Debug/Display uniqueness, serde roundtrips,
//! JSON field-name stability, BTreeSet/BTreeMap determinism, Copy semantics,
//! graph analysis invariants, cycle detection, topological ordering,
//! and N-run determinism proofs.

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

use frankenengine_engine::esm_loader::*;
use frankenengine_engine::module_resolver::ModuleSyntax;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_module(spec: &str, source: &str) -> EsmModule {
    EsmModule::new(spec, source, ModuleSyntax::EsModule)
}

fn linear_graph() -> ModuleGraph {
    let mut graph = ModuleGraph::new();
    let mut entry = make_module("./entry.js", "import { foo } from './a.js';");
    entry.add_import(ImportEntry::new("./a.js", "foo", "foo"));
    entry.add_export(ExportEntry::direct("main", "main"));
    graph.add_module(entry).unwrap();

    let mut a = make_module("./a.js", "export const foo = 42;");
    a.add_export(ExportEntry::direct("foo", "foo"));
    graph.add_module(a).unwrap();

    graph
}

fn cyclic_graph() -> ModuleGraph {
    let mut graph = ModuleGraph::new();
    let mut a = make_module("./a.js", "import { b } from './b.js';");
    a.add_import(ImportEntry::new("./b.js", "b", "b"));
    a.add_export(ExportEntry::direct("a", "a"));
    graph.add_module(a).unwrap();

    let mut b = make_module("./b.js", "import { a } from './a.js';");
    b.add_import(ImportEntry::new("./a.js", "a", "a"));
    b.add_export(ExportEntry::direct("b", "b"));
    graph.add_module(b).unwrap();

    graph
}

// ===========================================================================
// 1. ModuleStatus — Copy, Display uniqueness, serde, Debug
// ===========================================================================

#[test]
fn enrichment_module_status_copy_semantics() {
    let a = ModuleStatus::Unlinked;
    let b = a;
    let c = a;
    assert_eq!(b, c);
    assert_eq!(a, ModuleStatus::Unlinked);
}

#[test]
fn enrichment_module_status_display_all_unique() {
    let variants = [
        ModuleStatus::Unlinked,
        ModuleStatus::Linking,
        ModuleStatus::Linked,
        ModuleStatus::Evaluating,
        ModuleStatus::Evaluated,
        ModuleStatus::EvaluationError,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), variants.len());
}

#[test]
fn enrichment_module_status_debug_all_unique() {
    let variants = [
        ModuleStatus::Unlinked,
        ModuleStatus::Linking,
        ModuleStatus::Linked,
        ModuleStatus::Evaluating,
        ModuleStatus::Evaluated,
        ModuleStatus::EvaluationError,
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|s| format!("{s:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

#[test]
fn enrichment_module_status_serde_roundtrip_all() {
    let variants = [
        ModuleStatus::Unlinked,
        ModuleStatus::Linking,
        ModuleStatus::Linked,
        ModuleStatus::Evaluating,
        ModuleStatus::Evaluated,
        ModuleStatus::EvaluationError,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: ModuleStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn enrichment_module_status_ord_ordering() {
    assert!(ModuleStatus::Unlinked < ModuleStatus::Linking);
    assert!(ModuleStatus::Linking < ModuleStatus::Linked);
    assert!(ModuleStatus::Linked < ModuleStatus::Evaluating);
    assert!(ModuleStatus::Evaluating < ModuleStatus::Evaluated);
    assert!(ModuleStatus::Evaluated < ModuleStatus::EvaluationError);
}

// ===========================================================================
// 2. ExportEntry — constructors, serde, Clone
// ===========================================================================

#[test]
fn enrichment_export_entry_direct_constructor() {
    let entry = ExportEntry::direct("localFoo", "exportedFoo");
    assert_eq!(entry.local_name, Some("localFoo".to_string()));
    assert_eq!(entry.export_name, "exportedFoo");
    assert!(entry.module_request.is_none());
    assert!(entry.import_name.is_none());
}

#[test]
fn enrichment_export_entry_re_export_constructor() {
    let entry = ExportEntry::re_export("foo", "./mod.js", "bar");
    assert!(entry.local_name.is_none());
    assert_eq!(entry.export_name, "foo");
    assert_eq!(entry.module_request, Some("./mod.js".to_string()));
    assert_eq!(entry.import_name, Some("bar".to_string()));
}

#[test]
fn enrichment_export_entry_star_re_export_constructor() {
    let entry = ExportEntry::star_re_export("./mod.js");
    assert!(entry.local_name.is_none());
    assert_eq!(entry.export_name, "*");
    assert_eq!(entry.module_request, Some("./mod.js".to_string()));
    assert!(entry.import_name.is_none());
}

#[test]
fn enrichment_export_entry_serde_roundtrip() {
    let entries = [
        ExportEntry::direct("a", "a"),
        ExportEntry::re_export("b", "./m.js", "c"),
        ExportEntry::star_re_export("./n.js"),
    ];
    for entry in &entries {
        let json = serde_json::to_string(entry).unwrap();
        let restored: ExportEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(*entry, restored);
    }
}

#[test]
fn enrichment_export_entry_clone_independence() {
    let original = ExportEntry::direct("foo", "bar");
    let mut cloned = original.clone();
    cloned.export_name = "mutated".to_string();
    assert_eq!(original.export_name, "bar");
}

// ===========================================================================
// 3. ImportEntry — constructors, serde, Clone
// ===========================================================================

#[test]
fn enrichment_import_entry_new_constructor() {
    let entry = ImportEntry::new("./mod.js", "foo", "localFoo");
    assert_eq!(entry.module_request, "./mod.js");
    assert_eq!(entry.import_name, "foo");
    assert_eq!(entry.local_name, "localFoo");
}

#[test]
fn enrichment_import_entry_namespace_constructor() {
    let entry = ImportEntry::namespace("./mod.js", "ns");
    assert_eq!(entry.module_request, "./mod.js");
    assert_eq!(entry.import_name, "*");
    assert_eq!(entry.local_name, "ns");
}

#[test]
fn enrichment_import_entry_serde_roundtrip() {
    let entries = [
        ImportEntry::new("./a.js", "foo", "foo"),
        ImportEntry::namespace("./b.js", "ns"),
    ];
    for entry in &entries {
        let json = serde_json::to_string(entry).unwrap();
        let restored: ImportEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(*entry, restored);
    }
}

#[test]
fn enrichment_import_entry_clone_independence() {
    let original = ImportEntry::new("./a.js", "foo", "foo");
    let mut cloned = original.clone();
    cloned.local_name = "mutated".to_string();
    assert_eq!(original.local_name, "foo");
}

// ===========================================================================
// 4. EsmModule — construction, add_import, add_export, serde
// ===========================================================================

#[test]
fn enrichment_esm_module_new_defaults() {
    let module = make_module("./test.js", "const x = 1;");
    assert_eq!(module.specifier, "./test.js");
    assert_eq!(module.source, "const x = 1;");
    assert_eq!(module.status, ModuleStatus::Unlinked);
    assert!(module.imports.is_empty());
    assert!(module.exports.is_empty());
    assert!(module.dependencies.is_empty());
    assert!(!module.has_default_export);
    assert!(module.dfs_index.is_none());
    assert!(module.eval_order.is_none());
}

#[test]
fn enrichment_esm_module_content_hash_deterministic() {
    let m1 = make_module("./a.js", "hello");
    let m2 = make_module("./b.js", "hello");
    // Same source content → same hash
    assert_eq!(m1.content_hash, m2.content_hash);
}

#[test]
fn enrichment_esm_module_content_hash_differs_for_different_source() {
    let m1 = make_module("./a.js", "hello");
    let m2 = make_module("./a.js", "world");
    assert_ne!(m1.content_hash, m2.content_hash);
}

#[test]
fn enrichment_esm_module_add_import_updates_dependencies() {
    let mut module = make_module("./test.js", "");
    module.add_import(ImportEntry::new("./dep.js", "x", "x"));
    assert!(module.dependencies.contains("./dep.js"));
    assert_eq!(module.imports.len(), 1);
}

#[test]
fn enrichment_esm_module_add_export_default_sets_flag() {
    let mut module = make_module("./test.js", "");
    assert!(!module.has_default_export);
    module.add_export(ExportEntry::direct("myFunc", "default"));
    assert!(module.has_default_export);
}

#[test]
fn enrichment_esm_module_add_export_re_export_adds_dependency() {
    let mut module = make_module("./test.js", "");
    module.add_export(ExportEntry::re_export("foo", "./other.js", "bar"));
    assert!(module.dependencies.contains("./other.js"));
}

#[test]
fn enrichment_esm_module_serde_roundtrip() {
    let mut module = make_module("./test.js", "const x = 1;");
    module.add_import(ImportEntry::new("./dep.js", "y", "y"));
    module.add_export(ExportEntry::direct("x", "x"));
    let json = serde_json::to_string(&module).unwrap();
    let restored: EsmModule = serde_json::from_str(&json).unwrap();
    assert_eq!(module, restored);
}

#[test]
fn enrichment_esm_module_clone_independence() {
    let mut original = make_module("./test.js", "const x = 1;");
    original.add_import(ImportEntry::new("./a.js", "a", "a"));
    let mut cloned = original.clone();
    cloned.specifier = "mutated".to_string();
    cloned.status = ModuleStatus::Evaluated;
    assert_eq!(original.specifier, "./test.js");
    assert_eq!(original.status, ModuleStatus::Unlinked);
}

// ===========================================================================
// 5. ModuleGraph — construction, add_module, accessors
// ===========================================================================

#[test]
fn enrichment_module_graph_new_empty() {
    let graph = ModuleGraph::new();
    assert!(graph.is_empty());
    assert_eq!(graph.len(), 0);
    assert!(graph.entry_point().is_none());
    assert!(graph.trace_events().is_empty());
}

#[test]
fn enrichment_module_graph_default_same_as_new() {
    let g1 = ModuleGraph::new();
    let g2 = ModuleGraph::default();
    assert_eq!(g1.len(), g2.len());
    assert_eq!(g1.entry_point(), g2.entry_point());
}

#[test]
fn enrichment_module_graph_first_module_becomes_entry_point() {
    let mut graph = ModuleGraph::new();
    graph.add_module(make_module("./entry.js", "")).unwrap();
    assert_eq!(graph.entry_point(), Some("./entry.js"));
}

#[test]
fn enrichment_module_graph_specifiers_deterministic_order() {
    let mut graph = ModuleGraph::new();
    graph.add_module(make_module("./z.js", "")).unwrap();
    graph.add_module(make_module("./a.js", "")).unwrap();
    graph.add_module(make_module("./m.js", "")).unwrap();
    let specs: Vec<&str> = graph.specifiers().collect();
    // BTreeMap should give sorted order
    assert_eq!(specs, vec!["./a.js", "./m.js", "./z.js"]);
}

#[test]
fn enrichment_module_graph_get_module() {
    let mut graph = ModuleGraph::new();
    graph.add_module(make_module("./a.js", "source-a")).unwrap();
    let module = graph.get_module("./a.js").unwrap();
    assert_eq!(module.source, "source-a");
    assert!(graph.get_module("./nonexistent.js").is_none());
}

#[test]
fn enrichment_module_graph_get_module_mut() {
    let mut graph = ModuleGraph::new();
    graph.add_module(make_module("./a.js", "")).unwrap();
    let module = graph.get_module_mut("./a.js").unwrap();
    module.status = ModuleStatus::Linked;
    assert_eq!(
        graph.get_module("./a.js").unwrap().status,
        ModuleStatus::Linked
    );
}

// ===========================================================================
// 6. TracePhase — Copy, Display, serde
// ===========================================================================

#[test]
fn enrichment_trace_phase_copy_semantics() {
    let a = TracePhase::Resolve;
    let b = a;
    let c = a;
    assert_eq!(b, c);
}

#[test]
fn enrichment_trace_phase_display_all_unique() {
    let variants = [
        TracePhase::Resolve,
        TracePhase::Link,
        TracePhase::Evaluate,
        TracePhase::CycleDetected,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|p| p.to_string()).collect();
    assert_eq!(displays.len(), variants.len());
}

#[test]
fn enrichment_trace_phase_serde_roundtrip() {
    for v in [
        TracePhase::Resolve,
        TracePhase::Link,
        TracePhase::Evaluate,
        TracePhase::CycleDetected,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let restored: TracePhase = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

// ===========================================================================
// 7. Link phase — determinism, trace events
// ===========================================================================

#[test]
fn enrichment_link_linear_graph_succeeds() {
    let mut graph = linear_graph();
    let result = graph.link().unwrap();
    assert_eq!(result.linked_count, 2);
    assert_eq!(result.cycle_count, 0);
    assert!(result.cycles.is_empty());
}

#[test]
fn enrichment_link_sets_status_to_linked() {
    let mut graph = linear_graph();
    graph.link().unwrap();
    for module in graph.modules() {
        assert_eq!(module.status, ModuleStatus::Linked);
    }
}

#[test]
fn enrichment_link_emits_trace_events() {
    let mut graph = linear_graph();
    graph.link().unwrap();
    assert!(!graph.trace_events().is_empty());
    // All trace events should have Link phase
    for evt in graph.trace_events() {
        assert!(
            evt.phase == TracePhase::Link || evt.phase == TracePhase::CycleDetected,
            "link phase should only emit Link or CycleDetected events"
        );
    }
}

#[test]
fn enrichment_link_deterministic() {
    let mut g1 = linear_graph();
    let mut g2 = linear_graph();
    let r1 = g1.link().unwrap();
    let r2 = g2.link().unwrap();
    assert_eq!(r1.linked_count, r2.linked_count);
    assert_eq!(r1.cycle_count, r2.cycle_count);
}

#[test]
fn enrichment_link_detects_cycles() {
    let mut graph = cyclic_graph();
    let result = graph.link().unwrap();
    assert!(result.cycle_count > 0);
}

#[test]
fn enrichment_link_no_entry_point_error() {
    let mut graph = ModuleGraph::new();
    let err = graph.link().unwrap_err();
    assert!(matches!(err, EsmLoaderError::NoEntryPoint));
}

// ===========================================================================
// 8. Evaluate phase
// ===========================================================================

#[test]
fn enrichment_evaluate_linear_graph() {
    let mut graph = linear_graph();
    graph.link().unwrap();
    let result = graph.evaluate().unwrap();
    assert_eq!(result.evaluated_count, 2);
    assert_eq!(result.eval_order.len(), 2);
    // Dependencies should be evaluated before entry
    assert_eq!(result.eval_order[0], "./a.js");
    assert_eq!(result.eval_order[1], "./entry.js");
}

#[test]
fn enrichment_evaluate_sets_status_to_evaluated() {
    let mut graph = linear_graph();
    graph.link().unwrap();
    graph.evaluate().unwrap();
    for module in graph.modules() {
        assert_eq!(module.status, ModuleStatus::Evaluated);
    }
}

#[test]
fn enrichment_evaluate_no_entry_point_error() {
    let mut graph = ModuleGraph::new();
    let err = graph.evaluate().unwrap_err();
    assert!(matches!(err, EsmLoaderError::NoEntryPoint));
}

// ===========================================================================
// 9. Export resolution
// ===========================================================================

#[test]
fn enrichment_resolve_export_direct() {
    let mut graph = linear_graph();
    graph.link().unwrap();
    let binding = graph.resolve_export("./a.js", "foo").unwrap();
    assert_eq!(binding.module_specifier, "./a.js");
    assert_eq!(binding.local_name, "foo");
    assert_eq!(binding.binding_type, BindingType::Direct);
}

#[test]
fn enrichment_resolve_export_not_found() {
    let mut graph = linear_graph();
    graph.link().unwrap();
    let err = graph.resolve_export("./a.js", "nonexistent").unwrap_err();
    assert!(matches!(err, EsmLoaderError::ExportNotFound { .. }));
}

// ===========================================================================
// 10. Cycle detection (find_cycles, topological_order)
// ===========================================================================

#[test]
fn enrichment_find_cycles_linear_graph_no_cycles() {
    let graph = linear_graph();
    let cycles = graph.find_cycles();
    assert!(cycles.is_empty());
}

#[test]
fn enrichment_find_cycles_cyclic_graph_detects() {
    let graph = cyclic_graph();
    let cycles = graph.find_cycles();
    assert!(!cycles.is_empty());
    // The cycle should contain both ./a.js and ./b.js
    let all_in_cycle: BTreeSet<&str> = cycles
        .iter()
        .flat_map(|c| c.iter().map(|s| s.as_str()))
        .collect();
    assert!(all_in_cycle.contains("./a.js"));
    assert!(all_in_cycle.contains("./b.js"));
}

#[test]
fn enrichment_topological_order_linear_graph() {
    let graph = linear_graph();
    let order = graph.topological_order();
    assert_eq!(order.len(), 2);
    // Dependency should come before dependent
    let a_pos = order.iter().position(|s| s == "./a.js").unwrap();
    let entry_pos = order.iter().position(|s| s == "./entry.js").unwrap();
    assert!(
        a_pos < entry_pos,
        "dependency should come first in topo order"
    );
}

#[test]
fn enrichment_topological_order_deterministic() {
    let g1 = linear_graph();
    let g2 = linear_graph();
    assert_eq!(g1.topological_order(), g2.topological_order());
}

// ===========================================================================
// 11. Graph analysis — find_exporters, transitive_dependencies
// ===========================================================================

#[test]
fn enrichment_find_exporters() {
    let graph = linear_graph();
    let exporters = graph.find_exporters("foo");
    assert_eq!(exporters, vec!["./a.js"]);
}

#[test]
fn enrichment_find_exporters_not_found() {
    let graph = linear_graph();
    let exporters = graph.find_exporters("nonexistent");
    assert!(exporters.is_empty());
}

#[test]
fn enrichment_transitive_dependencies() {
    let graph = linear_graph();
    let deps = graph.transitive_dependencies("./entry.js");
    assert!(deps.contains("./a.js"));
    assert!(!deps.contains("./entry.js")); // should exclude self
}

#[test]
fn enrichment_transitive_dependencies_leaf_has_none() {
    let graph = linear_graph();
    let deps = graph.transitive_dependencies("./a.js");
    assert!(deps.is_empty());
}

// ===========================================================================
// 12. EsmLoaderError — Display uniqueness, Debug, serde, std::error::Error
// ===========================================================================

#[test]
fn enrichment_esm_loader_error_display_all_unique() {
    let variants: Vec<EsmLoaderError> = vec![
        EsmLoaderError::NoEntryPoint,
        EsmLoaderError::ModuleNotFound("m".to_string()),
        EsmLoaderError::GraphTooLarge { limit: 100 },
        EsmLoaderError::DepthExceeded {
            specifier: "s".to_string(),
            depth: 10,
            limit: 5,
        },
        EsmLoaderError::UnresolvedDependency {
            specifier: "s".to_string(),
            dependency: "d".to_string(),
        },
        EsmLoaderError::ExportNotFound {
            specifier: "s".to_string(),
            export_name: "e".to_string(),
        },
        EsmLoaderError::AmbiguousExport {
            specifier: "s".to_string(),
            export_name: "e".to_string(),
        },
        EsmLoaderError::EvaluationFailed {
            specifier: "s".to_string(),
            reason: "r".to_string(),
        },
        EsmLoaderError::InvalidStatus {
            specifier: "s".to_string(),
            expected: "linked",
            actual: "unlinked".to_string(),
        },
    ];
    let displays: BTreeSet<String> = variants.iter().map(|e| e.to_string()).collect();
    assert_eq!(
        displays.len(),
        variants.len(),
        "all EsmLoaderError Display strings should be unique"
    );
}

#[test]
fn enrichment_esm_loader_error_debug_all_unique() {
    let variants: Vec<EsmLoaderError> = vec![
        EsmLoaderError::NoEntryPoint,
        EsmLoaderError::ModuleNotFound("m".to_string()),
        EsmLoaderError::GraphTooLarge { limit: 100 },
        EsmLoaderError::DepthExceeded {
            specifier: "s".to_string(),
            depth: 10,
            limit: 5,
        },
        EsmLoaderError::UnresolvedDependency {
            specifier: "s".to_string(),
            dependency: "d".to_string(),
        },
        EsmLoaderError::ExportNotFound {
            specifier: "s".to_string(),
            export_name: "e".to_string(),
        },
        EsmLoaderError::AmbiguousExport {
            specifier: "s".to_string(),
            export_name: "e".to_string(),
        },
        EsmLoaderError::EvaluationFailed {
            specifier: "s".to_string(),
            reason: "r".to_string(),
        },
        EsmLoaderError::InvalidStatus {
            specifier: "s".to_string(),
            expected: "linked",
            actual: "unlinked".to_string(),
        },
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|e| format!("{e:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

#[test]
fn enrichment_esm_loader_error_serde_serializes() {
    // EsmLoaderError contains &'static str (InvalidStatus.expected), so Deserialize
    // only works for 'static data. We test that serialization produces valid JSON.
    let variants: Vec<EsmLoaderError> = vec![
        EsmLoaderError::NoEntryPoint,
        EsmLoaderError::ModuleNotFound("m".to_string()),
        EsmLoaderError::GraphTooLarge { limit: 100 },
        EsmLoaderError::UnresolvedDependency {
            specifier: "s".to_string(),
            dependency: "d".to_string(),
        },
        EsmLoaderError::ExportNotFound {
            specifier: "s".to_string(),
            export_name: "e".to_string(),
        },
        EsmLoaderError::AmbiguousExport {
            specifier: "s".to_string(),
            export_name: "e".to_string(),
        },
        EsmLoaderError::EvaluationFailed {
            specifier: "s".to_string(),
            reason: "r".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        assert!(!json.is_empty());
        // Verify it parses as valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_string() || parsed.is_object());
    }
}

// ===========================================================================
// 13. BindingType — Copy, serde, Debug
// ===========================================================================

#[test]
fn enrichment_binding_type_copy_semantics() {
    let a = BindingType::Direct;
    let b = a;
    let c = a;
    assert_eq!(b, c);
}

#[test]
fn enrichment_binding_type_serde_roundtrip() {
    for v in [
        BindingType::Direct,
        BindingType::ReExport,
        BindingType::StarReExport,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let restored: BindingType = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }
}

#[test]
fn enrichment_binding_type_debug_unique() {
    let debugs: BTreeSet<String> = [
        BindingType::Direct,
        BindingType::ReExport,
        BindingType::StarReExport,
    ]
    .iter()
    .map(|v| format!("{v:?}"))
    .collect();
    assert_eq!(debugs.len(), 3);
}

// ===========================================================================
// 14. CycleInfo, LinkResult, EvalResult — serde, Debug
// ===========================================================================

#[test]
fn enrichment_cycle_info_serde_roundtrip() {
    let info = CycleInfo {
        specifier: "./a.js".to_string(),
        stack_snapshot: vec!["./a.js".to_string(), "./b.js".to_string()],
    };
    let json = serde_json::to_string(&info).unwrap();
    let restored: CycleInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(info, restored);
}

#[test]
fn enrichment_link_result_debug() {
    let mut graph = linear_graph();
    let result = graph.link().unwrap();
    let dbg = format!("{result:?}");
    assert!(dbg.contains("LinkResult"));
}

#[test]
fn enrichment_eval_result_debug() {
    let mut graph = linear_graph();
    graph.link().unwrap();
    let result = graph.evaluate().unwrap();
    let dbg = format!("{result:?}");
    assert!(dbg.contains("EvalResult"));
}

// ===========================================================================
// 15. TraceEvent — serde, Debug
// ===========================================================================

#[test]
fn enrichment_trace_event_serde_roundtrip() {
    let evt = TraceEvent {
        phase: TracePhase::Link,
        specifier: "./a.js".to_string(),
        detail: "linking module".to_string(),
        seq: 0,
    };
    let json = serde_json::to_string(&evt).unwrap();
    let restored: TraceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, restored);
}

#[test]
fn enrichment_trace_event_seq_monotonic() {
    let mut graph = linear_graph();
    graph.link().unwrap();
    let events = graph.trace_events();
    for (i, evt) in events.iter().enumerate() {
        assert_eq!(evt.seq, i as u64, "trace event seq should be monotonic");
    }
}

// ===========================================================================
// 16. ResolvedBinding — serde, Debug
// ===========================================================================

#[test]
fn enrichment_resolved_binding_serde_roundtrip() {
    let binding = ResolvedBinding {
        module_specifier: "./a.js".to_string(),
        local_name: "foo".to_string(),
        binding_type: BindingType::Direct,
    };
    let json = serde_json::to_string(&binding).unwrap();
    let restored: ResolvedBinding = serde_json::from_str(&json).unwrap();
    assert_eq!(binding, restored);
}

#[test]
fn enrichment_resolved_binding_json_field_names() {
    let binding = ResolvedBinding {
        module_specifier: "./a.js".to_string(),
        local_name: "foo".to_string(),
        binding_type: BindingType::Direct,
    };
    let json = serde_json::to_string(&binding).unwrap();
    assert!(json.contains("module_specifier"));
    assert!(json.contains("local_name"));
    assert!(json.contains("binding_type"));
}

// ===========================================================================
// 17. Full pipeline determinism — N runs
// ===========================================================================

#[test]
fn enrichment_full_pipeline_determinism_five_runs() {
    let run = || {
        let mut graph = linear_graph();
        let link_result = graph.link().unwrap();
        let eval_result = graph.evaluate().unwrap();
        (link_result, eval_result)
    };
    let (ref_link, ref_eval) = run();
    for _ in 1..5 {
        let (link, eval) = run();
        assert_eq!(ref_link.linked_count, link.linked_count);
        assert_eq!(ref_link.cycle_count, link.cycle_count);
        assert_eq!(ref_eval.eval_order, eval.eval_order);
        assert_eq!(ref_eval.evaluated_count, eval.evaluated_count);
    }
}
