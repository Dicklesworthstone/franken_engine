#![forbid(unsafe_code)]

//! Imported-local exports must retain the source cell, including through barrel
//! modules. These are graph/live-binding tests, not claims about JS execution.
use frankenengine_engine::esm_loader::{
    BindingType, EsmLoaderError, EsmModule, ExportEntry, ImportEntry, ModuleGraph,
};
use frankenengine_engine::module_live_binding::{
    BindingCellState, BindingId, build_live_bindings, validate_bindings,
};
use frankenengine_engine::module_resolver::ModuleSyntax;

fn module(name: &str) -> EsmModule {
    EsmModule::new(name, "", ModuleSyntax::EsModule)
}

fn source(name: &str, export_name: &str) -> EsmModule {
    let mut source = module(name);
    source.add_export(ExportEntry::direct("storage", export_name));
    source
}

fn imported_export(name: &str, dependency: &str, imported: &str, exported: &str) -> EsmModule {
    let mut alias = module(name);
    alias.add_import(ImportEntry::new(dependency, imported, "local_alias"));
    alias.add_export(ExportEntry::direct("local_alias", exported));
    alias
}

fn graph(modules: Vec<EsmModule>) -> ModuleGraph {
    let mut graph = ModuleGraph::new();
    for module in modules {
        graph.add_module(module).unwrap();
    }
    graph
}

#[test]
fn imported_local_exports_are_indirect_in_either_declaration_order() {
    for export_first in [false, true] {
        let mut alias = module("alias");
        let import = ImportEntry::new("source", "value", "local_alias");
        let export = ExportEntry::direct("local_alias", "public_name");
        if export_first {
            alias.add_export(export);
            alias.add_import(import);
        } else {
            alias.add_import(import);
            alias.add_export(export);
        }
        assert_eq!(
            alias.exports,
            [ExportEntry::re_export("public_name", "source", "value")]
        );
        let graph = graph(vec![alias, source("source", "value")]);
        let binding = graph.resolve_export("alias", "public_name").unwrap();
        assert_eq!(binding.module_specifier, "source");
        assert_eq!(binding.local_name, "storage");
        assert_eq!(binding.binding_type, BindingType::ReExport);
    }
}

#[test]
fn raw_records_are_normalized_when_admitted_to_the_graph() {
    let mut alias = module("alias");
    alias.imports.push(ImportEntry::new("source", "value", "local"));
    alias.exports.push(ExportEntry::direct("local", "public"));
    let encoded = serde_json::to_string(&alias).unwrap();
    let decoded: EsmModule = serde_json::from_str(&encoded).unwrap();
    let mut graph = graph(vec![decoded, source("source", "value")]);
    assert_eq!(graph.link().unwrap().linked_count, 2);
    assert_eq!(
        graph.get_module("alias").unwrap().exports,
        [ExportEntry::re_export("public", "source", "value")]
    );
    assert!(
        graph
            .get_module("alias")
            .unwrap()
            .dependencies
            .contains("source")
    );
}

#[test]
fn renamed_default_imports_preserve_the_original_binding() {
    let graph = graph(vec![
        imported_export("public", "middle", "renamed", "default"),
        imported_export("middle", "source", "default", "renamed"),
        source("source", "default"),
    ]);
    let binding = graph.resolve_export("public", "default").unwrap();
    assert_eq!(binding.module_specifier, "source");
    assert_eq!(binding.local_name, "storage");
    assert!(graph.get_module("public").unwrap().has_default_export);
}

#[test]
fn imported_reexports_share_live_values_versions_and_dead_state() {
    let mut consumer = module("consumer");
    consumer.add_import(ImportEntry::new("alias", "public", "seen"));
    let mut graph = graph(vec![
        consumer,
        imported_export("alias", "source", "value", "public"),
        source("source", "value"),
    ]);
    graph.link().unwrap();
    let mut bindings = build_live_bindings(&graph).unwrap();
    assert!(validate_bindings(&bindings).is_empty());
    let source_id = BindingId::new("source", "value");
    let alias_id = BindingId::new("alias", "public");
    assert_eq!(bindings.get_cell(&alias_id), bindings.get_cell(&source_id));
    bindings.initialize_millionths(&source_id, 1_000_000).unwrap();
    assert_eq!(
        bindings
            .read_through_import("consumer", "seen")
            .unwrap()
            .value_millionths,
        Some(1_000_000)
    );
    bindings.mutate_millionths(&source_id, 2_000_000).unwrap();
    let observed = bindings.read_through_import("consumer", "seen").unwrap();
    assert_eq!(observed.value_millionths, Some(2_000_000));
    assert_eq!(observed.version, 2);
    bindings.mark_dead(&source_id).unwrap();
    assert_eq!(
        bindings
            .read_through_import("consumer", "seen")
            .unwrap()
            .state,
        BindingCellState::Dead
    );
    assert!(bindings.mutate_millionths(&alias_id, 3_000_000).is_err());
}

#[test]
fn diamond_paths_to_the_same_imported_binding_are_not_ambiguous() {
    let mut barrel = module("barrel");
    barrel.add_export(ExportEntry::star_re_export("left"));
    barrel.add_export(ExportEntry::star_re_export("right"));
    let mut right = module("right");
    right.add_export(ExportEntry::re_export("public", "source", "value"));
    let mut graph = graph(vec![
        barrel,
        imported_export("left", "source", "value", "public"),
        right,
        source("source", "value"),
    ]);
    graph.link().unwrap();
    let binding = graph.resolve_export("barrel", "public").unwrap();
    assert_eq!(binding.module_specifier, "source");
    assert_eq!(binding.local_name, "storage");
    let mut bindings = build_live_bindings(&graph).unwrap();
    let source_id = BindingId::new("source", "value");
    bindings.initialize_string(&source_id, "live".into()).unwrap();
    assert_eq!(
        bindings
            .get_cell(&BindingId::new("barrel", "public"))
            .unwrap()
            .value_string
            .as_deref(),
        Some("live")
    );
}

#[test]
fn distinct_imported_bindings_remain_ambiguous() {
    let mut barrel = module("barrel");
    barrel.add_export(ExportEntry::star_re_export("left"));
    barrel.add_export(ExportEntry::star_re_export("right"));
    let graph = graph(vec![
        barrel,
        imported_export("left", "a", "value", "public"),
        imported_export("right", "b", "value", "public"),
        source("a", "value"),
        source("b", "value"),
    ]);
    assert!(matches!(
        graph.resolve_export("barrel", "public"),
        Err(EsmLoaderError::AmbiguousExport { .. })
    ));
}

#[test]
fn circular_imported_exports_do_not_invent_local_cells() {
    let graph = graph(vec![
        imported_export("a", "b", "value", "value"),
        imported_export("b", "a", "value", "value"),
    ]);
    for name in ["a", "b"] {
        assert!(matches!(
            graph.resolve_export(name, "value"),
            Err(EsmLoaderError::ExportNotFound { .. })
        ));
    }
}

#[test]
fn unresolved_imports_cannot_be_exported_as_fake_locals() {
    let graph = graph(vec![
        imported_export("alias", "source", "missing", "public"),
        source("source", "value"),
    ]);
    assert!(matches!(
        graph.resolve_export("alias", "public"),
        Err(EsmLoaderError::ExportNotFound { .. })
    ));
}

#[test]
fn namespace_imports_and_unrelated_locals_are_not_retargeted() {
    let mut alias = module("alias");
    alias.add_import(ImportEntry::namespace("source", "namespace"));
    alias.add_export(ExportEntry::direct("namespace", "ns"));
    alias.add_export(ExportEntry::direct("own", "value"));
    alias.add_export(ExportEntry::re_export("explicit", "other", "value"));
    assert_eq!(alias.exports[0], ExportEntry::direct("namespace", "ns"));
    assert_eq!(alias.exports[1], ExportEntry::direct("own", "value"));
    assert_eq!(
        alias.exports[2],
        ExportEntry::re_export("explicit", "other", "value")
    );
}
