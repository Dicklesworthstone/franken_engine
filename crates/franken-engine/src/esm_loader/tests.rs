#[cfg(test)]
mod tests {
    use super::*;

    fn make_module(spec: &str, source: &str) -> EsmModule {
        EsmModule::new(spec, source, ModuleSyntax::EsModule)
    }

    // -- Basic graph construction tests --------------------------------------

    #[test]
    fn test_empty_graph() {
        let graph = ModuleGraph::new();
        assert!(graph.is_empty());
        assert_eq!(graph.len(), 0);
        assert!(graph.entry_point().is_none());
    }

    #[test]
    fn test_add_single_module() {
        let mut graph = ModuleGraph::new();
        let module = make_module("./main.js", "console.log('hello')");
        graph
            .add_module(module)
            .expect("operation should succeed for valid inputs");
        assert_eq!(graph.len(), 1);
        assert_eq!(graph.entry_point(), Some("./main.js"));
    }

    #[test]
    fn test_add_multiple_modules() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("./main.js", "import './dep.js'"))
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("./dep.js", "export const x = 1"))
            .expect("operation should succeed for valid inputs");
        assert_eq!(graph.len(), 2);
        assert_eq!(graph.entry_point(), Some("./main.js"));
    }

    // -- Module structure tests ----------------------------------------------

    #[test]
    fn test_esm_module_content_hash() {
        let m1 = make_module("a.js", "const x = 1");
        let m2 = make_module("b.js", "const x = 1");
        let m3 = make_module("c.js", "const x = 2");
        // Same source => same hash.
        assert_eq!(m1.content_hash, m2.content_hash);
        // Different source => different hash.
        assert_ne!(m1.content_hash, m3.content_hash);
    }

    #[test]
    fn test_add_import_tracks_dependency() {
        let mut module = make_module("main.js", "");
        module.add_import(ImportEntry::new("dep.js", "foo", "foo"));
        assert!(module.dependencies.contains("dep.js"));
        assert_eq!(module.imports.len(), 1);
    }

    #[test]
    fn test_add_export_direct() {
        let mut module = make_module("lib.js", "");
        module.add_export(ExportEntry::direct("myFn", "myFn"));
        assert_eq!(module.exports.len(), 1);
        assert!(!module.has_default_export);
    }

    #[test]
    fn test_add_export_default() {
        let mut module = make_module("lib.js", "");
        module.add_export(ExportEntry::direct("_default", "default"));
        assert!(module.has_default_export);
    }

    #[test]
    fn test_add_reexport_tracks_dependency() {
        let mut module = make_module("index.js", "");
        module.add_export(ExportEntry::re_export("foo", "dep.js", "foo"));
        assert!(module.dependencies.contains("dep.js"));
    }

    // -- Link phase tests ----------------------------------------------------

    #[test]
    fn test_link_single_module() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("main.js", ""))
            .expect("operation should succeed for valid inputs");
        let result = graph
            .link()
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.linked_count, 1);
        assert_eq!(result.cycle_count, 0);
        assert_eq!(
            graph
                .get_module("main.js")
                .expect("operation should succeed for valid inputs")
                .status,
            ModuleStatus::Linked
        );
    }

    #[test]
    fn test_link_chain() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("a.js", "x", "x"));
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "y", "y"));
        let b = make_module("b.js", "");

        graph
            .add_module(main)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(b)
            .expect("operation should succeed for valid inputs");

        let result = graph
            .link()
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.linked_count, 3);
        assert_eq!(result.cycle_count, 0);
    }

    #[test]
    fn test_link_detects_cycle() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "x", "x"));
        let mut b = make_module("b.js", "");
        b.add_import(ImportEntry::new("a.js", "y", "y"));

        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(b)
            .expect("operation should succeed for valid inputs");

        let result = graph
            .link()
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.linked_count, 2);
        assert_eq!(result.cycle_count, 1);
    }

    #[test]
    fn test_link_unresolved_dependency() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("missing.js", "x", "x"));
        graph
            .add_module(main)
            .expect("operation should succeed for valid inputs");

        let err = graph.link().unwrap_err();
        assert!(matches!(err, EsmLoaderError::UnresolvedDependency { .. }));
    }

    // -- Evaluate phase tests ------------------------------------------------

    #[test]
    fn test_evaluate_single() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("main.js", ""))
            .expect("operation should succeed for valid inputs");
        graph
            .link()
            .expect("operation should succeed for valid inputs");
        let result = graph
            .evaluate()
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.eval_order, vec!["main.js"]);
        assert_eq!(result.evaluated_count, 1);
    }

    #[test]
    fn test_evaluate_chain_order() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("a.js", "x", "x"));
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "y", "y"));
        let b = make_module("b.js", "");

        graph
            .add_module(main)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(b)
            .expect("operation should succeed for valid inputs");

        graph
            .link()
            .expect("operation should succeed for valid inputs");
        let result = graph
            .evaluate()
            .expect("operation should succeed for valid inputs");
        // Dependencies first: b -> a -> main.
        assert_eq!(result.eval_order, vec!["b.js", "a.js", "main.js"]);
    }

    #[test]
    fn test_evaluate_diamond() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("a.js", "x", "x"));
        main.add_import(ImportEntry::new("b.js", "y", "y"));
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("shared.js", "s", "s"));
        let mut b = make_module("b.js", "");
        b.add_import(ImportEntry::new("shared.js", "s", "s"));
        let shared = make_module("shared.js", "");

        graph
            .add_module(main)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(b)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(shared)
            .expect("operation should succeed for valid inputs");

        graph
            .link()
            .expect("operation should succeed for valid inputs");
        let result = graph
            .evaluate()
            .expect("operation should succeed for valid inputs");
        // Shared is evaluated once, before a and b.
        assert_eq!(result.eval_order[0], "shared.js");
        assert_eq!(
            *result
                .eval_order
                .last()
                .expect("operation should succeed for valid inputs"),
            "main.js"
        );
        assert_eq!(result.evaluated_count, 4);
    }

    #[test]
    fn test_evaluate_cycle() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "x", "x"));
        let mut b = make_module("b.js", "");
        b.add_import(ImportEntry::new("a.js", "y", "y"));

        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(b)
            .expect("operation should succeed for valid inputs");

        graph
            .link()
            .expect("operation should succeed for valid inputs");
        let result = graph
            .evaluate()
            .expect("operation should succeed for valid inputs");
        // Both should be evaluated despite cycle.
        assert_eq!(result.evaluated_count, 2);
    }

    // -- Export resolution tests ----------------------------------------------

    #[test]
    fn test_resolve_direct_export() {
        let mut graph = ModuleGraph::new();
        let mut lib = make_module("lib.js", "");
        lib.add_export(ExportEntry::direct("foo", "foo"));
        graph
            .add_module(lib)
            .expect("operation should succeed for valid inputs");

        let binding = graph
            .resolve_export("lib.js", "foo")
            .expect("operation should succeed for valid inputs");
        assert_eq!(binding.module_specifier, "lib.js");
        assert_eq!(binding.local_name, "foo");
        assert_eq!(binding.binding_type, BindingType::Direct);
    }

    #[test]
    fn test_resolve_reexport() {
        let mut graph = ModuleGraph::new();
        let mut lib = make_module("lib.js", "");
        lib.add_export(ExportEntry::direct("bar", "bar"));
        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::re_export("bar", "lib.js", "bar"));

        graph
            .add_module(index)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(lib)
            .expect("operation should succeed for valid inputs");

        let binding = graph
            .resolve_export("index.js", "bar")
            .expect("operation should succeed for valid inputs");
        assert_eq!(binding.module_specifier, "lib.js");
        assert_eq!(binding.local_name, "bar");
        assert_eq!(binding.binding_type, BindingType::ReExport);
    }

    #[test]
    fn test_resolve_star_reexport() {
        let mut graph = ModuleGraph::new();
        let mut lib = make_module("lib.js", "");
        lib.add_export(ExportEntry::direct("baz", "baz"));
        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::star_re_export("lib.js"));

        graph
            .add_module(index)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(lib)
            .expect("operation should succeed for valid inputs");

        let binding = graph
            .resolve_export("index.js", "baz")
            .expect("operation should succeed for valid inputs");
        assert_eq!(binding.module_specifier, "lib.js");
        assert_eq!(binding.binding_type, BindingType::StarReExport);
    }

    #[test]
    fn test_resolve_star_reexport_default_is_not_visible() {
        let mut graph = ModuleGraph::new();
        let mut lib = make_module("lib.js", "");
        lib.add_export(ExportEntry::direct("default_impl", "default"));
        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::star_re_export("lib.js"));

        graph
            .add_module(index)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(lib)
            .expect("operation should succeed for valid inputs");

        let err = graph.resolve_export("index.js", "default").unwrap_err();
        assert_eq!(
            err,
            EsmLoaderError::ExportNotFound {
                specifier: "index.js".into(),
                export_name: "default".into(),
            }
        );
    }

    #[test]
    fn test_resolve_identical_star_reexports_are_not_ambiguous() {
        let mut graph = ModuleGraph::new();
        let mut leaf = make_module("leaf.js", "");
        leaf.add_export(ExportEntry::direct("shared", "shared"));
        let mut left = make_module("left.js", "");
        left.add_export(ExportEntry::star_re_export("leaf.js"));
        let mut right = make_module("right.js", "");
        right.add_export(ExportEntry::star_re_export("leaf.js"));
        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::star_re_export("left.js"));
        index.add_export(ExportEntry::star_re_export("right.js"));

        graph
            .add_module(index)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(left)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(right)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(leaf)
            .expect("operation should succeed for valid inputs");

        let binding = graph
            .resolve_export("index.js", "shared")
            .expect("operation should succeed for valid inputs");
        assert_eq!(binding.module_specifier, "leaf.js");
        assert_eq!(binding.local_name, "shared");
        assert_eq!(binding.binding_type, BindingType::StarReExport);
    }

    #[test]
    fn test_resolve_star_reexport_ignores_cyclic_branch_without_binding() {
        let mut graph = ModuleGraph::new();

        let mut left = make_module("left.js", "");
        left.add_export(ExportEntry::star_re_export("mid.js"));

        let mut mid = make_module("mid.js", "");
        mid.add_export(ExportEntry::star_re_export("left.js"));

        let mut right = make_module("right.js", "");
        right.add_export(ExportEntry::direct("shared", "shared"));

        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::star_re_export("left.js"));
        index.add_export(ExportEntry::star_re_export("right.js"));

        graph
            .add_module(index)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(left)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(mid)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(right)
            .expect("operation should succeed for valid inputs");

        let binding = graph
            .resolve_export("index.js", "shared")
            .expect("operation should succeed for valid inputs");
        assert_eq!(binding.module_specifier, "right.js");
        assert_eq!(binding.local_name, "shared");
        assert_eq!(binding.binding_type, BindingType::StarReExport);
    }

    #[test]
    fn test_resolve_cyclic_star_reexport_without_binding_is_not_found() {
        let mut graph = ModuleGraph::new();

        let mut a = make_module("a.js", "");
        a.add_export(ExportEntry::star_re_export("b.js"));

        let mut b = make_module("b.js", "");
        b.add_export(ExportEntry::star_re_export("a.js"));

        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(b)
            .expect("operation should succeed for valid inputs");

        let err = graph.resolve_export("a.js", "missing").unwrap_err();
        assert_eq!(
            err,
            EsmLoaderError::ExportNotFound {
                specifier: "a.js".into(),
                export_name: "missing".into(),
            }
        );
    }

    #[test]
    fn test_resolve_named_reexport_missing_reports_surface_module() {
        let mut graph = ModuleGraph::new();

        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::re_export("shared", "lib.js", "shared"));

        let lib = make_module("lib.js", "");

        graph
            .add_module(index)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(lib)
            .expect("operation should succeed for valid inputs");

        let err = graph.resolve_export("index.js", "shared").unwrap_err();
        assert_eq!(
            err,
            EsmLoaderError::ExportNotFound {
                specifier: "index.js".into(),
                export_name: "shared".into(),
            }
        );
    }

    #[test]
    fn test_resolve_named_reexport_ambiguity_reports_surface_module() {
        let mut graph = ModuleGraph::new();

        let mut leaf = make_module("leaf.js", "");
        leaf.add_export(ExportEntry::direct("shared", "shared"));

        let mut left = make_module("left.js", "");
        left.add_export(ExportEntry::star_re_export("leaf.js"));

        let mut right = make_module("right.js", "");
        right.add_export(ExportEntry::direct("shared", "shared"));

        let mut lib = make_module("lib.js", "");
        lib.add_export(ExportEntry::star_re_export("left.js"));
        lib.add_export(ExportEntry::star_re_export("right.js"));

        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::re_export("shared", "lib.js", "shared"));

        graph
            .add_module(index)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(lib)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(left)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(right)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(leaf)
            .expect("operation should succeed for valid inputs");

        let err = graph.resolve_export("index.js", "shared").unwrap_err();
        assert_eq!(
            err,
            EsmLoaderError::AmbiguousExport {
                specifier: "index.js".into(),
                export_name: "shared".into(),
            }
        );
    }

    #[test]
    fn test_resolve_duplicate_explicit_exports_fail_closed() {
        let mut graph = ModuleGraph::new();
        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::direct("foo_local", "foo"));
        index.add_export(ExportEntry::re_export("foo", "lib.js", "foo"));
        graph
            .add_module(index)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("lib.js", ""))
            .expect("operation should succeed for valid inputs");

        let err = graph.resolve_export("index.js", "foo").unwrap_err();
        assert_eq!(
            err,
            EsmLoaderError::DuplicateExport {
                specifier: "index.js".into(),
                export_name: "foo".into(),
            }
        );
    }

    #[test]
    fn test_resolve_star_reexport_ambiguity_reports_surface_module() {
        let mut graph = ModuleGraph::new();

        let mut left = make_module("left.js", "");
        left.add_export(ExportEntry::direct("shared", "shared"));

        let mut right = make_module("right.js", "");
        right.add_export(ExportEntry::direct("shared", "shared"));

        let mut lib = make_module("lib.js", "");
        lib.add_export(ExportEntry::star_re_export("left.js"));
        lib.add_export(ExportEntry::star_re_export("right.js"));

        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::star_re_export("lib.js"));

        graph
            .add_module(index)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(lib)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(left)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(right)
            .expect("operation should succeed for valid inputs");

        let err = graph.resolve_export("index.js", "shared").unwrap_err();
        assert_eq!(
            err,
            EsmLoaderError::AmbiguousExport {
                specifier: "index.js".into(),
                export_name: "shared".into(),
            }
        );
    }

    #[test]
    fn test_resolve_export_not_found() {
        let mut graph = ModuleGraph::new();
        let lib = make_module("lib.js", "");
        graph
            .add_module(lib)
            .expect("operation should succeed for valid inputs");

        let err = graph.resolve_export("lib.js", "missing").unwrap_err();
        assert!(matches!(err, EsmLoaderError::ExportNotFound { .. }));
    }

    #[test]
    fn test_resolve_ambiguous_star_reexport() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_export(ExportEntry::direct("dup", "dup"));
        let mut b = make_module("b.js", "");
        b.add_export(ExportEntry::direct("dup", "dup"));
        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::star_re_export("a.js"));
        index.add_export(ExportEntry::star_re_export("b.js"));

        graph
            .add_module(index)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(b)
            .expect("operation should succeed for valid inputs");

        let err = graph.resolve_export("index.js", "dup").unwrap_err();
        assert!(matches!(err, EsmLoaderError::AmbiguousExport { .. }));
    }

    // -- Cycle detection tests -----------------------------------------------

    #[test]
    fn test_find_cycles_none() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("dep.js", "x", "x"));
        graph
            .add_module(main)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("dep.js", ""))
            .expect("operation should succeed for valid inputs");

        let cycles = graph.find_cycles();
        assert!(cycles.is_empty());
    }

    #[test]
    fn test_find_cycles_simple() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "x", "x"));
        let mut b = make_module("b.js", "");
        b.add_import(ImportEntry::new("a.js", "y", "y"));

        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(b)
            .expect("operation should succeed for valid inputs");

        let cycles = graph.find_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 2);
    }

    #[test]
    fn test_find_cycles_triangle() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "x", "x"));
        let mut b = make_module("b.js", "");
        b.add_import(ImportEntry::new("c.js", "x", "x"));
        let mut c = make_module("c.js", "");
        c.add_import(ImportEntry::new("a.js", "x", "x"));

        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(b)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(c)
            .expect("operation should succeed for valid inputs");

        let cycles = graph.find_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 3);
    }

    #[test]
    fn test_find_cycles_self_loop() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("a.js", "x", "x"));
        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");

        let cycles = graph.find_cycles();
        assert_eq!(cycles, vec![vec!["a.js".to_string()]]);
    }

    // -- Topological order tests ---------------------------------------------

    #[test]
    fn test_topological_order_chain() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("a.js", "x", "x"));
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "y", "y"));
        graph
            .add_module(main)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("b.js", ""))
            .expect("operation should succeed for valid inputs");

        let order = graph.topological_order();
        let b_pos = order
            .iter()
            .position(|s| s == "b.js")
            .expect("operation should succeed for valid inputs");
        let a_pos = order
            .iter()
            .position(|s| s == "a.js")
            .expect("operation should succeed for valid inputs");
        let main_pos = order
            .iter()
            .position(|s| s == "main.js")
            .expect("operation should succeed for valid inputs");
        assert!(b_pos < a_pos);
        assert!(a_pos < main_pos);
    }

    // -- Transitive dependency tests -----------------------------------------

    #[test]
    fn test_transitive_dependencies() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("a.js", "x", "x"));
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "y", "y"));
        graph
            .add_module(main)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("b.js", ""))
            .expect("operation should succeed for valid inputs");

        let deps = graph.transitive_dependencies("main.js");
        assert!(deps.contains("a.js"));
        assert!(deps.contains("b.js"));
        assert!(!deps.contains("main.js"));
    }

    // -- Find exporters test -------------------------------------------------

    #[test]
    fn test_find_exporters() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_export(ExportEntry::direct("foo", "foo"));
        let mut b = make_module("b.js", "");
        b.add_export(ExportEntry::direct("bar", "bar"));
        let mut c = make_module("c.js", "");
        c.add_export(ExportEntry::direct("foo", "foo"));

        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(b)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(c)
            .expect("operation should succeed for valid inputs");

        let exporters = graph.find_exporters("foo");
        assert_eq!(exporters.len(), 2);
        assert!(exporters.contains(&"a.js".to_string()));
        assert!(exporters.contains(&"c.js".to_string()));
    }

    // -- Trace events test ---------------------------------------------------

    #[test]
    fn test_trace_events_emitted() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("main.js", ""))
            .expect("operation should succeed for valid inputs");
        graph
            .link()
            .expect("operation should succeed for valid inputs");
        graph
            .evaluate()
            .expect("operation should succeed for valid inputs");

        let events = graph.trace_events();
        assert!(events.len() >= 2); // At least link + evaluate
        assert!(events.iter().any(|e| e.phase == TracePhase::Link));
        assert!(events.iter().any(|e| e.phase == TracePhase::Evaluate));
    }

    // -- Error display tests -------------------------------------------------

    #[test]
    fn test_error_display() {
        let err = EsmLoaderError::ModuleNotFound("foo.js".into());
        assert_eq!(format!("{err}"), "module not found: foo.js");

        let err = EsmLoaderError::UnresolvedDependency {
            specifier: "main.js".into(),
            dependency: "missing.js".into(),
        };
        assert!(format!("{err}").contains("main.js"));
        assert!(format!("{err}").contains("missing.js"));
    }

    #[test]
    fn test_no_entry_point_error() {
        let mut graph = ModuleGraph::new();
        let err = graph.link().unwrap_err();
        assert!(matches!(err, EsmLoaderError::NoEntryPoint));
    }

    // -- Graph size limit test -----------------------------------------------

    #[test]
    fn test_graph_size_limit() {
        let mut graph = ModuleGraph::new();
        // Add MAX + 1 modules to trigger limit.
        for i in 0..MAX_MODULE_GRAPH_SIZE {
            graph
                .add_module(make_module(&format!("mod_{i}.js"), ""))
                .expect("operation should succeed for valid inputs");
        }
        let err = graph
            .add_module(make_module("overflow.js", ""))
            .unwrap_err();
        assert!(matches!(err, EsmLoaderError::GraphTooLarge { .. }));
    }

    // -- Namespace import test -----------------------------------------------

    #[test]
    fn test_namespace_import() {
        let entry = ImportEntry::namespace("lib.js", "lib");
        assert_eq!(entry.import_name, "*");
        assert_eq!(entry.local_name, "lib");
    }

    // -- Module status display -----------------------------------------------

    #[test]
    fn test_module_status_display() {
        assert_eq!(format!("{}", ModuleStatus::Unlinked), "unlinked");
        assert_eq!(format!("{}", ModuleStatus::Linking), "linking");
        assert_eq!(format!("{}", ModuleStatus::Evaluated), "evaluated");
    }

    // -- Module status exhaustive display ------------------------------------

    #[test]
    fn module_status_display_all_variants() {
        assert_eq!(format!("{}", ModuleStatus::Linked), "linked");
        assert_eq!(format!("{}", ModuleStatus::Evaluating), "evaluating");
        assert_eq!(
            format!("{}", ModuleStatus::EvaluationError),
            "evaluation_error"
        );
    }

    #[test]
    fn module_status_ordering() {
        assert!(ModuleStatus::Unlinked < ModuleStatus::Linking);
        assert!(ModuleStatus::Linking < ModuleStatus::Linked);
        assert!(ModuleStatus::Linked < ModuleStatus::Evaluating);
        assert!(ModuleStatus::Evaluating < ModuleStatus::Evaluated);
        assert!(ModuleStatus::Evaluated < ModuleStatus::EvaluationError);
    }

    // -- ExportEntry constructors -------------------------------------------

    #[test]
    fn export_entry_direct_fields() {
        let e = ExportEntry::direct("localFn", "exportFn");
        assert_eq!(e.local_name, Some("localFn".to_string()));
        assert_eq!(e.export_name, "exportFn");
        assert!(e.module_request.is_none());
        assert!(e.import_name.is_none());
    }

    #[test]
    fn export_entry_re_export_fields() {
        let e = ExportEntry::re_export("foo", "other.js", "bar");
        assert!(e.local_name.is_none());
        assert_eq!(e.export_name, "foo");
        assert_eq!(e.module_request, Some("other.js".to_string()));
        assert_eq!(e.import_name, Some("bar".to_string()));
    }

    #[test]
    fn export_entry_star_re_export_fields() {
        let e = ExportEntry::star_re_export("source.js");
        assert!(e.local_name.is_none());
        assert_eq!(e.export_name, "*");
        assert_eq!(e.module_request, Some("source.js".to_string()));
        assert!(e.import_name.is_none());
    }

    // -- ImportEntry constructors -------------------------------------------

    #[test]
    fn import_entry_new_fields() {
        let i = ImportEntry::new("dep.js", "default", "myDefault");
        assert_eq!(i.module_request, "dep.js");
        assert_eq!(i.import_name, "default");
        assert_eq!(i.local_name, "myDefault");
    }

    #[test]
    fn import_entry_namespace_uses_star() {
        let i = ImportEntry::namespace("lib.js", "ns");
        assert_eq!(i.import_name, "*");
        assert_eq!(i.module_request, "lib.js");
        assert_eq!(i.local_name, "ns");
    }

    // -- EsmModule construction ---------------------------------------------

    #[test]
    fn esm_module_initial_status_is_unlinked() {
        let m = make_module("test.js", "");
        assert_eq!(m.status, ModuleStatus::Unlinked);
        assert!(m.dfs_index.is_none());
        assert!(m.dfs_ancestor_index.is_none());
        assert!(m.eval_order.is_none());
        assert!(!m.has_default_export);
        assert!(m.imports.is_empty());
        assert!(m.exports.is_empty());
        assert!(m.dependencies.is_empty());
    }

    #[test]
    fn esm_module_dependency_dedup() {
        let mut m = make_module("main.js", "");
        m.add_import(ImportEntry::new("dep.js", "a", "a"));
        m.add_import(ImportEntry::new("dep.js", "b", "b"));
        // Two imports from same module -> one dependency (BTreeSet dedup).
        assert_eq!(m.dependencies.len(), 1);
        assert_eq!(m.imports.len(), 2);
    }

    // -- Graph entry point logic --------------------------------------------

    #[test]
    fn entry_point_set_to_first_module() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("first.js", ""))
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("second.js", ""))
            .expect("operation should succeed for valid inputs");
        assert_eq!(graph.entry_point(), Some("first.js"));
    }

    #[test]
    fn default_trait_creates_empty_graph() {
        let graph = ModuleGraph::default();
        assert!(graph.is_empty());
        assert!(graph.entry_point().is_none());
    }

    // -- Graph accessor coverage --------------------------------------------

    #[test]
    fn get_module_returns_none_for_missing() {
        let graph = ModuleGraph::new();
        assert!(graph.get_module("nonexistent.js").is_none());
    }

    #[test]
    fn get_module_mut_returns_none_for_missing() {
        let mut graph = ModuleGraph::new();
        assert!(graph.get_module_mut("nonexistent.js").is_none());
    }

    #[test]
    fn specifiers_iterator_deterministic_order() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("c.js", ""))
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("a.js", ""))
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("b.js", ""))
            .expect("operation should succeed for valid inputs");
        let specs: Vec<&str> = graph.specifiers().collect();
        // BTreeMap guarantees sorted order.
        assert_eq!(specs, vec!["a.js", "b.js", "c.js"]);
    }

    #[test]
    fn modules_iterator_count() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("a.js", ""))
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("b.js", ""))
            .expect("operation should succeed for valid inputs");
        assert_eq!(graph.modules().count(), 2);
    }

    // -- Link phase DFS index assignment ------------------------------------

    #[test]
    fn link_assigns_dfs_indices() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("dep.js", "x", "x"));
        graph
            .add_module(main)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("dep.js", ""))
            .expect("operation should succeed for valid inputs");
        graph
            .link()
            .expect("operation should succeed for valid inputs");

        let m = graph
            .get_module("main.js")
            .expect("operation should succeed for valid inputs");
        assert!(m.dfs_index.is_some());
        assert!(m.dfs_ancestor_index.is_some());
        let d = graph
            .get_module("dep.js")
            .expect("operation should succeed for valid inputs");
        assert!(d.dfs_index.is_some());
    }

    #[test]
    fn link_cycle_info_contains_specifiers() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "x", "x"));
        let mut b = make_module("b.js", "");
        b.add_import(ImportEntry::new("a.js", "y", "y"));
        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(b)
            .expect("operation should succeed for valid inputs");

        let result = graph
            .link()
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.cycle_count, 1);
        assert!(!result.cycles.is_empty());
        let cycle = &result.cycles[0];
        assert!(!cycle.specifier.is_empty());
        assert!(!cycle.stack_snapshot.is_empty());
    }

    // -- Evaluate phase eval_order assignment --------------------------------

    #[test]
    fn evaluate_assigns_eval_order() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("dep.js", "x", "x"));
        graph
            .add_module(main)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("dep.js", ""))
            .expect("operation should succeed for valid inputs");
        graph
            .link()
            .expect("operation should succeed for valid inputs");
        graph
            .evaluate()
            .expect("operation should succeed for valid inputs");

        // dep.js evaluated first (order 0), main.js second (order 1).
        let dep = graph
            .get_module("dep.js")
            .expect("operation should succeed for valid inputs");
        let main = graph
            .get_module("main.js")
            .expect("operation should succeed for valid inputs");
        assert_eq!(dep.eval_order, Some(0));
        assert_eq!(main.eval_order, Some(1));
        assert_eq!(dep.status, ModuleStatus::Evaluated);
        assert_eq!(main.status, ModuleStatus::Evaluated);
    }

    #[test]
    fn evaluate_without_link_fails() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("main.js", ""))
            .expect("operation should succeed for valid inputs");
        // Skip link phase — module is still Unlinked.
        let err = graph.evaluate().unwrap_err();
        assert!(matches!(err, EsmLoaderError::InvalidStatus { .. }));
    }

    // -- Re-export chain resolution -----------------------------------------

    #[test]
    fn resolve_reexport_chain() {
        let mut graph = ModuleGraph::new();
        let mut origin = make_module("origin.js", "");
        origin.add_export(ExportEntry::direct("val", "val"));
        let mut mid = make_module("mid.js", "");
        mid.add_export(ExportEntry::re_export("val", "origin.js", "val"));
        let mut top = make_module("top.js", "");
        top.add_export(ExportEntry::re_export("val", "mid.js", "val"));

        graph
            .add_module(top)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(mid)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(origin)
            .expect("operation should succeed for valid inputs");

        let binding = graph
            .resolve_export("top.js", "val")
            .expect("operation should succeed for valid inputs");
        assert_eq!(binding.module_specifier, "origin.js");
        assert_eq!(binding.local_name, "val");
    }

    #[test]
    fn resolve_export_module_not_found() {
        let graph = ModuleGraph::new();
        let err = graph.resolve_export("nope.js", "x").unwrap_err();
        assert!(matches!(err, EsmLoaderError::ModuleNotFound(_)));
    }

    // -- Find exporters edge cases ------------------------------------------

    #[test]
    fn find_exporters_no_match() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_export(ExportEntry::direct("foo", "foo"));
        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        assert!(graph.find_exporters("bar").is_empty());
    }

    // -- Topological order edge cases ---------------------------------------

    #[test]
    fn topological_order_single_module() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("only.js", ""))
            .expect("operation should succeed for valid inputs");
        let order = graph.topological_order();
        assert_eq!(order, vec!["only.js"]);
    }

    #[test]
    fn topological_order_disconnected() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("a.js", ""))
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("b.js", ""))
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("c.js", ""))
            .expect("operation should succeed for valid inputs");
        let order = graph.topological_order();
        // All three present, BTreeMap order.
        assert_eq!(order.len(), 3);
    }

    // -- Transitive dependencies edge cases ---------------------------------

    #[test]
    fn transitive_deps_leaf_node_empty() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("leaf.js", ""))
            .expect("operation should succeed for valid inputs");
        let deps = graph.transitive_dependencies("leaf.js");
        assert!(deps.is_empty());
    }

    #[test]
    fn transitive_deps_does_not_include_self() {
        let mut graph = ModuleGraph::new();
        let mut main = make_module("main.js", "");
        main.add_import(ImportEntry::new("dep.js", "x", "x"));
        graph
            .add_module(main)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("dep.js", ""))
            .expect("operation should succeed for valid inputs");
        let deps = graph.transitive_dependencies("main.js");
        assert!(deps.contains("dep.js"));
        assert!(!deps.contains("main.js"));
    }

    // -- Trace event details ------------------------------------------------

    #[test]
    fn trace_events_sequential_seq() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("main.js", ""))
            .expect("operation should succeed for valid inputs");
        graph
            .link()
            .expect("operation should succeed for valid inputs");
        graph
            .evaluate()
            .expect("operation should succeed for valid inputs");
        let events = graph.trace_events();
        for pair in events.windows(2) {
            assert!(pair[0].seq < pair[1].seq);
        }
    }

    #[test]
    fn trace_cycle_detected_phase() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "x", "x"));
        let mut b = make_module("b.js", "");
        b.add_import(ImportEntry::new("a.js", "y", "y"));
        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(b)
            .expect("operation should succeed for valid inputs");
        graph
            .link()
            .expect("operation should succeed for valid inputs");

        let events = graph.trace_events();
        assert!(events.iter().any(|e| e.phase == TracePhase::CycleDetected));
    }

    #[test]
    fn trace_events_empty_before_link() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("main.js", ""))
            .expect("operation should succeed for valid inputs");
        assert!(graph.trace_events().is_empty());
    }

    // -- TracePhase display -------------------------------------------------

    #[test]
    fn trace_phase_display() {
        assert_eq!(format!("{}", TracePhase::Resolve), "resolve");
        assert_eq!(format!("{}", TracePhase::Link), "link");
        assert_eq!(format!("{}", TracePhase::Evaluate), "evaluate");
        assert_eq!(format!("{}", TracePhase::CycleDetected), "cycle_detected");
    }

    // -- Error display coverage ---------------------------------------------

    #[test]
    fn error_display_graph_too_large() {
        let err = EsmLoaderError::GraphTooLarge { limit: 100 };
        let msg = format!("{err}");
        assert!(msg.contains("100"));
    }

    #[test]
    fn error_display_depth_exceeded() {
        let err = EsmLoaderError::DepthExceeded {
            specifier: "deep.js".into(),
            depth: 513,
            limit: 512,
        };
        let msg = format!("{err}");
        assert!(msg.contains("deep.js"));
        assert!(msg.contains("513"));
        assert!(msg.contains("512"));
    }

    #[test]
    fn error_display_export_not_found() {
        let err = EsmLoaderError::ExportNotFound {
            specifier: "lib.js".into(),
            export_name: "missing".into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("lib.js"));
        assert!(msg.contains("missing"));
    }

    #[test]
    fn error_display_duplicate_export() {
        let err = EsmLoaderError::DuplicateExport {
            specifier: "index.js".into(),
            export_name: "dup".into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("index.js"));
        assert!(msg.contains("dup"));
    }

    #[test]
    fn error_display_ambiguous_export() {
        let err = EsmLoaderError::AmbiguousExport {
            specifier: "index.js".into(),
            export_name: "dup".into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("index.js"));
        assert!(msg.contains("dup"));
    }

    #[test]
    fn error_display_evaluation_failed() {
        let err = EsmLoaderError::EvaluationFailed {
            specifier: "bad.js".into(),
            reason: "runtime error".into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("bad.js"));
        assert!(msg.contains("runtime error"));
    }

    #[test]
    fn error_display_invalid_status() {
        let err = EsmLoaderError::InvalidStatus {
            specifier: "mod.js".into(),
            expected: "linked",
            actual: "unlinked".into(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("mod.js"));
        assert!(msg.contains("linked"));
        assert!(msg.contains("unlinked"));
    }

    #[test]
    fn error_display_no_entry_point() {
        let err = EsmLoaderError::NoEntryPoint;
        assert_eq!(format!("{err}"), "no entry point set");
    }

    // -- Serde roundtrip tests -----------------------------------------------

    #[test]
    fn esm_module_serde_roundtrip() {
        let mut m = make_module("test.js", "const x = 1");
        m.add_import(ImportEntry::new("dep.js", "foo", "foo"));
        m.add_export(ExportEntry::direct("bar", "bar"));
        let json = serde_json::to_string(&m).expect("serialize derived Serialize");
        let m2: EsmModule = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(m, m2);
    }

    #[test]
    fn module_graph_serde_roundtrip() {
        let mut graph = ModuleGraph::new();
        graph
            .add_module(make_module("a.js", ""))
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(make_module("b.js", ""))
            .expect("operation should succeed for valid inputs");
        let json = serde_json::to_string(&graph).expect("serialize derived Serialize");
        let g2: ModuleGraph = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(g2.len(), 2);
        assert_eq!(g2.entry_point(), Some("a.js"));
    }

    #[test]
    fn link_result_serde_roundtrip() {
        let result = LinkResult {
            linked_count: 3,
            cycle_count: 1,
            cycles: vec![CycleInfo {
                specifier: "a.js".into(),
                stack_snapshot: vec!["a.js".into(), "b.js".into()],
            }],
        };
        let json = serde_json::to_string(&result).expect("serialize derived Serialize");
        let r2: LinkResult = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(r2.linked_count, 3);
        assert_eq!(r2.cycle_count, 1);
    }

    #[test]
    fn eval_result_serde_roundtrip() {
        let result = EvalResult {
            eval_order: vec!["a.js".into(), "b.js".into()],
            evaluated_count: 2,
        };
        let json = serde_json::to_string(&result).expect("serialize derived Serialize");
        let r2: EvalResult = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(r2.evaluated_count, 2);
        assert_eq!(r2.eval_order.len(), 2);
    }

    #[test]
    fn binding_type_serde_roundtrip() {
        for bt in [
            BindingType::Direct,
            BindingType::ReExport,
            BindingType::StarReExport,
        ] {
            let json = serde_json::to_string(&bt).expect("serialize derived Serialize");
            let bt2: BindingType =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(bt, bt2);
        }
    }

    #[test]
    fn error_serde_roundtrip() {
        // Use a variant without &'static str field to avoid lifetime issues.
        let err = EsmLoaderError::UnresolvedDependency {
            specifier: "main.js".into(),
            dependency: "missing.js".into(),
        };
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        let val: serde_json::Value =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert!(val.get("UnresolvedDependency").is_some());
    }

    // -- BindingType ordering -----------------------------------------------

    #[test]
    fn binding_type_ordering() {
        assert!(BindingType::Direct < BindingType::ReExport);
        assert!(BindingType::ReExport < BindingType::StarReExport);
    }

    // -- Resolved binding fields --------------------------------------------

    #[test]
    fn resolved_binding_through_star_re_export() {
        // Star re-exports preserve the surface binding type of the exporting module.
        let mut graph = ModuleGraph::new();
        let mut lib = make_module("lib.js", "");
        lib.add_export(ExportEntry::direct("item", "item"));
        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::star_re_export("lib.js"));
        graph
            .add_module(index)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(lib)
            .expect("operation should succeed for valid inputs");

        let binding = graph
            .resolve_export("index.js", "item")
            .expect("operation should succeed for valid inputs");
        assert_eq!(binding.module_specifier, "lib.js");
        assert_eq!(binding.binding_type, BindingType::StarReExport);
    }

    #[test]
    fn resolved_binding_through_re_export() {
        // Named re-exports preserve the surface binding type of the exporting module.
        let mut graph = ModuleGraph::new();
        let mut lib = make_module("lib.js", "");
        lib.add_export(ExportEntry::direct("x", "x"));
        let mut index = make_module("index.js", "");
        index.add_export(ExportEntry::re_export("x", "lib.js", "x"));
        graph
            .add_module(index)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(lib)
            .expect("operation should succeed for valid inputs");

        let binding = graph
            .resolve_export("index.js", "x")
            .expect("operation should succeed for valid inputs");
        assert_eq!(binding.module_specifier, "lib.js");
        assert_eq!(binding.binding_type, BindingType::ReExport);
    }

    // -- Complex cycle patterns ---------------------------------------------

    #[test]
    fn find_cycles_four_node_ring() {
        let mut graph = ModuleGraph::new();
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "x", "x"));
        let mut b = make_module("b.js", "");
        b.add_import(ImportEntry::new("c.js", "x", "x"));
        let mut c = make_module("c.js", "");
        c.add_import(ImportEntry::new("d.js", "x", "x"));
        let mut d = make_module("d.js", "");
        d.add_import(ImportEntry::new("a.js", "x", "x"));
        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(b)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(c)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(d)
            .expect("operation should succeed for valid inputs");

        let cycles = graph.find_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 4);
    }

    #[test]
    fn find_cycles_two_independent() {
        let mut graph = ModuleGraph::new();
        // Cycle 1: a <-> b
        let mut a = make_module("a.js", "");
        a.add_import(ImportEntry::new("b.js", "x", "x"));
        let mut b = make_module("b.js", "");
        b.add_import(ImportEntry::new("a.js", "x", "x"));
        // Cycle 2: c <-> d
        let mut c = make_module("c.js", "");
        c.add_import(ImportEntry::new("d.js", "x", "x"));
        let mut d = make_module("d.js", "");
        d.add_import(ImportEntry::new("c.js", "x", "x"));
        graph
            .add_module(a)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(b)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(c)
            .expect("operation should succeed for valid inputs");
        graph
            .add_module(d)
            .expect("operation should succeed for valid inputs");

        let cycles = graph.find_cycles();
        assert_eq!(cycles.len(), 2);
    }

    // -- Content hash stability ----------------------------------------------

    #[test]
    fn content_hash_unchanged_after_link_evaluate() {
        let mut graph = ModuleGraph::new();
        let m = make_module("main.js", "const x = 1");
        let hash_before = m.content_hash;
        graph
            .add_module(m)
            .expect("operation should succeed for valid inputs");
        graph
            .link()
            .expect("operation should succeed for valid inputs");
        graph
            .evaluate()
            .expect("operation should succeed for valid inputs");
        assert_eq!(
            graph
                .get_module("main.js")
                .expect("operation should succeed for valid inputs")
                .content_hash,
            hash_before
        );
    }

    // -- Determinism ---------------------------------------------------------

    #[test]
    fn evaluate_deterministic_across_runs() {
        for _ in 0..5 {
            let mut graph = ModuleGraph::new();
            let mut main = make_module("main.js", "");
            main.add_import(ImportEntry::new("a.js", "x", "x"));
            main.add_import(ImportEntry::new("b.js", "y", "y"));
            let mut a = make_module("a.js", "");
            a.add_import(ImportEntry::new("shared.js", "s", "s"));
            let mut b = make_module("b.js", "");
            b.add_import(ImportEntry::new("shared.js", "s", "s"));
            graph
                .add_module(main)
                .expect("operation should succeed for valid inputs");
            graph
                .add_module(a)
                .expect("operation should succeed for valid inputs");
            graph
                .add_module(b)
                .expect("operation should succeed for valid inputs");
            graph
                .add_module(make_module("shared.js", ""))
                .expect("operation should succeed for valid inputs");
            graph
                .link()
                .expect("operation should succeed for valid inputs");
            let result = graph
                .evaluate()
                .expect("operation should succeed for valid inputs");
            assert_eq!(result.eval_order[0], "shared.js");
            assert_eq!(
                *result
                    .eval_order
                    .last()
                    .expect("operation should succeed for valid inputs"),
                "main.js"
            );
        }
    }
}
