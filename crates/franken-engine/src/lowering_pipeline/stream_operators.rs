//! Canonical CommonJS stream routing, including operators and adapters.
//!
//! Every free stream require selects the complete module. These regressions
//! exercise both simple producers and compositions that formerly needed a
//! whole-program heuristic to avoid the finite constructor facade.

#[cfg(test)]
mod tests {
    use super::super::{PureModule, is_module_declaration, rewrite_util_requires};
    use crate::ast::{ParseGoal, SyntaxTree};
    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
    use std::collections::BTreeSet;

    fn parse(source: &str) -> SyntaxTree {
        CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "readable-operators.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("operator fixture parses")
    }

    #[test]
    fn operators_and_aliases_select_one_complete_module() {
        for source in [
            "const { Readable } = require('stream'); Readable.from([1]).map(x => x);",
            "const { Readable } = require('node:stream'); const s = Readable.from([1]); s.filter(x => x);",
            "const { Readable } = require('stream'); const s = Readable.from([1]); s['toArray']();",
            "const { Readable } = require('stream'); Readable.from([1]).take(1);",
            "const { Readable } = require('node:stream'); const s = Readable.from([1]); s.drop(1);",
            "const { Readable } = require('stream'); const s = Readable.from([1]); s?.map(x => x);",
            "const { Readable } = require('stream'); const s = Readable.from([1]); const k = 'map'; s[k](x => x);",
            "const { Readable } = require('stream'); const { Writable } = require('node:stream'); Readable.from([1]).map(x => x).pipe(new Writable({}));",
        ] {
            let tree = parse(source);
            let rewritten = rewrite_util_requires(&tree)
                .expect("rewrite succeeds")
                .expect("operators must not be claimed by the legacy facade");
            assert_eq!(
                rewritten
                    .body
                    .iter()
                    .filter(|s| is_module_declaration(s))
                    .count(),
                3,
                "one events, string_decoder and stream module: {source}"
            );
            assert!(
                rewrite_util_requires(&rewritten)
                    .expect("idempotent rewrite")
                    .is_none()
            );
        }
    }

    #[test]
    fn duplex_conversion_keeps_separate_and_aliased_inputs_on_the_native_module() {
        for source in [
            "const { Duplex: D } = require('stream'); const { Readable: R } = require('node:stream'); D.from(R.from([1]));",
            "const { Writable: W } = require('stream'); const { Duplex } = require('node:stream'); Duplex.from(new W({}));",
            "const s = require('stream'); const { Readable } = require('stream'); s.Duplex.from(Readable.from([1]));",
            "const D = require('node:stream').Duplex; const { Readable } = require('stream'); D.from(Readable.from([1]));",
        ] {
            let tree = parse(source);
            let rewritten = rewrite_util_requires(&tree)
                .expect("duplex rewrite")
                .expect("full stream module");
            assert_eq!(
                rewritten
                    .body
                    .iter()
                    .filter(|s| is_module_declaration(s))
                    .count(),
                3,
                "{source}"
            );
            assert!(
                rewrite_util_requires(&rewritten)
                    .expect("idempotent rewrite")
                    .is_none()
            );
        }
    }

    #[test]
    fn paired_transport_keeps_pipeline_constructor_values_on_the_complete_module() {
        for source in [
            "const { duplexPair: pair } = require('stream'); const { Readable } = require('node:stream'); pair(); Readable.from([1]);",
            "const pair = require('node:stream').duplexPair; const { Writable } = require('stream'); pair(); new Writable({});",
            "const s = require('stream'); const { Transform: T } = require('node:stream'); s.duplexPair(); new T({});",
        ] {
            let tree = parse(source);
            let rewritten = rewrite_util_requires(&tree)
                .expect("paired transport rewrite")
                .expect("complete stream module");
            assert_eq!(
                rewritten
                    .body
                    .iter()
                    .filter(|s| is_module_declaration(s))
                    .count(),
                3,
                "{source}"
            );
            assert!(
                rewrite_util_requires(&rewritten)
                    .expect("second pass")
                    .is_none()
            );
        }
    }

    #[test]
    fn cancellation_keeps_separately_imported_stream_constructors_materialized() {
        for source in [
            "const { addAbortSignal: attach } = require('stream'); const { Readable: R } = require('node:stream'); attach(signal, new R({}));",
            "const attach = require('node:stream').addAbortSignal; const { Writable } = require('stream'); attach(signal, new Writable({}));",
            "const s = require('stream'); const { PassThrough } = require('node:stream'); s.addAbortSignal(signal, new PassThrough());",
        ] {
            let tree = parse(source);
            let rewritten = rewrite_util_requires(&tree)
                .expect("cancellation rewrite")
                .expect("complete stream module");
            assert_eq!(
                rewritten
                    .body
                    .iter()
                    .filter(|s| is_module_declaration(s))
                    .count(),
                3,
                "{source}"
            );
            assert!(
                rewrite_util_requires(&rewritten)
                    .expect("second pass")
                    .is_none()
            );
        }
    }

    #[test]
    fn ordinary_constructor_programs_use_the_same_complete_module() {
        for source in [
            "const { Readable } = require('stream'); Readable.from(['a']);",
            "const { Writable, PassThrough: P } = require('stream'); new Writable({}); new P();",
        ] {
            let tree = parse(source);
            let rewritten = rewrite_util_requires(&tree)
                .expect("rewrite")
                .expect("simple constructors also need the shared module");
            assert_eq!(
                rewritten
                    .body
                    .iter()
                    .filter(|statement| is_module_declaration(statement))
                    .count(),
                3,
                "one events, decoder and stream module: {source}"
            );
            assert!(
                rewrite_util_requires(&rewritten)
                    .expect("idempotent")
                    .is_none(),
                "{source}"
            );
        }
    }

    #[test]
    fn constructor_options_keep_all_endpoints_on_the_complete_module() {
        for source in [
            "const { Readable: R }=require('stream'); R.from([1],{signal:controller.signal});",
            "const { Writable: W }=require('node:stream'); new W({signal});",
            "const { PassThrough: P }=require('stream'); new P(settings);",
            "const { Transform: T }=require('stream'); new T({...settings});",
            "const { Writable: W }=require('stream'); W({get signal(){return controller.signal;}});",
            "const { Readable: R }=require('stream'); R.from(...args);",
            "const { Readable: R }=require('stream'); const { Writable: W }=require('node:stream'); R.from([1],settings).pipe(new W({}));",
            "const { Writable: W }=require('stream'); new W({[key]:value});",
        ] {
            let tree = parse(source);
            let rewritten = rewrite_util_requires(&tree)
                .expect("constructor lifecycle rewrite")
                .expect("complete stream module");
            assert_eq!(
                rewritten
                    .body
                    .iter()
                    .filter(|s| is_module_declaration(s))
                    .count(),
                3,
                "{source}"
            );
            assert!(
                rewrite_util_requires(&rewritten)
                    .expect("second pass")
                    .is_none()
            );
        }
    }

    #[test]
    fn unrelated_options_do_not_change_stream_routing_and_shadowed_loaders_stay_local() {
        for source in [
            "const cfg={signal:controller.signal}; const {Readable:R}=require('stream'); R.from([1]);",
            "const {Writable:W}=require('stream'); new Unrelated(settings); new W({});",
        ] {
            let rewritten = rewrite_util_requires(&parse(source))
                .expect("rewrite")
                .expect("the free stream require always selects the shared module");
            assert_eq!(
                rewritten
                    .body
                    .iter()
                    .filter(|statement| is_module_declaration(statement))
                    .count(),
                3,
                "{source}"
            );
        }
        for source in [
            "const require=custom; const {Writable:W}=require('stream'); new W({signal});",
            "function f(require){const {Readable:R}=require('stream'); return R.from([1],{signal});}",
        ] {
            assert!(
                rewrite_util_requires(&parse(source))
                    .expect("scoped loader")
                    .is_none(),
                "{source}"
            );
        }
    }

    #[test]
    fn constructor_cancellation_uses_the_realm_weakmap_not_a_guest_binding() {
        let names = BTreeSet::from(["WeakMap".to_string()]);
        let mut source = super::super::module_source(&names, PureModule::Stream)
            .expect("protected stream module source");
        let free = super::super::tests::free_names(&mut source);
        assert!(!free.contains("WeakMap"));
        assert!(free.contains("globalThis"));
    }

    #[test]
    fn object_keys_and_text_do_not_materialize_a_stream_module() {
        for source in ["const x = { map: 1 };", "const text = 'stream.map(fn)';"] {
            assert!(
                rewrite_util_requires(&parse(source))
                    .expect("rewrite")
                    .is_none()
            );
        }
    }

    #[test]
    fn consumers_materialize_once_and_keep_stream_sources_on_the_complete_path() {
        for (source, count) in [
            (
                "const a = require('stream/consumers'); const b = require('node:stream/consumers');",
                1,
            ),
            (
                "const { Readable } = require('stream'); const c = require('stream/consumers'); c.text(Readable.from(['a']));",
                4,
            ),
        ] {
            let tree = parse(source);
            let rewritten = rewrite_util_requires(&tree)
                .expect("consumer rewrite")
                .expect("consumer module is materialized");
            assert_eq!(
                rewritten
                    .body
                    .iter()
                    .filter(|s| is_module_declaration(s))
                    .count(),
                count,
                "{source}"
            );
            assert!(
                rewrite_util_requires(&rewritten)
                    .expect("second pass")
                    .is_none()
            );
        }
        for source in [
            "function f(require) { return require('stream/consumers'); }",
            "const name = 'stream/consumers'; require(name);",
            "require('stream/consumers/unknown');",
        ] {
            assert!(
                rewrite_util_requires(&parse(source))
                    .expect("rewrite")
                    .is_none()
            );
        }
    }

    #[test]
    fn consumer_source_protects_all_realm_globals_without_host_authority() {
        use super::super::{
            STREAM_CONSUMERS_GLOBALS, module_source, parse_module_source, tests::free_names,
        };
        use std::collections::BTreeSet;

        let expected: BTreeSet<String> = STREAM_CONSUMERS_GLOBALS
            .iter()
            .map(|name| name.to_string())
            .collect();
        assert_eq!(
            free_names(&mut parse_module_source(PureModule::StreamConsumers).expect("parses")),
            expected
        );
        assert_eq!(
            free_names(
                &mut module_source(&expected, PureModule::StreamConsumers)
                    .expect("protected source")
            ),
            BTreeSet::from(["globalThis".to_string()])
        );
    }

    #[test]
    fn web_stages_keep_named_pipeline_and_node_constructors_on_the_shared_module() {
        for source in [
            "const { pipeline } = require('stream'); const web = require('stream/web'); pipeline(source, new web.WritableStream(), done);",
            "const { promises: p, Readable: R } = require('node:stream'); const web = require('node:stream/web'); p.pipeline(R.from([1]), new web.WritableStream());",
        ] {
            let tree = parse(source);
            let rewritten = rewrite_util_requires(&tree)
                .expect("pipeline lowering")
                .expect("complete stream and Web module");
            assert_eq!(
                rewritten
                    .body
                    .iter()
                    .filter(|s| is_module_declaration(s))
                    .count(),
                4,
                "one events, decoder, Web and Node stream factory: {source}"
            );
            assert!(
                rewrite_util_requires(&rewritten)
                    .expect("idempotent")
                    .is_none()
            );
        }
    }

    #[test]
    fn composition_materializes_separately_imported_and_returned_stream_values() {
        for source in [
            "const { Readable: R } = require('stream'); R.from(['a']).compose(stage);",
            "const { Readable } = require('stream'); const s = Readable.from(['a']); s['compose'](stage);",
            "const { compose: chain } = require('node:stream'); const { Transform } = require('stream'); chain(new Transform({}), stage);",
            "const chain = require('stream').compose; const { PassThrough } = require('node:stream'); chain(new PassThrough(), stage);",
        ] {
            let tree = parse(source);
            let rewritten = rewrite_util_requires(&tree)
                .expect("composition lowering")
                .expect("complete stream module");
            assert_eq!(
                rewritten
                    .body
                    .iter()
                    .filter(|s| is_module_declaration(s))
                    .count(),
                3,
                "one events, decoder and stream module: {source}"
            );
            assert!(
                rewrite_util_requires(&rewritten)
                    .expect("idempotent")
                    .is_none()
            );
        }
    }
}
