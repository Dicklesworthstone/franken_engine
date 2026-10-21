//! First-class compression exports, sharing existing codec hostcalls and budgets.
//! No provider, external engine, new codec, or new capability is introduced.

pub(super) const BINDING: &str = "%zlib_module";
pub(super) const SOURCE: &str = include_str!("zlib_module.js");
pub(super) const GLOBALS: [&str; 1] = ["Object"];
pub(super) const PLACEHOLDERS: [(&str, &str); 14] = [
    ("__franken_zlib_gzip_sync", "%ZlibGzipSync"),
    ("__franken_zlib_gunzip_sync", "%ZlibGunzipSync"),
    ("__franken_zlib_deflate_sync", "%ZlibDeflateSync"),
    ("__franken_zlib_inflate_sync", "%ZlibInflateSync"),
    ("__franken_zlib_deflate_raw_sync", "%ZlibDeflateRawSync"),
    ("__franken_zlib_inflate_raw_sync", "%ZlibInflateRawSync"),
    ("__franken_zlib_unzip_sync", "%ZlibUnzipSync"),
    ("__franken_zlib_brotli_compress_sync", "%ZlibBrotliCompressSync"),
    ("__franken_zlib_brotli_decompress_sync", "%ZlibBrotliDecompressSync"),
    ("__franken_zlib_gzip", "%ZlibGzip"),
    ("__franken_zlib_gunzip", "%ZlibGunzip"),
    ("__franken_zlib_deflate", "%ZlibDeflate"),
    ("__franken_zlib_inflate", "%ZlibInflate"),
    ("__franken_zlib_constants", "%ZlibConstants"),
];

pub(super) fn intrinsic_capability(name: &str) -> Option<&'static str> {
    match name {
        "%ZlibGzipSync" => Some("builtin:ZlibGzipSync"),
        "%ZlibGunzipSync" => Some("builtin:ZlibGunzipSync"),
        "%ZlibDeflateSync" => Some("builtin:ZlibDeflateSync"),
        "%ZlibInflateSync" => Some("builtin:ZlibInflateSync"),
        "%ZlibDeflateRawSync" => Some("builtin:ZlibDeflateRawSync"),
        "%ZlibInflateRawSync" => Some("builtin:ZlibInflateRawSync"),
        "%ZlibUnzipSync" => Some("builtin:ZlibUnzipSync"),
        "%ZlibBrotliCompressSync" => Some("builtin:ZlibBrotliCompressSync"),
        "%ZlibBrotliDecompressSync" => Some("builtin:ZlibBrotliDecompressSync"),
        "%ZlibGzip" => Some("builtin:ZlibGzip"),
        "%ZlibGunzip" => Some("builtin:ZlibGunzip"),
        "%ZlibDeflate" => Some("builtin:ZlibDeflate"),
        "%ZlibInflate" => Some("builtin:ZlibInflate"),
        "%ZlibConstants" => Some("builtin:ZlibConstants"),
        _ => None,
    }
}

// Keep the legacy direct-call optimization only when EVERY literal zlib
// request in this program belongs to one of its proven top-level aliases.
// Mixing an elided alias with a materialized one would ignore public export
// replacement through the latter. Constants also have observable identity,
// so they use the cached module rather than repeated native allocations.
pub(super) fn claimed_declarators(
    body: &[super::Statement],
) -> std::collections::BTreeSet<(usize, usize)> {
    use super::{
        BindingPattern, Expression, Outcome, PureModule, Statement, Walk,
        builtin_require_member, walk_expression,
    };
    use std::collections::{BTreeMap, BTreeSet};

    struct Uses { requests: usize, constants: bool }
    impl Walk for Uses {
        fn expression(&mut self, expression: &mut Expression) -> Outcome {
            if matches!(builtin_require_member(expression), Some((PureModule::Zlib, None))) {
                self.requests += 1;
            }
            if let Expression::Member { property, computed, .. }
                | Expression::OptionalMember { property, computed, .. } = &*expression
                && ((!*computed && matches!(property.as_ref(), Expression::Identifier(n) if n == "constants"))
                    || (*computed && matches!(property.as_ref(), Expression::StringLiteral(n) if *n == "constants")))
            {
                self.constants = true;
            }
            walk_expression(self, expression)
        }
    }
    const ZLIB: super::Search = super::Search {
        statement: |_| false,
        expression: |expression| {
            matches!(super::builtin_require_member(expression), Some((super::PureModule::Zlib, None)))
        },
    };
    if !body.iter().any(|statement| ZLIB.in_statement(statement)) {
        return BTreeSet::new();
    }
    let mut uses = Uses { requests: 0, constants: false };
    if uses.statements(&mut body.to_vec()).is_err() || uses.constants {
        return BTreeSet::new();
    }
    let confirmed = super::super::confirmed_zlib_module_aliases(body, &BTreeMap::new());
    let mut claimed = BTreeSet::new();
    for (i, statement) in body.iter().enumerate() {
        let Statement::VariableDeclaration(declaration) = statement else { continue; };
        for (j, declarator) in declaration.declarations.iter().enumerate() {
            let BindingPattern::Identifier(local) = &declarator.pattern else { continue; };
            if confirmed.contains(local)
                && declarator.initializer.as_ref().is_some_and(|initializer| {
                    matches!(builtin_require_member(initializer), Some((PureModule::Zlib, None)))
                })
            {
                claimed.insert((i, j));
            }
        }
    }
    if uses.requests == claimed.len() { claimed } else { BTreeSet::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{
        PureModule, is_module_declaration, module_source, parse_module_source,
        rewrite_util_requires, tests::free_names,
    };
    use crate::ast::{ParseGoal, SyntaxTree};
    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
    use std::collections::BTreeSet;

    fn parse(source: &str) -> SyntaxTree {
        CanonicalEs2020Parser.parse_with_options(
            ParserSource { label: "first-class-zlib.js".into(), text: source.into() },
            ParseGoal::Script, &ParserOptions::default(),
        ).expect("zlib fixture parses")
    }

    #[test]
    fn escaped_exports_and_aliases_share_one_module_and_idempotent_loader() {
        for source in [
            "const z=require('zlib'); const g=z.gzipSync; g('x');",
            "const {gzipSync:g,gunzipSync:u}=require('node:zlib'); u(g('x'));",
            "const a=require('zlib'); const b=require('node:zlib'); console.log(a===b);",
            "function load(){return require('zlib');} load();",
            "const z=require('zlib'); z['gzipSync']('x');",
            "const a=require('zlib'); const b=require('node:zlib'); b.gzipSync=f; a.gzipSync('x');",
            "const z=require('node:zlib'); console.log(z.constants===z.constants);",
        ] {
            let tree = parse(source);
            let rewritten = rewrite_util_requires(&tree).unwrap().expect("zlib module");
            assert_eq!(rewritten.body.iter().filter(|s| is_module_declaration(s)).count(), 1, "{source}");
            assert!(rewrite_util_requires(&rewritten).unwrap().is_none(), "{source}");
        }
    }

    #[test]
    fn proven_direct_calls_keep_existing_fast_path_and_dynamic_requires_keep_authority() {
        for source in [
            "const z=require('zlib'); z.gunzipSync(z.gzipSync('x'));",
            "function f(require){return require('zlib');}",
            "{const require=custom;require('node:zlib');}",
            "const name='zlib'; require(name);",
            "require('zlib/unknown');",
        ] {
            assert!(rewrite_util_requires(&parse(source)).unwrap().is_none(), "{source}");
        }
    }

    #[test]
    fn esm_named_default_namespace_and_reexport_forms_materialize_the_same_module() {
        for source in [
            "import {gzipSync as pack} from 'node:zlib'; const call=pack; call('x');",
            "import z from 'zlib'; const pack=z.gzipSync; pack('x');",
            "import * as z from 'node:zlib'; const pack=z.gzipSync; pack('x');",
            "export {gzipSync as pack,gunzipSync as unpack} from 'node:zlib';",
            "export {default as codecs} from 'zlib';",
        ] {
            let tree = CanonicalEs2020Parser.parse_with_options(
                ParserSource { label: "zlib-exports.mjs".into(), text: source.into() },
                ParseGoal::Module, &ParserOptions::default(),
            ).unwrap();
            let imported = super::super::super::esm_core_imports::rewrite_core_module_imports(&tree)
                .expect("core import lowering");
            let rewritten = rewrite_util_requires(&imported).unwrap().expect("first-class zlib");
            assert_eq!(rewritten.body.iter().filter(|s| is_module_declaration(s)).count(), 1, "{source}");
            assert!(rewrite_util_requires(&rewritten).unwrap().is_none());
        }
        // Named imports are captured once. Rewriting every use into a public
        // property read would let a namespace mutation redirect `pack` later.
        let tree = CanonicalEs2020Parser.parse_with_options(
            ParserSource {
                label: "zlib-import-snapshot.mjs".into(),
                text: "import z,{gzipSync as pack} from 'zlib'; z.gzipSync=f; pack('x');".into(),
            },
            ParseGoal::Module, &ParserOptions::default(),
        ).unwrap();
        let imported = super::super::super::esm_core_imports::rewrite_core_module_imports(&tree)
            .expect("named import snapshot");
        assert!(imported.body.iter().any(|statement| {
            let crate::ast::Statement::VariableDeclaration(declaration) = statement else {
                return false;
            };
            declaration.declarations.iter().any(|declarator| {
                let crate::ast::BindingPattern::ObjectPattern(properties) = &declarator.pattern else {
                    return false;
                };
                properties.iter().any(|property| matches!(
                    &property.value, crate::ast::BindingPattern::Identifier(name) if name == "pack"
                ))
            })
        }), "the named import must retain its own binding");
    }

    #[test]
    fn compression_source_uses_exact_native_contracts_and_protects_guest_object_binding() {
        let mut expected: BTreeSet<String> = GLOBALS.iter().map(|s| (*s).into()).collect();
        expected.extend(PLACEHOLDERS.iter().map(|(name, _)| (*name).into()));
        assert_eq!(free_names(&mut parse_module_source(PureModule::Zlib).unwrap()), expected);
        let names = BTreeSet::from(["Object".to_string()]);
        let mut protected = BTreeSet::from(["globalThis".to_string()]);
        protected.extend(PLACEHOLDERS.iter().map(|(_, name)| (*name).into()));
        assert_eq!(free_names(&mut module_source(&names, PureModule::Zlib).unwrap()), protected);
        for (placeholder, intrinsic) in PLACEHOLDERS {
            assert_eq!(intrinsic_capability(placeholder), None);
            assert_eq!(intrinsic_capability(intrinsic).unwrap(), format!("builtin:{}", &intrinsic[1..]));
        }
        assert_eq!(intrinsic_capability(BINDING), None);
        assert_eq!(intrinsic_capability("%ZlibInvented"), None);
    }
}
