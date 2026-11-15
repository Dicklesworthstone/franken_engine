//! Keep low-level stream regressions independent of the public module route.
//!
//! Named ESM imports now resolve to the complete stream module, as CJS does.
//! The older kernel fixtures still need to exercise interpreter-owned state
//! and its GC roots. Replace only their parsed import declarations with
//! adapters to the existing typed builtin hostcall interface. The fixture's
//! call sites, callbacks, scheduling and assertions stay unchanged.

use frankenengine_engine::ast::{ImportClause, Statement};
use frankenengine_engine::parser_api_stability::parse_module;

pub fn source(source: &str) -> String {
    if !source.contains("import ") {
        return source.to_string();
    }
    let tree = parse_module(source).expect("native stream fixture parses");
    let mut declarations = String::new();
    let mut body = String::new();
    let mut cursor = 0;
    for statement in &tree.body {
        let Statement::Import(import) = statement else {
            continue;
        };
        let Some(specifier) = import.source.as_str() else {
            continue;
        };
        let module = specifier.strip_prefix("node:").unwrap_or(specifier);
        if !matches!(module, "stream" | "stream/promises") {
            continue;
        }
        assert!(import.import_attributes.is_empty());
        let ImportClause::Named { specifiers } = &import.clause else {
            panic!("kernel fixtures must name the stream kernels they exercise");
        };
        for specifier in specifiers {
            let local = &specifier.local_name;
            let kernel = match (module, specifier.import_name.as_str()) {
                ("stream", "Readable") => "StreamReadable",
                ("stream", "Writable") => "StreamWritable",
                ("stream", "PassThrough") => "StreamPassThrough",
                ("stream", "Transform") => "StreamTransform",
                ("stream", "pipeline") => "StreamPipeline",
                ("stream/promises", "pipeline") => "StreamPromisesPipeline",
                _ => panic!("unsupported kernel fixture binding: {specifier:?}"),
            };
            if specifier.import_name == "pipeline" {
                declarations.push_str(&format!(
                    "function {local}(...stages) {{ return \
                     hostcall<\"builtin:ApplyHostCall:builtin:{kernel}\">(\"builtin:{kernel}\", stages); }}\n"
                ));
            } else {
                declarations.push_str(&format!(
                    "function {local}(options) {{ return hostcall<\"builtin:{kernel}\">(options); }}\n"
                ));
                if specifier.import_name == "Readable" {
                    declarations.push_str(&format!(
                        "{local}.from = function (iterable, options) {{ return \
                         hostcall<\"builtin:StreamReadableFrom\">(iterable, options); }};\n"
                    ));
                }
            }
        }
        let start = usize::try_from(import.span.start_offset).expect("fixture import start");
        let end = usize::try_from(import.span.end_offset).expect("fixture import end");
        body.push_str(&source[cursor..start]);
        cursor = end;
    }
    if declarations.is_empty() {
        return source.to_string();
    }
    body.push_str(&source[cursor..]);
    // Retain the original module parse goal after removing its last import.
    format!("export {{}};\n{declarations}\n{body}")
}
