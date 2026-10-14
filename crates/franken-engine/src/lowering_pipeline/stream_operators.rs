//! Keep collection-operator programs on the complete stream module path.
//!
//! The legacy facade proves constructor forms, not the subsequent methods of
//! the values those forms return. Claiming `Readable.from(xs)` inside
//! `Readable.from(xs).map(fn)` would erase the binding and bypass the module
//! that installs the operators. The same problem occurs through an alias.
//!
//! Until the facade has value-flow/type information, a collection member (or
//! a dynamically computed member) conservatively selects the complete module
//! for ALL stream constructors in the program. Ordinary facade-only programs
//! keep their fast path; we do not guess that an alias is an array or a stream.

use super::{Expression, Outcome, Statement, Walk, walk_expression, walk_statement};

pub(super) fn requires_stream_module(body: &[Statement]) -> bool {
    let mut search = OperatorUse { found: false };
    // The canonical walker accepts mutable nodes; it does not change them.
    // Fail toward the full module if a future AST form cannot be walked.
    search.statements(&mut body.to_vec()).is_err() || search.found
}

struct OperatorUse {
    found: bool,
}

impl Walk for OperatorUse {
    fn statement(&mut self, statement: &mut Statement) -> Outcome {
        if self.found {
            return Ok(());
        }
        walk_statement(self, statement)
    }

    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if self.found {
            return Ok(());
        }
        if let Expression::Member { property, computed, .. }
        | Expression::OptionalMember { property, computed, .. } = &*expression
        {
            let name = match (*computed, property.as_ref()) {
                (false, Expression::Identifier(name)) => Some(name.as_str()),
                (true, Expression::StringLiteral(name)) => name.as_str(),
                // A dynamic key might be an operator name; constructor-form
                // recognition alone cannot prove the facade can service it.
                (true, _) => {
                    self.found = true;
                    return Ok(());
                }
                _ => None,
            };
            self.found = matches!(
                name,
                Some(
                    "map" | "filter" | "flatMap" | "toArray" | "forEach"
                        | "some" | "every" | "find" | "reduce" | "take" | "drop"
                )
            );
            if self.found {
                return Ok(());
            }
        }
        walk_expression(self, expression)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{is_module_declaration, rewrite_util_requires};
    use crate::ast::{ParseGoal, SyntaxTree};
    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

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
            assert!(requires_stream_module(&tree.body), "{source}");
            let rewritten = rewrite_util_requires(&tree)
                .expect("rewrite succeeds")
                .expect("operators must not be claimed by the legacy facade");
            assert_eq!(
                rewritten.body.iter().filter(|s| is_module_declaration(s)).count(),
                3,
                "one events, string_decoder and stream module: {source}"
            );
            assert!(rewrite_util_requires(&rewritten).expect("idempotent rewrite").is_none());
        }
    }

    #[test]
    fn ordinary_constructor_programs_keep_the_facade_fast_path() {
        for source in [
            "const { Readable } = require('stream'); Readable.from(['a']);",
            "const { Writable, PassThrough: P } = require('stream'); new Writable({}); new P();",
        ] {
            let tree = parse(source);
            assert!(!requires_stream_module(&tree.body), "{source}");
            assert!(rewrite_util_requires(&tree).expect("rewrite").is_none(), "{source}");
        }
    }

    #[test]
    fn object_keys_and_text_are_not_operator_accesses() {
        for source in ["const x = { map: 1 };", "const text = 'stream.map(fn)';"] {
            assert!(!requires_stream_module(&parse(source).body));
        }
    }
}
