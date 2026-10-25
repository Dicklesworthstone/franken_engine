//! Bounded parse-once syntax for engine-owned native module sources.
//!
//! A cache belongs to one statically embedded source, never to a guest key.
//! Only the untouched parser expression is shared: every request receives a
//! private clone before global protection, intrinsic renaming or dependency
//! rewriting. No exports, closures, capabilities or execution state are cached.

use std::sync::OnceLock;

use super::LoweringPipelineError;
use crate::ast::{Expression, ParseGoal, Statement};
use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

pub(super) struct NativeModuleSource {
    label: &'static str,
    source: &'static str,
    parsed: OnceLock<Result<Expression, ()>>,
    runtime_parsed: OnceLock<Result<Expression, ()>>,
    #[cfg(test)]
    parse_attempts: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    runtime_parse_attempts: std::sync::atomic::AtomicUsize,
}

impl NativeModuleSource {
    pub(super) const fn new(label: &'static str, source: &'static str) -> Self {
        Self {
            label,
            source,
            parsed: OnceLock::new(),
            runtime_parsed: OnceLock::new(),
            #[cfg(test)]
            parse_attempts: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            runtime_parse_attempts: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Clone syntax, not module instances. Keeping the cache before every
    /// program-dependent transform prevents one program's shadowed globals
    /// or private loader references from contaminating another compilation.
    pub(super) fn expression(&self) -> Result<Expression, LoweringPipelineError> {
        self.parsed
            .get_or_init(|| self.parse(false))
            .as_ref()
            .cloned()
            .map_err(|_| LoweringPipelineError::InvariantViolation {
                detail: "the engine's pure builtin module source failed to parse",
            })
    }

    /// One additional lazy template per fixed embedded source, never a
    /// guest-controlled key. Keep audit metadata out of the legacy template.
    pub(super) fn runtime_expression(&self) -> Result<Expression, LoweringPipelineError> {
        self.runtime_parsed
            .get_or_init(|| self.parse(true))
            .as_ref()
            .cloned()
            .map_err(|_| LoweringPipelineError::InvariantViolation {
                detail: "the engine's native runtime source failed to parse",
            })
    }

    /// Test-only observation of this exact source's production parse path.
    #[cfg(test)]
    pub(super) fn parse_attempt_count(&self) -> usize {
        self.parse_attempts.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn parse(&self, retain_runtime_sources: bool) -> Result<Expression, ()> {
        #[cfg(test)]
        {
            let attempts = if retain_runtime_sources {
                &self.runtime_parse_attempts
            } else {
                &self.parse_attempts
            };
            attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        let source = ParserSource {
            label: self.label.into(),
            text: self.source.into(),
        };
        let tree = if retain_runtime_sources {
            CanonicalEs2020Parser.parse_native_runtime_with_function_sources(
                source,
                ParseGoal::Script,
                &ParserOptions::default(),
            )
        } else {
            CanonicalEs2020Parser.parse_with_options(
                source,
                ParseGoal::Script,
                &ParserOptions::default(),
            )
        }
        .map_err(|_| ())?;
        // Move the owned expression out of the parser result. A cold parse
        // must not deep-clone the tree before saving its immutable template.
        let mut body = tree.body.into_iter();
        match (body.next(), body.next()) {
            (Some(Statement::Expression(statement)), None) => match statement.expression {
                // Raw is an unresolved parser fallback, not a parsed builtin
                // expression. Never publish it as a successful native template.
                Expression::Raw(_) => Err(()),
                expression => Ok(expression),
            },
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::sync::atomic::Ordering;

    use super::*;

    const SOURCE: &str = "(function () { return ['cached', 42]; })()";

    fn fresh_expression(label: &str, source: &str) -> Expression {
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource { label: label.into(), text: source.into() },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("reference source parses");
        let [Statement::Expression(statement)] = tree.body.as_slice() else {
            panic!("reference source is one expression");
        };
        statement.expression.clone()
    }

    #[test]
    fn construction_is_lazy_and_repeated_requests_parse_once() {
        let source = NativeModuleSource::new("franken:cache-probe", SOURCE);
        assert!(source.parsed.get().is_none());
        assert_eq!(source.parse_attempts.load(Ordering::Relaxed), 0);
        let expected = fresh_expression("franken:cache-probe", SOURCE);
        for _ in 0..32 {
            assert_eq!(source.expression().expect("cached expression"), expected);
        }
        assert_eq!(source.parse_attempts.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn native_runtime_metadata_templates_are_lazy_separate_and_parse_once() {
        fn source_text(expression: &Expression) -> Option<&str> {
            let Expression::Call { callee, .. } = expression else {
                panic!("factory call");
            };
            let Expression::Function { source_text, .. } = callee.as_ref() else {
                panic!("factory function");
            };
            source_text
                .as_ref()
                .map(crate::ast::FunctionSourceText::as_str)
        }
        let source = NativeModuleSource::new("franken:cache-audit", SOURCE);
        assert!(source.parsed.get().is_none() && source.runtime_parsed.get().is_none());
        let legacy = source.expression().unwrap();
        assert!(source_text(&legacy).is_none());
        assert!(source.runtime_parsed.get().is_none());
        let runtime = source.runtime_expression().unwrap();
        assert_eq!(
            source_text(&runtime),
            Some("function () { return ['cached', 42]; }")
        );
        assert_eq!(legacy.canonical_value(), runtime.canonical_value());
        for _ in 0..16 {
            assert_eq!(source.expression().unwrap(), legacy);
            assert_eq!(source.runtime_expression().unwrap(), runtime);
        }
        let mut changed = source.runtime_expression().unwrap();
        let Expression::Call { arguments, .. } = &mut changed else {
            panic!("factory call");
        };
        arguments.push(Expression::UndefinedLiteral);
        assert_eq!(source.runtime_expression().unwrap(), runtime);
        assert_eq!(source.expression().unwrap(), legacy);
        assert_eq!(source.parse_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(source.runtime_parse_attempts.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn modifying_a_returned_tree_cannot_modify_the_cached_template() {
        let source = NativeModuleSource::new("franken:cache-isolation", SOURCE);
        let expected = fresh_expression("franken:cache-isolation", SOURCE);
        let mut first = source.expression().expect("first parse");
        let Expression::Call { arguments, .. } = &mut first else {
            panic!("source is an IIFE");
        };
        arguments.push(Expression::UndefinedLiteral);
        assert_ne!(first, expected);
        assert_eq!(source.expression().expect("next request"), expected);
        assert_eq!(source.parse_attempts.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn simultaneous_first_requests_publish_one_complete_parse() {
        let source = NativeModuleSource::new("franken:cache-concurrent", SOURCE);
        let barrier = Barrier::new(8);
        let expected = fresh_expression("franken:cache-concurrent", SOURCE);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        source.expression().expect("shared first parse")
                    })
                })
                .collect();
            for handle in handles {
                assert_eq!(handle.join().expect("parser thread"), expected);
            }
        });
        assert_eq!(source.parse_attempts.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn failed_embedded_sources_are_cached_without_publishing_partial_syntax() {
        for text in ["(", "", "const value = 1;", "1; 2;"] {
            let source = NativeModuleSource::new("franken:invalid-source", text);
            assert!(source.parsed.get().is_none() && source.runtime_parsed.get().is_none());
            for _ in 0..3 {
                assert!(
                    matches!(
                        source.expression(),
                        Err(LoweringPipelineError::InvariantViolation {
                            detail: "the engine's pure builtin module source failed to parse"
                        })
                    ),
                    "legacy source {text:?}"
                );
                assert!(
                    matches!(
                        source.runtime_expression(),
                        Err(LoweringPipelineError::InvariantViolation {
                            detail: "the engine's native runtime source failed to parse"
                        })
                    ),
                    "runtime source {text:?}"
                );
            }
            assert!(matches!(source.parsed.get(), Some(Err(()))));
            assert!(matches!(source.runtime_parsed.get(), Some(Err(()))));
            assert_eq!(source.parse_attempts.load(Ordering::Relaxed), 1);
            assert_eq!(source.runtime_parse_attempts.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn equal_labels_do_not_alias_distinct_embedded_sources() {
        let first = NativeModuleSource::new("franken:same-label", "'first'");
        let second = NativeModuleSource::new("franken:same-label", "'second'");
        assert_ne!(first.expression().unwrap(), second.expression().unwrap());
        assert_eq!(first.parse_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(second.parse_attempts.load(Ordering::Relaxed), 1);
    }
}
