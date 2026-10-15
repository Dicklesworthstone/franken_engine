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
    #[cfg(test)]
    parse_attempts: std::sync::atomic::AtomicUsize,
}

impl NativeModuleSource {
    pub(super) const fn new(label: &'static str, source: &'static str) -> Self {
        Self {
            label,
            source,
            parsed: OnceLock::new(),
            #[cfg(test)]
            parse_attempts: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Clone syntax, not module instances. Keeping the cache before every
    /// program-dependent transform prevents one program's shadowed globals
    /// or private loader references from contaminating another compilation.
    pub(super) fn expression(&self) -> Result<Expression, LoweringPipelineError> {
        self.parsed
            .get_or_init(|| self.parse())
            .as_ref()
            .cloned()
            .map_err(|_| LoweringPipelineError::InvariantViolation {
                detail: "the engine's pure builtin module source failed to parse",
            })
    }

    /// Test-only observation of this exact source's production parse path.
    #[cfg(test)]
    pub(super) fn parse_attempt_count(&self) -> usize {
        self.parse_attempts.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn parse(&self) -> Result<Expression, ()> {
        #[cfg(test)]
        self.parse_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: self.label.into(),
                    text: self.source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .map_err(|_| ())?;
        // Move the owned expression out of the parser result. A cold parse
        // must not deep-clone the tree before saving its immutable template.
        let mut body = tree.body.into_iter();
        match (body.next(), body.next()) {
            (Some(Statement::Expression(statement)), None) => Ok(statement.expression),
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
            for _ in 0..3 {
                assert!(matches!(
                    source.expression(),
                    Err(LoweringPipelineError::InvariantViolation {
                        detail: "the engine's pure builtin module source failed to parse"
                    })
                ));
            }
            assert!(matches!(source.parsed.get(), Some(Err(()))));
            assert_eq!(source.parse_attempts.load(Ordering::Relaxed), 1);
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
