#![forbid(unsafe_code)]

//! Reusable JS conformance runner for YouTube BotGuard gap work.
//!
//! This helper is intentionally offline-first. CI tests provide frozen expected
//! values and compare FrankenEngine output against them without invoking Node,
//! the network, or any external service. Maintainer tooling can be layered on
//! top later to refresh expectations, but this module is the stable execution
//! and logging surface used by integration tests.

use frankenengine_engine::HybridRouter;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

pub const JS_CONFORMANCE_RUNNER_SCHEMA: &str = "franken-engine.js-conformance-report.v1";
pub const JS_CONFORMANCE_RUNNER_ID: &str =
    "franken-engine.hybrid-router.js-conformance-runner.offline.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsConformanceVector {
    pub id: &'static str,
    pub category: &'static str,
    pub source: &'static str,
    pub expected: JsConformanceExpectation,
}

impl JsConformanceVector {
    pub const fn value(
        id: &'static str,
        category: &'static str,
        source: &'static str,
        value: &'static str,
    ) -> Self {
        Self {
            id,
            category,
            source,
            expected: JsConformanceExpectation::Value { value },
        }
    }

    pub const fn caught_value(
        id: &'static str,
        category: &'static str,
        source: &'static str,
        value: &'static str,
    ) -> Self {
        Self {
            id,
            category,
            source,
            expected: JsConformanceExpectation::CaughtValue { value },
        }
    }

    pub const fn engine_error(
        id: &'static str,
        category: &'static str,
        source: &'static str,
        namespace: &'static str,
        message_contains: Option<&'static str>,
    ) -> Self {
        Self {
            id,
            category,
            source,
            expected: JsConformanceExpectation::EngineError {
                namespace,
                message_contains,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsConformanceExpectation {
    Value {
        value: &'static str,
    },
    CaughtValue {
        value: &'static str,
    },
    EngineError {
        namespace: &'static str,
        message_contains: Option<&'static str>,
    },
}

impl JsConformanceExpectation {
    fn expected_kind(&self) -> &'static str {
        match self {
            Self::Value { .. } => "value",
            Self::CaughtValue { .. } => "caught_value",
            Self::EngineError { .. } => "engine_error",
        }
    }

    fn expected_result(&self) -> String {
        match self {
            Self::Value { value } | Self::CaughtValue { value } => (*value).to_owned(),
            Self::EngineError { namespace, .. } => (*namespace).to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsConformanceReport {
    pub schema_version: String,
    pub runner_id: String,
    pub total_vectors: u32,
    pub passed: u32,
    pub failed: u32,
    pub logs: Vec<JsConformanceLog>,
}

impl JsConformanceReport {
    pub fn assert_all_passed(&self) {
        if self.failed == 0 {
            return;
        }

        let rendered = serde_json::to_string_pretty(self)
            .unwrap_or_else(|err| format!("failed to render conformance report: {err}"));
        panic!("JS conformance report contained failures:\n{rendered}");
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsConformanceLog {
    pub vector_id: String,
    pub category: String,
    pub expected_kind: String,
    pub expected_result: String,
    pub actual_kind: String,
    pub actual_result: String,
    pub passed: bool,
    pub duration_ns: u64,
    pub source_hash: String,
    pub engine: Option<String>,
    pub route_reason: Option<String>,
    pub error_class: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

pub fn run_js_conformance_vectors(vectors: &[JsConformanceVector]) -> JsConformanceReport {
    let mut logs = Vec::with_capacity(vectors.len());
    let mut router = HybridRouter::default();

    for vector in vectors {
        logs.push(run_one_vector(&mut router, vector));
    }

    let passed = logs.iter().filter(|log| log.passed).count() as u32;
    let total_vectors = logs.len() as u32;
    let failed = total_vectors.saturating_sub(passed);

    JsConformanceReport {
        schema_version: JS_CONFORMANCE_RUNNER_SCHEMA.to_owned(),
        runner_id: JS_CONFORMANCE_RUNNER_ID.to_owned(),
        total_vectors,
        passed,
        failed,
        logs,
    }
}

pub fn assert_js_conformance_vectors(vectors: &[JsConformanceVector]) -> JsConformanceReport {
    let report = run_js_conformance_vectors(vectors);
    report.assert_all_passed();
    report
}

fn run_one_vector(router: &mut HybridRouter, vector: &JsConformanceVector) -> JsConformanceLog {
    let source_hash = source_hash(vector.source);
    let started = Instant::now();
    let result = router.eval(vector.source);
    let duration_ns = saturating_duration_ns(started.elapsed().as_nanos());

    match result {
        Ok(outcome) => {
            let actual_result = outcome.value.clone();
            let passed = match &vector.expected {
                JsConformanceExpectation::Value { value }
                | JsConformanceExpectation::CaughtValue { value } => actual_result == *value,
                JsConformanceExpectation::EngineError { .. } => false,
            };

            JsConformanceLog {
                vector_id: vector.id.to_owned(),
                category: vector.category.to_owned(),
                expected_kind: vector.expected.expected_kind().to_owned(),
                expected_result: vector.expected.expected_result(),
                actual_kind: "value".to_owned(),
                actual_result,
                passed,
                duration_ns,
                source_hash,
                engine: Some(outcome.engine.to_string()),
                route_reason: Some(outcome.route_reason.to_string()),
                error_class: None,
                error_code: None,
                error_message: None,
            }
        }
        Err(err) => {
            let error_code = err.stable_namespace().to_owned();
            let error_message = err.message.clone();
            let passed = match &vector.expected {
                JsConformanceExpectation::EngineError {
                    namespace,
                    message_contains,
                } => {
                    error_code == *namespace
                        && message_contains.is_none_or(|needle| error_message.contains(needle))
                }
                JsConformanceExpectation::Value { .. }
                | JsConformanceExpectation::CaughtValue { .. } => false,
            };

            JsConformanceLog {
                vector_id: vector.id.to_owned(),
                category: vector.category.to_owned(),
                expected_kind: vector.expected.expected_kind().to_owned(),
                expected_result: vector.expected.expected_result(),
                actual_kind: "engine_error".to_owned(),
                actual_result: error_code.clone(),
                passed,
                duration_ns,
                source_hash,
                engine: None,
                route_reason: None,
                error_class: Some(err.class().stable_label().to_owned()),
                error_code: Some(error_code),
                error_message: Some(error_message),
            }
        }
    }
}

fn source_hash(source: &str) -> String {
    let digest = Sha256::digest(source.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

fn saturating_duration_ns(value: u128) -> u64 {
    if value > u128::from(u64::MAX) {
        u64::MAX
    } else {
        value as u64
    }
}
