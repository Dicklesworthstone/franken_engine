//! Service endpoint integration template backed by adapted `fastapi_rust` contracts.
//!
//! This module defines framework-agnostic request/response envelopes for
//! service surfaces that FrankenEngine exposes to operators and automation:
//! - health
//! - control actions
//! - evidence export
//! - replay control
//!
//! Engine-domain payloads stay transport-neutral, but the public route contract
//! and serialized HTTP response adapter use `/dp/fastapi_rust/crates/fastapi-core`
//! request/response primitives directly. That keeps the service/API boundary
//! tied to the sibling framework without forcing runtime internals to become
//! HTTP handlers.

use std::collections::BTreeMap;

use fastapi_core::{
    Method as FastapiMethod, Request as FastapiRequest, Response as FastapiResponse,
    ResponseBody as FastapiResponseBody, StatusCode as FastapiStatusCode,
};
use serde::{Deserialize, Serialize};

pub const FASTAPI_RUST_ADR: &str = "docs/adr/ADR-0002-fastapi-rust-reuse-scope.md";
pub const FASTAPI_RUST_BOUNDARY: &str = "/dp/fastapi_rust/crates/fastapi-core";

pub const SCOPE_HEALTH_READ: &str = "engine.health.read";
pub const SCOPE_CONTROL_WRITE: &str = "engine.control.write";
pub const SCOPE_EVIDENCE_READ: &str = "engine.evidence.read";
pub const SCOPE_REPLAY_READ: &str = "engine.replay.read";
pub const SCOPE_REPLAY_WRITE: &str = "engine.replay.write";

const FASTAPI_REQUEST_COMPONENT: &str = "fastapi_core::Request";
const FASTAPI_RESPONSE_COMPONENT: &str = "fastapi_core::Response";
const FASTAPI_STATUS_COMPONENT: &str = "fastapi_core::StatusCode";
const FASTAPI_METHOD_COMPONENT: &str = "fastapi_core::Method";
const FASTAPI_JSON_COMPONENT: &str = "fastapi_core::ResponseBody::Bytes";
const FASTAPI_AUTH_COMPONENT: &str = "fastapi_core::middleware::Middleware";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastapiEndpointFamily {
    Health,
    ControlAction,
    EvidenceExport,
    ReplayControl,
}

impl FastapiEndpointFamily {
    fn as_str(self) -> &'static str {
        match self {
            Self::Health => "health",
            Self::ControlAction => "control_action",
            Self::EvidenceExport => "evidence_export",
            Self::ReplayControl => "replay_control",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastapiEndpointContract {
    pub family: FastapiEndpointFamily,
    pub endpoint: &'static str,
    pub method: FastapiMethod,
    pub path: &'static str,
    pub required_scope: &'static str,
    pub component_refs: &'static [&'static str],
}

impl FastapiEndpointContract {
    pub fn method_name(&self) -> &'static str {
        self.method.as_str()
    }

    pub fn matches_request(&self, request: &FastapiRequest) -> bool {
        request.method() == self.method && request.path() == self.path
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastapiEndpointEvidence {
    pub family: String,
    pub endpoint: String,
    pub method: String,
    pub path: String,
    pub required_scope: String,
    pub backed_by: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastapiReuseEvidence {
    pub boundary: String,
    pub repo_path: String,
    pub adr: String,
    pub proof_state: String,
    pub components: Vec<String>,
    pub endpoints: Vec<FastapiEndpointEvidence>,
}

pub fn fastapi_endpoint_contracts() -> Vec<FastapiEndpointContract> {
    vec![
        FastapiEndpointContract {
            family: FastapiEndpointFamily::Health,
            endpoint: "health",
            method: FastapiMethod::Get,
            path: "/v1/engine/health",
            required_scope: SCOPE_HEALTH_READ,
            component_refs: &[
                FASTAPI_REQUEST_COMPONENT,
                FASTAPI_RESPONSE_COMPONENT,
                FASTAPI_STATUS_COMPONENT,
            ],
        },
        FastapiEndpointContract {
            family: FastapiEndpointFamily::ControlAction,
            endpoint: "control_action",
            method: FastapiMethod::Post,
            path: "/v1/engine/control/actions",
            required_scope: SCOPE_CONTROL_WRITE,
            component_refs: &[
                FASTAPI_REQUEST_COMPONENT,
                FASTAPI_RESPONSE_COMPONENT,
                FASTAPI_AUTH_COMPONENT,
            ],
        },
        FastapiEndpointContract {
            family: FastapiEndpointFamily::EvidenceExport,
            endpoint: "evidence_export",
            method: FastapiMethod::Get,
            path: "/v1/engine/evidence",
            required_scope: SCOPE_EVIDENCE_READ,
            component_refs: &[
                FASTAPI_REQUEST_COMPONENT,
                FASTAPI_RESPONSE_COMPONENT,
                FASTAPI_JSON_COMPONENT,
            ],
        },
        FastapiEndpointContract {
            family: FastapiEndpointFamily::ReplayControl,
            endpoint: "replay_status",
            method: FastapiMethod::Get,
            path: "/v1/engine/replay/status",
            required_scope: SCOPE_REPLAY_READ,
            component_refs: &[
                FASTAPI_REQUEST_COMPONENT,
                FASTAPI_RESPONSE_COMPONENT,
                FASTAPI_STATUS_COMPONENT,
            ],
        },
        FastapiEndpointContract {
            family: FastapiEndpointFamily::ReplayControl,
            endpoint: "replay_control",
            method: FastapiMethod::Post,
            path: "/v1/engine/replay/control",
            required_scope: SCOPE_REPLAY_WRITE,
            component_refs: &[
                FASTAPI_REQUEST_COMPONENT,
                FASTAPI_RESPONSE_COMPONENT,
                FASTAPI_STATUS_COMPONENT,
            ],
        },
    ]
}

pub fn match_fastapi_request(request: &FastapiRequest) -> Option<FastapiEndpointContract> {
    fastapi_endpoint_contracts()
        .into_iter()
        .find(|contract| contract.matches_request(request))
}

pub fn fastapi_reuse_evidence() -> FastapiReuseEvidence {
    FastapiReuseEvidence {
        boundary: "fastapi_rust".to_string(),
        repo_path: FASTAPI_RUST_BOUNDARY.to_string(),
        adr: FASTAPI_RUST_ADR.to_string(),
        proof_state: "adapted_fastapi_core_contracts".to_string(),
        components: vec![
            FASTAPI_REQUEST_COMPONENT.to_string(),
            FASTAPI_RESPONSE_COMPONENT.to_string(),
            FASTAPI_STATUS_COMPONENT.to_string(),
            FASTAPI_METHOD_COMPONENT.to_string(),
            FASTAPI_AUTH_COMPONENT.to_string(),
        ],
        endpoints: fastapi_endpoint_contracts()
            .into_iter()
            .map(|contract| FastapiEndpointEvidence {
                family: contract.family.as_str().to_string(),
                endpoint: contract.endpoint.to_string(),
                method: contract.method_name().to_string(),
                path: contract.path.to_string(),
                required_scope: contract.required_scope.to_string(),
                backed_by: contract
                    .component_refs
                    .iter()
                    .map(|component| (*component).to_string())
                    .collect(),
            })
            .collect(),
    }
}

pub fn validate_fastapi_reuse_evidence() -> Result<(), EndpointFailure> {
    let evidence = fastapi_reuse_evidence();
    if evidence.boundary != "fastapi_rust"
        || evidence.repo_path != FASTAPI_RUST_BOUNDARY
        || evidence.proof_state != "adapted_fastapi_core_contracts"
    {
        return Err(EndpointFailure::new(
            "fastapi_reuse_invalid",
            "fastapi_rust reuse evidence must declare adapted fastapi_core contracts",
        ));
    }
    for required in [
        FASTAPI_REQUEST_COMPONENT,
        FASTAPI_RESPONSE_COMPONENT,
        FASTAPI_STATUS_COMPONENT,
        FASTAPI_METHOD_COMPONENT,
    ] {
        if !evidence
            .components
            .iter()
            .any(|component| component == required)
        {
            return Err(EndpointFailure::new(
                "fastapi_reuse_missing_component",
                format!("missing {required}"),
            ));
        }
    }
    for family in [
        FastapiEndpointFamily::Health,
        FastapiEndpointFamily::ControlAction,
        FastapiEndpointFamily::EvidenceExport,
        FastapiEndpointFamily::ReplayControl,
    ] {
        let family_name = family.as_str();
        if !evidence
            .endpoints
            .iter()
            .any(|endpoint| endpoint.family == family_name && !endpoint.backed_by.is_empty())
        {
            return Err(EndpointFailure::new(
                "fastapi_reuse_missing_endpoint_family",
                format!("missing adapted fastapi_rust endpoint family {family_name}"),
            ));
        }
    }
    Ok(())
}

/// Shared request context populated by transport adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestContext {
    pub trace_id: String,
    pub request_id: String,
    pub component: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
}

/// Authentication principal and granted scopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthContext {
    pub subject: String,
    pub scopes: Vec<String>,
}

impl AuthContext {
    pub fn has_scope(&self, required_scope: &str) -> bool {
        self.scopes.iter().any(|scope| scope == required_scope)
    }
}

/// Canonical structured log event for endpoint execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredLogEvent {
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Canonical error envelope aligned with service API contract expectations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub error_code: String,
    pub message: String,
    pub trace_id: String,
    pub component: String,
    pub details: BTreeMap<String, String>,
}

/// Canonical endpoint response envelope for transport adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointResponse<T> {
    pub status: String,
    pub endpoint: String,
    pub trace_id: String,
    pub request_id: String,
    pub data: Option<T>,
    pub error: Option<ErrorEnvelope>,
    pub log: StructuredLogEvent,
}

impl<T> EndpointResponse<T> {
    pub fn fastapi_status(&self) -> FastapiStatusCode {
        fastapi_status_for_endpoint_response(self)
    }
}

impl<T: Serialize> EndpointResponse<T> {
    pub fn to_fastapi_response(&self) -> Result<FastapiResponse, serde_json::Error> {
        endpoint_response_to_fastapi(self)
    }
}

/// Framework-agnostic failure returned from backend providers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointFailure {
    pub error_code: String,
    pub message: String,
    pub details: BTreeMap<String, String>,
}

impl EndpointFailure {
    pub fn new(error_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error_code: error_code.into(),
            message: message.into(),
            details: BTreeMap::new(),
        }
    }
}

pub fn fastapi_status_for_endpoint_response<T>(
    response: &EndpointResponse<T>,
) -> FastapiStatusCode {
    if response.error.is_none() && response.status == "ok" {
        return FastapiStatusCode::OK;
    }

    match response
        .error
        .as_ref()
        .map(|error| error.error_code.as_str())
    {
        Some("unauthorized") => FastapiStatusCode::UNAUTHORIZED,
        Some("invalid_request") => FastapiStatusCode::BAD_REQUEST,
        Some("not_found") => FastapiStatusCode::NOT_FOUND,
        Some("timeout") => FastapiStatusCode::GATEWAY_TIMEOUT,
        Some("unavailable") => FastapiStatusCode::SERVICE_UNAVAILABLE,
        _ => FastapiStatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub fn endpoint_response_to_fastapi<T: Serialize>(
    response: &EndpointResponse<T>,
) -> Result<FastapiResponse, serde_json::Error> {
    let bytes = serde_json::to_vec(response)?;
    Ok(FastapiResponse::with_status(response.fastapi_status())
        .header("content-type", b"application/json".to_vec())
        .body(FastapiResponseBody::Bytes(bytes)))
}

/// Health endpoint payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthStatusResponse {
    pub runtime_status: String,
    pub loaded_extensions: Vec<String>,
    pub security_epoch: u64,
    pub gc_pressure_basis_points: u16,
}

/// Control endpoint action verbs routed through decision contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlAction {
    Start,
    Stop,
    Suspend,
    Quarantine,
}

/// Control action request payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlActionRequest {
    pub extension_id: String,
    pub action: ControlAction,
    pub reason: String,
}

/// Control action response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlActionResponse {
    pub extension_id: String,
    pub action: ControlAction,
    pub accepted: bool,
    pub decision_id: String,
}

/// Evidence export request payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceExportRequest {
    pub since_epoch_seconds: u64,
    pub until_epoch_seconds: Option<u64>,
    pub page_size: u16,
    pub cursor: Option<String>,
}

/// Evidence record payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub artifact_ref: String,
}

/// Evidence export response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceExportResponse {
    pub records: Vec<EvidenceRecord>,
    pub next_cursor: Option<String>,
}

/// Replay endpoint action verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayCommand {
    Start,
    Stop,
    Status,
}

/// Replay control request payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayControlRequest {
    pub command: ReplayCommand,
    pub trace_id: Option<String>,
    pub session_id: Option<String>,
}

/// Replay control response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayControlResponse {
    pub session_id: String,
    pub state: String,
    pub trace_id: Option<String>,
    pub note: String,
}

pub trait RuntimeHealthProvider {
    fn read_health(&self) -> HealthStatusResponse;
}

pub trait DecisionContractExecutor {
    fn execute_control_action(
        &mut self,
        request: &ControlActionRequest,
        context: &RequestContext,
    ) -> Result<ControlActionResponse, EndpointFailure>;
}

pub trait EvidenceExportProvider {
    fn export_evidence(
        &self,
        request: &EvidenceExportRequest,
        context: &RequestContext,
    ) -> Result<EvidenceExportResponse, EndpointFailure>;
}

pub trait ReplayController {
    fn control_replay(
        &mut self,
        request: &ReplayControlRequest,
        context: &RequestContext,
    ) -> Result<ReplayControlResponse, EndpointFailure>;
}

/// Thin endpoint template that transport adapters can wrap.
#[derive(Debug)]
pub struct ServiceEndpointTemplate<H, D, E, R> {
    health_provider: H,
    decision_executor: D,
    evidence_provider: E,
    replay_controller: R,
}

impl<H, D, E, R> ServiceEndpointTemplate<H, D, E, R>
where
    H: RuntimeHealthProvider,
    D: DecisionContractExecutor,
    E: EvidenceExportProvider,
    R: ReplayController,
{
    pub fn new(
        health_provider: H,
        decision_executor: D,
        evidence_provider: E,
        replay_controller: R,
    ) -> Self {
        Self {
            health_provider,
            decision_executor,
            evidence_provider,
            replay_controller,
        }
    }

    pub fn health_endpoint(
        &self,
        auth: &AuthContext,
        context: &RequestContext,
    ) -> EndpointResponse<HealthStatusResponse> {
        if !auth.has_scope(SCOPE_HEALTH_READ) {
            return unauthorized("health", context, SCOPE_HEALTH_READ);
        }

        ok_response(
            "health",
            "health.read",
            context,
            self.health_provider.read_health(),
        )
    }

    pub fn control_action_endpoint(
        &mut self,
        auth: &AuthContext,
        context: &RequestContext,
        request: &ControlActionRequest,
    ) -> EndpointResponse<ControlActionResponse> {
        if !auth.has_scope(SCOPE_CONTROL_WRITE) {
            return unauthorized("control_action", context, SCOPE_CONTROL_WRITE);
        }
        if let Some(error) = validate_control_action_request(request, context) {
            return error;
        }

        match self
            .decision_executor
            .execute_control_action(request, context)
        {
            Ok(response) => ok_response("control_action", "control.execute", context, response),
            Err(failure) => upstream_failure("control_action", context, failure),
        }
    }

    pub fn evidence_export_endpoint(
        &self,
        auth: &AuthContext,
        context: &RequestContext,
        request: &EvidenceExportRequest,
    ) -> EndpointResponse<EvidenceExportResponse> {
        if !auth.has_scope(SCOPE_EVIDENCE_READ) {
            return unauthorized("evidence_export", context, SCOPE_EVIDENCE_READ);
        }
        if let Some(error) = validate_evidence_export_request(request, context) {
            return error;
        }

        match self.evidence_provider.export_evidence(request, context) {
            Ok(response) => ok_response("evidence_export", "evidence.export", context, response),
            Err(failure) => upstream_failure("evidence_export", context, failure),
        }
    }

    pub fn replay_control_endpoint(
        &mut self,
        auth: &AuthContext,
        context: &RequestContext,
        request: &ReplayControlRequest,
    ) -> EndpointResponse<ReplayControlResponse> {
        let required_scope = match request.command {
            ReplayCommand::Status => SCOPE_REPLAY_READ,
            ReplayCommand::Start | ReplayCommand::Stop => SCOPE_REPLAY_WRITE,
        };
        if !auth.has_scope(required_scope) {
            return unauthorized("replay_control", context, required_scope);
        }
        if let Some(error) = validate_replay_control_request(request, context) {
            return error;
        }

        match self.replay_controller.control_replay(request, context) {
            Ok(response) => ok_response("replay_control", "replay.control", context, response),
            Err(failure) => upstream_failure("replay_control", context, failure),
        }
    }
}

fn validate_control_action_request(
    request: &ControlActionRequest,
    context: &RequestContext,
) -> Option<EndpointResponse<ControlActionResponse>> {
    if request.extension_id.trim().is_empty() {
        return Some(invalid_request(
            "control_action",
            context,
            "extension_id",
            "must not be empty",
        ));
    }
    if request.reason.trim().is_empty() {
        return Some(invalid_request(
            "control_action",
            context,
            "reason",
            "must not be empty",
        ));
    }
    if request.reason.chars().count() > 256 {
        return Some(invalid_request(
            "control_action",
            context,
            "reason",
            "must be <= 256 characters",
        ));
    }
    None
}

fn validate_evidence_export_request(
    request: &EvidenceExportRequest,
    context: &RequestContext,
) -> Option<EndpointResponse<EvidenceExportResponse>> {
    if request.page_size == 0 || request.page_size > 1_000 {
        return Some(invalid_request(
            "evidence_export",
            context,
            "page_size",
            "must be within 1..=1000",
        ));
    }
    if let Some(until) = request.until_epoch_seconds
        && until < request.since_epoch_seconds
    {
        return Some(invalid_request(
            "evidence_export",
            context,
            "until_epoch_seconds",
            "must be >= since_epoch_seconds",
        ));
    }
    None
}

fn validate_replay_control_request(
    request: &ReplayControlRequest,
    context: &RequestContext,
) -> Option<EndpointResponse<ReplayControlResponse>> {
    match request.command {
        ReplayCommand::Start => {
            if request
                .trace_id
                .as_ref()
                .is_none_or(|trace| trace.trim().is_empty())
            {
                return Some(invalid_request(
                    "replay_control",
                    context,
                    "trace_id",
                    "must be present for start command",
                ));
            }
        }
        ReplayCommand::Stop | ReplayCommand::Status => {
            if request
                .session_id
                .as_ref()
                .is_none_or(|session| session.trim().is_empty())
            {
                return Some(invalid_request(
                    "replay_control",
                    context,
                    "session_id",
                    "must be present for stop/status command",
                ));
            }
        }
    }
    None
}

fn ok_response<T>(
    endpoint: &str,
    event: &str,
    context: &RequestContext,
    data: T,
) -> EndpointResponse<T> {
    EndpointResponse {
        status: "ok".to_string(),
        endpoint: endpoint.to_string(),
        trace_id: context.trace_id.clone(),
        request_id: context.request_id.clone(),
        data: Some(data),
        error: None,
        log: StructuredLogEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: context.component.clone(),
            event: event.to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        },
    }
}

fn unauthorized<T>(
    endpoint: &str,
    context: &RequestContext,
    required_scope: &str,
) -> EndpointResponse<T> {
    let mut details = BTreeMap::new();
    details.insert("required_scope".to_string(), required_scope.to_string());
    error_response(
        endpoint,
        "authz.denied",
        context,
        "unauthorized",
        "missing required scope",
        details,
    )
}

fn invalid_request<T>(
    endpoint: &str,
    context: &RequestContext,
    field: &str,
    reason: &str,
) -> EndpointResponse<T> {
    let mut details = BTreeMap::new();
    details.insert("field".to_string(), field.to_string());
    details.insert("reason".to_string(), reason.to_string());
    error_response(
        endpoint,
        "request.invalid",
        context,
        "invalid_request",
        "request validation failed",
        details,
    )
}

fn upstream_failure<T>(
    endpoint: &str,
    context: &RequestContext,
    failure: EndpointFailure,
) -> EndpointResponse<T> {
    error_response(
        endpoint,
        "backend.failure",
        context,
        &failure.error_code,
        &failure.message,
        failure.details,
    )
}

fn error_response<T>(
    endpoint: &str,
    event: &str,
    context: &RequestContext,
    error_code: &str,
    message: &str,
    details: BTreeMap<String, String>,
) -> EndpointResponse<T> {
    EndpointResponse {
        status: "error".to_string(),
        endpoint: endpoint.to_string(),
        trace_id: context.trace_id.clone(),
        request_id: context.request_id.clone(),
        data: None,
        error: Some(ErrorEnvelope {
            error_code: error_code.to_string(),
            message: message.to_string(),
            trace_id: context.trace_id.clone(),
            component: context.component.clone(),
            details,
        }),
        log: StructuredLogEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: context.component.clone(),
            event: event.to_string(),
            outcome: "error".to_string(),
            error_code: Some(error_code.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;

    fn context() -> RequestContext {
        RequestContext {
            trace_id: "trace-01".to_string(),
            request_id: "req-01".to_string(),
            component: "service.api".to_string(),
            decision_id: Some("decision-01".to_string()),
            policy_id: Some("policy-01".to_string()),
        }
    }

    fn auth_with_scopes(scopes: &[&str]) -> AuthContext {
        AuthContext {
            subject: "operator@example".to_string(),
            scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
        }
    }

    #[derive(Debug, Clone)]
    struct MockHealthProvider {
        snapshot: HealthStatusResponse,
    }

    impl RuntimeHealthProvider for MockHealthProvider {
        fn read_health(&self) -> HealthStatusResponse {
            self.snapshot.clone()
        }
    }

    #[derive(Debug, Clone)]
    struct MockDecisionExecutor {
        calls: Rc<Cell<u32>>,
    }

    impl DecisionContractExecutor for MockDecisionExecutor {
        fn execute_control_action(
            &mut self,
            request: &ControlActionRequest,
            _context: &RequestContext,
        ) -> Result<ControlActionResponse, EndpointFailure> {
            self.calls.set(self.calls.get() + 1);
            Ok(ControlActionResponse {
                extension_id: request.extension_id.clone(),
                action: request.action,
                accepted: true,
                decision_id: "decision-contract-7".to_string(),
            })
        }
    }

    #[derive(Debug, Clone)]
    struct MockEvidenceProvider;

    impl EvidenceExportProvider for MockEvidenceProvider {
        fn export_evidence(
            &self,
            request: &EvidenceExportRequest,
            _context: &RequestContext,
        ) -> Result<EvidenceExportResponse, EndpointFailure> {
            Ok(EvidenceExportResponse {
                records: vec![EvidenceRecord {
                    trace_id: "trace-01".to_string(),
                    decision_id: "decision-01".to_string(),
                    policy_id: "policy-01".to_string(),
                    component: "policy_controller".to_string(),
                    event: "decision.publish".to_string(),
                    outcome: "allow".to_string(),
                    artifact_ref: format!("evidence://cursor/{}", request.page_size),
                }],
                next_cursor: request.cursor.clone(),
            })
        }
    }

    #[derive(Debug, Clone)]
    struct MockReplayController;

    impl ReplayController for MockReplayController {
        fn control_replay(
            &mut self,
            request: &ReplayControlRequest,
            _context: &RequestContext,
        ) -> Result<ReplayControlResponse, EndpointFailure> {
            let (session_id, state, note) = match request.command {
                ReplayCommand::Start => (
                    "session-01".to_string(),
                    "running".to_string(),
                    "replay session started".to_string(),
                ),
                ReplayCommand::Stop => (
                    request
                        .session_id
                        .clone()
                        .unwrap_or_else(|| "session-unknown".to_string()),
                    "stopped".to_string(),
                    "replay session stopped".to_string(),
                ),
                ReplayCommand::Status => (
                    request
                        .session_id
                        .clone()
                        .unwrap_or_else(|| "session-unknown".to_string()),
                    "running".to_string(),
                    "replay session status".to_string(),
                ),
            };
            Ok(ReplayControlResponse {
                session_id,
                state,
                trace_id: request.trace_id.clone(),
                note,
            })
        }
    }

    fn template(
        call_counter: Rc<Cell<u32>>,
    ) -> ServiceEndpointTemplate<
        MockHealthProvider,
        MockDecisionExecutor,
        MockEvidenceProvider,
        MockReplayController,
    > {
        ServiceEndpointTemplate::new(
            MockHealthProvider {
                snapshot: HealthStatusResponse {
                    runtime_status: "healthy".to_string(),
                    loaded_extensions: vec!["ext-a".to_string(), "ext-b".to_string()],
                    security_epoch: 42,
                    gc_pressure_basis_points: 180,
                },
            },
            MockDecisionExecutor {
                calls: call_counter,
            },
            MockEvidenceProvider,
            MockReplayController,
        )
    }

    #[test]
    fn fastapi_reuse_evidence_is_adapted_and_complete() {
        validate_fastapi_reuse_evidence().expect("fastapi reuse evidence");
        let evidence = fastapi_reuse_evidence();

        assert_eq!(evidence.boundary, "fastapi_rust");
        assert_eq!(evidence.repo_path, FASTAPI_RUST_BOUNDARY);
        assert_eq!(evidence.proof_state, "adapted_fastapi_core_contracts");
        assert!(
            evidence
                .components
                .iter()
                .any(|component| component == FASTAPI_RESPONSE_COMPONENT)
        );
        for family in [
            "health",
            "control_action",
            "evidence_export",
            "replay_control",
        ] {
            assert!(
                evidence
                    .endpoints
                    .iter()
                    .any(|endpoint| endpoint.family == family),
                "missing endpoint family {family}"
            );
        }
    }

    #[test]
    fn fastapi_route_contracts_match_core_requests() {
        let health_request = FastapiRequest::new(FastapiMethod::Get, "/v1/engine/health");
        let control_request =
            FastapiRequest::new(FastapiMethod::Post, "/v1/engine/control/actions");
        let miss_request = FastapiRequest::new(FastapiMethod::Delete, "/v1/engine/health");

        let health = match_fastapi_request(&health_request).expect("health route");
        assert_eq!(health.endpoint, "health");
        assert_eq!(health.required_scope, SCOPE_HEALTH_READ);
        assert_eq!(health.method_name(), "GET");

        let control = match_fastapi_request(&control_request).expect("control route");
        assert_eq!(control.endpoint, "control_action");
        assert_eq!(control.required_scope, SCOPE_CONTROL_WRITE);
        assert_eq!(control.method_name(), "POST");

        assert!(match_fastapi_request(&miss_request).is_none());
    }

    #[test]
    fn endpoint_response_serializes_through_fastapi_core_response() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response =
            template.health_endpoint(&auth_with_scopes(&[SCOPE_HEALTH_READ]), &context());

        let fastapi_response = response.to_fastapi_response().expect("fastapi response");
        assert_eq!(fastapi_response.status(), FastapiStatusCode::OK);
        assert!(fastapi_response.headers().iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type") && value == b"application/json"
        }));
        let FastapiResponseBody::Bytes(body) = fastapi_response.body_ref() else {
            panic!("expected JSON bytes body");
        };
        let json: serde_json::Value = serde_json::from_slice(body).expect("json body");
        assert_eq!(json["endpoint"], "health");
        assert_eq!(json["log"]["event"], "health.read");
    }

    #[test]
    fn endpoint_errors_map_to_fastapi_status_codes() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let unauthorized = template.health_endpoint(&auth_with_scopes(&[]), &context());
        assert_eq!(
            unauthorized.fastapi_status(),
            FastapiStatusCode::UNAUTHORIZED
        );

        let mut details = BTreeMap::new();
        details.insert("field".to_string(), "extension_id".to_string());
        let invalid = error_response::<ControlActionResponse>(
            "control_action",
            "request.invalid",
            &context(),
            "invalid_request",
            "request validation failed",
            details,
        );
        assert_eq!(invalid.fastapi_status(), FastapiStatusCode::BAD_REQUEST);
    }

    #[test]
    fn health_endpoint_response_schema_is_stable() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response =
            template.health_endpoint(&auth_with_scopes(&[SCOPE_HEALTH_READ]), &context());

        assert_eq!(response.status, "ok");
        assert_eq!(response.endpoint, "health");
        let data = response.data.expect("health payload");
        assert_eq!(data.runtime_status, "healthy");
        assert_eq!(data.security_epoch, 42);
        assert_eq!(response.log.event, "health.read");
        assert_eq!(response.log.outcome, "ok");
    }

    #[test]
    fn health_endpoint_reflects_provider_state() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response =
            template.health_endpoint(&auth_with_scopes(&[SCOPE_HEALTH_READ]), &context());
        let payload = response.data.expect("payload");
        assert_eq!(payload.loaded_extensions, vec!["ext-a", "ext-b"]);
        assert_eq!(payload.gc_pressure_basis_points, 180);
    }

    #[test]
    fn control_action_requires_valid_request() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(calls);
        let response = template.control_action_endpoint(
            &auth_with_scopes(&[SCOPE_CONTROL_WRITE]),
            &context(),
            &ControlActionRequest {
                extension_id: " ".to_string(),
                action: ControlAction::Suspend,
                reason: "maintenance".to_string(),
            },
        );

        assert_eq!(response.status, "error");
        let error = response.error.expect("error envelope");
        assert_eq!(error.error_code, "invalid_request");
        assert_eq!(error.details["field"], "extension_id");
        assert_eq!(response.log.error_code.as_deref(), Some("invalid_request"));
    }

    #[test]
    fn control_action_routes_through_decision_contract() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(Rc::clone(&calls));
        let response = template.control_action_endpoint(
            &auth_with_scopes(&[SCOPE_CONTROL_WRITE]),
            &context(),
            &ControlActionRequest {
                extension_id: "ext-a".to_string(),
                action: ControlAction::Quarantine,
                reason: "risk threshold crossed".to_string(),
            },
        );

        assert_eq!(response.status, "ok");
        let payload = response.data.expect("control payload");
        assert_eq!(payload.decision_id, "decision-contract-7");
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn evidence_export_validation_returns_structured_error() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response = template.evidence_export_endpoint(
            &auth_with_scopes(&[SCOPE_EVIDENCE_READ]),
            &context(),
            &EvidenceExportRequest {
                since_epoch_seconds: 50,
                until_epoch_seconds: Some(49),
                page_size: 100,
                cursor: None,
            },
        );

        assert_eq!(response.status, "error");
        let error = response.error.expect("error envelope");
        assert_eq!(error.error_code, "invalid_request");
        assert_eq!(error.details["field"], "until_epoch_seconds");
    }

    #[test]
    fn evidence_export_success_schema() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response = template.evidence_export_endpoint(
            &auth_with_scopes(&[SCOPE_EVIDENCE_READ]),
            &context(),
            &EvidenceExportRequest {
                since_epoch_seconds: 1,
                until_epoch_seconds: Some(10),
                page_size: 25,
                cursor: Some("cursor-a".to_string()),
            },
        );

        assert_eq!(response.status, "ok");
        let payload = response.data.expect("evidence payload");
        assert_eq!(payload.records.len(), 1);
        assert_eq!(payload.records[0].artifact_ref, "evidence://cursor/25");
        assert_eq!(payload.next_cursor.as_deref(), Some("cursor-a"));
    }

    #[test]
    fn replay_control_uses_scope_by_command() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(calls);

        let denied = template.replay_control_endpoint(
            &auth_with_scopes(&[SCOPE_REPLAY_WRITE]),
            &context(),
            &ReplayControlRequest {
                command: ReplayCommand::Status,
                trace_id: None,
                session_id: Some("session-42".to_string()),
            },
        );
        assert_eq!(denied.status, "error");
        assert_eq!(denied.error.expect("error").error_code, "unauthorized");

        let allowed = template.replay_control_endpoint(
            &auth_with_scopes(&[SCOPE_REPLAY_READ]),
            &context(),
            &ReplayControlRequest {
                command: ReplayCommand::Status,
                trace_id: None,
                session_id: Some("session-42".to_string()),
            },
        );
        assert_eq!(allowed.status, "ok");
        assert_eq!(
            allowed.data.expect("replay payload").session_id,
            "session-42"
        );
    }

    #[test]
    fn response_is_serializable_for_dashboard_consumers() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response =
            template.health_endpoint(&auth_with_scopes(&[SCOPE_HEALTH_READ]), &context());

        let json = serde_json::to_value(response).expect("serde deserialization should succeed");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["endpoint"], "health");
        assert!(json["trace_id"].is_string());
        assert!(json["log"]["event"].is_string());
    }

    // -- Scope constants --

    #[test]
    fn scope_constants_are_stable() {
        assert_eq!(SCOPE_HEALTH_READ, "engine.health.read");
        assert_eq!(SCOPE_CONTROL_WRITE, "engine.control.write");
        assert_eq!(SCOPE_EVIDENCE_READ, "engine.evidence.read");
        assert_eq!(SCOPE_REPLAY_READ, "engine.replay.read");
        assert_eq!(SCOPE_REPLAY_WRITE, "engine.replay.write");
    }

    // -- AuthContext --

    #[test]
    fn auth_context_has_scope_positive_and_negative() {
        let auth = auth_with_scopes(&[SCOPE_HEALTH_READ, SCOPE_CONTROL_WRITE]);
        assert!(auth.has_scope(SCOPE_HEALTH_READ));
        assert!(auth.has_scope(SCOPE_CONTROL_WRITE));
        assert!(!auth.has_scope(SCOPE_EVIDENCE_READ));
        assert!(!auth.has_scope(SCOPE_REPLAY_READ));
        assert!(!auth.has_scope(SCOPE_REPLAY_WRITE));
    }

    #[test]
    fn auth_context_empty_scopes_denies_everything() {
        let auth = auth_with_scopes(&[]);
        assert!(!auth.has_scope(SCOPE_HEALTH_READ));
        assert!(!auth.has_scope(SCOPE_CONTROL_WRITE));
    }

    // -- EndpointFailure --

    #[test]
    fn endpoint_failure_new_has_empty_details() {
        let f = EndpointFailure::new("ERR-001", "something broke");
        assert_eq!(f.error_code, "ERR-001");
        assert_eq!(f.message, "something broke");
        assert!(f.details.is_empty());
    }

    // -- Health endpoint unauthorized --

    #[test]
    fn health_endpoint_unauthorized_without_scope() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response = template.health_endpoint(&auth_with_scopes(&[]), &context());
        assert_eq!(response.status, "error");
        assert!(response.data.is_none());
        let error = response.error.expect("error envelope");
        assert_eq!(error.error_code, "unauthorized");
        assert_eq!(error.details["required_scope"], SCOPE_HEALTH_READ);
        assert_eq!(response.log.outcome, "error");
        assert_eq!(response.log.event, "authz.denied");
    }

    // -- Control action endpoints --

    #[test]
    fn control_action_unauthorized_without_scope() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(calls);
        let response = template.control_action_endpoint(
            &auth_with_scopes(&[SCOPE_HEALTH_READ]),
            &context(),
            &ControlActionRequest {
                extension_id: "ext-a".to_string(),
                action: ControlAction::Stop,
                reason: "maintenance".to_string(),
            },
        );
        assert_eq!(response.status, "error");
        let error = response.error.expect("error envelope");
        assert_eq!(error.error_code, "unauthorized");
    }

    #[test]
    fn control_action_rejects_empty_reason() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(calls);
        let response = template.control_action_endpoint(
            &auth_with_scopes(&[SCOPE_CONTROL_WRITE]),
            &context(),
            &ControlActionRequest {
                extension_id: "ext-a".to_string(),
                action: ControlAction::Start,
                reason: "   ".to_string(),
            },
        );
        assert_eq!(response.status, "error");
        let error = response.error.expect("error envelope");
        assert_eq!(error.details["field"], "reason");
    }

    #[test]
    fn control_action_rejects_reason_over_256_chars() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(calls);
        let long_reason = "x".repeat(257);
        let response = template.control_action_endpoint(
            &auth_with_scopes(&[SCOPE_CONTROL_WRITE]),
            &context(),
            &ControlActionRequest {
                extension_id: "ext-a".to_string(),
                action: ControlAction::Suspend,
                reason: long_reason,
            },
        );
        assert_eq!(response.status, "error");
        let error = response.error.expect("error envelope");
        assert_eq!(error.details["field"], "reason");
    }

    #[test]
    fn control_action_accepts_reason_at_256_chars() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(Rc::clone(&calls));
        let exact_reason = "x".repeat(256);
        let response = template.control_action_endpoint(
            &auth_with_scopes(&[SCOPE_CONTROL_WRITE]),
            &context(),
            &ControlActionRequest {
                extension_id: "ext-a".to_string(),
                action: ControlAction::Start,
                reason: exact_reason,
            },
        );
        assert_eq!(response.status, "ok");
        assert_eq!(calls.get(), 1);
    }

    // -- Evidence export endpoints --

    #[test]
    fn evidence_export_unauthorized_without_scope() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response = template.evidence_export_endpoint(
            &auth_with_scopes(&[]),
            &context(),
            &EvidenceExportRequest {
                since_epoch_seconds: 0,
                until_epoch_seconds: None,
                page_size: 10,
                cursor: None,
            },
        );
        assert_eq!(response.status, "error");
        let error = response.error.expect("error envelope");
        assert_eq!(error.error_code, "unauthorized");
    }

    #[test]
    fn evidence_export_rejects_page_size_zero() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response = template.evidence_export_endpoint(
            &auth_with_scopes(&[SCOPE_EVIDENCE_READ]),
            &context(),
            &EvidenceExportRequest {
                since_epoch_seconds: 0,
                until_epoch_seconds: None,
                page_size: 0,
                cursor: None,
            },
        );
        assert_eq!(response.status, "error");
        let error = response.error.expect("error envelope");
        assert_eq!(error.details["field"], "page_size");
    }

    #[test]
    fn evidence_export_rejects_page_size_over_1000() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response = template.evidence_export_endpoint(
            &auth_with_scopes(&[SCOPE_EVIDENCE_READ]),
            &context(),
            &EvidenceExportRequest {
                since_epoch_seconds: 0,
                until_epoch_seconds: None,
                page_size: 1001,
                cursor: None,
            },
        );
        assert_eq!(response.status, "error");
        let error = response.error.expect("error envelope");
        assert_eq!(error.details["field"], "page_size");
    }

    #[test]
    fn evidence_export_accepts_page_size_at_boundary() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        // page_size = 1 (minimum)
        let r1 = template.evidence_export_endpoint(
            &auth_with_scopes(&[SCOPE_EVIDENCE_READ]),
            &context(),
            &EvidenceExportRequest {
                since_epoch_seconds: 0,
                until_epoch_seconds: None,
                page_size: 1,
                cursor: None,
            },
        );
        assert_eq!(r1.status, "ok");

        // page_size = 1000 (maximum)
        let r2 = template.evidence_export_endpoint(
            &auth_with_scopes(&[SCOPE_EVIDENCE_READ]),
            &context(),
            &EvidenceExportRequest {
                since_epoch_seconds: 0,
                until_epoch_seconds: None,
                page_size: 1000,
                cursor: None,
            },
        );
        assert_eq!(r2.status, "ok");
    }

    #[test]
    fn evidence_export_accepts_equal_since_until() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response = template.evidence_export_endpoint(
            &auth_with_scopes(&[SCOPE_EVIDENCE_READ]),
            &context(),
            &EvidenceExportRequest {
                since_epoch_seconds: 100,
                until_epoch_seconds: Some(100),
                page_size: 50,
                cursor: None,
            },
        );
        assert_eq!(response.status, "ok");
    }

    // -- Replay control endpoints --

    #[test]
    fn replay_start_requires_trace_id() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(calls);
        let response = template.replay_control_endpoint(
            &auth_with_scopes(&[SCOPE_REPLAY_WRITE]),
            &context(),
            &ReplayControlRequest {
                command: ReplayCommand::Start,
                trace_id: None,
                session_id: None,
            },
        );
        assert_eq!(response.status, "error");
        let error = response.error.expect("error envelope");
        assert_eq!(error.details["field"], "trace_id");
    }

    #[test]
    fn replay_start_rejects_blank_trace_id() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(calls);
        let response = template.replay_control_endpoint(
            &auth_with_scopes(&[SCOPE_REPLAY_WRITE]),
            &context(),
            &ReplayControlRequest {
                command: ReplayCommand::Start,
                trace_id: Some("  ".to_string()),
                session_id: None,
            },
        );
        assert_eq!(response.status, "error");
        let error = response.error.expect("error envelope");
        assert_eq!(error.details["field"], "trace_id");
    }

    #[test]
    fn replay_stop_requires_session_id() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(calls);
        let response = template.replay_control_endpoint(
            &auth_with_scopes(&[SCOPE_REPLAY_WRITE]),
            &context(),
            &ReplayControlRequest {
                command: ReplayCommand::Stop,
                trace_id: None,
                session_id: None,
            },
        );
        assert_eq!(response.status, "error");
        let error = response.error.expect("error envelope");
        assert_eq!(error.details["field"], "session_id");
    }

    #[test]
    fn replay_status_requires_session_id() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(calls);
        let response = template.replay_control_endpoint(
            &auth_with_scopes(&[SCOPE_REPLAY_READ]),
            &context(),
            &ReplayControlRequest {
                command: ReplayCommand::Status,
                trace_id: None,
                session_id: None,
            },
        );
        assert_eq!(response.status, "error");
    }

    #[test]
    fn replay_start_success() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(calls);
        let response = template.replay_control_endpoint(
            &auth_with_scopes(&[SCOPE_REPLAY_WRITE]),
            &context(),
            &ReplayControlRequest {
                command: ReplayCommand::Start,
                trace_id: Some("trace-replay".to_string()),
                session_id: None,
            },
        );
        assert_eq!(response.status, "ok");
        let data = response.data.expect("replay payload");
        assert_eq!(data.session_id, "session-01");
        assert_eq!(data.state, "running");
    }

    #[test]
    fn replay_stop_success() {
        let calls = Rc::new(Cell::new(0));
        let mut template = template(calls);
        let response = template.replay_control_endpoint(
            &auth_with_scopes(&[SCOPE_REPLAY_WRITE]),
            &context(),
            &ReplayControlRequest {
                command: ReplayCommand::Stop,
                trace_id: None,
                session_id: Some("session-99".to_string()),
            },
        );
        assert_eq!(response.status, "ok");
        let data = response.data.expect("replay payload");
        assert_eq!(data.session_id, "session-99");
        assert_eq!(data.state, "stopped");
    }

    // -- Upstream failure propagation --

    #[test]
    fn upstream_failure_propagates_error_code_and_details() {
        // Use a mock that returns an error.
        struct FailingDecisionExecutor;
        impl DecisionContractExecutor for FailingDecisionExecutor {
            fn execute_control_action(
                &mut self,
                _request: &ControlActionRequest,
                _context: &RequestContext,
            ) -> Result<ControlActionResponse, EndpointFailure> {
                let mut details = BTreeMap::new();
                details.insert("subsystem".to_string(), "decision-engine".to_string());
                Err(EndpointFailure {
                    error_code: "BACKEND-500".to_string(),
                    message: "internal failure".to_string(),
                    details,
                })
            }
        }

        let mut tmpl = ServiceEndpointTemplate::new(
            MockHealthProvider {
                snapshot: HealthStatusResponse {
                    runtime_status: "healthy".to_string(),
                    loaded_extensions: vec![],
                    security_epoch: 1,
                    gc_pressure_basis_points: 0,
                },
            },
            FailingDecisionExecutor,
            MockEvidenceProvider,
            MockReplayController,
        );

        let response = tmpl.control_action_endpoint(
            &auth_with_scopes(&[SCOPE_CONTROL_WRITE]),
            &context(),
            &ControlActionRequest {
                extension_id: "ext-a".to_string(),
                action: ControlAction::Quarantine,
                reason: "test failure".to_string(),
            },
        );

        assert_eq!(response.status, "error");
        let error = response.error.expect("error envelope");
        assert_eq!(error.error_code, "BACKEND-500");
        assert_eq!(error.message, "internal failure");
        assert_eq!(error.details["subsystem"], "decision-engine");
        assert_eq!(response.log.outcome, "error");
    }

    // -- Log fields populated from context --

    #[test]
    fn ok_response_log_fields_populated_from_context() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let ctx = context();
        let response = template.health_endpoint(&auth_with_scopes(&[SCOPE_HEALTH_READ]), &ctx);
        assert_eq!(response.log.trace_id, ctx.trace_id);
        assert_eq!(response.log.decision_id, ctx.decision_id);
        assert_eq!(response.log.policy_id, ctx.policy_id);
        assert_eq!(response.log.component, ctx.component);
        assert!(response.log.error_code.is_none());
    }

    #[test]
    fn error_response_log_includes_error_code() {
        let calls = Rc::new(Cell::new(0));
        let template = template(calls);
        let response = template.health_endpoint(&auth_with_scopes(&[]), &context());
        assert_eq!(response.log.outcome, "error");
        assert_eq!(response.log.error_code.as_deref(), Some("unauthorized"));
    }

    // -- Serde roundtrips --

    #[test]
    fn request_context_serde_roundtrip() {
        let ctx = context();
        let json = serde_json::to_string(&ctx).expect("serde deserialization should succeed");
        let back: RequestContext =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(ctx, back);
    }

    #[test]
    fn auth_context_serde_roundtrip() {
        let auth = auth_with_scopes(&[SCOPE_HEALTH_READ, SCOPE_CONTROL_WRITE]);
        let json = serde_json::to_string(&auth).expect("serde deserialization should succeed");
        let back: AuthContext =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(auth, back);
    }

    #[test]
    fn control_action_serde_roundtrip() {
        for action in [
            ControlAction::Start,
            ControlAction::Stop,
            ControlAction::Suspend,
            ControlAction::Quarantine,
        ] {
            let json = serde_json::to_value(action).expect("serde deserialization should succeed");
            let back: ControlAction =
                serde_json::from_value(json).expect("serde deserialization should succeed");
            assert_eq!(action, back);
        }
    }

    #[test]
    fn replay_command_serde_roundtrip() {
        for cmd in [
            ReplayCommand::Start,
            ReplayCommand::Stop,
            ReplayCommand::Status,
        ] {
            let json = serde_json::to_value(cmd).expect("serde deserialization should succeed");
            let back: ReplayCommand =
                serde_json::from_value(json).expect("serde deserialization should succeed");
            assert_eq!(cmd, back);
        }
    }

    #[test]
    fn endpoint_failure_serde_roundtrip() {
        let mut f = EndpointFailure::new("E-42", "bad input");
        f.details.insert("key".to_string(), "value".to_string());
        let json = serde_json::to_string(&f).expect("serde deserialization should succeed");
        let back: EndpointFailure =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(f, back);
    }

    #[test]
    fn control_action_request_serde_roundtrip() {
        let req = ControlActionRequest {
            extension_id: "ext-x".to_string(),
            action: ControlAction::Quarantine,
            reason: "policy violation".to_string(),
        };
        let json = serde_json::to_string(&req).expect("serde deserialization should succeed");
        let back: ControlActionRequest =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(req, back);
    }

    #[test]
    fn evidence_export_request_serde_roundtrip() {
        let req = EvidenceExportRequest {
            since_epoch_seconds: 100,
            until_epoch_seconds: Some(200),
            page_size: 50,
            cursor: Some("cursor-abc".to_string()),
        };
        let json = serde_json::to_string(&req).expect("serde deserialization should succeed");
        let back: EvidenceExportRequest =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(req, back);
    }

    #[test]
    fn replay_control_request_serde_roundtrip() {
        let req = ReplayControlRequest {
            command: ReplayCommand::Start,
            trace_id: Some("trace-001".to_string()),
            session_id: None,
        };
        let json = serde_json::to_string(&req).expect("serde deserialization should succeed");
        let back: ReplayControlRequest =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(req, back);
    }

    #[test]
    fn health_status_response_serde_roundtrip() {
        let h = HealthStatusResponse {
            runtime_status: "degraded".to_string(),
            loaded_extensions: vec!["ext-a".to_string()],
            security_epoch: 7,
            gc_pressure_basis_points: 500,
        };
        let json = serde_json::to_string(&h).expect("serde deserialization should succeed");
        let back: HealthStatusResponse =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(h, back);
    }

    #[test]
    fn evidence_record_serde_roundtrip() {
        let r = EvidenceRecord {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "ok".to_string(),
            artifact_ref: "evidence://ref".to_string(),
        };
        let json = serde_json::to_string(&r).expect("serde deserialization should succeed");
        let back: EvidenceRecord =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(r, back);
    }

    #[test]
    fn structured_log_event_serde_roundtrip() {
        let e = StructuredLogEvent {
            trace_id: "t".to_string(),
            decision_id: Some("d".to_string()),
            policy_id: None,
            component: "engine".to_string(),
            event: "test.event".to_string(),
            outcome: "ok".to_string(),
            error_code: Some("E-1".to_string()),
        };
        let json = serde_json::to_string(&e).expect("serde deserialization should succeed");
        let back: StructuredLogEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(e, back);
    }

    #[test]
    fn error_envelope_serde_roundtrip() {
        let mut details = BTreeMap::new();
        details.insert("key".to_string(), "val".to_string());
        let env = ErrorEnvelope {
            error_code: "ERR-1".to_string(),
            message: "something".to_string(),
            trace_id: "t".to_string(),
            component: "c".to_string(),
            details,
        };
        let json = serde_json::to_string(&env).expect("serde deserialization should succeed");
        let back: ErrorEnvelope =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(env, back);
    }

    // -- Clone equality tests --

    #[test]
    fn request_context_clone_equality() {
        let ctx = context();
        let cloned = ctx.clone();
        assert_eq!(ctx, cloned);
    }

    #[test]
    fn auth_context_clone_equality() {
        let auth = auth_with_scopes(&[SCOPE_HEALTH_READ, SCOPE_CONTROL_WRITE, SCOPE_REPLAY_READ]);
        let cloned = auth.clone();
        assert_eq!(auth, cloned);
    }

    #[test]
    fn structured_log_event_clone_equality() {
        let event = StructuredLogEvent {
            trace_id: "t-clone".to_string(),
            decision_id: Some("d-clone".to_string()),
            policy_id: None,
            component: "engine.clone".to_string(),
            event: "clone.test".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    #[test]
    fn error_envelope_clone_equality() {
        let mut details = BTreeMap::new();
        details.insert("a".to_string(), "b".to_string());
        details.insert("c".to_string(), "d".to_string());
        let envelope = ErrorEnvelope {
            error_code: "E-CLONE".to_string(),
            message: "clone test".to_string(),
            trace_id: "t-clone".to_string(),
            component: "c-clone".to_string(),
            details,
        };
        let cloned = envelope.clone();
        assert_eq!(envelope, cloned);
    }

    #[test]
    fn endpoint_failure_clone_equality() {
        let mut f = EndpointFailure::new("CLONE-ERR", "clone failure msg");
        f.details
            .insert("detail_key".to_string(), "detail_val".to_string());
        let cloned = f.clone();
        assert_eq!(f, cloned);
    }

    // -- JSON field presence tests --

    #[test]
    fn request_context_json_field_names() {
        let ctx = context();
        let json = serde_json::to_value(&ctx).expect("serde deserialization should succeed");
        let obj = json
            .as_object()
            .expect("serde deserialization should succeed");
        assert!(obj.contains_key("trace_id"));
        assert!(obj.contains_key("request_id"));
        assert!(obj.contains_key("component"));
        assert!(obj.contains_key("decision_id"));
        assert!(obj.contains_key("policy_id"));
        assert_eq!(obj.len(), 5);
    }

    #[test]
    fn health_status_response_json_field_names() {
        let h = HealthStatusResponse {
            runtime_status: "healthy".to_string(),
            loaded_extensions: vec!["ext-z".to_string()],
            security_epoch: 99,
            gc_pressure_basis_points: 42,
        };
        let json = serde_json::to_value(&h).expect("serde deserialization should succeed");
        let obj = json
            .as_object()
            .expect("serde deserialization should succeed");
        assert!(obj.contains_key("runtime_status"));
        assert!(obj.contains_key("loaded_extensions"));
        assert!(obj.contains_key("security_epoch"));
        assert!(obj.contains_key("gc_pressure_basis_points"));
        assert_eq!(obj.len(), 4);
    }

    #[test]
    fn evidence_record_json_field_names() {
        let r = EvidenceRecord {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "ok".to_string(),
            artifact_ref: "ref".to_string(),
        };
        let json = serde_json::to_value(&r).expect("serde deserialization should succeed");
        let obj = json
            .as_object()
            .expect("serde deserialization should succeed");
        assert!(obj.contains_key("trace_id"));
        assert!(obj.contains_key("decision_id"));
        assert!(obj.contains_key("policy_id"));
        assert!(obj.contains_key("component"));
        assert!(obj.contains_key("event"));
        assert!(obj.contains_key("outcome"));
        assert!(obj.contains_key("artifact_ref"));
        assert_eq!(obj.len(), 7);
    }

    // -- Serde roundtrip --

    #[test]
    fn evidence_export_response_serde_roundtrip() {
        let resp = EvidenceExportResponse {
            records: vec![
                EvidenceRecord {
                    trace_id: "t1".to_string(),
                    decision_id: "d1".to_string(),
                    policy_id: "p1".to_string(),
                    component: "c1".to_string(),
                    event: "e1".to_string(),
                    outcome: "ok".to_string(),
                    artifact_ref: "evidence://r1".to_string(),
                },
                EvidenceRecord {
                    trace_id: "t2".to_string(),
                    decision_id: "d2".to_string(),
                    policy_id: "p2".to_string(),
                    component: "c2".to_string(),
                    event: "e2".to_string(),
                    outcome: "deny".to_string(),
                    artifact_ref: "evidence://r2".to_string(),
                },
            ],
            next_cursor: Some("cursor-next".to_string()),
        };
        let json = serde_json::to_string(&resp).expect("serde deserialization should succeed");
        let back: EvidenceExportResponse =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(resp, back);
    }

    // -- Display uniqueness --

    #[test]
    fn control_action_debug_variants_are_distinct() {
        let variants = [
            ControlAction::Start,
            ControlAction::Stop,
            ControlAction::Suspend,
            ControlAction::Quarantine,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            let repr = format!("{:?}", v);
            assert!(
                seen.insert(repr),
                "duplicate Debug output for ControlAction variant"
            );
        }
        assert_eq!(seen.len(), 4);
    }

    // -- Boundary condition --

    #[test]
    fn evidence_export_request_max_since_epoch_roundtrips() {
        let req = EvidenceExportRequest {
            since_epoch_seconds: u64::MAX,
            until_epoch_seconds: None,
            page_size: 1,
            cursor: None,
        };
        let json = serde_json::to_string(&req).expect("serde deserialization should succeed");
        let back: EvidenceExportRequest =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(req.since_epoch_seconds, back.since_epoch_seconds);
        assert_eq!(back.since_epoch_seconds, u64::MAX);
    }

    // -- Ord determinism --

    #[test]
    fn replay_command_debug_variants_are_distinct_and_deterministic() {
        let variants = [
            ReplayCommand::Start,
            ReplayCommand::Stop,
            ReplayCommand::Status,
        ];
        let mut outputs = Vec::new();
        for v in &variants {
            outputs.push(format!("{:?}", v));
        }
        // All distinct
        let deduped: std::collections::BTreeSet<&str> =
            outputs.iter().map(|s| s.as_str()).collect();
        assert_eq!(deduped.len(), 3);
        // Deterministic: second pass produces same output
        for (i, v) in variants.iter().enumerate() {
            assert_eq!(format!("{:?}", v), outputs[i]);
        }
    }

    // -- Enrichment: serde roundtrips for untested types (PearlTower 2026-02-26) --

    #[test]
    fn control_action_response_serde_roundtrip() {
        let r = ControlActionResponse {
            extension_id: "ext-a".into(),
            action: ControlAction::Quarantine,
            accepted: true,
            decision_id: "d-1".into(),
        };
        let json = serde_json::to_string(&r).expect("serde deserialization should succeed");
        let back: ControlActionResponse =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(r, back);
    }

    #[test]
    fn replay_control_response_serde_roundtrip() {
        let r = ReplayControlResponse {
            session_id: "sess-1".into(),
            state: "running".into(),
            trace_id: Some("t-1".into()),
            note: "replay in progress".into(),
        };
        let json = serde_json::to_string(&r).expect("serde deserialization should succeed");
        let back: ReplayControlResponse =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(r, back);
    }

    // -- Enrichment: edge cases and structural coverage (PearlTower 2026-03-02) --

    #[test]
    fn control_action_all_variants_accepted() {
        let counter = Rc::new(Cell::new(0u32));
        let mut tmpl = template(counter.clone());
        let auth = auth_with_scopes(&[SCOPE_CONTROL_WRITE]);
        let ctx = context();
        let variants = [
            ControlAction::Start,
            ControlAction::Stop,
            ControlAction::Suspend,
            ControlAction::Quarantine,
        ];
        for action in &variants {
            let req = ControlActionRequest {
                extension_id: "ext-1".into(),
                action: *action,
                reason: "test".into(),
            };
            let resp = tmpl.control_action_endpoint(&auth, &ctx, &req);
            assert_eq!(resp.status, "ok");
            let data = resp.data.expect("serde deserialization should succeed");
            assert_eq!(data.action, *action);
            assert!(data.accepted);
        }
        assert_eq!(counter.get(), 4);
    }

    #[test]
    fn control_action_rejects_whitespace_only_extension_id() {
        let counter = Rc::new(Cell::new(0u32));
        let mut tmpl = template(counter.clone());
        let auth = auth_with_scopes(&[SCOPE_CONTROL_WRITE]);
        let ctx = context();
        let req = ControlActionRequest {
            extension_id: "   \t  ".into(),
            action: ControlAction::Start,
            reason: "valid reason".into(),
        };
        let resp = tmpl.control_action_endpoint(&auth, &ctx, &req);
        assert_eq!(resp.status, "error");
        assert!(resp.data.is_none());
        let err = resp.error.expect("serde deserialization should succeed");
        assert_eq!(err.error_code, "invalid_request");
        assert_eq!(counter.get(), 0); // executor never called
    }

    #[test]
    fn evidence_export_until_before_since_rejected() {
        let counter = Rc::new(Cell::new(0u32));
        let tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_EVIDENCE_READ]);
        let ctx = context();
        let req = EvidenceExportRequest {
            since_epoch_seconds: 100,
            until_epoch_seconds: Some(50),
            page_size: 10,
            cursor: None,
        };
        let resp = tmpl.evidence_export_endpoint(&auth, &ctx, &req);
        assert_eq!(resp.status, "error");
        let err = resp.error.expect("serde deserialization should succeed");
        assert!(
            err.details
                .values()
                .any(|v| v.contains("since_epoch_seconds"))
        );
    }

    #[test]
    fn evidence_export_with_cursor_forwards_to_provider() {
        let counter = Rc::new(Cell::new(0u32));
        let tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_EVIDENCE_READ]);
        let ctx = context();
        let req = EvidenceExportRequest {
            since_epoch_seconds: 0,
            until_epoch_seconds: None,
            page_size: 50,
            cursor: Some("cursor-abc".into()),
        };
        let resp = tmpl.evidence_export_endpoint(&auth, &ctx, &req);
        assert_eq!(resp.status, "ok");
        let data = resp.data.expect("serde deserialization should succeed");
        // MockEvidenceProvider echoes cursor as next_cursor
        assert_eq!(data.next_cursor, Some("cursor-abc".to_string()));
        assert_eq!(data.records.len(), 1);
    }

    #[test]
    fn evidence_export_page_size_at_lower_boundary() {
        let counter = Rc::new(Cell::new(0u32));
        let tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_EVIDENCE_READ]);
        let ctx = context();
        let req = EvidenceExportRequest {
            since_epoch_seconds: 0,
            until_epoch_seconds: None,
            page_size: 1,
            cursor: None,
        };
        let resp = tmpl.evidence_export_endpoint(&auth, &ctx, &req);
        assert_eq!(resp.status, "ok");
    }

    #[test]
    fn evidence_export_page_size_1001_rejected() {
        let counter = Rc::new(Cell::new(0u32));
        let tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_EVIDENCE_READ]);
        let ctx = context();
        let req = EvidenceExportRequest {
            since_epoch_seconds: 0,
            until_epoch_seconds: None,
            page_size: 1001,
            cursor: None,
        };
        let resp = tmpl.evidence_export_endpoint(&auth, &ctx, &req);
        assert_eq!(resp.status, "error");
    }

    #[test]
    fn replay_status_requires_only_read_scope() {
        let counter = Rc::new(Cell::new(0u32));
        let mut tmpl = template(counter);
        // read-only scope should be sufficient for Status
        let auth = auth_with_scopes(&[SCOPE_REPLAY_READ]);
        let ctx = context();
        let req = ReplayControlRequest {
            command: ReplayCommand::Status,
            trace_id: None,
            session_id: Some("sess-1".into()),
        };
        let resp = tmpl.replay_control_endpoint(&auth, &ctx, &req);
        assert_eq!(resp.status, "ok");
    }

    #[test]
    fn replay_start_denied_with_only_read_scope() {
        let counter = Rc::new(Cell::new(0u32));
        let mut tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_REPLAY_READ]);
        let ctx = context();
        let req = ReplayControlRequest {
            command: ReplayCommand::Start,
            trace_id: Some("trace-x".into()),
            session_id: None,
        };
        let resp = tmpl.replay_control_endpoint(&auth, &ctx, &req);
        assert_eq!(resp.status, "error");
        let err = resp.error.expect("serde deserialization should succeed");
        assert_eq!(err.error_code, "unauthorized");
    }

    #[test]
    fn replay_stop_denied_with_only_read_scope() {
        let counter = Rc::new(Cell::new(0u32));
        let mut tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_REPLAY_READ]);
        let ctx = context();
        let req = ReplayControlRequest {
            command: ReplayCommand::Stop,
            trace_id: None,
            session_id: Some("sess-1".into()),
        };
        let resp = tmpl.replay_control_endpoint(&auth, &ctx, &req);
        assert_eq!(resp.status, "error");
        let err = resp.error.expect("serde deserialization should succeed");
        assert_eq!(err.error_code, "unauthorized");
    }

    #[test]
    fn auth_with_multiple_scopes_grants_all() {
        let auth = auth_with_scopes(&[
            SCOPE_HEALTH_READ,
            SCOPE_CONTROL_WRITE,
            SCOPE_EVIDENCE_READ,
            SCOPE_REPLAY_READ,
            SCOPE_REPLAY_WRITE,
        ]);
        assert!(auth.has_scope(SCOPE_HEALTH_READ));
        assert!(auth.has_scope(SCOPE_CONTROL_WRITE));
        assert!(auth.has_scope(SCOPE_EVIDENCE_READ));
        assert!(auth.has_scope(SCOPE_REPLAY_READ));
        assert!(auth.has_scope(SCOPE_REPLAY_WRITE));
        assert!(!auth.has_scope("engine.admin.write"));
    }

    #[test]
    fn endpoint_failure_details_can_be_populated() {
        let mut f = EndpointFailure::new("quota_exceeded", "too many requests");
        f.details.insert("retry_after_seconds".into(), "30".into());
        assert_eq!(f.details.len(), 1);
        assert_eq!(f.details["retry_after_seconds"], "30");
        // serde roundtrip preserves details
        let json = serde_json::to_string(&f).expect("serde deserialization should succeed");
        let back: EndpointFailure =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back.details.len(), 1);
    }

    #[test]
    fn health_endpoint_log_has_health_read_event() {
        let counter = Rc::new(Cell::new(0u32));
        let tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_HEALTH_READ]);
        let ctx = context();
        let resp = tmpl.health_endpoint(&auth, &ctx);
        assert_eq!(resp.log.event, "health.read");
        assert_eq!(resp.log.outcome, "ok");
        assert_eq!(resp.log.trace_id, "trace-01");
        assert_eq!(resp.log.component, "service.api");
    }

    #[test]
    fn control_action_log_has_control_execute_event() {
        let counter = Rc::new(Cell::new(0u32));
        let mut tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_CONTROL_WRITE]);
        let ctx = context();
        let req = ControlActionRequest {
            extension_id: "ext-1".into(),
            action: ControlAction::Start,
            reason: "testing".into(),
        };
        let resp = tmpl.control_action_endpoint(&auth, &ctx, &req);
        assert_eq!(resp.log.event, "control.execute");
        assert_eq!(resp.log.outcome, "ok");
    }

    #[test]
    fn evidence_export_log_has_evidence_export_event() {
        let counter = Rc::new(Cell::new(0u32));
        let tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_EVIDENCE_READ]);
        let ctx = context();
        let req = EvidenceExportRequest {
            since_epoch_seconds: 0,
            until_epoch_seconds: None,
            page_size: 100,
            cursor: None,
        };
        let resp = tmpl.evidence_export_endpoint(&auth, &ctx, &req);
        assert_eq!(resp.log.event, "evidence.export");
        assert_eq!(resp.log.outcome, "ok");
    }

    #[test]
    fn replay_control_log_has_replay_control_event() {
        let counter = Rc::new(Cell::new(0u32));
        let mut tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_REPLAY_WRITE]);
        let ctx = context();
        let req = ReplayControlRequest {
            command: ReplayCommand::Start,
            trace_id: Some("trace-replay".into()),
            session_id: None,
        };
        let resp = tmpl.replay_control_endpoint(&auth, &ctx, &req);
        assert_eq!(resp.log.event, "replay.control");
        assert_eq!(resp.log.outcome, "ok");
    }

    #[test]
    fn unauthorized_error_includes_required_scope_in_details() {
        let counter = Rc::new(Cell::new(0u32));
        let tmpl = template(counter);
        let auth = auth_with_scopes(&[]);
        let ctx = context();
        let resp = tmpl.health_endpoint(&auth, &ctx);
        assert_eq!(resp.status, "error");
        let err = resp.error.expect("serde deserialization should succeed");
        assert_eq!(err.error_code, "unauthorized");
        assert!(
            err.details
                .values()
                .any(|v| v.contains("engine.health.read"))
        );
    }

    #[test]
    fn ok_response_preserves_request_id_and_trace_id() {
        let counter = Rc::new(Cell::new(0u32));
        let tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_HEALTH_READ]);
        let ctx = RequestContext {
            trace_id: "trace-unique-42".into(),
            request_id: "req-unique-99".into(),
            component: "api.gateway".into(),
            decision_id: Some("dec-7".into()),
            policy_id: Some("pol-3".into()),
        };
        let resp = tmpl.health_endpoint(&auth, &ctx);
        assert_eq!(resp.trace_id, "trace-unique-42");
        assert_eq!(resp.request_id, "req-unique-99");
        assert_eq!(resp.log.decision_id, Some("dec-7".into()));
        assert_eq!(resp.log.policy_id, Some("pol-3".into()));
    }

    #[test]
    fn context_without_optional_fields_produces_none_in_log() {
        let counter = Rc::new(Cell::new(0u32));
        let tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_HEALTH_READ]);
        let ctx = RequestContext {
            trace_id: "trace-1".into(),
            request_id: "req-1".into(),
            component: "svc".into(),
            decision_id: None,
            policy_id: None,
        };
        let resp = tmpl.health_endpoint(&auth, &ctx);
        assert_eq!(resp.log.decision_id, None);
        assert_eq!(resp.log.policy_id, None);
    }

    #[test]
    fn control_action_serde_all_variants_roundtrip() {
        let variants = [
            ControlAction::Start,
            ControlAction::Stop,
            ControlAction::Suspend,
            ControlAction::Quarantine,
        ];
        for action in &variants {
            let json = serde_json::to_string(action).expect("serde deserialization should succeed");
            let back: ControlAction =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*action, back);
        }
    }

    #[test]
    fn replay_command_serde_all_variants_roundtrip() {
        let variants = [
            ReplayCommand::Start,
            ReplayCommand::Stop,
            ReplayCommand::Status,
        ];
        for cmd in &variants {
            let json = serde_json::to_string(cmd).expect("serde deserialization should succeed");
            let back: ReplayCommand =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*cmd, back);
        }
    }

    #[test]
    fn error_response_log_includes_error_code_in_log_event() {
        let counter = Rc::new(Cell::new(0u32));
        let tmpl = template(counter);
        let auth = auth_with_scopes(&[]);
        let ctx = context();
        let resp = tmpl.health_endpoint(&auth, &ctx);
        assert_eq!(resp.log.error_code, Some("unauthorized".into()));
    }

    #[test]
    fn health_endpoint_data_contains_provider_values() {
        let counter = Rc::new(Cell::new(0u32));
        let tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_HEALTH_READ]);
        let ctx = context();
        let resp = tmpl.health_endpoint(&auth, &ctx);
        let data = resp.data.expect("serde deserialization should succeed");
        assert_eq!(data.runtime_status, "healthy");
        assert!(data.loaded_extensions.contains(&"ext-a".to_string()));
        assert_eq!(data.security_epoch, 42);
        assert_eq!(data.gc_pressure_basis_points, 180);
    }

    #[test]
    fn endpoint_response_json_field_names_stable() {
        let counter = Rc::new(Cell::new(0u32));
        let tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_HEALTH_READ]);
        let ctx = context();
        let resp = tmpl.health_endpoint(&auth, &ctx);
        let json = serde_json::to_string(&resp).expect("serde deserialization should succeed");
        assert!(json.contains("\"status\""));
        assert!(json.contains("\"endpoint\""));
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"request_id\""));
        assert!(json.contains("\"data\""));
        assert!(json.contains("\"log\""));
    }

    #[test]
    fn evidence_export_none_until_accepted() {
        let counter = Rc::new(Cell::new(0u32));
        let tmpl = template(counter);
        let auth = auth_with_scopes(&[SCOPE_EVIDENCE_READ]);
        let ctx = context();
        let req = EvidenceExportRequest {
            since_epoch_seconds: 0,
            until_epoch_seconds: None,
            page_size: 500,
            cursor: None,
        };
        let resp = tmpl.evidence_export_endpoint(&auth, &ctx, &req);
        assert_eq!(resp.status, "ok");
    }

    #[test]
    fn control_action_reason_at_257_chars_rejected() {
        let counter = Rc::new(Cell::new(0u32));
        let mut tmpl = template(counter.clone());
        let auth = auth_with_scopes(&[SCOPE_CONTROL_WRITE]);
        let ctx = context();
        let long_reason: String = "x".repeat(257);
        let req = ControlActionRequest {
            extension_id: "ext-1".into(),
            action: ControlAction::Start,
            reason: long_reason,
        };
        let resp = tmpl.control_action_endpoint(&auth, &ctx, &req);
        assert_eq!(resp.status, "error");
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn scope_constants_are_dot_separated() {
        for scope in &[
            SCOPE_HEALTH_READ,
            SCOPE_CONTROL_WRITE,
            SCOPE_EVIDENCE_READ,
            SCOPE_REPLAY_READ,
            SCOPE_REPLAY_WRITE,
        ] {
            assert!(
                scope.contains('.'),
                "scope '{}' missing dot separator",
                scope
            );
            let parts: Vec<&str> = scope.split('.').collect();
            assert!(parts.len() >= 2, "scope '{}' needs at least 2 parts", scope);
        }
    }
}
