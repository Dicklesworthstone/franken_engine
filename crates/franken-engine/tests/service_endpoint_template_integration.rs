//! Integration tests for `policy_controller::service_endpoint_template`.
//!
//! Validates the full endpoint pipeline: authentication -> validation -> execution -> response
//! envelope construction, including cross-endpoint consistency, error propagation, and
//! JSON serialization stability.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

use frankenengine_engine::policy_controller::service_endpoint_template::{
    AuthContext, ControlAction, ControlActionRequest, ControlActionResponse,
    DecisionContractExecutor, EndpointFailure, EndpointResponse, ErrorEnvelope,
    EvidenceExportProvider, EvidenceExportRequest, EvidenceExportResponse, EvidenceRecord,
    HealthStatusResponse, ReplayCommand, ReplayControlRequest, ReplayControlResponse,
    ReplayController, RequestContext, RuntimeHealthProvider, SCOPE_CONTROL_WRITE,
    SCOPE_EVIDENCE_READ, SCOPE_HEALTH_READ, SCOPE_REPLAY_READ, SCOPE_REPLAY_WRITE,
    ServiceEndpointTemplate, StructuredLogEvent,
};

// ── Mock providers ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct StubHealthProvider {
    status: String,
    extensions: Vec<String>,
    epoch: u64,
    gc_bp: u16,
}

impl RuntimeHealthProvider for StubHealthProvider {
    fn read_health(&self) -> HealthStatusResponse {
        HealthStatusResponse {
            runtime_status: self.status.clone(),
            loaded_extensions: self.extensions.clone(),
            security_epoch: self.epoch,
            gc_pressure_basis_points: self.gc_bp,
        }
    }
}

#[derive(Debug, Clone)]
struct StubDecisionExecutor {
    calls: Rc<Cell<u32>>,
    fail_with: Option<EndpointFailure>,
}

impl DecisionContractExecutor for StubDecisionExecutor {
    fn execute_control_action(
        &mut self,
        request: &ControlActionRequest,
        _context: &RequestContext,
    ) -> Result<ControlActionResponse, EndpointFailure> {
        self.calls.set(self.calls.get() + 1);
        if let Some(f) = &self.fail_with {
            return Err(f.clone());
        }
        Ok(ControlActionResponse {
            extension_id: request.extension_id.clone(),
            action: request.action,
            accepted: true,
            decision_id: format!("decision-{}", self.calls.get()),
        })
    }
}

#[derive(Debug, Clone)]
struct StubEvidenceProvider {
    records: Vec<EvidenceRecord>,
    fail_with: Option<EndpointFailure>,
}

impl EvidenceExportProvider for StubEvidenceProvider {
    fn export_evidence(
        &self,
        request: &EvidenceExportRequest,
        _context: &RequestContext,
    ) -> Result<EvidenceExportResponse, EndpointFailure> {
        if let Some(f) = &self.fail_with {
            return Err(f.clone());
        }
        let page = self
            .records
            .iter()
            .take(request.page_size as usize)
            .cloned()
            .collect();
        Ok(EvidenceExportResponse {
            records: page,
            next_cursor: request.cursor.clone(),
        })
    }
}

#[derive(Debug, Clone)]
struct StubReplayController {
    calls: Rc<Cell<u32>>,
    fail_with: Option<EndpointFailure>,
}

impl ReplayController for StubReplayController {
    fn control_replay(
        &mut self,
        request: &ReplayControlRequest,
        _context: &RequestContext,
    ) -> Result<ReplayControlResponse, EndpointFailure> {
        self.calls.set(self.calls.get() + 1);
        if let Some(f) = &self.fail_with {
            return Err(f.clone());
        }
        let (session_id, state, note) = match request.command {
            ReplayCommand::Start => (
                format!("session-new-{}", self.calls.get()),
                "running".to_string(),
                "started".to_string(),
            ),
            ReplayCommand::Stop => (
                request
                    .session_id
                    .clone()
                    .unwrap_or_else(|| "unknown".into()),
                "stopped".to_string(),
                "stopped".to_string(),
            ),
            ReplayCommand::Status => (
                request
                    .session_id
                    .clone()
                    .unwrap_or_else(|| "unknown".into()),
                "running".to_string(),
                "queried".to_string(),
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

// ── Helpers ─────────────────────────────────────────────────────────

fn ctx() -> RequestContext {
    RequestContext {
        trace_id: "trace-integ-001".into(),
        request_id: "req-integ-001".into(),
        component: "integration.test".into(),
        decision_id: Some("decision-integ".into()),
        policy_id: Some("policy-integ".into()),
    }
}

fn ctx_with_trace(trace_id: &str) -> RequestContext {
    RequestContext {
        trace_id: trace_id.into(),
        request_id: "req-ctx-custom".into(),
        component: "integration.test".into(),
        decision_id: None,
        policy_id: None,
    }
}

fn auth(scopes: &[&str]) -> AuthContext {
    AuthContext {
        subject: "integ-operator@test".into(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
    }
}

fn all_scopes_auth() -> AuthContext {
    auth(&[
        SCOPE_HEALTH_READ,
        SCOPE_CONTROL_WRITE,
        SCOPE_EVIDENCE_READ,
        SCOPE_REPLAY_READ,
        SCOPE_REPLAY_WRITE,
    ])
}

fn default_health_provider() -> StubHealthProvider {
    StubHealthProvider {
        status: "healthy".into(),
        extensions: vec!["ext-alpha".into(), "ext-beta".into()],
        epoch: 100,
        gc_bp: 250,
    }
}

fn make_evidence_record(idx: u32) -> EvidenceRecord {
    EvidenceRecord {
        trace_id: format!("trace-ev-{idx}"),
        decision_id: format!("dec-ev-{idx}"),
        policy_id: format!("pol-ev-{idx}"),
        component: "evidence.provider".into(),
        event: format!("event-{idx}"),
        outcome: "allow".into(),
        artifact_ref: format!("evidence://artifact/{idx}"),
    }
}

struct TemplateKit {
    decision_calls: Rc<Cell<u32>>,
    replay_calls: Rc<Cell<u32>>,
    template: ServiceEndpointTemplate<
        StubHealthProvider,
        StubDecisionExecutor,
        StubEvidenceProvider,
        StubReplayController,
    >,
}

fn build_template() -> TemplateKit {
    let decision_calls = Rc::new(Cell::new(0));
    let replay_calls = Rc::new(Cell::new(0));
    let template = ServiceEndpointTemplate::new(
        default_health_provider(),
        StubDecisionExecutor {
            calls: Rc::clone(&decision_calls),
            fail_with: None,
        },
        StubEvidenceProvider {
            records: (0..10).map(make_evidence_record).collect(),
            fail_with: None,
        },
        StubReplayController {
            calls: Rc::clone(&replay_calls),
            fail_with: None,
        },
    );
    TemplateKit {
        decision_calls,
        replay_calls,
        template,
    }
}

fn control_req(ext_id: &str, action: ControlAction, reason: &str) -> ControlActionRequest {
    ControlActionRequest {
        extension_id: ext_id.into(),
        action,
        reason: reason.into(),
    }
}

fn evidence_req(since: u64, until: Option<u64>, page_size: u16) -> EvidenceExportRequest {
    EvidenceExportRequest {
        since_epoch_seconds: since,
        until_epoch_seconds: until,
        page_size,
        cursor: None,
    }
}

fn replay_start_req(trace_id: &str) -> ReplayControlRequest {
    ReplayControlRequest {
        command: ReplayCommand::Start,
        trace_id: Some(trace_id.into()),
        session_id: None,
    }
}

fn replay_stop_req(session_id: &str) -> ReplayControlRequest {
    ReplayControlRequest {
        command: ReplayCommand::Stop,
        trace_id: None,
        session_id: Some(session_id.into()),
    }
}

fn replay_status_req(session_id: &str) -> ReplayControlRequest {
    ReplayControlRequest {
        command: ReplayCommand::Status,
        trace_id: None,
        session_id: Some(session_id.into()),
    }
}

// ── Section 1: Health endpoint pipeline ─────────────────────────────

#[test]
fn health_endpoint_full_pipeline() {
    let kit = build_template();
    let resp = kit
        .template
        .health_endpoint(&auth(&[SCOPE_HEALTH_READ]), &ctx());
    assert_eq!(resp.status, "ok");
    assert_eq!(resp.endpoint, "health");
    assert_eq!(resp.trace_id, "trace-integ-001");
    assert_eq!(resp.request_id, "req-integ-001");
    let data = resp.data.expect("health data");
    assert_eq!(data.runtime_status, "healthy");
    assert_eq!(data.loaded_extensions, vec!["ext-alpha", "ext-beta"]);
    assert_eq!(data.security_epoch, 100);
    assert_eq!(data.gc_pressure_basis_points, 250);
    assert!(resp.error.is_none());
    assert_eq!(resp.log.event, "health.read");
    assert_eq!(resp.log.outcome, "ok");
    assert!(resp.log.error_code.is_none());
}

#[test]
fn health_endpoint_unauthorized_returns_structured_error() {
    let kit = build_template();
    let resp = kit.template.health_endpoint(&auth(&[]), &ctx());
    assert_eq!(resp.status, "error");
    assert!(resp.data.is_none());
    let err = resp.error.expect("error envelope");
    assert_eq!(err.error_code, "unauthorized");
    assert_eq!(err.details["required_scope"], SCOPE_HEALTH_READ);
    assert_eq!(resp.log.event, "authz.denied");
    assert_eq!(resp.log.outcome, "error");
    assert_eq!(resp.log.error_code.as_deref(), Some("unauthorized"));
}

#[test]
fn health_endpoint_wrong_scope_is_unauthorized() {
    let kit = build_template();
    let resp = kit
        .template
        .health_endpoint(&auth(&[SCOPE_CONTROL_WRITE, SCOPE_REPLAY_READ]), &ctx());
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.expect("err").error_code, "unauthorized");
}

#[test]
fn health_endpoint_reflects_provider_state_variants() {
    let template = ServiceEndpointTemplate::new(
        StubHealthProvider {
            status: "degraded".into(),
            extensions: vec![],
            epoch: 0,
            gc_bp: 10_000,
        },
        StubDecisionExecutor {
            calls: Rc::new(Cell::new(0)),
            fail_with: None,
        },
        StubEvidenceProvider {
            records: vec![],
            fail_with: None,
        },
        StubReplayController {
            calls: Rc::new(Cell::new(0)),
            fail_with: None,
        },
    );
    let resp = template.health_endpoint(&auth(&[SCOPE_HEALTH_READ]), &ctx());
    let data = resp.data.expect("data");
    assert_eq!(data.runtime_status, "degraded");
    assert!(data.loaded_extensions.is_empty());
    assert_eq!(data.security_epoch, 0);
    assert_eq!(data.gc_pressure_basis_points, 10_000);
}

// ── Section 2: Control action endpoint pipeline ─────────────────────

#[test]
fn control_action_full_pipeline_all_actions() {
    let kit = build_template();
    let mut tmpl = kit.template;
    let a = all_scopes_auth();
    let c = ctx();

    for (i, action) in [
        ControlAction::Start,
        ControlAction::Stop,
        ControlAction::Suspend,
        ControlAction::Quarantine,
    ]
    .into_iter()
    .enumerate()
    {
        let resp = tmpl.control_action_endpoint(
            &a,
            &c,
            &control_req("ext-target", action, "integration test"),
        );
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.endpoint, "control_action");
        let data = resp.data.expect("control data");
        assert_eq!(data.extension_id, "ext-target");
        assert_eq!(data.action, action);
        assert!(data.accepted);
        assert_eq!(data.decision_id, format!("decision-{}", i + 1));
        assert_eq!(resp.log.event, "control.execute");
    }
    assert_eq!(kit.decision_calls.get(), 4);
}

#[test]
fn control_action_unauthorized_without_scope() {
    let mut kit = build_template();
    let resp = kit.template.control_action_endpoint(
        &auth(&[SCOPE_HEALTH_READ]),
        &ctx(),
        &control_req("ext-a", ControlAction::Start, "reason"),
    );
    assert_eq!(resp.status, "error");
    let err = resp.error.expect("err");
    assert_eq!(err.error_code, "unauthorized");
    assert_eq!(err.details["required_scope"], SCOPE_CONTROL_WRITE);
    assert_eq!(kit.decision_calls.get(), 0, "executor must not be called");
}

#[test]
fn control_action_empty_extension_id_rejected() {
    let mut kit = build_template();
    let resp = kit.template.control_action_endpoint(
        &all_scopes_auth(),
        &ctx(),
        &control_req("", ControlAction::Stop, "valid reason"),
    );
    assert_eq!(resp.status, "error");
    let err = resp.error.expect("err");
    assert_eq!(err.error_code, "invalid_request");
    assert_eq!(err.details["field"], "extension_id");
    assert_eq!(kit.decision_calls.get(), 0);
}

#[test]
fn control_action_whitespace_extension_id_rejected() {
    let mut kit = build_template();
    let resp = kit.template.control_action_endpoint(
        &all_scopes_auth(),
        &ctx(),
        &control_req("   ", ControlAction::Stop, "valid reason"),
    );
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.expect("err").details["field"], "extension_id");
}

#[test]
fn control_action_empty_reason_rejected() {
    let mut kit = build_template();
    let resp = kit.template.control_action_endpoint(
        &all_scopes_auth(),
        &ctx(),
        &control_req("ext-a", ControlAction::Suspend, ""),
    );
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.expect("err").details["field"], "reason");
}

#[test]
fn control_action_whitespace_reason_rejected() {
    let mut kit = build_template();
    let resp = kit.template.control_action_endpoint(
        &all_scopes_auth(),
        &ctx(),
        &control_req("ext-a", ControlAction::Quarantine, "   \t  "),
    );
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.expect("err").details["field"], "reason");
}

#[test]
fn control_action_reason_length_boundary() {
    let mut kit = build_template();
    // Exactly 256 chars: accepted
    let resp_256 = kit.template.control_action_endpoint(
        &all_scopes_auth(),
        &ctx(),
        &control_req("ext-a", ControlAction::Start, &"x".repeat(256)),
    );
    assert_eq!(resp_256.status, "ok");

    // 257 chars: rejected
    let resp_257 = kit.template.control_action_endpoint(
        &all_scopes_auth(),
        &ctx(),
        &control_req("ext-a", ControlAction::Start, &"y".repeat(257)),
    );
    assert_eq!(resp_257.status, "error");
    assert_eq!(resp_257.error.expect("err").details["field"], "reason");
}

#[test]
fn control_action_upstream_failure_propagation() {
    let calls = Rc::new(Cell::new(0));
    let mut details = BTreeMap::new();
    details.insert("subsystem".into(), "decision-core".into());
    let mut tmpl = ServiceEndpointTemplate::new(
        default_health_provider(),
        StubDecisionExecutor {
            calls: Rc::clone(&calls),
            fail_with: Some(EndpointFailure {
                error_code: "BACKEND-503".into(),
                message: "service unavailable".into(),
                details,
            }),
        },
        StubEvidenceProvider {
            records: vec![],
            fail_with: None,
        },
        StubReplayController {
            calls: Rc::new(Cell::new(0)),
            fail_with: None,
        },
    );
    let resp = tmpl.control_action_endpoint(
        &all_scopes_auth(),
        &ctx(),
        &control_req("ext-b", ControlAction::Quarantine, "test failure"),
    );
    assert_eq!(resp.status, "error");
    let err = resp.error.expect("err");
    assert_eq!(err.error_code, "BACKEND-503");
    assert_eq!(err.message, "service unavailable");
    assert_eq!(err.details["subsystem"], "decision-core");
    assert_eq!(resp.log.outcome, "error");
    assert_eq!(calls.get(), 1);
}

#[test]
fn control_action_validation_precedes_execution() {
    // Auth passes but validation fails => executor not called
    let mut kit = build_template();
    let _resp = kit.template.control_action_endpoint(
        &all_scopes_auth(),
        &ctx(),
        &control_req("", ControlAction::Start, "reason"),
    );
    assert_eq!(
        kit.decision_calls.get(),
        0,
        "executor must not run on invalid input"
    );
}

// ── Section 3: Evidence export endpoint pipeline ────────────────────

#[test]
fn evidence_export_full_pipeline() {
    let kit = build_template();
    let resp = kit.template.evidence_export_endpoint(
        &auth(&[SCOPE_EVIDENCE_READ]),
        &ctx(),
        &evidence_req(0, Some(1000), 5),
    );
    assert_eq!(resp.status, "ok");
    assert_eq!(resp.endpoint, "evidence_export");
    let data = resp.data.expect("evidence data");
    assert_eq!(data.records.len(), 5);
    assert!(data.next_cursor.is_none());
    assert_eq!(resp.log.event, "evidence.export");
}

#[test]
fn evidence_export_with_cursor_passthrough() {
    let kit = build_template();
    let req = EvidenceExportRequest {
        since_epoch_seconds: 0,
        until_epoch_seconds: None,
        page_size: 3,
        cursor: Some("cursor-abc-123".into()),
    };
    let resp = kit
        .template
        .evidence_export_endpoint(&auth(&[SCOPE_EVIDENCE_READ]), &ctx(), &req);
    assert_eq!(resp.status, "ok");
    let data = resp.data.expect("data");
    assert_eq!(data.next_cursor.as_deref(), Some("cursor-abc-123"));
}

#[test]
fn evidence_export_unauthorized() {
    let kit = build_template();
    let resp = kit.template.evidence_export_endpoint(
        &auth(&[SCOPE_HEALTH_READ]),
        &ctx(),
        &evidence_req(0, None, 10),
    );
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.expect("err").error_code, "unauthorized");
}

#[test]
fn evidence_export_page_size_zero_rejected() {
    let kit = build_template();
    let resp = kit.template.evidence_export_endpoint(
        &auth(&[SCOPE_EVIDENCE_READ]),
        &ctx(),
        &evidence_req(0, None, 0),
    );
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.expect("err").details["field"], "page_size");
}

#[test]
fn evidence_export_page_size_over_1000_rejected() {
    let kit = build_template();
    let resp = kit.template.evidence_export_endpoint(
        &auth(&[SCOPE_EVIDENCE_READ]),
        &ctx(),
        &evidence_req(0, None, 1001),
    );
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.expect("err").details["field"], "page_size");
}

#[test]
fn evidence_export_page_size_boundary_values() {
    let kit = build_template();
    // page_size=1: ok
    let r1 = kit.template.evidence_export_endpoint(
        &auth(&[SCOPE_EVIDENCE_READ]),
        &ctx(),
        &evidence_req(0, None, 1),
    );
    assert_eq!(r1.status, "ok");
    assert_eq!(r1.data.expect("d").records.len(), 1);

    // page_size=1000: ok
    let r2 = kit.template.evidence_export_endpoint(
        &auth(&[SCOPE_EVIDENCE_READ]),
        &ctx(),
        &evidence_req(0, None, 1000),
    );
    assert_eq!(r2.status, "ok");
}

#[test]
fn evidence_export_until_before_since_rejected() {
    let kit = build_template();
    let resp = kit.template.evidence_export_endpoint(
        &auth(&[SCOPE_EVIDENCE_READ]),
        &ctx(),
        &evidence_req(100, Some(99), 10),
    );
    assert_eq!(resp.status, "error");
    assert_eq!(
        resp.error.expect("err").details["field"],
        "until_epoch_seconds"
    );
}

#[test]
fn evidence_export_equal_since_until_accepted() {
    let kit = build_template();
    let resp = kit.template.evidence_export_endpoint(
        &auth(&[SCOPE_EVIDENCE_READ]),
        &ctx(),
        &evidence_req(500, Some(500), 10),
    );
    assert_eq!(resp.status, "ok");
}

#[test]
fn evidence_export_upstream_failure() {
    let tmpl = ServiceEndpointTemplate::new(
        default_health_provider(),
        StubDecisionExecutor {
            calls: Rc::new(Cell::new(0)),
            fail_with: None,
        },
        StubEvidenceProvider {
            records: vec![],
            fail_with: Some(EndpointFailure::new("EV-FAIL", "export broken")),
        },
        StubReplayController {
            calls: Rc::new(Cell::new(0)),
            fail_with: None,
        },
    );
    let resp = tmpl.evidence_export_endpoint(
        &auth(&[SCOPE_EVIDENCE_READ]),
        &ctx(),
        &evidence_req(0, None, 10),
    );
    assert_eq!(resp.status, "error");
    let err = resp.error.expect("err");
    assert_eq!(err.error_code, "EV-FAIL");
    assert_eq!(err.message, "export broken");
}

// ── Section 4: Replay control endpoint pipeline ─────────────────────

#[test]
fn replay_start_full_pipeline() {
    let mut kit = build_template();
    let resp = kit.template.replay_control_endpoint(
        &auth(&[SCOPE_REPLAY_WRITE]),
        &ctx(),
        &replay_start_req("trace-replay-001"),
    );
    assert_eq!(resp.status, "ok");
    assert_eq!(resp.endpoint, "replay_control");
    let data = resp.data.expect("replay data");
    assert_eq!(data.session_id, "session-new-1");
    assert_eq!(data.state, "running");
    assert_eq!(data.trace_id.as_deref(), Some("trace-replay-001"));
    assert_eq!(kit.replay_calls.get(), 1);
}

#[test]
fn replay_stop_full_pipeline() {
    let mut kit = build_template();
    let resp = kit.template.replay_control_endpoint(
        &auth(&[SCOPE_REPLAY_WRITE]),
        &ctx(),
        &replay_stop_req("session-42"),
    );
    assert_eq!(resp.status, "ok");
    let data = resp.data.expect("data");
    assert_eq!(data.session_id, "session-42");
    assert_eq!(data.state, "stopped");
}

#[test]
fn replay_status_full_pipeline() {
    let mut kit = build_template();
    let resp = kit.template.replay_control_endpoint(
        &auth(&[SCOPE_REPLAY_READ]),
        &ctx(),
        &replay_status_req("session-77"),
    );
    assert_eq!(resp.status, "ok");
    let data = resp.data.expect("data");
    assert_eq!(data.session_id, "session-77");
    assert_eq!(data.state, "running");
}

#[test]
fn replay_start_requires_write_scope() {
    let mut kit = build_template();
    let resp = kit.template.replay_control_endpoint(
        &auth(&[SCOPE_REPLAY_READ]),
        &ctx(),
        &replay_start_req("trace-001"),
    );
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.expect("err").error_code, "unauthorized");
}

#[test]
fn replay_stop_requires_write_scope() {
    let mut kit = build_template();
    let resp = kit.template.replay_control_endpoint(
        &auth(&[SCOPE_REPLAY_READ]),
        &ctx(),
        &replay_stop_req("session-1"),
    );
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.expect("err").error_code, "unauthorized");
}

#[test]
fn replay_status_requires_read_scope() {
    let mut kit = build_template();
    let resp = kit.template.replay_control_endpoint(
        &auth(&[SCOPE_REPLAY_WRITE]),
        &ctx(),
        &replay_status_req("session-1"),
    );
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.expect("err").error_code, "unauthorized");
}

#[test]
fn replay_start_missing_trace_id_rejected() {
    let mut kit = build_template();
    let resp = kit.template.replay_control_endpoint(
        &auth(&[SCOPE_REPLAY_WRITE]),
        &ctx(),
        &ReplayControlRequest {
            command: ReplayCommand::Start,
            trace_id: None,
            session_id: None,
        },
    );
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.expect("err").details["field"], "trace_id");
}

#[test]
fn replay_start_blank_trace_id_rejected() {
    let mut kit = build_template();
    let resp = kit.template.replay_control_endpoint(
        &auth(&[SCOPE_REPLAY_WRITE]),
        &ctx(),
        &ReplayControlRequest {
            command: ReplayCommand::Start,
            trace_id: Some("   ".into()),
            session_id: None,
        },
    );
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.expect("err").details["field"], "trace_id");
}

#[test]
fn replay_stop_missing_session_id_rejected() {
    let mut kit = build_template();
    let resp = kit.template.replay_control_endpoint(
        &auth(&[SCOPE_REPLAY_WRITE]),
        &ctx(),
        &ReplayControlRequest {
            command: ReplayCommand::Stop,
            trace_id: None,
            session_id: None,
        },
    );
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.expect("err").details["field"], "session_id");
}

#[test]
fn replay_status_missing_session_id_rejected() {
    let mut kit = build_template();
    let resp = kit.template.replay_control_endpoint(
        &auth(&[SCOPE_REPLAY_READ]),
        &ctx(),
        &ReplayControlRequest {
            command: ReplayCommand::Status,
            trace_id: None,
            session_id: None,
        },
    );
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.expect("err").details["field"], "session_id");
}

#[test]
fn replay_upstream_failure_propagation() {
    let mut tmpl = ServiceEndpointTemplate::new(
        default_health_provider(),
        StubDecisionExecutor {
            calls: Rc::new(Cell::new(0)),
            fail_with: None,
        },
        StubEvidenceProvider {
            records: vec![],
            fail_with: None,
        },
        StubReplayController {
            calls: Rc::new(Cell::new(0)),
            fail_with: Some(EndpointFailure::new("REPLAY-ERR", "session corrupt")),
        },
    );
    let resp = tmpl.replay_control_endpoint(
        &auth(&[SCOPE_REPLAY_WRITE]),
        &ctx(),
        &replay_start_req("trace-fail"),
    );
    assert_eq!(resp.status, "error");
    let err = resp.error.expect("err");
    assert_eq!(err.error_code, "REPLAY-ERR");
    assert_eq!(err.message, "session corrupt");
}

// ── Section 5: Cross-endpoint consistency ───────────────────────────

#[test]
fn trace_id_propagated_across_all_endpoints() {
    let mut kit = build_template();
    let c = ctx_with_trace("trace-cross-01");
    let a = all_scopes_auth();

    let h = kit.template.health_endpoint(&a, &c);
    assert_eq!(h.trace_id, "trace-cross-01");
    assert_eq!(h.log.trace_id, "trace-cross-01");

    let ctrl = kit.template.control_action_endpoint(
        &a,
        &c,
        &control_req("ext", ControlAction::Start, "reason"),
    );
    assert_eq!(ctrl.trace_id, "trace-cross-01");
    assert_eq!(ctrl.log.trace_id, "trace-cross-01");

    let ev = kit
        .template
        .evidence_export_endpoint(&a, &c, &evidence_req(0, None, 5));
    assert_eq!(ev.trace_id, "trace-cross-01");
    assert_eq!(ev.log.trace_id, "trace-cross-01");

    let rp = kit
        .template
        .replay_control_endpoint(&a, &c, &replay_start_req("trace-rp"));
    assert_eq!(rp.trace_id, "trace-cross-01");
    assert_eq!(rp.log.trace_id, "trace-cross-01");
}

#[test]
fn request_id_propagated_to_all_ok_responses() {
    let mut kit = build_template();
    let c = ctx();
    let a = all_scopes_auth();

    assert_eq!(
        kit.template.health_endpoint(&a, &c).request_id,
        "req-integ-001"
    );
    assert_eq!(
        kit.template
            .control_action_endpoint(&a, &c, &control_req("ext", ControlAction::Start, "r"))
            .request_id,
        "req-integ-001"
    );
    assert_eq!(
        kit.template
            .evidence_export_endpoint(&a, &c, &evidence_req(0, None, 1))
            .request_id,
        "req-integ-001"
    );
    assert_eq!(
        kit.template
            .replay_control_endpoint(&a, &c, &replay_start_req("t"))
            .request_id,
        "req-integ-001"
    );
}

#[test]
fn error_envelope_always_has_trace_id_and_component() {
    let mut kit = build_template();
    let c = ctx();
    let no_auth = auth(&[]);

    let responses: Vec<String> = vec![
        kit.template
            .health_endpoint(&no_auth, &c)
            .error
            .expect("err")
            .trace_id
            .clone(),
        kit.template
            .control_action_endpoint(&no_auth, &c, &control_req("ext", ControlAction::Start, "r"))
            .error
            .expect("err")
            .trace_id
            .clone(),
        kit.template
            .evidence_export_endpoint(&no_auth, &c, &evidence_req(0, None, 10))
            .error
            .expect("err")
            .trace_id
            .clone(),
        kit.template
            .replay_control_endpoint(&no_auth, &c, &replay_start_req("t"))
            .error
            .expect("err")
            .trace_id
            .clone(),
    ];
    for trace in &responses {
        assert_eq!(trace, "trace-integ-001");
    }
}

// ── Section 6: Context field propagation to logs ────────────────────

#[test]
fn log_captures_decision_id_and_policy_id_from_context() {
    let kit = build_template();
    let c = RequestContext {
        trace_id: "t".into(),
        request_id: "r".into(),
        component: "comp".into(),
        decision_id: Some("dec-ctx".into()),
        policy_id: Some("pol-ctx".into()),
    };
    let resp = kit
        .template
        .health_endpoint(&auth(&[SCOPE_HEALTH_READ]), &c);
    assert_eq!(resp.log.decision_id.as_deref(), Some("dec-ctx"));
    assert_eq!(resp.log.policy_id.as_deref(), Some("pol-ctx"));
    assert_eq!(resp.log.component, "comp");
}

#[test]
fn log_handles_none_decision_id_and_policy_id() {
    let kit = build_template();
    let c = RequestContext {
        trace_id: "t".into(),
        request_id: "r".into(),
        component: "comp".into(),
        decision_id: None,
        policy_id: None,
    };
    let resp = kit
        .template
        .health_endpoint(&auth(&[SCOPE_HEALTH_READ]), &c);
    assert!(resp.log.decision_id.is_none());
    assert!(resp.log.policy_id.is_none());
}

// ── Section 7: Multiple sequential calls ────────────────────────────

#[test]
fn multiple_control_actions_increment_call_counter() {
    let mut kit = build_template();
    let a = all_scopes_auth();
    let c = ctx();

    for i in 1..=5 {
        let resp = kit.template.control_action_endpoint(
            &a,
            &c,
            &control_req("ext-a", ControlAction::Suspend, "batch test"),
        );
        assert_eq!(resp.status, "ok");
        assert_eq!(kit.decision_calls.get(), i);
        let data = resp.data.expect("data");
        assert_eq!(data.decision_id, format!("decision-{i}"));
    }
}

#[test]
fn multiple_replay_calls_increment_call_counter() {
    let mut kit = build_template();
    let a = auth(&[SCOPE_REPLAY_WRITE, SCOPE_REPLAY_READ]);
    let c = ctx();

    kit.template
        .replay_control_endpoint(&a, &c, &replay_start_req("trace-1"));
    kit.template
        .replay_control_endpoint(&a, &c, &replay_stop_req("session-1"));
    kit.template
        .replay_control_endpoint(&a, &c, &replay_status_req("session-1"));

    // Note: status requires SCOPE_REPLAY_READ which we have
    // But we need to check with the right scopes
    assert_eq!(kit.replay_calls.get(), 3);
}

// ── Section 8: JSON serialization stability ─────────────────────────

#[test]
fn health_ok_response_json_schema_stable() {
    let kit = build_template();
    let resp = kit
        .template
        .health_endpoint(&auth(&[SCOPE_HEALTH_READ]), &ctx());
    let json = serde_json::to_value(&resp).expect("serialize");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["endpoint"], "health");
    assert!(json["trace_id"].is_string());
    assert!(json["request_id"].is_string());
    assert!(json["data"]["runtime_status"].is_string());
    assert!(json["data"]["loaded_extensions"].is_array());
    assert!(json["data"]["security_epoch"].is_number());
    assert!(json["data"]["gc_pressure_basis_points"].is_number());
    assert!(json["error"].is_null());
    assert!(json["log"]["event"].is_string());
    assert!(json["log"]["outcome"].is_string());
}

#[test]
fn error_response_json_schema_stable() {
    let kit = build_template();
    let resp = kit.template.health_endpoint(&auth(&[]), &ctx());
    let json = serde_json::to_value(&resp).expect("serialize");
    assert_eq!(json["status"], "error");
    assert!(json["data"].is_null());
    assert!(json["error"]["error_code"].is_string());
    assert!(json["error"]["message"].is_string());
    assert!(json["error"]["trace_id"].is_string());
    assert!(json["error"]["component"].is_string());
    assert!(json["error"]["details"].is_object());
}

#[test]
fn control_action_ok_response_json_schema() {
    let mut kit = build_template();
    let resp = kit.template.control_action_endpoint(
        &all_scopes_auth(),
        &ctx(),
        &control_req("ext-x", ControlAction::Quarantine, "test"),
    );
    let json = serde_json::to_value(&resp).expect("serialize");
    assert_eq!(json["data"]["extension_id"], "ext-x");
    assert_eq!(json["data"]["action"], "Quarantine");
    assert_eq!(json["data"]["accepted"], true);
    assert!(json["data"]["decision_id"].is_string());
}

#[test]
fn evidence_export_ok_response_json_schema() {
    let kit = build_template();
    let resp = kit.template.evidence_export_endpoint(
        &auth(&[SCOPE_EVIDENCE_READ]),
        &ctx(),
        &evidence_req(0, None, 2),
    );
    let json = serde_json::to_value(&resp).expect("serialize");
    assert!(json["data"]["records"].is_array());
    assert_eq!(json["data"]["records"].as_array().unwrap().len(), 2);
    let rec = &json["data"]["records"][0];
    assert!(rec["trace_id"].is_string());
    assert!(rec["decision_id"].is_string());
    assert!(rec["artifact_ref"].is_string());
}

#[test]
fn replay_ok_response_json_schema() {
    let mut kit = build_template();
    let resp = kit.template.replay_control_endpoint(
        &auth(&[SCOPE_REPLAY_WRITE]),
        &ctx(),
        &replay_start_req("trace-json"),
    );
    let json = serde_json::to_value(&resp).expect("serialize");
    assert!(json["data"]["session_id"].is_string());
    assert!(json["data"]["state"].is_string());
    assert!(json["data"]["note"].is_string());
}

// ── Section 9: Serde roundtrips for all public types ────────────────

#[test]
fn request_context_serde_roundtrip() {
    let c = ctx();
    let json = serde_json::to_string(&c).unwrap();
    let back: RequestContext = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn request_context_none_fields_roundtrip() {
    let c = RequestContext {
        trace_id: "t".into(),
        request_id: "r".into(),
        component: "c".into(),
        decision_id: None,
        policy_id: None,
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: RequestContext = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn auth_context_serde_roundtrip() {
    let a = all_scopes_auth();
    let json = serde_json::to_string(&a).unwrap();
    let back: AuthContext = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn auth_context_empty_scopes_serde_roundtrip() {
    let a = auth(&[]);
    let json = serde_json::to_string(&a).unwrap();
    let back: AuthContext = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
    assert!(back.scopes.is_empty());
}

#[test]
fn structured_log_event_serde_roundtrip() {
    let e = StructuredLogEvent {
        trace_id: "t-log".into(),
        decision_id: Some("d-log".into()),
        policy_id: None,
        component: "engine".into(),
        event: "test.event".into(),
        outcome: "ok".into(),
        error_code: Some("E-1".into()),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn error_envelope_serde_roundtrip() {
    let mut details = BTreeMap::new();
    details.insert("key".into(), "val".into());
    let env = ErrorEnvelope {
        error_code: "ERR-RT".into(),
        message: "roundtrip test".into(),
        trace_id: "t-rt".into(),
        component: "c-rt".into(),
        details,
    };
    let json = serde_json::to_string(&env).unwrap();
    let back: ErrorEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, back);
}

#[test]
fn endpoint_failure_serde_roundtrip() {
    let mut f = EndpointFailure::new("F-001", "failure test");
    f.details.insert("k".into(), "v".into());
    let json = serde_json::to_string(&f).unwrap();
    let back: EndpointFailure = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

#[test]
fn health_status_response_serde_roundtrip() {
    let h = HealthStatusResponse {
        runtime_status: "degraded".into(),
        loaded_extensions: vec!["x".into(), "y".into(), "z".into()],
        security_epoch: u64::MAX,
        gc_pressure_basis_points: u16::MAX,
    };
    let json = serde_json::to_string(&h).unwrap();
    let back: HealthStatusResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(h, back);
}

#[test]
fn control_action_all_variants_serde_roundtrip() {
    for action in [
        ControlAction::Start,
        ControlAction::Stop,
        ControlAction::Suspend,
        ControlAction::Quarantine,
    ] {
        let json = serde_json::to_value(action).unwrap();
        let back: ControlAction = serde_json::from_value(json).unwrap();
        assert_eq!(action, back);
    }
}

#[test]
fn replay_command_all_variants_serde_roundtrip() {
    for cmd in [
        ReplayCommand::Start,
        ReplayCommand::Stop,
        ReplayCommand::Status,
    ] {
        let json = serde_json::to_value(cmd).unwrap();
        let back: ReplayCommand = serde_json::from_value(json).unwrap();
        assert_eq!(cmd, back);
    }
}

#[test]
fn control_action_request_serde_roundtrip() {
    let req = control_req("ext-serde", ControlAction::Quarantine, "serde test");
    let json = serde_json::to_string(&req).unwrap();
    let back: ControlActionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn control_action_response_serde_roundtrip() {
    let r = ControlActionResponse {
        extension_id: "ext-resp".into(),
        action: ControlAction::Suspend,
        accepted: false,
        decision_id: "dec-serde".into(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: ControlActionResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn evidence_export_request_serde_roundtrip() {
    let req = EvidenceExportRequest {
        since_epoch_seconds: 100,
        until_epoch_seconds: Some(200),
        page_size: 50,
        cursor: Some("cursor-serde".into()),
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: EvidenceExportRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn evidence_record_serde_roundtrip() {
    let r = make_evidence_record(42);
    let json = serde_json::to_string(&r).unwrap();
    let back: EvidenceRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn evidence_export_response_serde_roundtrip() {
    let resp = EvidenceExportResponse {
        records: (0..3).map(make_evidence_record).collect(),
        next_cursor: Some("next".into()),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let back: EvidenceExportResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, back);
}

#[test]
fn replay_control_request_serde_roundtrip() {
    let req = replay_start_req("trace-serde");
    let json = serde_json::to_string(&req).unwrap();
    let back: ReplayControlRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn replay_control_response_serde_roundtrip() {
    let r = ReplayControlResponse {
        session_id: "sess-rt".into(),
        state: "stopped".into(),
        trace_id: Some("t-rt".into()),
        note: "roundtrip".into(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: ReplayControlResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ── Section 10: EndpointResponse serde roundtrip ────────────────────

#[test]
fn endpoint_response_ok_serde_roundtrip() {
    let kit = build_template();
    let resp = kit
        .template
        .health_endpoint(&auth(&[SCOPE_HEALTH_READ]), &ctx());
    let json = serde_json::to_string(&resp).unwrap();
    let back: EndpointResponse<HealthStatusResponse> = serde_json::from_str(&json).unwrap();
    assert_eq!(resp.status, back.status);
    assert_eq!(resp.endpoint, back.endpoint);
    assert_eq!(resp.data, back.data);
    assert_eq!(resp.error, back.error);
    assert_eq!(resp.log, back.log);
}

#[test]
fn endpoint_response_error_serde_roundtrip() {
    let kit = build_template();
    let resp = kit.template.health_endpoint(&auth(&[]), &ctx());
    let json = serde_json::to_string(&resp).unwrap();
    let back: EndpointResponse<HealthStatusResponse> = serde_json::from_str(&json).unwrap();
    assert_eq!(resp.status, back.status);
    assert!(back.data.is_none());
    assert_eq!(resp.error, back.error);
}

// ── Section 11: Edge cases and boundary conditions ──────────────────

#[test]
fn endpoint_failure_new_has_empty_details() {
    let f = EndpointFailure::new("CODE", "msg");
    assert!(f.details.is_empty());
    assert_eq!(f.error_code, "CODE");
    assert_eq!(f.message, "msg");
}

#[test]
fn scope_constants_values() {
    assert_eq!(SCOPE_HEALTH_READ, "engine.health.read");
    assert_eq!(SCOPE_CONTROL_WRITE, "engine.control.write");
    assert_eq!(SCOPE_EVIDENCE_READ, "engine.evidence.read");
    assert_eq!(SCOPE_REPLAY_READ, "engine.replay.read");
    assert_eq!(SCOPE_REPLAY_WRITE, "engine.replay.write");
}

#[test]
fn auth_context_has_scope_exact_match_required() {
    let a = auth(&["engine.health.read"]);
    assert!(a.has_scope("engine.health.read"));
    assert!(!a.has_scope("engine.health"));
    assert!(!a.has_scope("engine.health.read.extra"));
    assert!(!a.has_scope("Engine.health.read"));
}

#[test]
fn control_action_multibyte_reason_counted_by_chars() {
    // Unicode chars: each emoji is 1 char but multiple bytes
    let emoji_reason = "🔒".repeat(256);
    assert_eq!(emoji_reason.chars().count(), 256);
    let mut kit = build_template();
    let resp_ok = kit.template.control_action_endpoint(
        &all_scopes_auth(),
        &ctx(),
        &control_req("ext", ControlAction::Start, &emoji_reason),
    );
    assert_eq!(resp_ok.status, "ok");

    let emoji_reason_over = "🔒".repeat(257);
    let resp_err = kit.template.control_action_endpoint(
        &all_scopes_auth(),
        &ctx(),
        &control_req("ext", ControlAction::Start, &emoji_reason_over),
    );
    assert_eq!(resp_err.status, "error");
}

#[test]
fn evidence_export_max_u64_since_epoch() {
    let kit = build_template();
    let resp = kit.template.evidence_export_endpoint(
        &auth(&[SCOPE_EVIDENCE_READ]),
        &ctx(),
        &evidence_req(u64::MAX, None, 1),
    );
    assert_eq!(resp.status, "ok");
}

#[test]
fn empty_extensions_list_in_health() {
    let tmpl = ServiceEndpointTemplate::new(
        StubHealthProvider {
            status: "healthy".into(),
            extensions: vec![],
            epoch: 0,
            gc_bp: 0,
        },
        StubDecisionExecutor {
            calls: Rc::new(Cell::new(0)),
            fail_with: None,
        },
        StubEvidenceProvider {
            records: vec![],
            fail_with: None,
        },
        StubReplayController {
            calls: Rc::new(Cell::new(0)),
            fail_with: None,
        },
    );
    let resp = tmpl.health_endpoint(&auth(&[SCOPE_HEALTH_READ]), &ctx());
    let data = resp.data.expect("data");
    assert!(data.loaded_extensions.is_empty());
}

// ── Section 12: Auth check precedes validation ──────────────────────

#[test]
fn control_action_auth_check_before_validation() {
    // No scope, AND invalid input => should get auth error, not validation error
    let mut kit = build_template();
    let resp = kit.template.control_action_endpoint(
        &auth(&[]),
        &ctx(),
        &control_req("", ControlAction::Start, ""),
    );
    assert_eq!(resp.error.expect("err").error_code, "unauthorized");
}

#[test]
fn evidence_export_auth_check_before_validation() {
    let kit = build_template();
    let resp =
        kit.template
            .evidence_export_endpoint(&auth(&[]), &ctx(), &evidence_req(100, Some(50), 0));
    assert_eq!(resp.error.expect("err").error_code, "unauthorized");
}

#[test]
fn replay_control_auth_check_before_validation() {
    let mut kit = build_template();
    let resp = kit.template.replay_control_endpoint(
        &auth(&[]),
        &ctx(),
        &ReplayControlRequest {
            command: ReplayCommand::Start,
            trace_id: None,
            session_id: None,
        },
    );
    assert_eq!(resp.error.expect("err").error_code, "unauthorized");
}

// ── Section 13: Clone equality ──────────────────────────────────────

#[test]
fn request_context_clone_equality() {
    let c = ctx();
    assert_eq!(c, c.clone());
}

#[test]
fn auth_context_clone_equality() {
    let a = all_scopes_auth();
    assert_eq!(a, a.clone());
}

#[test]
fn endpoint_failure_clone_equality() {
    let mut f = EndpointFailure::new("C", "m");
    f.details.insert("k".into(), "v".into());
    assert_eq!(f, f.clone());
}

#[test]
fn health_status_response_clone_equality() {
    let h = HealthStatusResponse {
        runtime_status: "ok".into(),
        loaded_extensions: vec!["a".into()],
        security_epoch: 42,
        gc_pressure_basis_points: 100,
    };
    assert_eq!(h, h.clone());
}

#[test]
fn evidence_record_clone_equality() {
    let r = make_evidence_record(7);
    assert_eq!(r, r.clone());
}

// ── Section 14: JSON field names stable ─────────────────────────────

#[test]
fn request_context_json_field_names_stable() {
    let json = serde_json::to_value(ctx()).unwrap();
    let obj = json.as_object().unwrap();
    for key in [
        "trace_id",
        "request_id",
        "component",
        "decision_id",
        "policy_id",
    ] {
        assert!(obj.contains_key(key), "missing field: {key}");
    }
    assert_eq!(obj.len(), 5);
}

#[test]
fn health_status_json_field_names_stable() {
    let h = HealthStatusResponse {
        runtime_status: "ok".into(),
        loaded_extensions: vec![],
        security_epoch: 1,
        gc_pressure_basis_points: 0,
    };
    let json = serde_json::to_value(&h).unwrap();
    let obj = json.as_object().unwrap();
    for key in [
        "runtime_status",
        "loaded_extensions",
        "security_epoch",
        "gc_pressure_basis_points",
    ] {
        assert!(obj.contains_key(key), "missing field: {key}");
    }
    assert_eq!(obj.len(), 4);
}

#[test]
fn evidence_record_json_field_names_stable() {
    let r = make_evidence_record(0);
    let json = serde_json::to_value(&r).unwrap();
    let obj = json.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "artifact_ref",
    ] {
        assert!(obj.contains_key(key), "missing field: {key}");
    }
    assert_eq!(obj.len(), 7);
}

#[test]
fn structured_log_event_json_field_names_stable() {
    let e = StructuredLogEvent {
        trace_id: "t".into(),
        decision_id: Some("d".into()),
        policy_id: Some("p".into()),
        component: "c".into(),
        event: "e".into(),
        outcome: "o".into(),
        error_code: Some("ec".into()),
    };
    let json = serde_json::to_value(&e).unwrap();
    let obj = json.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(obj.contains_key(key), "missing field: {key}");
    }
    assert_eq!(obj.len(), 7);
}

// ── Section 15: Debug distinctness ──────────────────────────────────

#[test]
fn control_action_variants_debug_distinct() {
    let variants = [
        ControlAction::Start,
        ControlAction::Stop,
        ControlAction::Suspend,
        ControlAction::Quarantine,
    ];
    let reprs: std::collections::BTreeSet<String> =
        variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(reprs.len(), 4);
}

#[test]
fn replay_command_variants_debug_distinct() {
    let variants = [
        ReplayCommand::Start,
        ReplayCommand::Stop,
        ReplayCommand::Status,
    ];
    let reprs: std::collections::BTreeSet<String> =
        variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(reprs.len(), 3);
}
