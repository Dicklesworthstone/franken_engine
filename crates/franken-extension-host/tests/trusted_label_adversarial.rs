use frankenengine_extension_host::{
    Capability, DataRef, DecisionSigningKey, DeclassificationGateway, DeclassificationOutcome,
    DeclassificationPurpose, DeclassificationRequest, DenialReason, FlowEnforcementContext,
    FlowLabel, HostcallDispatcher, HostcallResult, HostcallSinkPolicy, HostcallType,
    IntegrityLevel, Labeled, SecrecyLevel,
};
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn net_caps() -> BTreeSet<Capability> {
    [Capability::NetClient].into_iter().collect()
}

fn flow_context() -> FlowEnforcementContext<'static> {
    FlowEnforcementContext::new("trace-adversarial", "decision-adversarial", "policy-ifc")
}

fn assert_untrusted_network_send_is_denied<T: Clone>(extension_id: &str, payload: Labeled<T>) {
    assert!(
        !payload.label().is_host_trusted(),
        "adversarial payload unexpectedly gained host-trusted authority"
    );

    let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
    let outcome = dispatcher.dispatch(
        extension_id,
        HostcallType::NetworkSend,
        &net_caps(),
        Capability::NetClient,
        payload,
        &flow_context(),
    );

    match outcome.result {
        HostcallResult::Denied {
            reason: DenialReason::FlowViolation { source, sink },
        } => {
            assert_eq!(source, FlowLabel::default());
            assert_eq!(sink, HostcallSinkPolicy::default().network_send);
        }
        other => panic!("expected untrusted trusted-label spoof to be blocked, got {other:?}"),
    }
    assert!(outcome.output.is_none());
    assert_eq!(dispatcher.violation_events().len(), 1);
}

fn approved_public_label() -> FlowLabel {
    let mut gateway =
        DeclassificationGateway::with_default_contracts(DecisionSigningKey::new([0xE4; 32]));
    let caps: BTreeSet<Capability> = [Capability::Declassify, Capability::NetClient]
        .into_iter()
        .collect();
    let request = DeclassificationRequest {
        request_id: "req-adversarial-label-copy".to_string(),
        requester: "ext-adversarial".to_string(),
        data_ref: DataRef::new("secrets", "token"),
        current_label: FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
        target_label: FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Validated),
        purpose: DeclassificationPurpose::OperatorOverride,
        justification: "operator-approved adversarial regression fixture".to_string(),
        timestamp_ns: 1_000,
    };

    match gateway.evaluate_request(request, &caps, 500_000, &flow_context()) {
        DeclassificationOutcome::Approved { new_label, receipt } => {
            assert!(receipt.verify(&gateway.public_key()));
            assert!(new_label.is_host_trusted());
            new_label
        }
        other => panic!("expected approved declassification label, got {other:?}"),
    }
}

#[test]
fn public_new_constructor_cannot_mint_host_trusted_label() {
    let label = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
    assert_eq!(label.secrecy(), SecrecyLevel::Public);
    assert_eq!(label.integrity(), IntegrityLevel::Trusted);
    assert!(!label.is_host_trusted());

    assert_untrusted_network_send_is_denied(
        "ext-new-constructor",
        Labeled::new("exfil via new".to_string(), label),
    );
}

#[test]
fn public_system_generated_constructor_cannot_mint_host_trusted_label() {
    let payload = Labeled::system_generated("exfil via system_generated".to_string());
    assert_eq!(payload.label().secrecy(), SecrecyLevel::Public);
    assert_eq!(payload.label().integrity(), IntegrityLevel::Trusted);

    assert_untrusted_network_send_is_denied("ext-system-generated", payload);
}

#[test]
fn public_from_constructor_downgrades_to_restrictive_untrusted_label() {
    let payload = Labeled::from("exfil via from".to_string());
    assert_eq!(payload.label(), FlowLabel::default());

    assert_untrusted_network_send_is_denied("ext-from", payload);
}

#[test]
fn public_join_and_map_paths_cannot_promote_to_host_trusted() {
    let public_trusted = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
    let joined = public_trusted.join(public_trusted);
    assert_eq!(joined.secrecy(), SecrecyLevel::Public);
    assert_eq!(joined.integrity(), IntegrityLevel::Trusted);
    assert!(!joined.is_host_trusted());

    let mapped = Labeled::new("exfil via map".to_string(), joined).map(|value| value.len());
    assert_eq!(mapped.label().secrecy(), SecrecyLevel::Public);
    assert_eq!(mapped.label().integrity(), IntegrityLevel::Trusted);

    assert_untrusted_network_send_is_denied("ext-map", mapped);
}

#[test]
fn copied_host_trusted_declassification_label_cannot_relabel_extension_payload() {
    let copied_label = approved_public_label();
    assert!(copied_label.is_host_trusted());

    let payload = Labeled::new("exfil via copied approval label".to_string(), copied_label);
    assert_eq!(payload.label().secrecy(), SecrecyLevel::Public);
    assert_eq!(payload.label().integrity(), IntegrityLevel::Validated);
    assert!(!payload.label().is_host_trusted());

    assert_untrusted_network_send_is_denied("ext-copied-approved-label", payload);
}

#[test]
fn old_two_field_unsafe_labeled_recast_no_longer_compiles() {
    let stderr = compile_fail_probe(
        "unsafe_two_field_labeled_recast",
        r#"use frankenengine_extension_host::{
    FlowLabel, IntegrityLevel, Labeled, SecrecyLevel,
};

#[repr(C)]
struct OldLabeledShape<T> {
    value: T,
    label: FlowLabel,
}

fn main() {
    let forged = OldLabeledShape {
        value: String::from("exfil via unsafe recast"),
        label: FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted),
    };
    let _payload: Labeled<String> = unsafe { std::mem::transmute(forged) };
}
"#,
    );
    assert!(
        stderr.contains("transmute") || stderr.contains("different sizes"),
        "unsafe recast probe failed for an unexpected reason:\n{stderr}"
    );
}

#[test]
fn deserialize_cannot_inject_host_trusted_flow_label_authority() {
    let label: FlowLabel = serde_json::from_value(json!({
        "secrecy": "public",
        "integrity": "trusted",
        "authority": "host_trusted"
    }))
    .expect("deserialize adversarial FlowLabel");

    assert_eq!(label.secrecy(), SecrecyLevel::Public);
    assert_eq!(label.integrity(), IntegrityLevel::Trusted);
    assert!(!label.is_host_trusted());

    assert_untrusted_network_send_is_denied(
        "ext-deserialize-label",
        Labeled::new("exfil via label deserialize".to_string(), label),
    );
}

#[test]
fn deserialize_cannot_inject_host_trusted_labeled_payload_authority() {
    let payload: Labeled<String> = serde_json::from_value(json!({
        "value": "exfil via payload deserialize",
        "label": {
            "secrecy": "public",
            "integrity": "trusted",
            "authority": "host_trusted"
        }
    }))
    .expect("deserialize adversarial Labeled payload");

    assert_eq!(payload.label().secrecy(), SecrecyLevel::Public);
    assert_eq!(payload.label().integrity(), IntegrityLevel::Trusted);

    assert_untrusted_network_send_is_denied("ext-deserialize-payload", payload);
}

#[test]
fn public_field_assignment_escape_does_not_compile_for_external_extension_code() {
    let flow_label_stderr = compile_fail_probe(
        "flow_label_field_assignment",
        r#"use frankenengine_extension_host::{
    FlowLabel, IntegrityLevel, SecrecyLevel,
};

fn main() {
    let _label = FlowLabel {
        secrecy: SecrecyLevel::Public,
        integrity: IntegrityLevel::Trusted,
    };
}
"#,
    );
    assert!(
        flow_label_stderr.contains("private") && flow_label_stderr.contains("FlowLabel"),
        "FlowLabel field-assignment probe failed for an unexpected reason:\n{flow_label_stderr}"
    );

    let labeled_stderr = compile_fail_probe(
        "labeled_field_assignment",
        r#"use frankenengine_extension_host::{
    FlowLabel, IntegrityLevel, Labeled, SecrecyLevel,
};

fn main() {
    let _payload = Labeled {
        value: String::from("exfil via field assignment"),
        label: FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted),
    };
}
"#,
    );
    assert!(
        labeled_stderr.contains("private") && labeled_stderr.contains("Labeled"),
        "Labeled field-assignment probe failed for an unexpected reason:\n{labeled_stderr}"
    );
}

fn compile_fail_probe(probe_name: &str, main_rs: &str) -> String {
    let probe_root = probe_project_root(probe_name);
    fs::create_dir_all(probe_root.join("src")).expect("create compile-fail probe project");
    fs::write(
        probe_root.join("Cargo.toml"),
        format!(
            r#"[package]
name = "{probe_name}"
version = "0.0.0"
edition = "2024"

[dependencies]
frankenengine-extension-host = {{ path = "{}" }}

[workspace]
"#,
            Path::new(env!("CARGO_MANIFEST_DIR")).display()
        ),
    )
    .expect("write probe Cargo.toml");
    fs::write(probe_root.join("src/main.rs"), main_rs).expect("write probe main.rs");

    let output = Command::new(env!("CARGO"))
        .arg("check")
        .arg("--quiet")
        .arg("--offline")
        .current_dir(&probe_root)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_TARGET_DIR", probe_root.join("target"))
        .output()
        .expect("run external extension compile-fail probe");

    assert!(
        !output.status.success(),
        "external field-assignment spoof unexpectedly compiled for {probe_name}"
    );

    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn probe_project_root(probe_name: &str) -> PathBuf {
    let target_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("target"));
    target_root
        .join("trusted_label_field_assignment_probe")
        .join(format!("{}-{probe_name}", std::process::id()))
}
