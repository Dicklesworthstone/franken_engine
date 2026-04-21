#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use frankenengine_extension_host::{
    Capability, DataRef, DeclassificationGateway, DeclassificationOutcome, DeclassificationPurpose,
    DeclassificationRequest, DenialReason, FlowEnforcementContext, FlowLabel, HostcallDispatcher,
    HostcallResult, HostcallSinkPolicy, HostcallType, IntegrityLevel, Labeled, SecrecyLevel,
};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadOrigin {
    ExtensionSource,
    HostSource,
}

struct FuzzExtensionContext {
    origin: PayloadOrigin,
    extension_id: String,
    hostcall_type: HostcallType,
    attempted_capability: Capability,
    declared_capabilities: BTreeSet<Capability>,
}

struct FuzzFlowLabel {
    label: FlowLabel,
    claims_trusted: bool,
}

struct FuzzInput {
    label: FuzzFlowLabel,
    context: FuzzExtensionContext,
    payload: String,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let secrecy = arbitrary_secrecy(u)?;
        let integrity = arbitrary_integrity(u)?;
        let claim_style = u.int_in_range(0_u8..=2)?;
        let label = match claim_style {
            0 => FuzzFlowLabel {
                label: FlowLabel::new(secrecy, integrity),
                claims_trusted: false,
            },
            1 => FuzzFlowLabel {
                label: json_claimed_host_trusted_label(secrecy, integrity),
                claims_trusted: true,
            },
            _ => FuzzFlowLabel {
                label: approved_or_json_claimed_host_trusted_label(secrecy, integrity),
                claims_trusted: true,
            },
        };

        let context = FuzzExtensionContext {
            origin: if bool::arbitrary(u)? {
                PayloadOrigin::ExtensionSource
            } else {
                PayloadOrigin::HostSource
            },
            extension_id: bounded_string(u, 80)?,
            hostcall_type: arbitrary_hostcall_type(u)?,
            attempted_capability: arbitrary_capability(u)?,
            declared_capabilities: arbitrary_capability_set(u)?,
        };
        let payload = bounded_string(u, 128)?;

        Ok(Self {
            label,
            context,
            payload,
        })
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };

    exercise_arbitrary_dispatch_path(&input);

    if input.label.claims_trusted && input.context.origin == PayloadOrigin::ExtensionSource {
        assert_extension_source_trusted_claim_is_rejected(&input);
    }
});

fn assert_extension_source_trusted_claim_is_rejected(input: &FuzzInput) {
    let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
    let payload = Labeled::new(input.payload.clone(), input.label.label);
    let outcome = dispatcher.dispatch(
        extension_id_or_default(&input.context.extension_id),
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
            assert!(outcome.output.is_none());
        }
        other => panic!("extension-source trusted FlowLabel claim bypassed gate: {other:?}"),
    }
}

fn exercise_arbitrary_dispatch_path(input: &FuzzInput) {
    let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
    let payload = Labeled::new(input.payload.clone(), input.label.label);
    let _ = dispatcher.dispatch(
        extension_id_or_default(&input.context.extension_id),
        input.context.hostcall_type,
        &input.context.declared_capabilities,
        input.context.attempted_capability,
        payload,
        &flow_context(),
    );
}

fn approved_or_json_claimed_host_trusted_label(
    secrecy: SecrecyLevel,
    integrity: IntegrityLevel,
) -> FlowLabel {
    let target = FlowLabel::new(secrecy, integrity);
    let Some(current) = declassifying_current_label(secrecy, integrity) else {
        return json_claimed_host_trusted_label(secrecy, integrity);
    };

    let mut gateway = DeclassificationGateway::default();
    let request = DeclassificationRequest {
        request_id: "fuzz-flow-label-authority".to_string(),
        requester: "fuzz-extension".to_string(),
        data_ref: DataRef::new("fuzz", "payload"),
        current_label: current,
        target_label: target,
        purpose: DeclassificationPurpose::OperatorOverride,
        justification: "fuzz host-trusted label authority fixture".to_string(),
        timestamp_ns: 1_000,
    };

    match gateway.evaluate_request(request, &declass_caps(), 500_000, &flow_context()) {
        DeclassificationOutcome::Approved { new_label, .. } => new_label,
        _ => json_claimed_host_trusted_label(secrecy, integrity),
    }
}

fn json_claimed_host_trusted_label(secrecy: SecrecyLevel, integrity: IntegrityLevel) -> FlowLabel {
    let value = serde_json::json!({
        "secrecy": secrecy.json_name(),
        "integrity": integrity.json_name(),
        "authority": "host_trusted",
    });
    serde_json::from_value(value).expect("fuzz FlowLabel JSON should deserialize")
}

fn declassifying_current_label(
    target_secrecy: SecrecyLevel,
    target_integrity: IntegrityLevel,
) -> Option<FlowLabel> {
    if let Some(secrecy) = next_higher_secrecy(target_secrecy) {
        return Some(FlowLabel::new(secrecy, target_integrity));
    }
    lower_integrity(target_integrity).map(|integrity| FlowLabel::new(target_secrecy, integrity))
}

fn next_higher_secrecy(secrecy: SecrecyLevel) -> Option<SecrecyLevel> {
    match secrecy {
        SecrecyLevel::Public => Some(SecrecyLevel::Internal),
        SecrecyLevel::Internal => Some(SecrecyLevel::Confidential),
        SecrecyLevel::Confidential => Some(SecrecyLevel::Secret),
        SecrecyLevel::Secret => Some(SecrecyLevel::TopSecret),
        SecrecyLevel::TopSecret => None,
    }
}

fn lower_integrity(integrity: IntegrityLevel) -> Option<IntegrityLevel> {
    match integrity {
        IntegrityLevel::Untrusted => None,
        IntegrityLevel::Validated => Some(IntegrityLevel::Untrusted),
        IntegrityLevel::Verified => Some(IntegrityLevel::Validated),
        IntegrityLevel::Trusted => Some(IntegrityLevel::Verified),
    }
}

fn arbitrary_secrecy(u: &mut Unstructured<'_>) -> arbitrary::Result<SecrecyLevel> {
    Ok(match u.int_in_range(0_u8..=4)? {
        0 => SecrecyLevel::Public,
        1 => SecrecyLevel::Internal,
        2 => SecrecyLevel::Confidential,
        3 => SecrecyLevel::Secret,
        _ => SecrecyLevel::TopSecret,
    })
}

fn arbitrary_integrity(u: &mut Unstructured<'_>) -> arbitrary::Result<IntegrityLevel> {
    Ok(match u.int_in_range(0_u8..=3)? {
        0 => IntegrityLevel::Untrusted,
        1 => IntegrityLevel::Validated,
        2 => IntegrityLevel::Verified,
        _ => IntegrityLevel::Trusted,
    })
}

fn arbitrary_capability(u: &mut Unstructured<'_>) -> arbitrary::Result<Capability> {
    Ok(match u.int_in_range(0_u8..=5)? {
        0 => Capability::FsRead,
        1 => Capability::FsWrite,
        2 => Capability::NetClient,
        3 => Capability::HostCall,
        4 => Capability::ProcessSpawn,
        _ => Capability::Declassify,
    })
}

fn arbitrary_capability_set(u: &mut Unstructured<'_>) -> arbitrary::Result<BTreeSet<Capability>> {
    let mut capabilities = BTreeSet::new();
    for capability in [
        Capability::FsRead,
        Capability::FsWrite,
        Capability::NetClient,
        Capability::HostCall,
        Capability::ProcessSpawn,
        Capability::Declassify,
    ] {
        if bool::arbitrary(u)? {
            capabilities.insert(capability);
        }
    }
    Ok(capabilities)
}

fn arbitrary_hostcall_type(u: &mut Unstructured<'_>) -> arbitrary::Result<HostcallType> {
    Ok(match u.int_in_range(0_u8..=10)? {
        0 => HostcallType::FsRead,
        1 => HostcallType::FsWrite,
        2 => HostcallType::NetworkSend,
        3 => HostcallType::NetworkRecv,
        4 => HostcallType::ProcessSpawn,
        5 => HostcallType::EnvRead,
        6 => HostcallType::MemAlloc,
        7 => HostcallType::TimerCreate,
        8 => HostcallType::CryptoOp,
        9 => HostcallType::IpcSend,
        _ => HostcallType::IpcRecv,
    })
}

fn bounded_string(u: &mut Unstructured<'_>, max_len: usize) -> arbitrary::Result<String> {
    let len = u.int_in_range(0_usize..=max_len.min(u.len()))?;
    let bytes = u.bytes(len)?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn extension_id_or_default(extension_id: &str) -> &str {
    if extension_id.is_empty() {
        "fuzz-extension"
    } else {
        extension_id
    }
}

fn flow_context() -> FlowEnforcementContext<'static> {
    FlowEnforcementContext::new("trace-fuzz", "decision-fuzz", "policy-fuzz")
}

fn net_caps() -> BTreeSet<Capability> {
    [Capability::NetClient].into_iter().collect()
}

fn declass_caps() -> BTreeSet<Capability> {
    [Capability::Declassify, Capability::NetClient]
        .into_iter()
        .collect()
}

trait FlowLabelJsonName {
    fn json_name(self) -> &'static str;
}

impl FlowLabelJsonName for SecrecyLevel {
    fn json_name(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
            Self::Secret => "secret",
            Self::TopSecret => "top_secret",
        }
    }
}

impl FlowLabelJsonName for IntegrityLevel {
    fn json_name(self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::Validated => "validated",
            Self::Verified => "verified",
            Self::Trusted => "trusted",
        }
    }
}
