#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::capability_token::PrincipalId;
use frankenengine_engine::engine_object_id::{ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::fleet_immune_protocol::{
    ContainmentAction, ContainmentIntent, EvidencePacket, FleetProtocolState, GossipConfig,
    HeartbeatLiveness, MessageSignature, NodeId, ProtocolVersion,
};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::revocation_chain::{
    Revocation, RevocationChain, RevocationReason, RevocationTargetType,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, sign_preimage,
};
use serde::Serialize;

const ZONE: &str = "fleet-quarantine-mesh";
const EXTENSION_ID: &str = "demo:compromised-module";
const HEARTBEAT_EMIT_NS: u64 = 900_000_000;
const EVIDENCE_LAG_NS: u64 = 25_000_000;
const INTENT_LAG_NS: u64 = 50_000_000;
const CHECKPOINT_LAG_NS: u64 = 25_000_000;
const BOUNDED_CONVERGENCE_SLO_NS: u64 = 1_000_000_000;
const REVOCATION_TICK: u64 = 42;
const DELIVERY_DELAY_NS: [[u64; 3]; 3] = [
    [0, 80_000_000, 120_000_000],
    [60_000_000, 0, 70_000_000],
    [90_000_000, 50_000_000, 0],
];

#[derive(Clone, Copy)]
struct NodeSpec {
    name: &'static str,
    signing_seed: u8,
    revocation_applied_ns: u64,
}

const NODE_SPECS: [NodeSpec; 3] = [
    NodeSpec {
        name: "mesh-a",
        signing_seed: 11,
        revocation_applied_ns: 1_000_000_000,
    },
    NodeSpec {
        name: "mesh-b",
        signing_seed: 22,
        revocation_applied_ns: 1_320_000_000,
    },
    NodeSpec {
        name: "mesh-c",
        signing_seed: 33,
        revocation_applied_ns: 1_640_000_000,
    },
];

#[derive(Clone)]
struct NodeMaterial {
    node_id: NodeId,
    signing_key: SigningKey,
    revocation_applied_ns: u64,
}

#[derive(Clone)]
enum ScheduledMessage {
    Heartbeat(HeartbeatLiveness),
    Evidence(EvidencePacket),
    Intent(ContainmentIntent),
}

impl ScheduledMessage {
    fn timestamp_ns(&self) -> u64 {
        match self {
            Self::Heartbeat(message) => message.timestamp_ns,
            Self::Evidence(message) => message.timestamp_ns,
            Self::Intent(message) => message.timestamp_ns,
        }
    }

    fn source_id(&self) -> &NodeId {
        match self {
            Self::Heartbeat(message) => &message.node_id,
            Self::Evidence(message) => &message.node_id,
            Self::Intent(message) => &message.node_id,
        }
    }

    fn kind_rank(&self) -> u8 {
        match self {
            Self::Heartbeat(_) => 0,
            Self::Evidence(_) => 1,
            Self::Intent(_) => 2,
        }
    }
}

#[derive(Default)]
struct ReceiptBuilder {
    heartbeat_received_ns: Option<u64>,
    evidence_received_ns: Option<u64>,
    intent_received_ns: Option<u64>,
}

#[derive(Serialize)]
struct PropagationLog {
    scenario: &'static str,
    zone: &'static str,
    extension_id: &'static str,
    protocol_version: String,
    bounded_convergence_slo_ns: u64,
    quarantine_goal: &'static str,
    revocation: RevocationSummary,
    instances: Vec<InstanceReport>,
    fleet_convergence: FleetConvergence,
}

#[derive(Serialize)]
struct RevocationSummary {
    authority_node: String,
    reason: String,
    issued_at_tick: u64,
}

#[derive(Serialize)]
struct InstanceReport {
    instance_id: String,
    local_revocation_applied_ns: u64,
    chain_head_seq: u64,
    target_revoked: bool,
    evidence_packets_observed: usize,
    resolved_action: String,
    checkpoint_timestamp_ns: u64,
    checkpoint_seq: u64,
    healthy_nodes_at_checkpoint: Vec<String>,
    contributing_intent_ids: Vec<String>,
    receipts: Vec<ReceiptLog>,
    convergence_from_first_revocation_ns: u64,
    convergence_from_last_revocation_ns: u64,
    within_bounded_slo: bool,
}

#[derive(Serialize)]
struct ReceiptLog {
    from_instance: String,
    heartbeat_received_ns: u64,
    evidence_received_ns: u64,
    intent_received_ns: u64,
}

#[derive(Serialize)]
struct FleetConvergence {
    first_revocation_applied_ns: u64,
    last_revocation_applied_ns: u64,
    revocation_spread_ns: u64,
    first_checkpoint_ns: u64,
    last_checkpoint_ns: u64,
    checkpoint_spread_ns: u64,
    within_bounded_slo: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = GossipConfig::default();
    let nodes = build_nodes();
    let authority = &nodes[0];
    let revocation = build_revocation(authority)?;

    let mut instances = Vec::with_capacity(nodes.len());
    for local_index in 0..nodes.len() {
        instances.push(simulate_instance(
            local_index,
            &nodes,
            &config,
            &revocation,
            authority,
        )?);
    }

    let fleet_convergence = FleetConvergence {
        first_revocation_applied_ns: nodes
            .iter()
            .map(|node| node.revocation_applied_ns)
            .min()
            .unwrap_or(0),
        last_revocation_applied_ns: nodes
            .iter()
            .map(|node| node.revocation_applied_ns)
            .max()
            .unwrap_or(0),
        revocation_spread_ns: spread_ns(
            nodes
                .iter()
                .map(|node| node.revocation_applied_ns)
                .collect(),
        ),
        first_checkpoint_ns: instances
            .iter()
            .map(|instance| instance.checkpoint_timestamp_ns)
            .min()
            .unwrap_or(0),
        last_checkpoint_ns: instances
            .iter()
            .map(|instance| instance.checkpoint_timestamp_ns)
            .max()
            .unwrap_or(0),
        checkpoint_spread_ns: spread_ns(
            instances
                .iter()
                .map(|instance| instance.checkpoint_timestamp_ns)
                .collect(),
        ),
        within_bounded_slo: spread_ns(
            instances
                .iter()
                .map(|instance| instance.checkpoint_timestamp_ns)
                .collect(),
        ) <= BOUNDED_CONVERGENCE_SLO_NS,
    };

    let log = PropagationLog {
        scenario: "three-instance signed quarantine mesh",
        zone: ZONE,
        extension_id: EXTENSION_ID,
        protocol_version: ProtocolVersion::CURRENT.to_string(),
        bounded_convergence_slo_ns: BOUNDED_CONVERGENCE_SLO_NS,
        quarantine_goal: "fleet-wide revocation and quarantine checkpoint convergence",
        revocation: RevocationSummary {
            authority_node: authority.node_id.to_string(),
            reason: revocation.reason.to_string(),
            issued_at_tick: revocation.issued_at.0,
        },
        instances,
        fleet_convergence,
    };

    println!("{}", serde_json::to_string_pretty(&log)?);
    Ok(())
}

fn build_nodes() -> Vec<NodeMaterial> {
    NODE_SPECS
        .iter()
        .map(|spec| NodeMaterial {
            node_id: NodeId::new(spec.name),
            signing_key: signing_key(spec.signing_seed),
            revocation_applied_ns: spec.revocation_applied_ns,
        })
        .collect()
}

fn signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    bytes[31] = seed.wrapping_add(1);
    SigningKey::from_bytes(bytes).expect("demo signing key must be valid")
}

fn build_revocation(authority: &NodeMaterial) -> Result<Revocation, Box<dyn std::error::Error>> {
    let schema = SchemaId::from_definition(b"examples.07.quarantine_mesh.revocation.v1");
    let target_id = derive_id(
        ObjectDomain::SignedManifest,
        ZONE,
        &schema,
        EXTENSION_ID.as_bytes(),
    )?;
    let revocation_id = derive_id(
        ObjectDomain::Revocation,
        ZONE,
        &schema,
        b"examples/07_quarantine_mesh/revocation-1",
    )?;
    let issued_by = PrincipalId::from_verification_key(&authority.signing_key.verification_key());
    let mut revocation = Revocation {
        revocation_id,
        target_type: RevocationTargetType::Extension,
        target_id,
        reason: RevocationReason::Compromised,
        issued_by,
        issued_at: DeterministicTimestamp(REVOCATION_TICK),
        zone: ZONE.to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    let preimage = revocation.preimage_bytes();
    revocation.signature = sign_preimage(&authority.signing_key, &preimage)?;
    Ok(revocation)
}

fn simulate_instance(
    local_index: usize,
    nodes: &[NodeMaterial],
    config: &GossipConfig,
    revocation: &Revocation,
    authority: &NodeMaterial,
) -> Result<InstanceReport, Box<dyn std::error::Error>> {
    let local_node = &nodes[local_index];
    let mut chain = RevocationChain::new(ZONE);
    chain.authorize_revocation_key(authority.signing_key.verification_key());
    chain.authorize_head_key(local_node.signing_key.verification_key());
    chain.append(
        revocation.clone(),
        &local_node.signing_key,
        &format!("quarantine-mesh-{}", local_node.node_id),
    )?;
    chain.verify_chain("quarantine-mesh-demo")?;

    let mut state = FleetProtocolState::new(local_node.node_id.clone(), config.clone());
    let mut receipts: BTreeMap<String, ReceiptBuilder> = nodes
        .iter()
        .map(|node| (node.node_id.to_string(), ReceiptBuilder::default()))
        .collect();
    let mut scheduled = schedule_messages(local_index, nodes, &mut receipts);
    scheduled.sort_by_key(|message| {
        (
            message.timestamp_ns(),
            message.kind_rank(),
            message.source_id().to_string(),
        )
    });

    for message in &scheduled {
        match message {
            ScheduledMessage::Heartbeat(heartbeat) => state.process_heartbeat(heartbeat)?,
            ScheduledMessage::Evidence(evidence) => state.process_evidence(evidence)?,
            ScheduledMessage::Intent(intent) => state.process_intent(intent)?,
        }
    }

    let last_intent_received_ns = receipts
        .values()
        .filter_map(|receipt| receipt.intent_received_ns)
        .max()
        .unwrap_or(local_node.revocation_applied_ns);
    let checkpoint_timestamp_ns = last_intent_received_ns.saturating_add(CHECKPOINT_LAG_NS);
    let checkpoint = state.build_checkpoint(
        checkpoint_timestamp_ns,
        message_signature(local_node, "checkpoint", checkpoint_timestamp_ns),
    )?;
    let decision = checkpoint
        .containment_decisions
        .iter()
        .find(|decision| decision.extension_id == EXTENSION_ID)
        .ok_or_else(|| {
            format!(
                "missing containment decision for {} on {}",
                EXTENSION_ID, local_node.node_id
            )
        })?;
    let mut contributing_intent_ids = decision.contributing_intent_ids.clone();
    contributing_intent_ids.sort();

    let first_revocation_applied_ns = nodes
        .iter()
        .map(|node| node.revocation_applied_ns)
        .min()
        .unwrap_or(local_node.revocation_applied_ns);
    let last_revocation_applied_ns = nodes
        .iter()
        .map(|node| node.revocation_applied_ns)
        .max()
        .unwrap_or(local_node.revocation_applied_ns);

    Ok(InstanceReport {
        instance_id: local_node.node_id.to_string(),
        local_revocation_applied_ns: local_node.revocation_applied_ns,
        chain_head_seq: chain.head_seq().unwrap_or(0),
        target_revoked: chain.is_revoked(&revocation.target_id),
        evidence_packets_observed: nodes.len(),
        resolved_action: decision.resolved_action.to_string(),
        checkpoint_timestamp_ns,
        checkpoint_seq: checkpoint.checkpoint_seq,
        healthy_nodes_at_checkpoint: checkpoint
            .participating_nodes
            .iter()
            .map(ToString::to_string)
            .collect(),
        contributing_intent_ids,
        receipts: nodes
            .iter()
            .map(|node| ReceiptLog {
                from_instance: node.node_id.to_string(),
                heartbeat_received_ns: receipts
                    .get(node.node_id.as_str())
                    .and_then(|receipt| receipt.heartbeat_received_ns)
                    .unwrap_or(0),
                evidence_received_ns: receipts
                    .get(node.node_id.as_str())
                    .and_then(|receipt| receipt.evidence_received_ns)
                    .unwrap_or(0),
                intent_received_ns: receipts
                    .get(node.node_id.as_str())
                    .and_then(|receipt| receipt.intent_received_ns)
                    .unwrap_or(0),
            })
            .collect(),
        convergence_from_first_revocation_ns: checkpoint_timestamp_ns
            .saturating_sub(first_revocation_applied_ns),
        convergence_from_last_revocation_ns: checkpoint_timestamp_ns
            .saturating_sub(last_revocation_applied_ns),
        within_bounded_slo: checkpoint_timestamp_ns.saturating_sub(first_revocation_applied_ns)
            <= BOUNDED_CONVERGENCE_SLO_NS,
    })
}

fn schedule_messages(
    local_index: usize,
    nodes: &[NodeMaterial],
    receipts: &mut BTreeMap<String, ReceiptBuilder>,
) -> Vec<ScheduledMessage> {
    let mut scheduled = Vec::with_capacity(nodes.len() * 3);
    for (remote_index, node) in nodes.iter().enumerate() {
        let delay_ns = DELIVERY_DELAY_NS[remote_index][local_index];

        let heartbeat_timestamp_ns = HEARTBEAT_EMIT_NS.saturating_add(delay_ns);
        receipts
            .entry(node.node_id.to_string())
            .or_default()
            .heartbeat_received_ns = Some(heartbeat_timestamp_ns);
        scheduled.push(ScheduledMessage::Heartbeat(heartbeat_message(
            node,
            heartbeat_timestamp_ns,
        )));

        let evidence_timestamp_ns = node
            .revocation_applied_ns
            .saturating_add(EVIDENCE_LAG_NS)
            .saturating_add(delay_ns);
        receipts
            .entry(node.node_id.to_string())
            .or_default()
            .evidence_received_ns = Some(evidence_timestamp_ns);
        scheduled.push(ScheduledMessage::Evidence(evidence_message(
            node,
            evidence_timestamp_ns,
        )));

        let intent_timestamp_ns = node
            .revocation_applied_ns
            .saturating_add(INTENT_LAG_NS)
            .saturating_add(delay_ns);
        receipts
            .entry(node.node_id.to_string())
            .or_default()
            .intent_received_ns = Some(intent_timestamp_ns);
        scheduled.push(ScheduledMessage::Intent(intent_message(
            node,
            intent_timestamp_ns,
        )));
    }
    scheduled
}

fn heartbeat_message(node: &NodeMaterial, timestamp_ns: u64) -> HeartbeatLiveness {
    let mut local_health = BTreeMap::new();
    local_health.insert("mode".to_string(), "quarantine-demo".to_string());
    local_health.insert("zone".to_string(), ZONE.to_string());
    local_health.insert(
        "revocation_applied_ns".to_string(),
        node.revocation_applied_ns.to_string(),
    );
    HeartbeatLiveness {
        node_id: node.node_id.clone(),
        policy_version: 1,
        evidence_frontier_hash: ContentHash::compute(
            format!("frontier:{}:{timestamp_ns}", node.node_id).as_bytes(),
        ),
        local_health,
        epoch: SecurityEpoch::GENESIS,
        sequence: 1,
        timestamp_ns,
        signature: message_signature(node, "heartbeat", timestamp_ns),
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    }
}

fn evidence_message(node: &NodeMaterial, timestamp_ns: u64) -> EvidencePacket {
    EvidencePacket {
        trace_id: evidence_trace_id(&node.node_id),
        extension_id: EXTENSION_ID.to_string(),
        evidence_hash: ContentHash::compute(
            format!("evidence:{}:{timestamp_ns}", node.node_id).as_bytes(),
        ),
        posterior_delta_millionths: 900_000,
        policy_version: 1,
        epoch: SecurityEpoch::GENESIS,
        node_id: node.node_id.clone(),
        sequence: 2,
        timestamp_ns,
        signature: message_signature(node, "evidence", timestamp_ns),
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    }
}

fn intent_message(node: &NodeMaterial, timestamp_ns: u64) -> ContainmentIntent {
    ContainmentIntent {
        intent_id: format!("intent-{}-quarantine", node.node_id),
        extension_id: EXTENSION_ID.to_string(),
        proposed_action: ContainmentAction::Quarantine,
        confidence_millionths: 975_000,
        supporting_evidence_ids: vec![evidence_trace_id(&node.node_id)],
        policy_version: 1,
        epoch: SecurityEpoch::GENESIS,
        node_id: node.node_id.clone(),
        sequence: 3,
        timestamp_ns,
        signature: message_signature(node, "intent", timestamp_ns),
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    }
}

fn message_signature(node: &NodeMaterial, label: &str, timestamp_ns: u64) -> MessageSignature {
    MessageSignature {
        signer: node.node_id.clone(),
        hash: AuthenticityHash::compute_keyed(
            node.node_id.as_str().as_bytes(),
            format!("{label}:{}:{timestamp_ns}", node.node_id).as_bytes(),
        ),
    }
}

fn evidence_trace_id(node_id: &NodeId) -> String {
    format!("trace-{}-revocation", node_id)
}

fn spread_ns(mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    match (values.first(), values.last()) {
        (Some(first), Some(last)) => last.saturating_sub(*first),
        _ => 0,
    }
}
