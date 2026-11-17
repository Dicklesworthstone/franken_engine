#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::capability_token::PrincipalId;
use frankenengine_engine::engine_object_id::{ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::fleet_checkpoint_v2::FleetCheckpointQuorumV2;
use frankenengine_engine::fleet_immune_protocol::{
    AuthenticatedFleetProtocolStateV2, ContainmentAction, ContainmentIntent,
    DurableFleetVerificationRegistry, EvidencePacket, FleetAuthorityId, FleetIdentityError,
    FleetRegistryAnchorAuthority, FleetRegistrySnapshotAnchorClaim, FleetSignatureV2, FleetSigner,
    FleetVerificationRegistryPersistence, GossipConfig, HeartbeatLiveness, MessageSignature,
    NodeId, ProtocolVersion,
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
use frankenengine_engine::storage_adapter::{EventContext, InMemoryStorageAdapter};
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

struct NodeMaterial {
    node_id: NodeId,
    signing_key: SigningKey,
    fleet_signer: FleetSigner,
    revocation_applied_ns: u64,
}

struct DemoAnchorAuthority {
    authority_id: FleetAuthorityId,
    current: RefCell<Option<FleetRegistrySnapshotAnchorClaim>>,
}

impl DemoAnchorAuthority {
    fn new(authority_id: FleetAuthorityId) -> Self {
        Self {
            authority_id,
            current: RefCell::new(None),
        }
    }
}

impl FleetRegistryAnchorAuthority for DemoAnchorAuthority {
    fn fleet_authority_id(&self) -> FleetAuthorityId {
        self.authority_id
    }

    fn authenticate_current_registry_anchor(
        &self,
        claim: &FleetRegistrySnapshotAnchorClaim,
    ) -> Result<String, FleetIdentityError> {
        if self.current.borrow().as_ref() != Some(claim) {
            return Err(FleetIdentityError::UnverifiedRegistryAnchor {
                detail: "demo authority anchor mismatch".to_string(),
            });
        }
        Ok(format!("quarantine-mesh-anchor-{}", claim.generation))
    }

    fn prepare_registry_anchor_advance(
        &self,
        expected: Option<&FleetRegistrySnapshotAnchorClaim>,
        next: &FleetRegistrySnapshotAnchorClaim,
    ) -> Result<Vec<u8>, FleetIdentityError> {
        if self.current.borrow().as_ref() != expected
            || next.fleet_authority_id != self.authority_id
        {
            return Err(FleetIdentityError::UnverifiedRegistryAnchor {
                detail: "demo authority prepare CAS mismatch".to_string(),
            });
        }
        serde_json::to_vec(&(expected.cloned(), next.clone())).map_err(|error| {
            FleetIdentityError::UnverifiedRegistryAnchor {
                detail: error.to_string(),
            }
        })
    }

    fn finalize_registry_anchor_advance(
        &self,
        permit: &[u8],
        next: &FleetRegistrySnapshotAnchorClaim,
    ) -> Result<String, FleetIdentityError> {
        let (expected, authorized): (
            Option<FleetRegistrySnapshotAnchorClaim>,
            FleetRegistrySnapshotAnchorClaim,
        ) = serde_json::from_slice(permit).map_err(|error| {
            FleetIdentityError::UnverifiedRegistryAnchor {
                detail: error.to_string(),
            }
        })?;
        let mut current = self.current.borrow_mut();
        if &authorized != next || (*current != expected && current.as_ref() != Some(next)) {
            return Err(FleetIdentityError::UnverifiedRegistryAnchor {
                detail: "demo authority finalize CAS mismatch".to_string(),
            });
        }
        *current = Some(next.clone());
        Ok(format!("quarantine-mesh-finalized-{}", next.generation))
    }
}

#[derive(Clone)]
enum ScheduledMessage {
    Heartbeat {
        received_ns: u64,
        message: HeartbeatLiveness,
        signature: FleetSignatureV2,
    },
    Evidence {
        received_ns: u64,
        message: EvidencePacket,
        signature: FleetSignatureV2,
    },
    Intent {
        received_ns: u64,
        message: ContainmentIntent,
        signature: FleetSignatureV2,
    },
}

impl ScheduledMessage {
    fn received_ns(&self) -> u64 {
        match self {
            Self::Heartbeat { received_ns, .. } => *received_ns,
            Self::Evidence { received_ns, .. } => *received_ns,
            Self::Intent { received_ns, .. } => *received_ns,
        }
    }

    fn source_id(&self) -> &NodeId {
        match self {
            Self::Heartbeat { message, .. } => &message.node_id,
            Self::Evidence { message, .. } => &message.node_id,
            Self::Intent { message, .. } => &message.node_id,
        }
    }

    fn kind_rank(&self) -> u8 {
        match self {
            Self::Heartbeat { .. } => 0,
            Self::Evidence { .. } => 1,
            Self::Intent { .. } => 2,
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
    let authority_id = FleetAuthorityId::from_provisioned_bytes(
        *ContentHash::compute(ZONE.as_bytes()).as_bytes(),
    )?;
    let nodes = build_nodes(authority_id)?;
    let anchor = DemoAnchorAuthority::new(authority_id);
    let registry = build_registry(&nodes, &anchor)?;
    let quorum = FleetCheckpointQuorumV2::new(
        nodes
            .iter()
            .map(|node| node.node_id.clone())
            .collect::<BTreeSet<_>>(),
        config.quorum_threshold_millionths,
    )?;
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
            authority_id,
            &registry,
            &anchor,
            &quorum,
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

fn build_nodes(
    authority_id: FleetAuthorityId,
) -> Result<Vec<NodeMaterial>, Box<dyn std::error::Error>> {
    NODE_SPECS
        .iter()
        .map(|spec| {
            let node_id = NodeId::new(spec.name);
            let key = signing_key(spec.signing_seed);
            let fleet_signer = FleetSigner::new(authority_id, node_id.clone(), 1, key.clone())?;
            Ok(NodeMaterial {
                node_id,
                signing_key: key,
                fleet_signer,
                revocation_applied_ns: spec.revocation_applied_ns,
            })
        })
        .collect()
}

fn build_registry(
    nodes: &[NodeMaterial],
    anchor: &DemoAnchorAuthority,
) -> Result<DurableFleetVerificationRegistry, Box<dyn std::error::Error>> {
    let mut storage = InMemoryStorageAdapter::new();
    let context =
        EventContext::new("quarantine-mesh-trace", "quarantine-mesh-dec", "mesh-pol")?;
    let first = &nodes[0];
    let mut registry = FleetVerificationRegistryPersistence::new(&mut storage, &context)
        .prepare_initial_registration(
            first.node_id.clone(),
            1,
            first.fleet_signer.verification_key().clone(),
            SecurityEpoch::GENESIS,
            anchor,
        )?
        .finalize_and_publish(anchor)?;
    for node in &nodes[1..] {
        registry = FleetVerificationRegistryPersistence::new(&mut storage, &context)
            .prepare_register_node(
                &registry,
                node.node_id.clone(),
                1,
                node.fleet_signer.verification_key().clone(),
                SecurityEpoch::GENESIS,
                anchor,
            )?
            .finalize_and_publish(anchor)?;
    }
    Ok(registry)
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

#[allow(clippy::too_many_arguments)]
fn simulate_instance(
    local_index: usize,
    nodes: &[NodeMaterial],
    config: &GossipConfig,
    revocation: &Revocation,
    authority: &NodeMaterial,
    authority_id: FleetAuthorityId,
    registry: &DurableFleetVerificationRegistry,
    anchor: &DemoAnchorAuthority,
    quorum: &FleetCheckpointQuorumV2,
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

    let mut peer_states: Vec<AuthenticatedFleetProtocolStateV2> = nodes
        .iter()
        .map(|node| {
            AuthenticatedFleetProtocolStateV2::new(
                authority_id,
                node.node_id.clone(),
                config.clone(),
                SecurityEpoch::GENESIS,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut receipts: BTreeMap<String, ReceiptBuilder> = nodes
        .iter()
        .map(|node| (node.node_id.to_string(), ReceiptBuilder::default()))
        .collect();
    let mut scheduled = schedule_messages(local_index, nodes, &mut receipts)?;
    scheduled.sort_by_key(|message| {
        (
            message.received_ns(),
            message.kind_rank(),
            message.source_id().to_string(),
        )
    });

    for message in &scheduled {
        for peer_state in &mut peer_states {
            match message {
                ScheduledMessage::Heartbeat {
                    message, signature, ..
                } => peer_state.process_heartbeat(message, signature, registry, anchor)?,
                ScheduledMessage::Evidence {
                    message, signature, ..
                } => peer_state.process_evidence(message, signature, registry, anchor)?,
                ScheduledMessage::Intent {
                    message, signature, ..
                } => peer_state.process_intent(message, signature, registry, anchor)?,
            }
        }
    }

    let last_intent_received_ns = receipts
        .values()
        .filter_map(|receipt| receipt.intent_received_ns)
        .max()
        .unwrap_or(local_node.revocation_applied_ns);
    let checkpoint_timestamp_ns = last_intent_received_ns.saturating_add(CHECKPOINT_LAG_NS);
    let mut draft = peer_states[local_index].draft_checkpoint_v2(checkpoint_timestamp_ns, quorum)?;
    for (peer_idx, node) in nodes.iter().enumerate() {
        let sig = if peer_idx == local_index {
            peer_states[peer_idx].sign_checkpoint_v2(
                &draft,
                quorum,
                &node.fleet_signer,
                registry,
                anchor,
            )?
        } else {
            let peer_draft =
                peer_states[peer_idx].import_checkpoint_proposal_v2(draft.checkpoint(), quorum)?;
            peer_states[peer_idx].sign_checkpoint_v2(
                &peer_draft,
                quorum,
                &node.fleet_signer,
                registry,
                anchor,
            )?
        };
        draft.add_signature(sig, registry, anchor)?;
    }
    let signed_checkpoint = peer_states[local_index].finalize_checkpoint_v2(
        &draft,
        quorum,
        checkpoint_timestamp_ns,
        registry,
        anchor,
    )?;
    let checkpoint = &signed_checkpoint.checkpoint;
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
) -> Result<Vec<ScheduledMessage>, Box<dyn std::error::Error>> {
    let mut scheduled = Vec::with_capacity(nodes.len() * 3);
    for (remote_index, node) in nodes.iter().enumerate() {
        let delay_ns = DELIVERY_DELAY_NS[remote_index][local_index];

        let heartbeat_received_ns = HEARTBEAT_EMIT_NS.saturating_add(delay_ns);
        receipts
            .entry(node.node_id.to_string())
            .or_default()
            .heartbeat_received_ns = Some(heartbeat_received_ns);
        let heartbeat = heartbeat_message(node, HEARTBEAT_EMIT_NS);
        let heartbeat_sig = node.fleet_signer.sign_detached_message_v2(&heartbeat)?;
        scheduled.push(ScheduledMessage::Heartbeat {
            received_ns: heartbeat_received_ns,
            message: heartbeat,
            signature: heartbeat_sig,
        });

        let evidence_emit_ns = node.revocation_applied_ns.saturating_add(EVIDENCE_LAG_NS);
        let evidence_received_ns = evidence_emit_ns.saturating_add(delay_ns);
        receipts
            .entry(node.node_id.to_string())
            .or_default()
            .evidence_received_ns = Some(evidence_received_ns);
        let evidence = evidence_message(node, evidence_emit_ns);
        let evidence_sig = node.fleet_signer.sign_detached_message_v2(&evidence)?;
        scheduled.push(ScheduledMessage::Evidence {
            received_ns: evidence_received_ns,
            message: evidence,
            signature: evidence_sig,
        });

        let intent_emit_ns = node.revocation_applied_ns.saturating_add(INTENT_LAG_NS);
        let intent_received_ns = intent_emit_ns.saturating_add(delay_ns);
        receipts
            .entry(node.node_id.to_string())
            .or_default()
            .intent_received_ns = Some(intent_received_ns);
        let intent = intent_message(node, intent_emit_ns);
        let intent_sig = node.fleet_signer.sign_detached_message_v2(&intent)?;
        scheduled.push(ScheduledMessage::Intent {
            received_ns: intent_received_ns,
            message: intent,
            signature: intent_sig,
        });
    }
    Ok(scheduled)
}

fn unauthenticated_carrier_marker(node: &NodeMaterial) -> MessageSignature {
    MessageSignature {
        signer: node.node_id.clone(),
        hash: AuthenticityHash([0; 32]),
    }
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
        signature: unauthenticated_carrier_marker(node),
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
        signature: unauthenticated_carrier_marker(node),
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
        signature: unauthenticated_carrier_marker(node),
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
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
