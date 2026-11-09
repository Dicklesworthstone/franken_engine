#![forbid(unsafe_code)]
//! Raw network-boundary tests using real Ed25519 signatures and actual fleet
//! state. The authority and storage fixture are in-memory contract fixtures;
//! this suite does not establish database durability or cross-process CAS.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::fleet_checkpoint_v2::{FleetCheckpointQuorumV2, FleetCheckpointV2Error};
use frankenengine_engine::fleet_immune_protocol::{
    AuthenticatedFleetProtocolStateV2, ContainmentAction, ContainmentIntent,
    DurableFleetVerificationRegistry, EvidencePacket, FLEET_V2_MAX_FRAME_BYTES,
    FLEET_V2_MAX_VALUE_BYTES, FleetAuthorityId, FleetIdentityError, FleetRegistryAnchorAuthority,
    FleetRegistrySnapshotAnchorClaim, FleetSigner, FleetVerificationRegistryPersistence,
    GossipConfig, HeartbeatLiveness, MessageSignature, NodeId, ProtocolVersion,
};
use frankenengine_engine::fleet_transport::{
    FLEET_TRANSPORT_MAX_DEPTH, FLEET_TRANSPORT_SCHEMA, FleetTransportContext, FleetTransportError,
    FleetTransportMessage, FleetTransportOutcome,
};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::storage_adapter::{EventContext, InMemoryStorageAdapter};
use serde_json::{Value, json};

type Claim = FleetRegistrySnapshotAnchorClaim;
type Transition = (Option<Claim>, Claim);

#[derive(Default)]
struct AnchorState {
    current: Option<Claim>,
    permits: BTreeMap<Vec<u8>, Transition>,
    next_permit: u64,
}

struct TestAuthority {
    id: FleetAuthorityId,
    state: RefCell<AnchorState>,
}

fn untrusted(detail: &str) -> FleetIdentityError {
    FleetIdentityError::UnverifiedRegistryAnchor {
        detail: detail.to_string(),
    }
}

impl FleetRegistryAnchorAuthority for TestAuthority {
    fn fleet_authority_id(&self) -> FleetAuthorityId {
        self.id
    }

    fn authenticate_current_registry_anchor(
        &self,
        claim: &Claim,
    ) -> Result<String, FleetIdentityError> {
        if self.state.borrow().current.as_ref() != Some(claim) {
            return Err(untrusted("fixture authority anchor is no longer current"));
        }
        Ok(format!("current-{}", claim.generation))
    }

    fn prepare_registry_anchor_advance(
        &self,
        expected: Option<&Claim>,
        next: &Claim,
    ) -> Result<Vec<u8>, FleetIdentityError> {
        let mut state = self.state.borrow_mut();
        if state.current.as_ref() != expected || next.fleet_authority_id != self.id {
            return Err(untrusted("fixture prepare compare-and-swap refused"));
        }
        state.next_permit += 1;
        let permit = state.next_permit.to_be_bytes().to_vec();
        state
            .permits
            .insert(permit.clone(), (expected.cloned(), next.clone()));
        Ok(permit)
    }

    fn finalize_registry_anchor_advance(
        &self,
        permit: &[u8],
        next: &Claim,
    ) -> Result<String, FleetIdentityError> {
        let mut state = self.state.borrow_mut();
        let Some((expected, authorized)) = state.permits.get(permit).cloned() else {
            return Err(untrusted("unissued fixture permit"));
        };
        if authorized != *next
            || (state.current != expected && state.current.as_ref() != Some(next))
        {
            return Err(untrusted(
                "fixture finalized transition does not match permit",
            ));
        }
        state.current = Some(next.clone());
        Ok(format!("finalized-{}", next.generation))
    }
}

struct Fleet {
    authority: TestAuthority,
    registry: DurableFleetVerificationRegistry,
    signers: Vec<FleetSigner>,
    quorum: FleetCheckpointQuorumV2,
    epoch: SecurityEpoch,
}

impl Fleet {
    fn new(count: usize) -> Self {
        let id = FleetAuthorityId::from_provisioned_bytes([0xc3; 32]).unwrap();
        let authority = TestAuthority {
            id,
            state: RefCell::new(AnchorState::default()),
        };
        let epoch = SecurityEpoch::from_raw(7);
        let signers = (0..count)
            .map(|node| {
                FleetSigner::new(
                    id,
                    NodeId::new(format!("wire-node-{node}")),
                    1,
                    SigningKey::from_bytes([0x61 + node as u8; 32]).unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mut storage = InMemoryStorageAdapter::new();
        let event =
            EventContext::new("transport-trace", "transport-decision", "transport-policy").unwrap();
        let first = &signers[0];
        let mut registry = FleetVerificationRegistryPersistence::new(&mut storage, &event)
            .prepare_initial_registration(
                first.identity().signer.clone(),
                1,
                first.verification_key().clone(),
                epoch,
                &authority,
            )
            .unwrap()
            .finalize_and_publish(&authority)
            .unwrap();
        for signer in &signers[1..] {
            registry = FleetVerificationRegistryPersistence::new(&mut storage, &event)
                .prepare_register_node(
                    &registry,
                    signer.identity().signer.clone(),
                    1,
                    signer.verification_key().clone(),
                    epoch,
                    &authority,
                )
                .unwrap()
                .finalize_and_publish(&authority)
                .unwrap();
        }
        let quorum = FleetCheckpointQuorumV2::new(
            signers
                .iter()
                .map(|signer| signer.identity().signer.clone())
                .collect::<BTreeSet<_>>(),
            500_000,
        )
        .unwrap();
        Self {
            authority,
            registry,
            signers,
            quorum,
            epoch,
        }
    }

    fn context(&self) -> FleetTransportContext<'_, TestAuthority> {
        FleetTransportContext {
            quorum: &self.quorum,
            registry: &self.registry,
            authority: &self.authority,
            current_time_ns: 100,
        }
    }

    fn state(&self, node: usize) -> AuthenticatedFleetProtocolStateV2 {
        AuthenticatedFleetProtocolStateV2::new(
            self.authority.id,
            self.signers[node].identity().signer.clone(),
            GossipConfig::default(),
            self.epoch,
        )
        .unwrap()
    }

    fn evidence(&self, node: usize, sequence: u64) -> EvidencePacket {
        let node_id = self.signers[node].identity().signer.clone();
        EvidencePacket {
            trace_id: format!("wire-evidence-{node}-{sequence}"),
            extension_id: "extension-a".into(),
            evidence_hash: ContentHash::compute(
                format!("wire-content-{node}-{sequence}").as_bytes(),
            ),
            posterior_delta_millionths: 400_000,
            policy_version: 7,
            epoch: self.epoch,
            node_id: node_id.clone(),
            sequence,
            timestamp_ns: 100,
            signature: marker(node_id),
            protocol_version: ProtocolVersion::V2,
            extensions: BTreeMap::new(),
        }
    }

    fn intent(&self, node: usize, sequence: u64) -> ContainmentIntent {
        let node_id = self.signers[node].identity().signer.clone();
        ContainmentIntent {
            intent_id: format!("wire-intent-{node}-{sequence}"),
            extension_id: "extension-a".into(),
            proposed_action: ContainmentAction::Quarantine,
            confidence_millionths: 900_000,
            supporting_evidence_ids: vec!["wire-evidence".into()],
            policy_version: 7,
            epoch: self.epoch,
            node_id: node_id.clone(),
            sequence,
            timestamp_ns: 100,
            signature: marker(node_id),
            protocol_version: ProtocolVersion::V2,
            extensions: BTreeMap::new(),
        }
    }

    fn heartbeat(&self, node: usize, sequence: u64) -> HeartbeatLiveness {
        let node_id = self.signers[node].identity().signer.clone();
        HeartbeatLiveness {
            node_id: node_id.clone(),
            policy_version: 7,
            evidence_frontier_hash: ContentHash::compute(b"wire-frontier"),
            local_health: BTreeMap::from([("status".into(), "ready".into())]),
            epoch: self.epoch,
            sequence,
            timestamp_ns: 100,
            signature: marker(node_id),
            protocol_version: ProtocolVersion::V2,
            extensions: BTreeMap::new(),
        }
    }

    fn evidence_frame(&self, node: usize, sequence: u64) -> Vec<u8> {
        let message = self.evidence(node, sequence);
        let signature = self.signers[node]
            .sign_detached_message_v2(&message)
            .unwrap();
        FleetTransportMessage::Evidence { message, signature }
            .encode()
            .unwrap()
    }

    fn intent_frame(&self, node: usize, sequence: u64) -> Vec<u8> {
        let message = self.intent(node, sequence);
        let signature = self.signers[node]
            .sign_detached_message_v2(&message)
            .unwrap();
        FleetTransportMessage::Intent { message, signature }
            .encode()
            .unwrap()
    }

    fn heartbeat_frame(&self, node: usize, sequence: u64) -> Vec<u8> {
        let message = self.heartbeat(node, sequence);
        let signature = self.signers[node]
            .sign_detached_message_v2(&message)
            .unwrap();
        FleetTransportMessage::Heartbeat { message, signature }
            .encode()
            .unwrap()
    }

    fn populated(&self, node: usize) -> AuthenticatedFleetProtocolStateV2 {
        let mut state = self.state(node);
        for sender in 0..self.signers.len() {
            state
                .process_frame_v2(&self.heartbeat_frame(sender, 1), &self.context(), None)
                .unwrap();
        }
        state
            .process_frame_v2(&self.evidence_frame(0, 2), &self.context(), None)
            .unwrap();
        state
            .process_frame_v2(&self.intent_frame(0, 3), &self.context(), None)
            .unwrap();
        state
    }
}

fn marker(node_id: NodeId) -> MessageSignature {
    MessageSignature {
        signer: node_id,
        hash: AuthenticityHash([0; 32]),
    }
}

fn image(state: &AuthenticatedFleetProtocolStateV2) -> Value {
    serde_json::to_value(state.state()).unwrap()
}

fn assert_roundtrip(frame: &[u8]) {
    let decoded = FleetTransportMessage::decode(frame).unwrap();
    assert_eq!(decoded.encode().unwrap(), frame);
    let json: Value = serde_json::from_slice(frame).unwrap();
    assert!(json["message"]["payload"].get("signature").is_none());
    assert!(
        json["message"]["payload"]
            .get("quorum_signatures")
            .is_none()
    );
    assert!(json["message"]["payload"].get("protocol_version").is_none());
}

#[test]
fn raw_frames_admit_all_three_message_families_and_share_replay_frontier() {
    let fleet = Fleet::new(1);
    let mut state = fleet.state(0);
    let frames = [
        fleet.evidence_frame(0, 1),
        fleet.intent_frame(0, 2),
        fleet.heartbeat_frame(0, 3),
    ];
    for (index, frame) in frames.iter().enumerate() {
        assert_roundtrip(frame);
        let outcome = state
            .process_frame_v2(frame, &fleet.context(), None)
            .unwrap();
        match (index, outcome) {
            (0, FleetTransportOutcome::EvidenceAccepted { sequence: 1, .. })
            | (1, FleetTransportOutcome::IntentAccepted { sequence: 2, .. })
            | (2, FleetTransportOutcome::HeartbeatAccepted { sequence: 3, .. }) => {}
            other => panic!("wrong dispatch outcome: {other:?}"),
        }
    }
    assert_eq!(
        state.state().evidence.posterior_delta("extension-a"),
        400_000
    );
    assert_eq!(state.state().pending_intents["extension-a"].len(), 1);
    assert_eq!(state.state().health.known_node_count(), 1);
    let before = image(&state);
    assert!(
        state
            .process_frame_v2(&frames[0], &fleet.context(), None)
            .is_err()
    );
    assert_eq!(image(&state), before);
}

#[test]
fn wire_checkpoint_exchange_finalizes_on_peers_and_preserves_post_vote_arrivals() {
    let fleet = Fleet::new(3);
    let mut proposer = fleet.populated(0);
    let mut peer = fleet.populated(1);
    let mut observer = fleet.populated(2);
    let mut draft = proposer.draft_checkpoint_v2(100, &fleet.quorum).unwrap();
    let proposal_signature = proposer
        .sign_checkpoint_v2(
            &draft,
            &fleet.quorum,
            &fleet.signers[0],
            &fleet.registry,
            &fleet.authority,
        )
        .unwrap();
    draft
        .add_signature(
            proposal_signature.clone(),
            &fleet.registry,
            &fleet.authority,
        )
        .unwrap();
    let proposal = FleetTransportMessage::CheckpointProposal {
        checkpoint: draft.checkpoint().clone(),
        signature: proposal_signature,
    }
    .encode()
    .unwrap();
    assert_roundtrip(&proposal);
    let FleetTransportOutcome::CheckpointProposed(peer_draft) = peer
        .process_frame_v2(&proposal, &fleet.context(), None)
        .unwrap()
    else {
        panic!("proposal did not produce a draft");
    };
    assert_eq!(peer_draft.signatures().len(), 1);
    let peer_signature = peer
        .sign_checkpoint_v2(
            &peer_draft,
            &fleet.quorum,
            &fleet.signers[1],
            &fleet.registry,
            &fleet.authority,
        )
        .unwrap();
    let vote = FleetTransportMessage::CheckpointVote {
        checkpoint: peer_draft.checkpoint().clone(),
        signature: peer_signature,
    }
    .encode()
    .unwrap();
    assert_roundtrip(&vote);
    assert!(matches!(
        proposer
            .process_frame_v2(&vote, &fleet.context(), Some(&mut draft))
            .unwrap(),
        FleetTransportOutcome::CheckpointVoteAdded {
            checkpoint_seq: 1,
            ..
        }
    ));
    let signed = proposer
        .finalize_checkpoint_v2(
            &draft,
            &fleet.quorum,
            100,
            &fleet.registry,
            &fleet.authority,
        )
        .unwrap();
    let finalized = FleetTransportMessage::CheckpointFinalized(signed)
        .encode()
        .unwrap();
    assert_roundtrip(&finalized);

    peer.process_frame_v2(&fleet.evidence_frame(1, 2), &fleet.context(), None)
        .unwrap();
    peer.process_frame_v2(&fleet.intent_frame(1, 3), &fleet.context(), None)
        .unwrap();
    assert!(matches!(
        peer.process_frame_v2(&finalized, &fleet.context(), None)
            .unwrap(),
        FleetTransportOutcome::CheckpointFinalized(_)
    ));
    assert_eq!(peer.state().last_checkpoint_seq, 1);
    assert_eq!(
        peer.state().evidence.posterior_delta("extension-a"),
        800_000
    );
    assert_eq!(peer.state().pending_intents["extension-a"].len(), 1);
    assert_eq!(
        peer.state().pending_intents["extension-a"][0].intent_id,
        "wire-intent-1-3"
    );
    observer
        .process_frame_v2(&finalized, &fleet.context(), None)
        .unwrap();
    assert_eq!(observer.state().last_checkpoint_seq, 1);
    assert!(observer.state().pending_intents.is_empty());
    let before = image(&peer);
    assert!(
        peer.process_frame_v2(&finalized, &fleet.context(), None)
            .is_err()
    );
    assert_eq!(image(&peer), before);
}

#[test]
fn raw_limits_precede_typed_payload_allocation() {
    let oversized = vec![b' '; FLEET_V2_MAX_FRAME_BYTES + 1];
    assert!(matches!(
        FleetTransportMessage::decode(&oversized),
        Err(FleetTransportError::Identity(
            FleetIdentityError::NonCanonicalMessage { message_type, detail }
        )) if message_type == "fleet-v2-frame" && detail.contains("frame_bytes")
    ));
    assert!(matches!(
        FleetTransportMessage::decode(&vec![b' '; FLEET_V2_MAX_FRAME_BYTES]),
        Err(FleetTransportError::MalformedFrame { .. })
    ));
    let nested = format!(
        "{}0{}",
        "[".repeat(FLEET_TRANSPORT_MAX_DEPTH + 2),
        "]".repeat(FLEET_TRANSPORT_MAX_DEPTH + 2)
    );
    assert!(matches!(FleetTransportMessage::decode(nested.as_bytes()),
        Err(FleetTransportError::MalformedFrame { detail }) if detail.contains("nesting limit")));
    let too_many = format!(
        "[{}]",
        std::iter::repeat_n("0", 1025).collect::<Vec<_>>().join(",")
    );
    assert!(matches!(FleetTransportMessage::decode(too_many.as_bytes()),
        Err(FleetTransportError::MalformedFrame { detail }) if detail.contains("array item limit")));
}

#[test]
fn malformed_unknown_duplicate_and_legacy_frames_leave_state_untouched() {
    let fleet = Fleet::new(1);
    let mut state = fleet.state(0);
    let valid = fleet.heartbeat_frame(0, 1);
    let text = String::from_utf8(valid.clone()).unwrap();
    let mut cases = vec![
        ("truncated", valid[..valid.len() - 1].to_vec()),
        ("trailing", [valid.clone(), b"{}".to_vec()].concat()),
        ("invalid utf8", vec![0xff]),
        (
            "duplicate schema",
            text.replacen(
                "{",
                &format!("{{\"schema\":\"{FLEET_TRANSPORT_SCHEMA}\","),
                1,
            )
            .into_bytes(),
        ),
        (
            "escaped duplicate schema",
            text.replacen(
                "{",
                &format!("{{\"\\u0073chema\":\"{FLEET_TRANSPORT_SCHEMA}\","),
                1,
            )
            .into_bytes(),
        ),
        (
            "duplicate sequence",
            text.replacen("\"sequence\":1", "\"sequence\":1,\"sequence\":2", 1)
                .into_bytes(),
        ),
        (
            "duplicate health key",
            text.replacen(
                "\"status\":\"ready\"",
                "\"status\":\"ready\",\"status\":\"other\"",
                1,
            )
            .into_bytes(),
        ),
    ];
    type Mutation = (&'static str, fn(&mut Value));
    let mutations: &[Mutation] = &[
        ("unknown envelope", |v| {
            v["unknown"] = json!(true);
        }),
        ("unknown message", |v| {
            v["message"]["unknown"] = json!(true);
        }),
        ("unknown payload", |v| {
            v["message"]["payload"]["unknown"] = json!(true);
        }),
        ("unknown signature", |v| {
            v["message"]["signature"]["unknown"] = json!(true);
        }),
        ("legacy payload tag", |v| {
            v["message"]["payload"]["signature"] = json!({"signer":"attacker","hash":[0]});
        }),
        ("legacy protocol override", |v| {
            v["message"]["payload"]["protocol_version"] = json!({"major":1,"minor":0});
        }),
        ("other schema", |v| {
            v["schema"] = json!("frankenengine.fleet-transport.v1");
        }),
        ("unknown kind", |v| {
            v["message"]["type"] = json!("reconciliation");
        }),
        ("negative sequence", |v| {
            v["message"]["payload"]["sequence"] = json!(-1);
        }),
        ("floating sequence", |v| {
            v["message"]["payload"]["sequence"] = json!(1.0);
        }),
        ("missing signature", |v| {
            v["message"].as_object_mut().unwrap().remove("signature");
        }),
        ("uppercase signature", |v| {
            v["message"]["signature"]["signature"] = json!("AA".repeat(64));
        }),
        ("short signature", |v| {
            v["message"]["signature"]["signature"] = json!("00");
        }),
        ("oversized identifier", |v| {
            v["message"]["payload"]["node_id"] = json!("x".repeat(257));
        }),
    ];
    for (name, mutate) in mutations {
        let mut value = serde_json::from_slice(&valid).unwrap();
        mutate(&mut value);
        cases.push((name, serde_json::to_vec(&value).unwrap()));
    }
    cases.push((
        "legacy envelope",
        serde_json::to_vec(
            &frankenengine_engine::fleet_immune_protocol::FleetMessage::Heartbeat(
                fleet.heartbeat(0, 1),
            ),
        )
        .unwrap(),
    ));
    let before = image(&state);
    for (name, frame) in cases {
        assert!(
            state
                .process_frame_v2(&frame, &fleet.context(), None)
                .is_err(),
            "accepted {name}"
        );
        assert_eq!(image(&state), before, "mutated state for {name}");
    }
    state
        .process_frame_v2(&valid, &fleet.context(), None)
        .unwrap();
}

#[test]
fn signed_payload_tampering_wrong_epoch_and_stale_anchor_cannot_consume_sequence() {
    let fleet = Fleet::new(1);
    let mut state = fleet.state(0);
    let valid = fleet.evidence_frame(0, 1);
    type Mutation = (&'static str, fn(&mut Value));
    let mutations: &[Mutation] = &[
        ("posterior", |v| {
            v["message"]["payload"]["posterior_delta_millionths"] = json!(1);
        }),
        ("trace", |v| {
            v["message"]["payload"]["trace_id"] = json!("altered");
        }),
        ("extension", |v| {
            v["message"]["payload"]["extension_id"] = json!("other");
        }),
        ("epoch", |v| {
            v["message"]["payload"]["epoch"] = json!(8);
        }),
        ("key sequence", |v| {
            v["message"]["signature"]["key_sequence"] = json!(2);
        }),
        ("authority", |v| {
            v["message"]["signature"]["fleet_authority_id"] = json!("f3".repeat(32));
        }),
        ("signature", |v| {
            v["message"]["signature"]["signature"] = json!("00".repeat(64));
        }),
    ];
    let before = image(&state);
    for (name, mutate) in mutations {
        let mut value = serde_json::from_slice(&valid).unwrap();
        mutate(&mut value);
        let frame = serde_json::to_vec(&value).unwrap();
        assert!(
            FleetTransportMessage::decode(&frame).is_ok(),
            "{name} must reach authentication"
        );
        assert!(
            state
                .process_frame_v2(&frame, &fleet.context(), None)
                .is_err(),
            "accepted {name}"
        );
        assert_eq!(image(&state), before, "consumed {name}");
    }
    let claim = fleet.authority.state.borrow_mut().current.take();
    assert!(
        state
            .process_frame_v2(&valid, &fleet.context(), None)
            .is_err()
    );
    assert_eq!(image(&state), before);
    fleet.authority.state.borrow_mut().current = claim;
    state
        .process_frame_v2(&valid, &fleet.context(), None)
        .unwrap();
}

#[test]
fn checkpoint_votes_require_the_exact_pending_draft_and_distinct_signers() {
    let fleet = Fleet::new(3);
    let mut state = fleet.populated(0);
    let mut peer = fleet.populated(1);
    let mut draft = state.draft_checkpoint_v2(100, &fleet.quorum).unwrap();
    let signature = peer
        .sign_checkpoint_v2(
            &draft,
            &fleet.quorum,
            &fleet.signers[1],
            &fleet.registry,
            &fleet.authority,
        )
        .unwrap();
    let frame = FleetTransportMessage::CheckpointVote {
        checkpoint: draft.checkpoint().clone(),
        signature,
    }
    .encode()
    .unwrap();
    assert!(matches!(
        state.process_frame_v2(&frame, &fleet.context(), None),
        Err(FleetTransportError::MissingCheckpointDraft)
    ));
    let mut other = state.draft_checkpoint_v2(101, &fleet.quorum).unwrap();
    assert!(matches!(
        state.process_frame_v2(&frame, &fleet.context(), Some(&mut other)),
        Err(FleetTransportError::CheckpointVoteMismatch)
    ));
    assert!(other.signatures().is_empty());
    state
        .process_frame_v2(&frame, &fleet.context(), Some(&mut draft))
        .unwrap();
    let votes = draft.signatures().clone();
    let before = image(&state);
    assert!(matches!(
        state.process_frame_v2(&frame, &fleet.context(), Some(&mut draft)),
        Err(FleetTransportError::Checkpoint(
            FleetCheckpointV2Error::DuplicateSigner { .. }
        ))
    ));
    assert_eq!(draft.signatures(), &votes);
    assert_eq!(image(&state), before);
}

#[test]
fn authenticated_proposal_must_match_the_receivers_evidence_and_electorate() {
    let fleet = Fleet::new(3);
    let mut proposer = fleet.populated(0);
    let mut peer = fleet.populated(1);
    let draft = proposer.draft_checkpoint_v2(100, &fleet.quorum).unwrap();
    let signature = proposer
        .sign_checkpoint_v2(
            &draft,
            &fleet.quorum,
            &fleet.signers[0],
            &fleet.registry,
            &fleet.authority,
        )
        .unwrap();
    let frame = FleetTransportMessage::CheckpointProposal {
        checkpoint: draft.checkpoint().clone(),
        signature,
    }
    .encode()
    .unwrap();
    let minority = FleetCheckpointQuorumV2::new(
        fleet.signers[..2]
            .iter()
            .map(|s| s.identity().signer.clone())
            .collect(),
        500_000,
    )
    .unwrap();
    let mut wrong_context = fleet.context();
    wrong_context.quorum = &minority;
    let before = image(&peer);
    assert!(peer.process_frame_v2(&frame, &wrong_context, None).is_err());
    assert_eq!(image(&peer), before);
    peer.process_frame_v2(&fleet.evidence_frame(1, 2), &fleet.context(), None)
        .unwrap();
    let before = image(&peer);
    assert!(
        peer.process_frame_v2(&frame, &fleet.context(), None)
            .is_err()
    );
    assert_eq!(image(&peer), before);
}

#[test]
fn checkpoint_wire_rejects_duplicate_collections_and_unsigned_legacy_fields() {
    let fleet = Fleet::new(3);
    let mut state = fleet.populated(0);
    let mut peer = fleet.populated(1);
    let mut draft = state.draft_checkpoint_v2(100, &fleet.quorum).unwrap();
    for (node, signer_state) in [(0, &mut state), (1, &mut peer)] {
        let signature = signer_state
            .sign_checkpoint_v2(
                &draft,
                &fleet.quorum,
                &fleet.signers[node],
                &fleet.registry,
                &fleet.authority,
            )
            .unwrap();
        draft
            .add_signature(signature, &fleet.registry, &fleet.authority)
            .unwrap();
    }
    let signed = state
        .finalize_checkpoint_v2(
            &draft,
            &fleet.quorum,
            100,
            &fleet.registry,
            &fleet.authority,
        )
        .unwrap();
    let frame = FleetTransportMessage::CheckpointFinalized(signed)
        .encode()
        .unwrap();
    type Mutation = (&'static str, fn(&mut Value));
    let mutations: &[Mutation] = &[
        ("duplicate participant", |v| {
            let p = &mut v["message"]["payload"]["participating_nodes"];
            let duplicate = p[0].clone();
            p.as_array_mut().unwrap().push(duplicate);
        }),
        ("reordered participants", |v| {
            v["message"]["payload"]["participating_nodes"]
                .as_array_mut()
                .unwrap()
                .reverse();
        }),
        ("duplicate signer", |v| {
            let s = &mut v["message"]["signatures"];
            let duplicate = s[0].clone();
            s.as_array_mut().unwrap().push(duplicate);
        }),
        ("reordered signers", |v| {
            v["message"]["signatures"].as_array_mut().unwrap().reverse();
        }),
        ("legacy signature bundle", |v| {
            v["message"]["payload"]["quorum_signatures"] = json!({});
        }),
        ("unknown nested decision", |v| {
            v["message"]["payload"]["containment_decisions"][0]["unexpected"] = json!(1);
        }),
        ("duplicate intent", |v| {
            let ids =
                &mut v["message"]["payload"]["containment_decisions"][0]["contributing_intent_ids"];
            let duplicate = ids[0].clone();
            ids.as_array_mut().unwrap().push(duplicate);
        }),
    ];
    let mut receiver = fleet.populated(2);
    let before = image(&receiver);
    for (name, mutate) in mutations {
        let mut value = serde_json::from_slice(&frame).unwrap();
        mutate(&mut value);
        assert!(
            receiver
                .process_frame_v2(&serde_json::to_vec(&value).unwrap(), &fleet.context(), None)
                .is_err(),
            "accepted {name}"
        );
        assert_eq!(image(&receiver), before, "consumed {name}");
    }
    receiver
        .process_frame_v2(&frame, &fleet.context(), None)
        .unwrap();
}

#[test]
fn outbound_encoding_refuses_legacy_versions_and_escaped_frames_over_the_raw_cap() {
    let fleet = Fleet::new(1);
    let mut message = fleet.evidence(0, 1);
    let signature = fleet.signers[0].sign_detached_message_v2(&message).unwrap();
    message.protocol_version = ProtocolVersion::V1;
    assert!(
        FleetTransportMessage::Evidence { message, signature }
            .encode()
            .is_err()
    );
    let mut message = fleet.evidence(0, 1);
    for index in 0..3 {
        message.extensions.insert(
            format!("escaped-{index}"),
            "\u{0001}".repeat(FLEET_V2_MAX_VALUE_BYTES),
        );
    }
    let signature = fleet.signers[0].sign_detached_message_v2(&message).unwrap();
    assert!(matches!(
        FleetTransportMessage::Evidence { message, signature }.encode(),
        Err(FleetTransportError::Identity(
            FleetIdentityError::NonCanonicalMessage { message_type, detail }
        )) if message_type == "fleet-v2-frame" && detail.contains("frame_bytes")
    ));
}
