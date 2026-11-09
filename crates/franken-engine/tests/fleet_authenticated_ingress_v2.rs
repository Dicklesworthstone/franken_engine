#![forbid(unsafe_code)]
//! Public-API security regressions for authenticated fleet admission and quorum
//! checkpoints. These tests use real Ed25519 message signatures. The external
//! anchor authority and storage are deterministic in-memory contract fixtures;
//! they make no claim about filesystem durability or cross-process CAS.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::fleet_checkpoint_v2::{
    FleetCheckpointDraftV2, FleetCheckpointQuorumV2, FleetCheckpointV2Error,
    SignedFleetCheckpointV2,
};
use frankenengine_engine::fleet_immune_protocol::{
    AuthenticatedFleetProtocolStateV2, ContainmentAction, ContainmentIntent,
    DurableFleetVerificationRegistry, EvidencePacket, FLEET_V2_MAX_IDENTIFIER_BYTES,
    FLEET_V2_MAX_PENDING_INTENT_BYTES, FLEET_V2_MAX_PENDING_INTENTS, FleetAuthorityId,
    FleetIdentityError, FleetIngressV2Error, FleetRegistryAnchorAuthority,
    FleetRegistrySnapshotAnchorClaim, FleetRevocationPolicy, FleetSigner,
    FleetVerificationRegistryPersistence, GossipConfig, HeartbeatLiveness, MessageSignature,
    NodeId, ProtocolError, ProtocolVersion,
};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::storage_adapter::{EventContext, InMemoryStorageAdapter};

type Transition = (
    Option<FleetRegistrySnapshotAnchorClaim>,
    FleetRegistrySnapshotAnchorClaim,
);

#[derive(Default)]
struct AuthorityState {
    current: Option<FleetRegistrySnapshotAnchorClaim>,
    // An issued token authorizes exactly the transition retained here. Permits
    // are never authenticated by trusting bytes read from the storage fixture.
    permits: BTreeMap<Vec<u8>, Transition>,
    next_permit: u64,
}

struct TestAuthority {
    id: FleetAuthorityId,
    state: RefCell<AuthorityState>,
}

fn untrusted_anchor(detail: &str) -> FleetIdentityError {
    FleetIdentityError::UnverifiedRegistryAnchor {
        detail: detail.to_string(),
    }
}

impl TestAuthority {
    fn new(id: FleetAuthorityId) -> Self {
        Self {
            id,
            state: RefCell::new(AuthorityState::default()),
        }
    }
}

impl FleetRegistryAnchorAuthority for TestAuthority {
    fn fleet_authority_id(&self) -> FleetAuthorityId {
        self.id
    }

    fn authenticate_current_registry_anchor(
        &self,
        claim: &FleetRegistrySnapshotAnchorClaim,
    ) -> Result<String, FleetIdentityError> {
        if self.state.borrow().current.as_ref() != Some(claim) {
            return Err(untrusted_anchor(
                "the retained authority anchor has advanced",
            ));
        }
        Ok(format!("test-authority-current-{}", claim.generation))
    }

    fn prepare_registry_anchor_advance(
        &self,
        expected: Option<&FleetRegistrySnapshotAnchorClaim>,
        next: &FleetRegistrySnapshotAnchorClaim,
    ) -> Result<Vec<u8>, FleetIdentityError> {
        let mut state = self.state.borrow_mut();
        if state.current.as_ref() != expected || next.fleet_authority_id != self.id {
            return Err(untrusted_anchor(
                "wrong expected anchor or authority domain",
            ));
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
        next: &FleetRegistrySnapshotAnchorClaim,
    ) -> Result<String, FleetIdentityError> {
        let mut state = self.state.borrow_mut();
        let (expected, authorized) = state
            .permits
            .get(permit)
            .ok_or_else(|| untrusted_anchor("unissued transition permit"))?;
        if authorized != next {
            return Err(untrusted_anchor(
                "permit is bound to a different transition",
            ));
        }
        if state.current.as_ref() != Some(next) {
            if state.current.as_ref() != expected.as_ref() {
                return Err(untrusted_anchor("transition starts at a stale anchor"));
            }
            state.current = Some(next.clone());
        }
        Ok(format!("test-authority-finalized-{}", next.generation))
    }
}

struct FleetFixture {
    authority: TestAuthority,
    storage: InMemoryStorageAdapter,
    context: EventContext,
    registry: DurableFleetVerificationRegistry,
    signers: Vec<FleetSigner>,
    epoch: SecurityEpoch,
}

impl FleetFixture {
    fn new(node_count: usize) -> Self {
        assert!((1..=8).contains(&node_count));
        let id = FleetAuthorityId::from_provisioned_bytes([0xa7; 32]).unwrap();
        let epoch = SecurityEpoch::from_raw(4);
        let authority = TestAuthority::new(id);
        let context = EventContext::new("fleet-v2-test", "admission", "policy-4").unwrap();
        let mut storage = InMemoryStorageAdapter::new();
        let signers = (0..node_count)
            .map(|index| {
                FleetSigner::new(
                    id,
                    NodeId::new(format!("node-{index}")),
                    1,
                    SigningKey::from_bytes([0x31 + index as u8; 32]).unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let first = &signers[0];
        let mut registry = FleetVerificationRegistryPersistence::new(&mut storage, &context)
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
            registry = FleetVerificationRegistryPersistence::new(&mut storage, &context)
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
        Self {
            authority,
            storage,
            context,
            registry,
            signers,
            epoch,
        }
    }

    fn state(&self, local_index: usize) -> AuthenticatedFleetProtocolStateV2 {
        AuthenticatedFleetProtocolStateV2::new(
            self.authority.id,
            self.signers[local_index].identity().signer.clone(),
            GossipConfig::default(),
            self.epoch,
        )
        .unwrap()
    }

    fn electorate(&self) -> BTreeSet<NodeId> {
        self.signers
            .iter()
            .map(|signer| signer.identity().signer.clone())
            .collect()
    }

    fn evidence(&self, node_index: usize, sequence: u64) -> EvidencePacket {
        let node = self.signers[node_index].identity().signer.clone();
        EvidencePacket {
            trace_id: format!("trace-{node}-{sequence}"),
            extension_id: "extension-a".to_string(),
            evidence_hash: ContentHash::compute(format!("evidence-{node}-{sequence}").as_bytes()),
            posterior_delta_millionths: 400_000,
            policy_version: 4,
            epoch: self.epoch,
            node_id: node.clone(),
            sequence,
            timestamp_ns: 100,
            signature: legacy_marker(node),
            protocol_version: ProtocolVersion::V2,
            extensions: BTreeMap::new(),
        }
    }

    fn intent(&self, node_index: usize, sequence: u64) -> ContainmentIntent {
        let node = self.signers[node_index].identity().signer.clone();
        ContainmentIntent {
            intent_id: format!("intent-{node}-{sequence}"),
            extension_id: "extension-a".to_string(),
            proposed_action: ContainmentAction::Quarantine,
            confidence_millionths: 900_000,
            supporting_evidence_ids: vec!["evidence-a".to_string()],
            policy_version: 4,
            epoch: self.epoch,
            node_id: node.clone(),
            sequence,
            timestamp_ns: 100,
            signature: legacy_marker(node),
            protocol_version: ProtocolVersion::V2,
            extensions: BTreeMap::new(),
        }
    }

    fn heartbeat(&self, node_index: usize, sequence: u64) -> HeartbeatLiveness {
        let node = self.signers[node_index].identity().signer.clone();
        HeartbeatLiveness {
            node_id: node.clone(),
            policy_version: 4,
            evidence_frontier_hash: ContentHash::compute(b"frontier"),
            local_health: BTreeMap::from([("status".to_string(), "ready".to_string())]),
            epoch: self.epoch,
            sequence,
            timestamp_ns: 100,
            signature: legacy_marker(node),
            protocol_version: ProtocolVersion::V2,
            extensions: BTreeMap::new(),
        }
    }

    fn populated_state(&self, local_index: usize) -> AuthenticatedFleetProtocolStateV2 {
        let mut state = self.state(local_index);
        for (index, signer) in self.signers.iter().enumerate() {
            let heartbeat = self.heartbeat(index, 1);
            state
                .process_heartbeat(
                    &heartbeat,
                    &signer.sign_detached_message_v2(&heartbeat).unwrap(),
                    &self.registry,
                    &self.authority,
                )
                .unwrap();
        }
        let evidence = self.evidence(0, 2);
        state
            .process_evidence(
                &evidence,
                &self.signers[0].sign_detached_message_v2(&evidence).unwrap(),
                &self.registry,
                &self.authority,
            )
            .unwrap();
        let intent = self.intent(0, 3);
        state
            .process_intent(
                &intent,
                &self.signers[0].sign_detached_message_v2(&intent).unwrap(),
                &self.registry,
                &self.authority,
            )
            .unwrap();
        state
    }
}

fn legacy_marker(node: NodeId) -> MessageSignature {
    MessageSignature {
        signer: node,
        hash: AuthenticityHash([0; 32]),
    }
}

fn state_image(state: &AuthenticatedFleetProtocolStateV2) -> serde_json::Value {
    serde_json::to_value(state.state()).unwrap()
}

#[test]
fn authenticated_message_families_share_one_replay_frontier() {
    let fixture = FleetFixture::new(1);
    let signer = &fixture.signers[0];
    let mut state = fixture.state(0);
    let evidence = fixture.evidence(0, 1);
    state
        .process_evidence(
            &evidence,
            &signer.sign_detached_message_v2(&evidence).unwrap(),
            &fixture.registry,
            &fixture.authority,
        )
        .unwrap();
    let before = state_image(&state);
    let replay = fixture.heartbeat(0, 1);
    assert!(matches!(
        state.process_heartbeat(
            &replay,
            &signer.sign_detached_message_v2(&replay).unwrap(),
            &fixture.registry,
            &fixture.authority,
        ),
        Err(FleetIngressV2Error::Protocol(
            ProtocolError::ReplayDetected { .. }
        ))
    ));
    assert_eq!(state_image(&state), before);
    let intent = fixture.intent(0, 2);
    state
        .process_intent(
            &intent,
            &signer.sign_detached_message_v2(&intent).unwrap(),
            &fixture.registry,
            &fixture.authority,
        )
        .unwrap();
    let heartbeat = fixture.heartbeat(0, 3);
    state
        .process_heartbeat(
            &heartbeat,
            &signer.sign_detached_message_v2(&heartbeat).unwrap(),
            &fixture.registry,
            &fixture.authority,
        )
        .unwrap();
    assert_eq!(
        state.state().evidence.posterior_delta("extension-a"),
        400_000
    );
    assert_eq!(state.state().health.known_node_count(), 1);
    assert_eq!(state.state().pending_intents["extension-a"].len(), 1);
}

#[test]
fn unsigned_legacy_intent_tags_cannot_become_authenticated_state() {
    let fixture = FleetFixture::new(1);
    let mut first_state = fixture.state(0);
    let mut second_state = fixture.state(0);
    let mut intent = fixture.intent(0, 1);
    let signature = fixture.signers[0]
        .sign_detached_message_v2(&intent)
        .unwrap();
    first_state
        .process_intent(&intent, &signature, &fixture.registry, &fixture.authority)
        .unwrap();
    intent.signature = MessageSignature {
        signer: NodeId::new("attacker-chosen-legacy-signer"),
        hash: AuthenticityHash([0xff; 32]),
    };
    second_state
        .process_intent(&intent, &signature, &fixture.registry, &fixture.authority)
        .unwrap();
    assert_eq!(state_image(&first_state), state_image(&second_state));
    let admitted = &second_state.state().pending_intents["extension-a"][0];
    assert_eq!(admitted.signature, legacy_marker(admitted.node_id.clone()));
}

#[test]
fn revocation_invalidates_old_and_current_registry_admission_without_consuming_sequence() {
    let mut fixture = FleetFixture::new(2);
    let mut state = fixture.state(0);
    let intent = fixture.intent(0, 1);
    let signature = fixture.signers[0]
        .sign_detached_message_v2(&intent)
        .unwrap();
    let revoked = FleetVerificationRegistryPersistence::new(&mut fixture.storage, &fixture.context)
        .prepare_revocation(
            &fixture.registry,
            fixture.signers[0].identity().signer.clone(),
            1,
            fixture.epoch,
            fixture.epoch,
            FleetRevocationPolicy::Retroactive,
            &fixture.authority,
        )
        .unwrap()
        .finalize_and_publish(&fixture.authority)
        .unwrap();
    let before = state_image(&state);
    assert!(matches!(
        state.process_intent(&intent, &signature, &fixture.registry, &fixture.authority),
        Err(FleetIngressV2Error::Identity(
            FleetIdentityError::UnverifiedRegistryAnchor { .. }
        ))
    ));
    assert!(matches!(
        state.process_intent(&intent, &signature, &revoked, &fixture.authority),
        Err(FleetIngressV2Error::Identity(
            FleetIdentityError::RevokedKey { .. }
        ))
    ));
    assert_eq!(state_image(&state), before);

    // A healthy peer's first sequence remains admissible under the updated
    // authority; rejection did not turn into a global replay/health mutation.
    let heartbeat = fixture.heartbeat(1, 1);
    state
        .process_heartbeat(
            &heartbeat,
            &fixture.signers[1]
                .sign_detached_message_v2(&heartbeat)
                .unwrap(),
            &revoked,
            &fixture.authority,
        )
        .unwrap();
    assert_eq!(state.state().health.known_node_count(), 1);
    assert!(state.state().pending_intents.is_empty());
}

#[test]
fn globally_conflicting_intent_identity_is_rejected_before_it_can_block_checkpoints() {
    let fixture = FleetFixture::new(1);
    let mut state = fixture.populated_state(0);
    let quorum = FleetCheckpointQuorumV2::new(fixture.electorate(), 500_000).unwrap();
    let before = state_image(&state);
    let mut conflicting = fixture.intent(0, 4);
    conflicting.intent_id = state.state().pending_intents["extension-a"][0]
        .intent_id
        .clone();
    conflicting.extension_id = "extension-b".to_string();
    assert!(matches!(
        state.process_intent(
            &conflicting,
            &fixture.signers[0]
                .sign_detached_message_v2(&conflicting)
                .unwrap(),
            &fixture.registry,
            &fixture.authority,
        ),
        Err(FleetIngressV2Error::Protocol(
            ProtocolError::DuplicateIntentId { .. }
        ))
    ));
    assert_eq!(state_image(&state), before);
    assert!(state.draft_checkpoint_v2(100, &quorum).is_ok());

    // The refused message did not consume sequence 4, so a repaired intent
    // can be admitted without fabricating a gap in the sender's frontier.
    conflicting.intent_id = "different-intent".to_string();
    state
        .process_intent(
            &conflicting,
            &fixture.signers[0]
                .sign_detached_message_v2(&conflicting)
                .unwrap(),
            &fixture.registry,
            &fixture.authority,
        )
        .unwrap();
    assert!(state.draft_checkpoint_v2(100, &quorum).is_ok());
}

fn collect_votes(
    fixture: &FleetFixture,
    draft: &mut FleetCheckpointDraftV2,
    quorum: &FleetCheckpointQuorumV2,
    voter_indices: &[usize],
) {
    for &index in voter_indices {
        let mut peer = fixture.populated_state(index);
        let signature = peer
            .sign_checkpoint_v2(
                draft,
                quorum,
                &fixture.signers[index],
                &fixture.registry,
                &fixture.authority,
            )
            .unwrap();
        draft
            .add_signature(signature, &fixture.registry, &fixture.authority)
            .unwrap();
    }
}

#[test]
fn even_electorate_needs_a_strict_majority_and_finalization_is_once_only() {
    let fixture = FleetFixture::new(4);
    let quorum = FleetCheckpointQuorumV2::new(fixture.electorate(), 500_000).unwrap();
    assert_eq!(quorum.required_signatures(), 3);
    let mut proposer = fixture.populated_state(0);
    let before = state_image(&proposer);
    let mut draft = proposer.draft_checkpoint_v2(100, &quorum).unwrap();
    collect_votes(&fixture, &mut draft, &quorum, &[0, 1]);
    assert!(matches!(
        proposer.finalize_checkpoint_v2(
            &draft,
            &quorum,
            100,
            &fixture.registry,
            &fixture.authority,
        ),
        Err(FleetCheckpointV2Error::InsufficientQuorum {
            required: 3,
            actual: 2
        })
    ));
    assert_eq!(state_image(&proposer), before);

    let duplicate = draft.signatures().values().next().unwrap().clone();
    let signatures = draft.signatures().clone();
    assert!(matches!(
        draft.add_signature(duplicate, &fixture.registry, &fixture.authority),
        Err(FleetCheckpointV2Error::DuplicateSigner { .. })
    ));
    assert_eq!(draft.signatures(), &signatures);
    collect_votes(&fixture, &mut draft, &quorum, &[2]);

    let signed = proposer
        .finalize_checkpoint_v2(&draft, &quorum, 100, &fixture.registry, &fixture.authority)
        .unwrap();
    assert_eq!(signed.checkpoint.checkpoint_seq, 1);
    assert_eq!(signed.checkpoint.containment_decisions.len(), 1);
    assert_eq!(
        signed.checkpoint.containment_decisions[0].resolved_action,
        ContainmentAction::Quarantine
    );
    assert!(proposer.state().pending_intents.is_empty());
    assert_eq!(proposer.state().last_checkpoint_seq, 1);
    let restored: SignedFleetCheckpointV2 =
        serde_json::from_slice(&serde_json::to_vec(&signed).unwrap()).unwrap();
    restored
        .verify(
            &quorum,
            &fixture.registry,
            fixture.epoch,
            &fixture.authority,
        )
        .unwrap();
    let after = state_image(&proposer);
    assert!(matches!(
        proposer.finalize_checkpoint_v2(
            &draft,
            &quorum,
            100,
            &fixture.registry,
            &fixture.authority,
        ),
        Err(FleetCheckpointV2Error::StaleDraft)
    ));
    assert_eq!(state_image(&proposer), after);
    let next = proposer.draft_checkpoint_v2(100, &quorum).unwrap();
    assert_eq!(next.checkpoint().checkpoint_seq, 2);
    assert!(next.checkpoint().containment_decisions.is_empty());
}

#[test]
fn proposer_cannot_shrink_a_peers_or_verifiers_independent_electorate() {
    let fixture = FleetFixture::new(4);
    let full = FleetCheckpointQuorumV2::new(fixture.electorate(), 500_000).unwrap();
    let minority = FleetCheckpointQuorumV2::new(
        fixture
            .signers
            .iter()
            .take(2)
            .map(|signer| signer.identity().signer.clone())
            .collect(),
        500_000,
    )
    .unwrap();
    let mut proposer = fixture.populated_state(0);
    let mut honest_peer = fixture.populated_state(1);
    let mut draft = proposer.draft_checkpoint_v2(100, &minority).unwrap();
    assert!(matches!(
        honest_peer.sign_checkpoint_v2(
            &draft,
            &full,
            &fixture.signers[1],
            &fixture.registry,
            &fixture.authority,
        ),
        Err(FleetCheckpointV2Error::CheckpointMismatch)
    ));

    // Two compromised nodes can legitimately sign a two-node payload with
    // their own keys. Those valid signatures must still not authorize a
    // checkpoint for the independently configured four-node electorate.
    for signer in fixture.signers.iter().take(2) {
        draft
            .add_signature(
                signer.sign_detached_message_v2(draft.checkpoint()).unwrap(),
                &fixture.registry,
                &fixture.authority,
            )
            .unwrap();
    }
    let before = state_image(&proposer);
    assert!(matches!(
        proposer.finalize_checkpoint_v2(&draft, &full, 100, &fixture.registry, &fixture.authority,),
        Err(FleetCheckpointV2Error::StaleDraft)
    ));
    assert_eq!(state_image(&proposer), before);
    let minority_checkpoint = SignedFleetCheckpointV2 {
        checkpoint: draft.checkpoint().clone(),
        signatures: draft.signatures().clone(),
    };
    minority_checkpoint
        .verify(
            &minority,
            &fixture.registry,
            fixture.epoch,
            &fixture.authority,
        )
        .unwrap();
    assert!(matches!(
        minority_checkpoint.verify(&full, &fixture.registry, fixture.epoch, &fixture.authority),
        Err(FleetCheckpointV2Error::CheckpointMismatch)
    ));
}

#[test]
fn evidence_arriving_after_signatures_requires_a_new_draft_without_losing_intents() {
    let fixture = FleetFixture::new(3);
    let quorum = FleetCheckpointQuorumV2::new(fixture.electorate(), 500_000).unwrap();
    let mut proposer = fixture.populated_state(0);
    let mut draft = proposer.draft_checkpoint_v2(100, &quorum).unwrap();
    collect_votes(&fixture, &mut draft, &quorum, &[0, 1]);
    let evidence = fixture.evidence(0, 4);
    proposer
        .process_evidence(
            &evidence,
            &fixture.signers[0]
                .sign_detached_message_v2(&evidence)
                .unwrap(),
            &fixture.registry,
            &fixture.authority,
        )
        .unwrap();
    let before = state_image(&proposer);
    assert!(matches!(
        proposer.finalize_checkpoint_v2(
            &draft,
            &quorum,
            100,
            &fixture.registry,
            &fixture.authority,
        ),
        Err(FleetCheckpointV2Error::StaleDraft)
    ));
    assert_eq!(state_image(&proposer), before);
    assert_eq!(
        proposer.state().evidence.posterior_delta("extension-a"),
        800_000
    );
    assert_eq!(proposer.state().pending_intents["extension-a"].len(), 1);
    let mut replacement = proposer.draft_checkpoint_v2(100, &quorum).unwrap();
    assert!(
        replacement
            .add_signature(
                draft.signatures().values().next().unwrap().clone(),
                &fixture.registry,
                &fixture.authority,
            )
            .is_err()
    );
    assert!(replacement.signatures().is_empty());
}

#[test]
fn epoch_rollover_invalidates_old_intents_and_preserves_evidence_and_replay_frontiers() {
    let fixture = FleetFixture::new(3);
    let quorum = FleetCheckpointQuorumV2::new(fixture.electorate(), 500_000).unwrap();
    let mut proposer = fixture.populated_state(0);
    let mut draft = proposer.draft_checkpoint_v2(100, &quorum).unwrap();
    collect_votes(&fixture, &mut draft, &quorum, &[0, 1]);
    let original = state_image(&proposer);
    proposer.advance_epoch(fixture.epoch).unwrap();
    assert_eq!(
        state_image(&proposer),
        original,
        "same-epoch advance is inert"
    );
    let evidence_hash = proposer.state().evidence.summary_hash();
    proposer.advance_epoch(SecurityEpoch::from_raw(5)).unwrap();
    assert!(proposer.state().pending_intents.is_empty());
    assert_eq!(proposer.state().evidence.summary_hash(), evidence_hash);
    assert_eq!(
        proposer
            .state()
            .sequence_tracker
            .last_sequence(&fixture.signers[0].identity().signer),
        3
    );
    let before = state_image(&proposer);
    assert!(matches!(
        proposer.finalize_checkpoint_v2(
            &draft,
            &quorum,
            100,
            &fixture.registry,
            &fixture.authority,
        ),
        Err(FleetCheckpointV2Error::StaleDraft)
    ));
    assert_eq!(state_image(&proposer), before);
    let new_draft = proposer.draft_checkpoint_v2(100, &quorum).unwrap();
    assert!(new_draft.checkpoint().containment_decisions.is_empty());
    assert_eq!(new_draft.checkpoint().epoch, SecurityEpoch::from_raw(5));

    let mut intent = fixture.intent(0, 4);
    intent.intent_id = fixture.intent(0, 3).intent_id;
    assert!(matches!(
        proposer.process_intent(
            &intent,
            &fixture.signers[0]
                .sign_detached_message_v2(&intent)
                .unwrap(),
            &fixture.registry,
            &fixture.authority,
        ),
        Err(FleetIngressV2Error::Identity(
            FleetIdentityError::UntrustedMessageEpoch { .. }
        ))
    ));
    assert_eq!(state_image(&proposer), before);
    intent.epoch = SecurityEpoch::from_raw(5);
    proposer
        .process_intent(
            &intent,
            &fixture.signers[0]
                .sign_detached_message_v2(&intent)
                .unwrap(),
            &fixture.registry,
            &fixture.authority,
        )
        .unwrap();
    assert_eq!(
        proposer.state().pending_intents["extension-a"][0].epoch,
        intent.epoch
    );
    let after = state_image(&proposer);
    assert!(matches!(
        proposer.advance_epoch(fixture.epoch),
        Err(FleetIdentityError::AuthorityEpochRegression { .. })
    ));
    assert_eq!(state_image(&proposer), after);
}

#[test]
fn future_heartbeat_cannot_veto_a_healthy_majority_or_lower_the_quorum() {
    let fixture = FleetFixture::new(4);
    let quorum = FleetCheckpointQuorumV2::new(fixture.electorate(), 500_000).unwrap();
    let mut proposer = fixture.populated_state(0);
    let mut future = fixture.heartbeat(3, 2);
    future.timestamp_ns = u64::MAX;
    proposer
        .process_heartbeat(
            &future,
            &fixture.signers[3]
                .sign_detached_message_v2(&future)
                .unwrap(),
            &fixture.registry,
            &fixture.authority,
        )
        .unwrap();
    let draft = proposer.draft_checkpoint_v2(100, &quorum).unwrap();
    assert_eq!(draft.checkpoint().participating_nodes.len(), 3);
    assert!(
        !draft
            .checkpoint()
            .participating_nodes
            .contains(&fixture.signers[3].identity().signer)
    );
    assert_eq!(quorum.required_signatures(), 3);
    assert!(
        draft
            .checkpoint()
            .participating_nodes
            .contains(&fixture.signers[0].identity().signer)
    );

    future.node_id = fixture.signers[2].identity().signer.clone();
    future.signature = legacy_marker(future.node_id.clone());
    proposer
        .process_heartbeat(
            &future,
            &fixture.signers[2]
                .sign_detached_message_v2(&future)
                .unwrap(),
            &fixture.registry,
            &fixture.authority,
        )
        .unwrap();
    assert!(matches!(
        proposer.draft_checkpoint_v2(100, &quorum),
        Err(FleetCheckpointV2Error::InsufficientQuorum {
            required: 3,
            actual: 2
        })
    ));
}

#[test]
fn cosigners_compare_evidence_identity_even_when_posterior_summaries_agree() {
    let fixture = FleetFixture::new(2);
    let quorum = FleetCheckpointQuorumV2::new(fixture.electorate(), 500_000).unwrap();
    let proposer = fixture.populated_state(0);
    let mut peer = fixture.state(1);
    for (index, signer) in fixture.signers.iter().enumerate() {
        let heartbeat = fixture.heartbeat(index, 1);
        peer.process_heartbeat(
            &heartbeat,
            &signer.sign_detached_message_v2(&heartbeat).unwrap(),
            &fixture.registry,
            &fixture.authority,
        )
        .unwrap();
    }
    let mut evidence = fixture.evidence(0, 2);
    evidence.evidence_hash = ContentHash::compute(b"different signed observation, identical delta");
    peer.process_evidence(
        &evidence,
        &fixture.signers[0]
            .sign_detached_message_v2(&evidence)
            .unwrap(),
        &fixture.registry,
        &fixture.authority,
    )
    .unwrap();
    let intent = fixture.intent(0, 3);
    peer.process_intent(
        &intent,
        &fixture.signers[0]
            .sign_detached_message_v2(&intent)
            .unwrap(),
        &fixture.registry,
        &fixture.authority,
    )
    .unwrap();
    assert_eq!(
        proposer.state().evidence.summary_hash(),
        peer.state().evidence.summary_hash(),
        "this is an equal-aggregate substitution, not a different-risk control"
    );
    let draft = proposer.draft_checkpoint_v2(100, &quorum).unwrap();
    assert!(matches!(
        peer.sign_checkpoint_v2(
            &draft,
            &quorum,
            &fixture.signers[1],
            &fixture.registry,
            &fixture.authority,
        ),
        Err(FleetCheckpointV2Error::CheckpointMismatch)
    ));
}

#[test]
fn different_arrival_orders_of_independent_nodes_produce_the_same_checkpoint() {
    let fixture = FleetFixture::new(3);
    let quorum = FleetCheckpointQuorumV2::new(fixture.electorate(), 500_000).unwrap();
    let mut proposer = fixture.populated_state(0);
    let mut peer = fixture.populated_state(1);
    for (state, order) in [(&mut proposer, [1, 2]), (&mut peer, [2, 1])] {
        for index in order {
            let intent = fixture.intent(index, 2);
            state
                .process_intent(
                    &intent,
                    &fixture.signers[index]
                        .sign_detached_message_v2(&intent)
                        .unwrap(),
                    &fixture.registry,
                    &fixture.authority,
                )
                .unwrap();
            let evidence = fixture.evidence(index, 3);
            state
                .process_evidence(
                    &evidence,
                    &fixture.signers[index]
                        .sign_detached_message_v2(&evidence)
                        .unwrap(),
                    &fixture.registry,
                    &fixture.authority,
                )
                .unwrap();
        }
    }
    let draft = proposer.draft_checkpoint_v2(100, &quorum).unwrap();
    let peer_draft = peer.draft_checkpoint_v2(100, &quorum).unwrap();
    assert_eq!(draft.checkpoint(), peer_draft.checkpoint());
    peer.sign_checkpoint_v2(
        &draft,
        &quorum,
        &fixture.signers[1],
        &fixture.registry,
        &fixture.authority,
    )
    .unwrap();
}

#[test]
fn revoked_vote_and_stale_anchor_cannot_consume_pending_intents() {
    let mut fixture = FleetFixture::new(3);
    let quorum = FleetCheckpointQuorumV2::new(fixture.electorate(), 500_000).unwrap();
    let mut proposer = fixture.populated_state(0);
    let mut draft = proposer.draft_checkpoint_v2(100, &quorum).unwrap();
    collect_votes(&fixture, &mut draft, &quorum, &[0, 1]);
    let revoked = FleetVerificationRegistryPersistence::new(&mut fixture.storage, &fixture.context)
        .prepare_revocation(
            &fixture.registry,
            fixture.signers[1].identity().signer.clone(),
            1,
            fixture.epoch,
            fixture.epoch,
            FleetRevocationPolicy::Retroactive,
            &fixture.authority,
        )
        .unwrap()
        .finalize_and_publish(&fixture.authority)
        .unwrap();
    let before = state_image(&proposer);
    assert!(matches!(
        proposer.finalize_checkpoint_v2(
            &draft,
            &quorum,
            100,
            &fixture.registry,
            &fixture.authority,
        ),
        Err(FleetCheckpointV2Error::Identity(
            FleetIdentityError::UnverifiedRegistryAnchor { .. }
        ))
    ));
    assert!(matches!(
        proposer.finalize_checkpoint_v2(&draft, &quorum, 100, &revoked, &fixture.authority,),
        Err(FleetCheckpointV2Error::Identity(
            FleetIdentityError::RevokedKey { .. }
        ))
    ));
    assert_eq!(state_image(&proposer), before);

    let mut replacement = proposer.draft_checkpoint_v2(100, &quorum).unwrap();
    for index in [0, 2] {
        // These peers already hold the observations admitted before key 1 was
        // revoked. Revocation changes voting authority, not stored history.
        let signature = fixture.signers[index]
            .sign_detached_message_v2(replacement.checkpoint())
            .unwrap();
        replacement
            .add_signature(signature, &revoked, &fixture.authority)
            .unwrap();
    }
    proposer
        .finalize_checkpoint_v2(&replacement, &quorum, 100, &revoked, &fixture.authority)
        .unwrap();
    assert_eq!(proposer.state().last_checkpoint_seq, 1);
    assert!(proposer.state().pending_intents.is_empty());
}

#[test]
fn repeat_vote_is_idempotent_and_a_new_view_waits_for_the_next_checkpoint() {
    let fixture = FleetFixture::new(1);
    let quorum = FleetCheckpointQuorumV2::new(fixture.electorate(), 500_000).unwrap();
    let signer = &fixture.signers[0];
    let mut state = fixture.populated_state(0);
    let mut first = state.draft_checkpoint_v2(100, &quorum).unwrap();
    let signature = state
        .sign_checkpoint_v2(
            &first,
            &quorum,
            signer,
            &fixture.registry,
            &fixture.authority,
        )
        .unwrap();
    assert_eq!(
        state
            .sign_checkpoint_v2(
                &first,
                &quorum,
                signer,
                &fixture.registry,
                &fixture.authority
            )
            .unwrap(),
        signature
    );
    first
        .add_signature(signature.clone(), &fixture.registry, &fixture.authority)
        .unwrap();

    // Input arriving after a vote belongs to the next checkpoint. It must not
    // permit a second vote in this round or disappear when the first completes.
    let evidence = fixture.evidence(0, 4);
    state
        .process_evidence(
            &evidence,
            &signer.sign_detached_message_v2(&evidence).unwrap(),
            &fixture.registry,
            &fixture.authority,
        )
        .unwrap();
    let intent = fixture.intent(0, 5);
    state
        .process_intent(
            &intent,
            &signer.sign_detached_message_v2(&intent).unwrap(),
            &fixture.registry,
            &fixture.authority,
        )
        .unwrap();
    // A lost vote response can be retried even after later input arrived.
    assert_eq!(
        state
            .sign_checkpoint_v2(
                &first,
                &quorum,
                signer,
                &fixture.registry,
                &fixture.authority,
            )
            .unwrap(),
        signature,
    );
    let different = state.draft_checkpoint_v2(100, &quorum).unwrap();
    assert_ne!(first.checkpoint(), different.checkpoint());
    let before = state_image(&state);
    assert!(matches!(
        state.sign_checkpoint_v2(
            &different,
            &quorum,
            signer,
            &fixture.registry,
            &fixture.authority,
        ),
        Err(FleetCheckpointV2Error::ConflictingVote { epoch, sequence: 1 })
            if epoch == fixture.epoch
    ));
    assert_eq!(state_image(&state), before);

    state
        .finalize_checkpoint_v2(&first, &quorum, 100, &fixture.registry, &fixture.authority)
        .unwrap();
    assert_eq!(state.state().last_checkpoint_seq, 1);
    assert_eq!(
        state.state().evidence.posterior_delta("extension-a"),
        800_000
    );
    let remaining = &state.state().pending_intents["extension-a"];
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].intent_id, intent.intent_id);
    assert_eq!(
        state
            .state()
            .sequence_tracker
            .last_sequence(&signer.identity().signer),
        5
    );
    let next = state.draft_checkpoint_v2(100, &quorum).unwrap();
    assert_eq!(next.checkpoint().checkpoint_seq, 2);
    assert_eq!(
        next.checkpoint().containment_decisions[0].contributing_intent_ids,
        vec![intent.intent_id]
    );
    state
        .sign_checkpoint_v2(
            &next,
            &quorum,
            signer,
            &fixture.registry,
            &fixture.authority,
        )
        .unwrap();
}

#[test]
fn signed_evidence_sums_are_order_independent_across_i64_projection_overflow() {
    let fixture = FleetFixture::new(3);
    let quorum = FleetCheckpointQuorumV2::new(fixture.electorate(), 500_000).unwrap();
    let packets = [i64::MAX, 1, -1]
        .into_iter()
        .enumerate()
        .map(|(node, delta)| {
            let mut packet = fixture.evidence(node, 2);
            packet.posterior_delta_millionths = delta;
            let signature = fixture.signers[node]
                .sign_detached_message_v2(&packet)
                .unwrap();
            (packet, signature)
        })
        .collect::<Vec<_>>();
    let orders = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let mut expected_checkpoint = None;
    for order in orders {
        let mut state = fixture.state(0);
        for (node, signer) in fixture.signers.iter().enumerate() {
            let heartbeat = fixture.heartbeat(node, 1);
            state
                .process_heartbeat(
                    &heartbeat,
                    &signer.sign_detached_message_v2(&heartbeat).unwrap(),
                    &fixture.registry,
                    &fixture.authority,
                )
                .unwrap();
        }
        for index in order {
            let (packet, signature) = &packets[index];
            state
                .process_evidence(packet, signature, &fixture.registry, &fixture.authority)
                .unwrap();
        }
        assert_eq!(
            state.state().evidence.posterior_delta("extension-a"),
            i64::MAX,
            "{order:?}"
        );
        let draft = state.draft_checkpoint_v2(100, &quorum).unwrap();
        if let Some(expected) = &expected_checkpoint {
            assert_eq!(draft.checkpoint(), expected, "{order:?}");
        } else {
            expected_checkpoint = Some(draft.checkpoint().clone());
        }
        state
            .sign_checkpoint_v2(
                &draft,
                &quorum,
                &fixture.signers[0],
                &fixture.registry,
                &fixture.authority,
            )
            .unwrap();
    }
}

#[test]
fn pending_intent_backpressure_releases_capacity_without_consuming_rejected_sequences() {
    let fixture = FleetFixture::new(1);
    let quorum = FleetCheckpointQuorumV2::new(fixture.electorate(), 500_000).unwrap();
    let signer = &fixture.signers[0];
    let extension_bytes = fixture.intent(0, 2).extension_id.len();
    let cases = [
        (
            FLEET_V2_MAX_PENDING_INTENTS,
            32,
            "pending_intents",
            FLEET_V2_MAX_PENDING_INTENTS,
        ),
        (
            (FLEET_V2_MAX_PENDING_INTENT_BYTES - extension_bytes) / FLEET_V2_MAX_IDENTIFIER_BYTES,
            FLEET_V2_MAX_IDENTIFIER_BYTES,
            "checkpoint_intent_bytes",
            FLEET_V2_MAX_PENDING_INTENT_BYTES,
        ),
    ];
    for (accepted_count, identifier_bytes, resource_name, expected_limit) in cases {
        let mut state = fixture.state(0);
        let heartbeat = fixture.heartbeat(0, 1);
        state
            .process_heartbeat(
                &heartbeat,
                &signer.sign_detached_message_v2(&heartbeat).unwrap(),
                &fixture.registry,
                &fixture.authority,
            )
            .unwrap();
        let make_intent = |index: usize| {
            let mut intent = fixture.intent(0, index as u64 + 2);
            intent.intent_id = format!("{index:04}{}", "i".repeat(identifier_bytes - 4));
            intent
        };
        for index in 0..accepted_count {
            let intent = make_intent(index);
            state
                .process_intent(
                    &intent,
                    &signer.sign_detached_message_v2(&intent).unwrap(),
                    &fixture.registry,
                    &fixture.authority,
                )
                .unwrap();
        }
        let rejected = make_intent(accepted_count);
        let rejected_signature = signer.sign_detached_message_v2(&rejected).unwrap();
        let before = state_image(&state);
        assert!(matches!(
            state.process_intent(
                &rejected,
                &rejected_signature,
                &fixture.registry,
                &fixture.authority,
            ),
            Err(FleetIngressV2Error::Protocol(ProtocolError::PendingIntentCapacityExceeded {
                resource,
                limit,
                actual,
            })) if resource == resource_name && limit == expected_limit && actual > limit
        ));
        assert_eq!(state_image(&state), before, "{resource_name}");
        assert_eq!(
            state.state().pending_intents["extension-a"].len(),
            accepted_count
        );
        assert_eq!(
            state
                .state()
                .sequence_tracker
                .last_sequence(&signer.identity().signer),
            rejected.sequence - 1
        );
        let mut draft = state.draft_checkpoint_v2(100, &quorum).unwrap();
        let signature = state
            .sign_checkpoint_v2(
                &draft,
                &quorum,
                signer,
                &fixture.registry,
                &fixture.authority,
            )
            .unwrap();
        draft
            .add_signature(signature, &fixture.registry, &fixture.authority)
            .unwrap();
        state
            .finalize_checkpoint_v2(&draft, &quorum, 100, &fixture.registry, &fixture.authority)
            .unwrap();
        assert!(state.state().pending_intents.is_empty());
        state
            .process_intent(
                &rejected,
                &rejected_signature,
                &fixture.registry,
                &fixture.authority,
            )
            .unwrap();
        assert_eq!(state.state().pending_intents["extension-a"].len(), 1);
        assert_eq!(
            state
                .state()
                .sequence_tracker
                .last_sequence(&signer.identity().signer),
            rejected.sequence
        );
        assert!(state.draft_checkpoint_v2(100, &quorum).is_ok());
    }
}

#[test]
fn every_checkpoint_payload_and_signature_identity_change_is_detected() {
    let fixture = FleetFixture::new(3);
    let quorum = FleetCheckpointQuorumV2::new(fixture.electorate(), 500_000).unwrap();
    let mut proposer = fixture.populated_state(0);
    let mut draft = proposer.draft_checkpoint_v2(100, &quorum).unwrap();
    collect_votes(&fixture, &mut draft, &quorum, &[0, 1]);
    let signed = proposer
        .finalize_checkpoint_v2(&draft, &quorum, 100, &fixture.registry, &fixture.authority)
        .unwrap();
    signed
        .verify(
            &quorum,
            &fixture.registry,
            fixture.epoch,
            &fixture.authority,
        )
        .unwrap();

    type Mutation = (&'static str, fn(&mut SignedFleetCheckpointV2));
    let mutations: &[Mutation] = &[
        ("checkpoint sequence", |value| {
            value.checkpoint.checkpoint_seq += 1
        }),
        ("security epoch", |value| {
            value.checkpoint.epoch = SecurityEpoch::from_raw(5)
        }),
        ("evidence summary", |value| {
            value.checkpoint.evidence_summary_hash = ContentHash::compute(b"forged")
        }),
        ("participating nodes", |value| {
            value.checkpoint.participating_nodes.pop_last();
        }),
        ("containment action", |value| {
            value.checkpoint.containment_decisions[0].resolved_action = ContainmentAction::Allow
        }),
        ("intent provenance", |value| {
            value.checkpoint.containment_decisions[0].contributing_intent_ids =
                vec!["forged-intent".to_string()]
        }),
        ("timestamp", |value| value.checkpoint.timestamp_ns += 1),
        ("protocol version", |value| {
            value.checkpoint.protocol_version = ProtocolVersion::V1
        }),
        ("signed extensions", |value| {
            value
                .checkpoint
                .extensions
                .insert("attacker-added".to_string(), "unauthorized".to_string());
        }),
        ("legacy signature map", |value| {
            value
                .checkpoint
                .quorum_signatures
                .insert(NodeId::new("node-0"), legacy_marker(NodeId::new("node-0")));
        }),
        ("signature count", |value| {
            value.signatures.pop_last();
        }),
        ("signature map key", |value| {
            let (_, signature) = value.signatures.pop_last().unwrap();
            value.signatures.insert(NodeId::new("node-2"), signature);
        }),
        ("signing key sequence", |value| {
            value.signatures.values_mut().next().unwrap().key_sequence += 1
        }),
    ];
    for (name, mutate) in mutations {
        let mut forged = signed.clone();
        mutate(&mut forged);
        assert!(
            forged
                .verify(
                    &quorum,
                    &fixture.registry,
                    fixture.epoch,
                    &fixture.authority
                )
                .is_err(),
            "unverified mutation accepted: {name}"
        );
    }
}
