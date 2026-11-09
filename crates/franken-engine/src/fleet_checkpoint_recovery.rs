//! Recoverable fleet votes and checkpoints, anchored outside the database's
//! rollback domain. Ingress is volatile until an explicit flush, vote,
//! checkpoint finalization, or epoch transition commits the complete state.
//!
//! A signature is released only after its vote and frozen proposal are stored
//! and the independent node-state anchor has advanced. An uncertain write or
//! anchor response disables the controller until recovery reconciles the row.

use std::collections::BTreeSet;
use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::fleet_checkpoint_store::{
    FLEET_CHECKPOINT_MAX_ANCHOR_PERMIT_BYTES, FLEET_CHECKPOINT_MAX_SNAPSHOT_BYTES,
    FleetCheckpointStore, FleetCheckpointStoreCasOutcome, FleetCheckpointStoreError,
    FleetCheckpointStoreHead, FleetCheckpointStoreRecord,
};
use crate::fleet_checkpoint_v2::{
    FleetCheckpointDraftV2, FleetCheckpointQuorumV2, FleetCheckpointV2Error,
    SignedFleetCheckpointV2,
};
use crate::fleet_immune_protocol::{
    AuthenticatedFleetProtocolStateV2, ContainmentIntent, DurableFleetVerificationRegistry,
    EvidencePacket, FleetAuthorityId, FleetIdentityError, FleetIngressV2Error,
    FleetProtocolRecoverySnapshotV2, FleetProtocolState, FleetRegistryAnchorAuthority,
    FleetSignatureV2, FleetSigner, GossipConfig, HeartbeatLiveness, NodeId, QuorumCheckpoint,
};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

/// Domain separation required of external node-state anchor implementations.
pub const FLEET_CHECKPOINT_ANCHOR_DOMAIN: &str = "frankenengine.fleet-checkpoint-state.v1";

/// Leave room for both the frozen proposal and latest quorum certificate.
/// Their bounded identifiers, collections, hashes, and detached signatures fit
/// below this reserve even with maximal JSON escaping. Admission accounts for
/// the base state separately so reaching capacity cannot prevent checkpointing.
pub const FLEET_CHECKPOINT_ADMISSION_BUDGET_BYTES: usize =
    FLEET_CHECKPOINT_MAX_SNAPSHOT_BYTES - 2 * 1024 * 1024;

/// An untrusted claim until authenticated by the independently provisioned
/// authority. The database revision is independent of the registry generation
/// and of the network checkpoint sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetCheckpointAnchorClaim {
    pub fleet_authority_id: FleetAuthorityId,
    pub node_id: NodeId,
    pub revision: u64,
    pub state_hash: ContentHash,
    pub prior_state_hash: ContentHash,
}

impl FleetCheckpointAnchorClaim {
    pub fn head(&self) -> FleetCheckpointStoreHead {
        FleetCheckpointStoreHead {
            fleet_authority_id: self.fleet_authority_id,
            node_id: self.node_id.clone(),
            revision: self.revision,
            state_hash: self.state_hash,
        }
    }

    fn from_record(record: &FleetCheckpointStoreRecord) -> Self {
        Self {
            fleet_authority_id: record.fleet_authority_id,
            node_id: record.node_id.clone(),
            revision: record.revision,
            state_hash: record.state_hash,
            prior_state_hash: record.prior_state_hash,
        }
    }
}

/// A separate trust boundary from the verification-key registry. Implementors
/// must retain their current head outside the checkpoint database's rollback
/// domain and authenticate permits over the domain and complete transition.
pub trait FleetCheckpointAnchorAuthority {
    fn fleet_authority_id(&self) -> FleetAuthorityId;
    fn node_id(&self) -> &NodeId;

    /// Authenticate this exact current head; cached acceptance is insufficient.
    fn authenticate_current_checkpoint_anchor(
        &self,
        claim: &FleetCheckpointAnchorClaim,
    ) -> Result<String, FleetCheckpointRecoveryError>;

    /// Issue an authenticated, idempotent permit without advancing the head.
    fn prepare_checkpoint_anchor_advance(
        &self,
        expected: Option<&FleetCheckpointAnchorClaim>,
        next: &FleetCheckpointAnchorClaim,
    ) -> Result<Vec<u8>, FleetCheckpointRecoveryError>;

    /// Authenticate the permit, compare its expected head, and advance. An
    /// exact already-finalized transition must succeed while next stays current.
    fn finalize_checkpoint_anchor_advance(
        &self,
        permit: &[u8],
        next: &FleetCheckpointAnchorClaim,
    ) -> Result<String, FleetCheckpointRecoveryError>;
}

/// Operator configuration supplied independently of persisted bytes.
#[derive(Debug, Clone)]
pub struct FleetCheckpointRecoveryConfig {
    pub fleet_authority_id: FleetAuthorityId,
    pub node_id: NodeId,
    pub gossip: GossipConfig,
    pub quorum: FleetCheckpointQuorumV2,
    pub minimum_epoch: SecurityEpoch,
}

impl FleetCheckpointRecoveryConfig {
    fn validate(&self) -> Result<(), FleetCheckpointRecoveryError> {
        if !self.quorum.electorate().contains(&self.node_id)
            || self.gossip.quorum_threshold_millionths != self.quorum.threshold_millionths()
        {
            return Err(invalid_snapshot(
                "provisioned node or threshold disagrees with electorate",
            ));
        }
        AuthenticatedFleetProtocolStateV2::new(
            self.fleet_authority_id,
            self.node_id.clone(),
            self.gossip.clone(),
            self.minimum_epoch,
        )?;
        Ok(())
    }
}

/// Current key-registry trust and independent checkpoint durability trust.
pub struct FleetCheckpointRecoveryContext<'a, R, A> {
    pub registry: &'a DurableFleetVerificationRegistry,
    pub registry_authority: &'a R,
    pub checkpoint_authority: &'a A,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverySnapshot {
    schema_version: u32,
    electorate: BTreeSet<NodeId>,
    threshold_millionths: u64,
    protocol: FleetProtocolRecoverySnapshotV2,
    reserved_checkpoint: Option<QuorumCheckpoint>,
    last_finalized_checkpoint: Option<SignedFleetCheckpointV2>,
}

/// Non-cloneable controller for one durable node. It exposes no mutable state
/// or unanchored deserializer. Callers must retransmit ingress accepted after
/// the last durable boundary if the process is lost before its next boundary.
#[derive(Debug)]
pub struct DurableFleetCheckpointStateV2 {
    config: FleetCheckpointRecoveryConfig,
    state: AuthenticatedFleetProtocolStateV2,
    claim: FleetCheckpointAnchorClaim,
    reserved_checkpoint: Option<QuorumCheckpoint>,
    last_finalized_checkpoint: Option<SignedFleetCheckpointV2>,
    admission_budget_bytes: usize,
    requires_recovery: bool,
}

impl DurableFleetCheckpointStateV2 {
    pub fn create<S: FleetCheckpointStore, A: FleetCheckpointAnchorAuthority>(
        config: FleetCheckpointRecoveryConfig,
        store: &mut S,
        authority: &A,
    ) -> Result<Self, FleetCheckpointRecoveryError> {
        config.validate()?;
        check_namespace(&config, authority)?;
        let state = AuthenticatedFleetProtocolStateV2::new(
            config.fleet_authority_id,
            config.node_id.clone(),
            config.gossip.clone(),
            config.minimum_epoch,
        )?;
        let snapshot_json = encode_snapshot(&config, &state, None, None)?;
        let admission_budget_bytes =
            check_admission_budget(admission_base_bytes(&config, &state)?)?;
        let record = prepare_record(&config, None, snapshot_json, authority)?;
        commit_record(store, &record, None)?;
        let claim = finalize_anchor(&record, authority)?;
        Ok(Self {
            config,
            state,
            claim,
            reserved_checkpoint: None,
            last_finalized_checkpoint: None,
            admission_budget_bytes,
            requires_recovery: false,
        })
    }

    /// Recover a committed candidate, including a vote whose response was
    /// lost or whose external-anchor finalization was interrupted by a crash.
    pub fn restore<S: FleetCheckpointStore, A: FleetCheckpointAnchorAuthority>(
        config: FleetCheckpointRecoveryConfig,
        store: &mut S,
        authority: &A,
    ) -> Result<Self, FleetCheckpointRecoveryError> {
        config.validate()?;
        check_namespace(&config, authority)?;
        let record = store
            .load()?
            .ok_or(FleetCheckpointRecoveryError::MissingState)?;
        record.validate()?;
        if record.fleet_authority_id != config.fleet_authority_id
            || record.node_id != config.node_id
        {
            return Err(invalid_snapshot(
                "stored fleet or node does not match provisioned identity",
            ));
        }
        let snapshot: RecoverySnapshot = serde_json::from_str(&record.snapshot_json)
            .map_err(|error| invalid_snapshot(&format!("snapshot decoding failed: {error}")))?;
        if snapshot.schema_version != 1
            || snapshot.electorate != *config.quorum.electorate()
            || snapshot.threshold_millionths != config.quorum.threshold_millionths()
            || encode_bounded(&snapshot)? != record.snapshot_json
        {
            return Err(invalid_snapshot(
                "snapshot schema, electorate, or canonical encoding differs",
            ));
        }
        let state = AuthenticatedFleetProtocolStateV2::restore_checkpoint_snapshot(
            snapshot.protocol,
            config.fleet_authority_id,
            &config.node_id,
            &config.gossip,
        )
        .map_err(|detail| FleetCheckpointRecoveryError::InvalidSnapshot { detail })?;
        if state.state().current_epoch < config.minimum_epoch {
            return Err(invalid_snapshot(
                "snapshot precedes the independently trusted minimum epoch",
            ));
        }
        match (&snapshot.reserved_checkpoint, state.checkpoint_vote) {
            (Some(checkpoint), Some(_)) => {
                state.import_checkpoint_proposal_v2(checkpoint, &config.quorum)?;
            }
            (None, None) => {}
            _ => {
                return Err(invalid_snapshot(
                    "frozen proposal and reserved vote disagree",
                ));
            }
        }
        match &snapshot.last_finalized_checkpoint {
            Some(signed) => {
                config.quorum.validate_checkpoint(&signed.checkpoint)?;
                if signed.checkpoint.checkpoint_seq != state.state().last_checkpoint_seq
                    || signed.checkpoint.epoch > state.state().current_epoch
                    || signed.signatures.len() < config.quorum.required_signatures()
                    || signed.signatures.len() > signed.checkpoint.participating_nodes.len()
                    || signed.signatures.iter().any(|(node, signature)| {
                        node != &signature.signer
                            || !signed.checkpoint.participating_nodes.contains(node)
                            || signature.fleet_authority_id != config.fleet_authority_id
                    })
                {
                    return Err(invalid_snapshot(
                        "finalized certificate and recovered frontier disagree",
                    ));
                }
            }
            None if state.state().last_checkpoint_seq == 0 => {}
            None => {
                return Err(invalid_snapshot(
                    "checkpoint frontier has no persisted certificate",
                ));
            }
        }
        let admission_budget_bytes =
            check_admission_budget(admission_base_bytes(&config, &state)?)?;
        // Historical acceptance is authenticated by the node-state anchor,
        // not reinterpreted through today's possibly rotated verification key.
        // A prior write error may have left readable but unflushed bytes. A
        // successful fresh durable write must precede anchor advancement.
        store.confirm_durable(&record)?;
        let claim = finalize_anchor(&record, authority)?;
        if store.load()?.as_ref() != Some(&record) {
            return Err(FleetCheckpointRecoveryError::ConcurrentUpdate);
        }
        check_receipt(authority.authenticate_current_checkpoint_anchor(&claim)?)?;
        Ok(Self {
            config,
            state,
            claim,
            reserved_checkpoint: snapshot.reserved_checkpoint,
            last_finalized_checkpoint: snapshot.last_finalized_checkpoint,
            admission_budget_bytes,
            requires_recovery: false,
        })
    }

    pub fn recover<S: FleetCheckpointStore, A: FleetCheckpointAnchorAuthority>(
        &mut self,
        store: &mut S,
        authority: &A,
    ) -> Result<(), FleetCheckpointRecoveryError> {
        self.requires_recovery = true;
        let recovered = Self::restore(self.config.clone(), store, authority)?;
        *self = recovered;
        Ok(())
    }

    pub fn requires_recovery(&self) -> bool {
        self.requires_recovery
    }

    pub fn anchor_claim(&self) -> &FleetCheckpointAnchorClaim {
        &self.claim
    }

    pub fn state(&self) -> Result<&FleetProtocolState, FleetCheckpointRecoveryError> {
        self.ensure_available()?;
        Ok(self.state.state())
    }

    /// Historical local acceptance, not a proof that its voters remain current.
    pub fn last_finalized_checkpoint(
        &self,
    ) -> Result<Option<&SignedFleetCheckpointV2>, FleetCheckpointRecoveryError> {
        self.ensure_available()?;
        Ok(self.last_finalized_checkpoint.as_ref())
    }

    pub fn draft_checkpoint_v2(
        &self,
        timestamp_ns: u64,
    ) -> Result<FleetCheckpointDraftV2, FleetCheckpointRecoveryError> {
        self.ensure_available()?;
        Ok(self
            .state
            .draft_checkpoint_v2(timestamp_ns, &self.config.quorum)?)
    }

    /// Resume the exact frozen proposal after a restart. Co-signatures can be
    /// recollected; the local vote may only be repeated for this same payload.
    pub fn resumed_checkpoint_draft_v2(
        &self,
    ) -> Result<Option<FleetCheckpointDraftV2>, FleetCheckpointRecoveryError> {
        self.ensure_available()?;
        self.reserved_checkpoint
            .as_ref()
            .map(|checkpoint| {
                self.state
                    .import_checkpoint_proposal_v2(checkpoint, &self.config.quorum)
                    .map_err(FleetCheckpointRecoveryError::from)
            })
            .transpose()
    }

    pub fn process_evidence<R: FleetRegistryAnchorAuthority, A: FleetCheckpointAnchorAuthority>(
        &mut self,
        packet: &EvidencePacket,
        signature: &FleetSignatureV2,
        context: &FleetCheckpointRecoveryContext<'_, R, A>,
    ) -> Result<(), FleetCheckpointRecoveryError> {
        self.ensure_current(context.checkpoint_authority)?;
        let budget = self.admission_budget_after(
            AuthenticatedFleetProtocolStateV2::recovery_evidence_growth_bound(packet)?,
        )?;
        self.state.process_evidence(
            packet,
            signature,
            context.registry,
            context.registry_authority,
        )?;
        self.admission_budget_bytes = budget;
        Ok(())
    }

    pub fn process_intent<R: FleetRegistryAnchorAuthority, A: FleetCheckpointAnchorAuthority>(
        &mut self,
        intent: &ContainmentIntent,
        signature: &FleetSignatureV2,
        context: &FleetCheckpointRecoveryContext<'_, R, A>,
    ) -> Result<(), FleetCheckpointRecoveryError> {
        self.ensure_current(context.checkpoint_authority)?;
        let budget = self.admission_budget_after(
            AuthenticatedFleetProtocolStateV2::recovery_intent_growth_bound(intent)?,
        )?;
        self.state.process_intent(
            intent,
            signature,
            context.registry,
            context.registry_authority,
        )?;
        self.admission_budget_bytes = budget;
        Ok(())
    }

    pub fn process_heartbeat<R: FleetRegistryAnchorAuthority, A: FleetCheckpointAnchorAuthority>(
        &mut self,
        heartbeat: &HeartbeatLiveness,
        signature: &FleetSignatureV2,
        context: &FleetCheckpointRecoveryContext<'_, R, A>,
    ) -> Result<(), FleetCheckpointRecoveryError> {
        self.ensure_current(context.checkpoint_authority)?;
        let budget = self.admission_budget_after(
            AuthenticatedFleetProtocolStateV2::recovery_heartbeat_growth_bound(heartbeat)?,
        )?;
        self.state.process_heartbeat(
            heartbeat,
            signature,
            context.registry,
            context.registry_authority,
        )?;
        self.admission_budget_bytes = budget;
        Ok(())
    }

    pub fn flush<S: FleetCheckpointStore, A: FleetCheckpointAnchorAuthority>(
        &mut self,
        store: &mut S,
        authority: &A,
    ) -> Result<(), FleetCheckpointRecoveryError> {
        self.ensure_current(authority)?;
        let staged = self.state.stage_checkpoint_update();
        self.persist(
            staged,
            self.reserved_checkpoint.clone(),
            self.last_finalized_checkpoint.clone(),
            store,
            authority,
            || Ok(()),
        )
    }

    pub fn advance_epoch<S: FleetCheckpointStore, A: FleetCheckpointAnchorAuthority>(
        &mut self,
        epoch: SecurityEpoch,
        store: &mut S,
        authority: &A,
    ) -> Result<(), FleetCheckpointRecoveryError> {
        self.ensure_current(authority)?;
        let mut staged = self.state.stage_checkpoint_update();
        staged.advance_epoch(epoch)?;
        let reserved = if epoch > self.state.state().current_epoch {
            None
        } else {
            self.reserved_checkpoint.clone()
        };
        self.persist(
            staged,
            reserved,
            self.last_finalized_checkpoint.clone(),
            store,
            authority,
            || Ok(()),
        )
    }

    pub fn sign_checkpoint_v2<S, R, A>(
        &mut self,
        draft: &FleetCheckpointDraftV2,
        signer: &FleetSigner,
        store: &mut S,
        context: &FleetCheckpointRecoveryContext<'_, R, A>,
    ) -> Result<FleetSignatureV2, FleetCheckpointRecoveryError>
    where
        S: FleetCheckpointStore,
        R: FleetRegistryAnchorAuthority,
        A: FleetCheckpointAnchorAuthority,
    {
        self.ensure_current(context.checkpoint_authority)?;
        let mut staged = self.state.stage_checkpoint_update();
        let signature = staged.sign_checkpoint_v2(
            draft,
            &self.config.quorum,
            signer,
            context.registry,
            context.registry_authority,
        )?;
        self.persist(
            staged,
            Some(draft.checkpoint().clone()),
            self.last_finalized_checkpoint.clone(),
            store,
            context.checkpoint_authority,
            || {
                context
                    .registry
                    .active_identity(&signature.signer, context.registry_authority)?;
                Ok(())
            },
        )?;
        // Storage and external-anchor callbacks may race key rotation. The vote
        // is already durable, but no stale signature may escape this boundary.
        if let Err(error) = context.registry.verify_live_detached_message_v2(
            draft.checkpoint(),
            &signature,
            self.state.state().current_epoch,
            context.registry_authority,
        ) {
            self.requires_recovery = true;
            return Err(error.into());
        }
        if let Err(error) = context
            .registry
            .active_identity(&signature.signer, context.registry_authority)
        {
            self.requires_recovery = true;
            return Err(error.into());
        }
        self.check_output_anchor(context.checkpoint_authority)?;
        Ok(signature)
    }

    pub fn finalize_checkpoint_v2<S, R, A>(
        &mut self,
        draft: &FleetCheckpointDraftV2,
        current_time_ns: u64,
        store: &mut S,
        context: &FleetCheckpointRecoveryContext<'_, R, A>,
    ) -> Result<SignedFleetCheckpointV2, FleetCheckpointRecoveryError>
    where
        S: FleetCheckpointStore,
        R: FleetRegistryAnchorAuthority,
        A: FleetCheckpointAnchorAuthority,
    {
        self.ensure_current(context.checkpoint_authority)?;
        let mut staged = self.state.stage_checkpoint_update();
        let signed = staged.finalize_checkpoint_v2(
            draft,
            &self.config.quorum,
            current_time_ns,
            context.registry,
            context.registry_authority,
        )?;
        let voter = signed
            .signatures
            .keys()
            .next()
            .ok_or_else(|| invalid_snapshot("verified checkpoint has no voters"))?;
        self.persist(
            staged,
            None,
            Some(signed.clone()),
            store,
            context.checkpoint_authority,
            || {
                context
                    .registry
                    .active_identity(voter, context.registry_authority)?;
                Ok(())
            },
        )?;
        if let Err(error) = signed.verify(
            &self.config.quorum,
            context.registry,
            self.state.state().current_epoch,
            context.registry_authority,
        ) {
            self.requires_recovery = true;
            return Err(error.into());
        }
        self.check_output_anchor(context.checkpoint_authority)?;
        Ok(signed)
    }

    pub fn accept_checkpoint_v2<S, R, A>(
        &mut self,
        signed: &SignedFleetCheckpointV2,
        current_time_ns: u64,
        store: &mut S,
        context: &FleetCheckpointRecoveryContext<'_, R, A>,
    ) -> Result<SignedFleetCheckpointV2, FleetCheckpointRecoveryError>
    where
        S: FleetCheckpointStore,
        R: FleetRegistryAnchorAuthority,
        A: FleetCheckpointAnchorAuthority,
    {
        self.ensure_current(context.checkpoint_authority)?;
        let mut staged = self.state.stage_checkpoint_update();
        let accepted = staged.accept_checkpoint_v2(
            signed,
            &self.config.quorum,
            current_time_ns,
            context.registry,
            context.registry_authority,
        )?;
        let voter = accepted
            .signatures
            .keys()
            .next()
            .ok_or_else(|| invalid_snapshot("verified checkpoint has no voters"))?;
        self.persist(
            staged,
            None,
            Some(accepted.clone()),
            store,
            context.checkpoint_authority,
            || {
                context
                    .registry
                    .active_identity(voter, context.registry_authority)?;
                Ok(())
            },
        )?;
        if let Err(error) = accepted.verify(
            &self.config.quorum,
            context.registry,
            self.state.state().current_epoch,
            context.registry_authority,
        ) {
            self.requires_recovery = true;
            return Err(error.into());
        }
        self.check_output_anchor(context.checkpoint_authority)?;
        Ok(accepted)
    }

    fn ensure_available(&self) -> Result<(), FleetCheckpointRecoveryError> {
        if self.requires_recovery {
            Err(FleetCheckpointRecoveryError::RecoveryRequired)
        } else {
            Ok(())
        }
    }

    fn admission_budget_after(&self, growth: usize) -> Result<usize, FleetCheckpointRecoveryError> {
        check_admission_budget(self.admission_budget_bytes.saturating_add(growth))
    }

    fn check_output_anchor<A: FleetCheckpointAnchorAuthority>(
        &mut self,
        authority: &A,
    ) -> Result<(), FleetCheckpointRecoveryError> {
        if let Err(error) = self.ensure_current(authority) {
            self.requires_recovery = true;
            return Err(error);
        }
        Ok(())
    }

    fn ensure_current<A: FleetCheckpointAnchorAuthority>(
        &self,
        authority: &A,
    ) -> Result<(), FleetCheckpointRecoveryError> {
        self.ensure_available()?;
        check_namespace(&self.config, authority)?;
        check_receipt(authority.authenticate_current_checkpoint_anchor(&self.claim)?)
    }

    fn persist<S: FleetCheckpointStore, A: FleetCheckpointAnchorAuthority>(
        &mut self,
        staged: AuthenticatedFleetProtocolStateV2,
        reserved: Option<QuorumCheckpoint>,
        finalized: Option<SignedFleetCheckpointV2>,
        store: &mut S,
        authority: &A,
        check_registry: impl FnOnce() -> Result<(), FleetCheckpointRecoveryError>,
    ) -> Result<(), FleetCheckpointRecoveryError> {
        let admission_budget_bytes =
            check_admission_budget(admission_base_bytes(&self.config, &staged)?)?;
        let snapshot_json =
            encode_snapshot(&self.config, &staged, reserved.as_ref(), finalized.as_ref())?;
        let record = prepare_record(&self.config, Some(&self.claim), snapshot_json, authority)?;
        // Serialization and prepare callbacks must not carry a stale registry
        // authorization into the database commit.
        check_registry()?;
        // From this point on even an error can mean a write reached disk. Keep
        // the old in-memory state inaccessible until exact recovery succeeds.
        self.requires_recovery = true;
        commit_record(store, &record, Some(&self.claim.head()))?;
        let claim = finalize_anchor(&record, authority)?;
        self.state = staged;
        self.claim = claim;
        self.reserved_checkpoint = reserved;
        self.last_finalized_checkpoint = finalized;
        self.admission_budget_bytes = admission_budget_bytes;
        self.requires_recovery = false;
        Ok(())
    }
}

fn check_namespace<A: FleetCheckpointAnchorAuthority>(
    config: &FleetCheckpointRecoveryConfig,
    authority: &A,
) -> Result<(), FleetCheckpointRecoveryError> {
    if config.fleet_authority_id != authority.fleet_authority_id()
        || &config.node_id != authority.node_id()
    {
        return Err(FleetCheckpointRecoveryError::Anchor {
            detail: "checkpoint authority is for a different provisioned fleet or node".into(),
        });
    }
    Ok(())
}

fn encode_snapshot(
    config: &FleetCheckpointRecoveryConfig,
    state: &AuthenticatedFleetProtocolStateV2,
    reserved: Option<&QuorumCheckpoint>,
    finalized: Option<&SignedFleetCheckpointV2>,
) -> Result<String, FleetCheckpointRecoveryError> {
    encode_bounded(&RecoverySnapshot {
        schema_version: 1,
        electorate: config.quorum.electorate().clone(),
        threshold_millionths: config.quorum.threshold_millionths(),
        protocol: state.recovery_snapshot(),
        reserved_checkpoint: reserved.cloned(),
        last_finalized_checkpoint: finalized.cloned(),
    })
}

/// Normalize round headers to their maximum encoding size. Otherwise a state
/// exactly at its admission limit could become uncheckpointable when `None`
/// becomes a vote or an epoch/sequence acquires another decimal digit.
fn admission_base_bytes(
    config: &FleetCheckpointRecoveryConfig,
    state: &AuthenticatedFleetProtocolStateV2,
) -> Result<usize, FleetCheckpointRecoveryError> {
    let base = encode_snapshot(config, state, None, None)?.len();
    let current_header = serde_json::to_vec(&(
        state.state().current_epoch,
        state.state().last_checkpoint_seq,
        state.checkpoint_vote,
    ))
    .map_err(|error| invalid_snapshot(&error.to_string()))?;
    let maximum_header = serde_json::to_vec(&(
        SecurityEpoch::from_raw(u64::MAX),
        u64::MAX,
        Some((
            SecurityEpoch::from_raw(u64::MAX),
            u64::MAX,
            ContentHash::from_bytes([255; 32]),
        )),
    ))
    .map_err(|error| invalid_snapshot(&error.to_string()))?;
    base.checked_sub(current_header.len())
        .and_then(|bytes| bytes.checked_add(maximum_header.len()))
        .ok_or_else(|| invalid_snapshot("snapshot header accounting overflow"))
}

struct BoundedSnapshotWriter(Vec<u8>);

impl Write for BoundedSnapshotWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > FLEET_CHECKPOINT_MAX_SNAPSHOT_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other(
                "checkpoint snapshot exceeds its byte budget",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode_bounded(snapshot: &RecoverySnapshot) -> Result<String, FleetCheckpointRecoveryError> {
    let mut writer = BoundedSnapshotWriter(Vec::new());
    serde_json::to_writer(&mut writer, snapshot)
        .map_err(|error| invalid_snapshot(&format!("snapshot encoding failed: {error}")))?;
    String::from_utf8(writer.0).map_err(|error| invalid_snapshot(&error.to_string()))
}

fn prepare_record<A: FleetCheckpointAnchorAuthority>(
    config: &FleetCheckpointRecoveryConfig,
    expected: Option<&FleetCheckpointAnchorClaim>,
    snapshot_json: String,
    authority: &A,
) -> Result<FleetCheckpointStoreRecord, FleetCheckpointRecoveryError> {
    check_namespace(config, authority)?;
    if let Some(expected) = expected {
        check_receipt(authority.authenticate_current_checkpoint_anchor(expected)?)?;
    }
    let revision = expected
        .map_or(Some(1), |current| current.revision.checked_add(1))
        .ok_or(FleetCheckpointRecoveryError::RevisionExhausted)?;
    let claim = FleetCheckpointAnchorClaim {
        fleet_authority_id: config.fleet_authority_id,
        node_id: config.node_id.clone(),
        revision,
        state_hash: ContentHash::compute(snapshot_json.as_bytes()),
        prior_state_hash: expected
            .map(|current| current.state_hash)
            .unwrap_or_default(),
    };
    let anchor_permit = authority.prepare_checkpoint_anchor_advance(expected, &claim)?;
    if anchor_permit.is_empty() || anchor_permit.len() > FLEET_CHECKPOINT_MAX_ANCHOR_PERMIT_BYTES {
        return Err(FleetCheckpointRecoveryError::Anchor {
            detail: "checkpoint authority returned an empty or oversized transition permit".into(),
        });
    }
    let record = FleetCheckpointStoreRecord {
        fleet_authority_id: claim.fleet_authority_id,
        node_id: claim.node_id.clone(),
        revision: claim.revision,
        prior_state_hash: claim.prior_state_hash,
        state_hash: claim.state_hash,
        snapshot_json,
        anchor_permit,
    };
    record.validate()?;
    Ok(record)
}

fn commit_record<S: FleetCheckpointStore>(
    store: &mut S,
    record: &FleetCheckpointStoreRecord,
    expected: Option<&FleetCheckpointStoreHead>,
) -> Result<(), FleetCheckpointRecoveryError> {
    let outcome = store.compare_and_swap(expected, record);
    let readback = store.load()?;
    let exact = readback.as_ref() == Some(record);
    match outcome {
        Ok(FleetCheckpointStoreCasOutcome::Applied(applied)) if exact && applied == *record => {
            Ok(())
        }
        Ok(FleetCheckpointStoreCasOutcome::Applied(_)) => Err(invalid_snapshot(
            "storage reported success without the exact candidate in durable readback",
        )),
        Ok(FleetCheckpointStoreCasOutcome::Conflict { .. }) => {
            Err(FleetCheckpointRecoveryError::ConcurrentUpdate)
        }
        Err(error) => Err(error.into()),
    }
}

fn finalize_anchor<A: FleetCheckpointAnchorAuthority>(
    record: &FleetCheckpointStoreRecord,
    authority: &A,
) -> Result<FleetCheckpointAnchorClaim, FleetCheckpointRecoveryError> {
    let claim = FleetCheckpointAnchorClaim::from_record(record);
    check_receipt(authority.finalize_checkpoint_anchor_advance(&record.anchor_permit, &claim)?)?;
    check_receipt(authority.authenticate_current_checkpoint_anchor(&claim)?)?;
    Ok(claim)
}

fn check_receipt(receipt: String) -> Result<(), FleetCheckpointRecoveryError> {
    if receipt.trim().is_empty() {
        Err(FleetCheckpointRecoveryError::Anchor {
            detail: "checkpoint authority returned an empty authentication receipt".into(),
        })
    } else {
        Ok(())
    }
}

fn check_admission_budget(actual: usize) -> Result<usize, FleetCheckpointRecoveryError> {
    if actual > FLEET_CHECKPOINT_ADMISSION_BUDGET_BYTES {
        Err(FleetCheckpointRecoveryError::AdmissionCapacityExceeded {
            actual,
            limit: FLEET_CHECKPOINT_ADMISSION_BUDGET_BYTES,
        })
    } else {
        Ok(actual)
    }
}

fn invalid_snapshot(detail: &str) -> FleetCheckpointRecoveryError {
    FleetCheckpointRecoveryError::InvalidSnapshot {
        detail: detail.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FleetCheckpointRecoveryError {
    #[error("checkpoint storage failed: {0}")]
    Storage(#[from] FleetCheckpointStoreError),
    #[error("checkpoint validation failed: {0}")]
    Checkpoint(#[from] FleetCheckpointV2Error),
    #[error("fleet identity verification failed: {0}")]
    Identity(#[from] FleetIdentityError),
    #[error("fleet admission failed: {0}")]
    Ingress(#[from] FleetIngressV2Error),
    #[error("checkpoint anchor authentication failed: {detail}")]
    Anchor { detail: String },
    #[error("invalid authenticated recovery snapshot: {detail}")]
    InvalidSnapshot { detail: String },
    #[error("durable fleet admission requires {actual} bytes, capacity is {limit}")]
    AdmissionCapacityExceeded { actual: usize, limit: usize },
    #[error("no durable checkpoint state exists for this node")]
    MissingState,
    #[error("another writer changed the durable checkpoint state")]
    ConcurrentUpdate,
    #[error("checkpoint storage revision counter is exhausted")]
    RevisionExhausted,
    #[error("checkpoint controller requires recovery before further use")]
    RecoveryRequired,
}

#[cfg(test)]
mod recovery_capacity_tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::fleet_immune_protocol::{
        ContainmentAction, FLEET_V2_MAX_COLLECTION_ITEMS, FLEET_V2_MAX_DYNAMIC_BYTES,
        FLEET_V2_MAX_PENDING_INTENT_BYTES, FleetKeyId, ProtocolVersion,
        ResolvedContainmentDecision,
    };
    use crate::signature_preimage::Signature;

    // Distinct UTF-8 identifiers consisting entirely of bytes that JSON must
    // escape as six characters. Avoid whitespace controls rejected in node IDs.
    fn fully_escaped_identifier(index: usize, length: usize) -> String {
        let mut bytes = vec![1_u8; length];
        bytes[0] = 1 + (index % 7) as u8;
        bytes[1] = 1 + ((index / 7) % 7) as u8;
        bytes[2] = 1 + ((index / 49) % 7) as u8;
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn recovery_reserve_covers_maximal_checkpoint_shapes_and_header_growth() {
        let count = FLEET_V2_MAX_COLLECTION_ITEMS;
        let roster_bytes = FLEET_V2_MAX_DYNAMIC_BYTES / 2;
        let electorate = (0..count)
            .map(|index| NodeId::new(fully_escaped_identifier(index, roster_bytes / count)))
            .collect::<BTreeSet<_>>();
        assert_eq!(electorate.len(), count);
        assert_eq!(
            electorate
                .iter()
                .map(|node| node.as_str().len())
                .sum::<usize>(),
            roster_bytes
        );
        let quorum = FleetCheckpointQuorumV2::new(electorate.clone(), 1_000_000).unwrap();
        let electorate_hash = ContentHash::compute(
            &serde_json::to_vec(&("frankenengine.fleet-checkpoint-electorate.v2", &electorate))
                .unwrap(),
        );
        let id_bytes = FLEET_V2_MAX_PENDING_INTENT_BYTES / (2 * count);
        let decisions = (0..count)
            .map(|index| {
                let id = fully_escaped_identifier(index, id_bytes);
                (
                    id.clone(),
                    ResolvedContainmentDecision {
                        extension_id: id.clone(),
                        resolved_action: ContainmentAction::Quarantine,
                        contributing_intent_ids: vec![id],
                        epoch: SecurityEpoch::from_raw(u64::MAX),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(decisions.len(), count);
        assert_eq!(
            decisions
                .values()
                .map(|decision| decision.extension_id.len()
                    + decision
                        .contributing_intent_ids
                        .iter()
                        .map(String::len)
                        .sum::<usize>())
                .sum::<usize>(),
            FLEET_V2_MAX_PENDING_INTENT_BYTES
        );
        let checkpoint = QuorumCheckpoint {
            checkpoint_seq: u64::MAX,
            epoch: SecurityEpoch::from_raw(u64::MAX),
            participating_nodes: electorate.clone(),
            evidence_summary_hash: ContentHash::from_bytes([255; 32]),
            containment_decisions: decisions.into_values().collect(),
            quorum_signatures: BTreeMap::new(),
            timestamp_ns: u64::MAX,
            protocol_version: ProtocolVersion::V2,
            extensions: BTreeMap::from([
                (
                    "fleet.checkpoint-v2.electorate_hash".into(),
                    electorate_hash.to_hex(),
                ),
                (
                    "fleet.checkpoint-v2.quorum_millionths".into(),
                    "1000000".into(),
                ),
                ("fleet.checkpoint-v2.evidence_hash".into(), "f".repeat(64)),
                ("fleet.checkpoint-v2.intents_hash".into(), "f".repeat(64)),
            ]),
        };
        quorum.validate_checkpoint(&checkpoint).unwrap();
        let fleet = FleetAuthorityId::from_provisioned_bytes([255; 32]).unwrap();
        let key_id: FleetKeyId =
            serde_json::from_value(serde_json::to_value([255_u8; 32]).unwrap()).unwrap();
        // These are maximal-size untrusted signature values, not a claim of
        // cryptographic validity. The test proves the serializer's byte budget.
        let signatures = electorate
            .iter()
            .map(|node| {
                (
                    node.clone(),
                    FleetSignatureV2 {
                        fleet_authority_id: fleet,
                        signer: node.clone(),
                        key_id,
                        key_sequence: u64::MAX,
                        signature: Signature::from_bytes([255; 64]),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let signed = SignedFleetCheckpointV2 {
            checkpoint: checkpoint.clone(),
            signatures,
        };

        // One checkpoint: <=6 bytes per identifier byte, <=128 fixed bytes
        // per decision, <=3 bytes of quoting/punctuation per participant and
        // intent ID, and 4 KiB for fixed labels/scalars/hashes/extensions.
        let checkpoint_bound =
            6 * (roster_bytes + FLEET_V2_MAX_PENDING_INTENT_BYTES) + 128 * count + 6 * count + 4096;
        // A signer ID appears twice (map key and signature identity). Every
        // other per-signature field, plus map punctuation, fits within 768 bytes:
        // authority hex66, key hash129, sequence20, Ed25519 JSON277, labels<100.
        let signature_bundle_bound = 12 * roster_bytes + 768 * count + 4096;
        let reserve_bound = 2 * checkpoint_bound + signature_bundle_bound;
        let reserve = FLEET_CHECKPOINT_MAX_SNAPSHOT_BYTES - FLEET_CHECKPOINT_ADMISSION_BUDGET_BYTES;
        assert!(serde_json::to_vec(&checkpoint).unwrap().len() <= checkpoint_bound);
        assert!(serde_json::to_vec(&signed.signatures).unwrap().len() <= signature_bundle_bound);
        assert!(
            reserve_bound <= reserve,
            "derived reserve {reserve_bound} exceeds {reserve}"
        );

        let config = FleetCheckpointRecoveryConfig {
            fleet_authority_id: fleet,
            node_id: electorate.first().unwrap().clone(),
            gossip: GossipConfig {
                quorum_threshold_millionths: 1_000_000,
                ..GossipConfig::default()
            },
            quorum,
            minimum_epoch: SecurityEpoch::GENESIS,
        };
        let mut state = AuthenticatedFleetProtocolStateV2::new(
            fleet,
            config.node_id.clone(),
            config.gossip.clone(),
            SecurityEpoch::GENESIS,
        )
        .unwrap();
        let normalized_before = admission_base_bytes(&config, &state).unwrap();
        state.state.current_epoch = SecurityEpoch::from_raw(u64::MAX);
        state.state.last_checkpoint_seq = u64::MAX;
        state.checkpoint_vote = Some((
            SecurityEpoch::from_raw(u64::MAX),
            u64::MAX,
            ContentHash::from_bytes([255; 32]),
        ));
        let normalized_after = admission_base_bytes(&config, &state).unwrap();
        assert_eq!(
            normalized_before, normalized_after,
            "header changes must not spend admission capacity"
        );
        let full = encode_snapshot(&config, &state, Some(&checkpoint), Some(&signed)).unwrap();
        let actual_extra = full.len().saturating_sub(normalized_after);
        assert!(actual_extra <= reserve_bound);
        assert!(actual_extra <= reserve);
        eprintln!(
            "checkpoint reserve: actual={actual_extra}, conservative_bound={reserve_bound}, available={reserve}"
        );
    }
}
