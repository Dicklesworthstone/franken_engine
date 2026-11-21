//! Participant-local, authenticated pairwise masking for complete rosters.
//!
//! Each participant owns its signing key, fresh per-peer X25519 secrets and
//! plaintext. Only signed public-key announcements and signed masked vectors
//! cross the coordinator boundary. The complete key transcript, trusted roster,
//! session, dimension and field are bound into the signatures and HKDF-SHA256.
//! No participant's net mask is disclosed. Missing peers abort the round; this
//! API deliberately has no dropout-secret disclosure or threshold-recovery path.
//!
//! The application must provision the same trusted identity roster to all peers,
//! assign a fresh session identifier to each release, and charge any DP budget
//! before releasing a contribution. Signatures authenticate membership, not the
//! correctness of a malicious member's update. Privacy requires at least two
//! non-colluding participants; this is not a Byzantine agreement protocol or a
//! complete implementation of Bonawitz threshold recovery.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::SecurityParameters;
use crate::{
    AggregationProtocol, MaskedContribution, PairwiseMaskParticipant, ParticipantId, Result,
    SecureAggregationError,
};

/// Trusted public configuration for one complete-roster aggregation round.
///
/// Construction validates all identities. This type is not deserializable:
/// untrusted wire data must not silently become a trusted identity roster.
#[derive(Debug, Clone)]
pub struct AuthenticatedAggregationRound {
    session_id: String,
    identities: BTreeMap<ParticipantId, VerifyingKey>,
    dimension: usize,
    field_modulus: u64,
    binding: [u8; 32],
}

impl AuthenticatedAggregationRound {
    pub fn new(
        session_id: String,
        identities: BTreeMap<ParticipantId, [u8; 32]>,
        dimension: usize,
        field_modulus: u64,
    ) -> Result<Self> {
        if session_id.trim().is_empty() {
            return Err(protocol_error("Session identifier must not be empty"));
        }
        if identities.len() < 3 {
            return Err(SecureAggregationError::InsufficientParticipants);
        }
        if dimension == 0 {
            return Err(SecureAggregationError::InvalidDimension);
        }
        if !(2..=i64::MAX as u64).contains(&field_modulus) {
            return Err(protocol_error("Field modulus must be in 2..=i64::MAX"));
        }
        let mut keys = BTreeMap::new();
        let mut distinct_keys = BTreeSet::new();
        let mut digest = Sha256::new();
        digest.update(b"franken-dp.authenticated-round.v1\0");
        hash_bytes(&mut digest, session_id.as_bytes());
        digest.update((dimension as u64).to_le_bytes());
        digest.update(field_modulus.to_le_bytes());
        digest.update((identities.len() as u64).to_le_bytes());
        for (id, bytes) in identities {
            if id.as_str().trim().is_empty() || !distinct_keys.insert(bytes) {
                return Err(protocol_error(
                    "Roster identities and signing keys must be distinct",
                ));
            }
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| crypto_error("Invalid identity verification key"))?;
            if key.is_weak() {
                return Err(crypto_error("Weak identity verification key"));
            }
            hash_bytes(&mut digest, id.as_str().as_bytes());
            digest.update(bytes);
            keys.insert(id, key);
        }
        Ok(Self {
            session_id,
            identities: keys,
            dimension,
            field_modulus,
            binding: digest.finalize().into(),
        })
    }

    /// Public commitment to the session, identity roster and arithmetic domain.
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }

    /// Verify a complete set of signed public announcements, without secrets.
    /// Every peer independently runs this before consuming its local setup.
    pub fn verify_announcements(
        &self,
        announcements: &[KeyAnnouncement],
    ) -> Result<AuthenticatedKeySet> {
        if announcements.len() != self.identities.len() {
            return Err(protocol_error(
                "Announcements must cover the complete roster",
            ));
        }
        let mut verified = BTreeMap::new();
        for announcement in announcements {
            let key = self
                .identities
                .get(&announcement.participant_id)
                .ok_or(SecureAggregationError::ParticipantNotFound)?;
            if announcement.round_binding != self.binding {
                return Err(protocol_error("Announcement belongs to a different round"));
            }
            if announcement.peer_keys.len() != self.identities.len() - 1
                || !announcement.peer_keys.keys().eq(self
                    .identities
                    .keys()
                    .filter(|id| *id != &announcement.participant_id))
            {
                return Err(protocol_error(
                    "Announcement peer keys do not match the roster",
                ));
            }
            verify_signature(key, &announcement.digest(), &announcement.signature)?;
            if verified
                .insert(announcement.participant_id.clone(), announcement.clone())
                .is_some()
            {
                return Err(protocol_error("Duplicate key announcement"));
            }
        }
        let mut digest = Sha256::new();
        digest.update(b"franken-dp.authenticated-key-set.v1\0");
        digest.update(self.binding);
        for announcement in verified.values() {
            digest.update(announcement.digest());
        }
        Ok(AuthenticatedKeySet {
            round: self.clone(),
            announcements: verified,
            binding: digest.finalize().into(),
        })
    }
}

/// Public, signed ephemeral keys. One fresh secret is used for each peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAnnouncement {
    pub participant_id: ParticipantId,
    pub round_binding: [u8; 32],
    pub peer_keys: BTreeMap<ParticipantId, [u8; 32]>,
    pub signature: Vec<u8>,
}

impl KeyAnnouncement {
    fn digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"franken-dp.key-announcement.v1\0");
        digest.update(self.round_binding);
        hash_bytes(&mut digest, self.participant_id.as_str().as_bytes());
        digest.update((self.peer_keys.len() as u64).to_le_bytes());
        for (id, public_key) in &self.peer_keys {
            hash_bytes(&mut digest, id.as_str().as_bytes());
            digest.update(public_key);
        }
        digest.finalize().into()
    }
}

/// One participant's secret setup. It cannot be cloned, serialized or printed.
/// Completing setup consumes all ephemeral secrets, including on failure.
pub struct ParticipantKeySetup {
    round: AuthenticatedAggregationRound,
    signing_key: SigningKey,
    announcement: KeyAnnouncement,
    secrets: BTreeMap<ParticipantId, EphemeralSecret>,
}

impl ParticipantKeySetup {
    pub fn new<R: RngCore + CryptoRng>(
        round: &AuthenticatedAggregationRound,
        id: ParticipantId,
        signing_key: SigningKey,
        rng: &mut R,
    ) -> Result<Self> {
        if round.identities.get(&id) != Some(&signing_key.verifying_key()) {
            return Err(crypto_error(
                "Signing key does not match the trusted participant",
            ));
        }
        let mut secrets = BTreeMap::new();
        let mut peer_keys = BTreeMap::new();
        for peer in round.identities.keys().filter(|peer| *peer != &id) {
            let secret = EphemeralSecret::random_from_rng(&mut *rng);
            peer_keys.insert(peer.clone(), PublicKey::from(&secret).to_bytes());
            secrets.insert(peer.clone(), secret);
        }
        let mut announcement = KeyAnnouncement {
            participant_id: id,
            round_binding: round.binding,
            peer_keys,
            signature: Vec::new(),
        };
        announcement.signature = signing_key.sign(&announcement.digest()).to_bytes().to_vec();
        Ok(Self {
            round: round.clone(),
            signing_key,
            announcement,
            secrets,
        })
    }

    pub fn announcement(&self) -> &KeyAnnouncement {
        &self.announcement
    }

    /// Establish peer-local seeds from the authenticated public transcript.
    /// The coordinator need not, and must not, receive this participant state.
    pub fn complete(self, key_set: &AuthenticatedKeySet) -> Result<AuthenticatedParticipant> {
        let id = &self.announcement.participant_id;
        if self.round.binding != key_set.round.binding
            || key_set.announcements.get(id) != Some(&self.announcement)
        {
            return Err(protocol_error(
                "Key set does not contain this participant's setup",
            ));
        }
        let mut participant = AuthenticatedParticipant {
            round: self.round,
            key_set_binding: key_set.binding,
            signing_key: self.signing_key,
            masks: PairwiseMaskParticipant::new(id.clone()),
        };
        for (peer, secret) in self.secrets {
            let peer_key = key_set.announcements[&peer].peer_keys[id];
            let shared = secret.diffie_hellman(&PublicKey::from(peer_key));
            // RFC 7748 section 6: low-order keys must not yield a public mask.
            if !shared.was_contributory() {
                return Err(crypto_error("Non-contributory X25519 peer key"));
            }
            let (low, high, low_key, high_key) = if id < &peer {
                (id, &peer, self.announcement.peer_keys[&peer], peer_key)
            } else {
                (&peer, id, peer_key, self.announcement.peer_keys[&peer])
            };
            let mut context = Sha256::new();
            context.update(b"franken-dp.pairwise-key.v1\0");
            context.update(key_set.binding);
            hash_bytes(&mut context, low.as_str().as_bytes());
            hash_bytes(&mut context, high.as_str().as_bytes());
            context.update(low_key);
            context.update(high_key);
            let mut seed = Zeroizing::new([0u8; 32]);
            Hkdf::<Sha256>::new(None, shared.as_bytes())
                .expand(&context.finalize(), seed.as_mut())
                .map_err(|_| crypto_error("Pairwise key derivation failed"))?;
            participant.masks.pairwise_seeds.insert(peer, *seed);
        }
        Ok(participant)
    }
}

/// Participant-local masking state. No public operation discloses mask seeds.
/// Each instance releases at most one contribution for its exact key transcript.
pub struct AuthenticatedParticipant {
    round: AuthenticatedAggregationRound,
    key_set_binding: [u8; 32],
    signing_key: SigningKey,
    masks: PairwiseMaskParticipant,
}

impl AuthenticatedParticipant {
    /// Mask a vector of signed integers in the round's field, then authenticate
    /// the resulting vector. Invalid dimensions do not consume the submission.
    pub fn mask(&mut self, input: &[i64]) -> Result<SignedMaskedContribution> {
        if input.len() != self.round.dimension {
            return Err(SecureAggregationError::InvalidDimension);
        }
        let masked = self.masks.create_masked_contribution(
            &self.round.session_id,
            input,
            self.round.field_modulus,
        )?;
        let mut message = SignedMaskedContribution {
            participant_id: masked.participant_id,
            key_set_binding: self.key_set_binding,
            masked_values: masked.masked_values,
            signature: Vec::new(),
        };
        message.signature = self.signing_key.sign(&message.digest()).to_bytes().to_vec();
        Ok(message)
    }
}

impl Drop for AuthenticatedParticipant {
    fn drop(&mut self) {
        for seed in self.masks.pairwise_seeds.values_mut() {
            seed.zeroize();
        }
    }
}

/// The only per-participant update sent to the coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMaskedContribution {
    pub participant_id: ParticipantId,
    pub key_set_binding: [u8; 32],
    pub masked_values: Vec<i64>,
    pub signature: Vec<u8>,
}

impl SignedMaskedContribution {
    fn digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"franken-dp.signed-masked-contribution.v1\0");
        digest.update(self.key_set_binding);
        hash_bytes(&mut digest, self.participant_id.as_str().as_bytes());
        digest.update((self.masked_values.len() as u64).to_le_bytes());
        for value in &self.masked_values {
            digest.update(value.to_le_bytes());
        }
        digest.finalize().into()
    }
}

/// Public coordinator state: trusted configuration and verified public keys.
/// Contains no plaintext vectors, private keys, mask seeds or unmasking values.
#[derive(Debug, Clone)]
pub struct AuthenticatedKeySet {
    round: AuthenticatedAggregationRound,
    announcements: BTreeMap<ParticipantId, KeyAnnouncement>,
    binding: [u8; 32],
}

impl AuthenticatedKeySet {
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }

    /// Authenticate the entire batch before exposing any sum. Missing, duplicate,
    /// foreign, tampered or differently bound messages fail the whole round.
    pub fn aggregate(&self, contributions: &[SignedMaskedContribution]) -> Result<Vec<i64>> {
        if contributions.len() != self.round.identities.len() {
            return Err(protocol_error(
                "Contributions must cover the complete roster",
            ));
        }
        let mut seen = BTreeSet::new();
        let mut masked = Vec::with_capacity(contributions.len());
        for contribution in contributions {
            let key = self
                .round
                .identities
                .get(&contribution.participant_id)
                .ok_or(SecureAggregationError::ParticipantNotFound)?;
            if !seen.insert(&contribution.participant_id) {
                return Err(protocol_error("Duplicate masked contribution"));
            }
            if contribution.key_set_binding != self.binding {
                return Err(protocol_error(
                    "Contribution belongs to a different key transcript",
                ));
            }
            let values = MaskedContribution::new(
                contribution.participant_id.clone(),
                contribution.masked_values.clone(),
                Vec::new(),
            );
            values.verify_dimension(self.round.dimension)?;
            values.verify_field_bounds(self.round.field_modulus)?;
            verify_signature(key, &contribution.digest(), &contribution.signature)?;
            masked.push(values);
        }
        AggregationProtocol::new(SecurityParameters {
            field_modulus: self.round.field_modulus,
            min_participants: self.round.identities.len(),
            dropout_threshold: 0,
            vector_dimension: self.round.dimension,
        })
        .aggregate_masked_contributions(masked)
    }
}

fn hash_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

fn verify_signature(key: &VerifyingKey, message: &[u8], bytes: &[u8]) -> Result<()> {
    let signature =
        Signature::from_slice(bytes).map_err(|_| crypto_error("Invalid signature encoding"))?;
    key.verify_strict(message, &signature)
        .map_err(|_| crypto_error("Signature verification failed"))
}

fn protocol_error(message: &str) -> SecureAggregationError {
    SecureAggregationError::ProtocolViolation(message.into())
}

fn crypto_error(message: &str) -> SecureAggregationError {
    SecureAggregationError::CryptographicError(message.into())
}

#[cfg(test)]
mod tests;
