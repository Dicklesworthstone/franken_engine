//! Key-attestation compatibility with hardened persistence boundaries.
//!
//! Historical attestation objects remain available from `compat`. The exported
//! compatibility store/nonce registry enforce owner/principal binding,
//! content-derived IDs, and replay-safe persistence. `versioned` provides the
//! SHA-256-v2 object/store for new persisted attestations.

mod compat;
mod strict_store;
mod versioned;

pub use compat::{
    attestation_schema, attestation_schema_id, AttestationError, AttestationEvent,
    AttestationEventType, AttestationNonce, CreateAttestationInput, DevicePosture,
    DevicePostureVerifier, KeyAttestation,
};
pub use strict_store::{AttestationStore, NonceRegistry};
pub use versioned::*;
