//! Validated recovery of canonical evidence emission state (bd-8yhg4).
//!
//! Deserialization checks self-consistency, not origin or freshness. A caller
//! accepting an untrusted checkpoint must additionally authenticate its bytes
//! against an independently held commitment. In particular, an attacker can
//! recompute an unkeyed chain; a valid chain alone is not a trust anchor.

use super::*;

/// A persisted emitter cannot safely resume at the claimed ledger position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitterRestoreError {
    Capacity { entries: usize, capacity: usize },
    Sequence { expected: u64, actual: u64 },
    NextSequence { expected: u64, actual: u64 },
    Entry { sequence: u64, reason: String },
    RollingHash,
    CategoryCounts,
    Epoch { minimum: u64, actual: u64 },
    Events { index: usize, reason: String },
}

impl fmt::Display for EmitterRestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity { entries, capacity } => {
                write!(f, "evidence snapshot has {entries} entries, capacity is {capacity}")
            }
            Self::Sequence { expected, actual } => {
                write!(f, "evidence sequence is {actual}, expected {expected}")
            }
            Self::NextSequence { expected, actual } => {
                write!(f, "next evidence sequence is {actual}, expected {expected}")
            }
            Self::Entry { sequence, reason } => {
                write!(f, "invalid evidence entry at sequence {sequence}: {reason}")
            }
            Self::RollingHash => f.write_str("evidence snapshot rolling hash mismatch"),
            Self::CategoryCounts => f.write_str("evidence snapshot category counts mismatch"),
            Self::Epoch { minimum, actual } => {
                write!(f, "evidence epoch {actual} is below ledger epoch {minimum}")
            }
            Self::Events { index, reason } => {
                write!(f, "invalid evidence emission event at index {index}: {reason}")
            }
        }
    }
}

impl std::error::Error for EmitterRestoreError {}

/// Same wire fields as the emitter, but never usable as a live emitter until
/// all entries and derived state have been checked. Scratch storage is private
/// process state and is reconstructed, never loaded from a snapshot.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmitterSnapshot {
    config: EmitterConfig,
    entries: Vec<CanonicalEvidenceEntry>,
    events: Vec<EvidenceEmissionEvent>,
    epoch: SecurityEpoch,
    next_sequence: u64,
    rolling_hash: ContentHash,
    category_counts: BTreeMap<ActionCategory, u64>,
}

impl<'de> Deserialize<'de> for CanonicalEvidenceEmitter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let snapshot = EmitterSnapshot::deserialize(deserializer)?;
        let emitter = Self {
            config: snapshot.config,
            entries: snapshot.entries,
            events: snapshot.events,
            epoch: snapshot.epoch,
            next_sequence: snapshot.next_sequence,
            rolling_hash: snapshot.rolling_hash,
            category_counts: snapshot.category_counts,
            scratch: Vec::with_capacity(HASH_SCRATCH_CAPACITY),
        };
        emitter
            .validate_integrity()
            .map_err(serde::de::Error::custom)?;
        Ok(emitter)
    }
}

impl CanonicalEvidenceEmitter {
    /// Validate the complete resumable state, including all derived caches.
    ///
    /// The retained ledger is an append-only prefix starting at sequence zero.
    /// This check rejects gaps, duplicated positions, stale counters, altered
    /// category totals, inconsistent epochs and contradictory success events.
    /// It does not authenticate the producer or detect a fully resealed prefix
    /// rollback; those require an independently trusted checkpoint commitment.
    pub fn validate_integrity(&self) -> Result<(), EmitterRestoreError> {
        if self.entries.len() > self.config.buffer_capacity {
            return Err(EmitterRestoreError::Capacity {
                entries: self.entries.len(),
                capacity: self.config.buffer_capacity,
            });
        }

        let mut sequence = 0_u64;
        let mut previous: Option<&CanonicalEvidenceEntry> = None;
        let mut rolling_hash = ContentHash::compute(b"evidence-genesis");
        let mut category_counts = BTreeMap::new();
        let mut rolling_preimage = [0_u8; 64];
        for entry in &self.entries {
            if entry.sequence != sequence {
                return Err(EmitterRestoreError::Sequence {
                    expected: sequence,
                    actual: entry.sequence,
                });
            }
            let invalid_entry = |reason: &str| EmitterRestoreError::Entry {
                sequence,
                reason: reason.to_string(),
            };
            if entry.schema_version != SCHEMA_VERSION {
                return Err(invalid_entry("unsupported schema version"));
            }
            let expected_id = format!("ev-{}-{}-{}", entry.category, sequence, entry.ts_unix_ms);
            if entry.entry_id.as_str() != expected_id {
                return Err(invalid_entry("entry identifier does not match its coordinates"));
            }
            if !entry.verify_artifact_integrity() {
                return Err(invalid_entry("artifact hash or canonical envelope mismatch"));
            }
            if !entry.verify_chain_link(previous) {
                return Err(invalid_entry("predecessor chain hash mismatch"));
            }
            if let Some(previous) = previous {
                if entry.epoch < previous.epoch {
                    return Err(EmitterRestoreError::Epoch {
                        minimum: previous.epoch.as_u64(),
                        actual: entry.epoch.as_u64(),
                    });
                }
            }
            rolling_preimage[..32].copy_from_slice(rolling_hash.as_bytes());
            rolling_preimage[32..].copy_from_slice(entry.artifact_hash.as_bytes());
            rolling_hash = ContentHash::compute(&rolling_preimage);
            *category_counts.entry(entry.category).or_insert(0_u64) += 1;
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| invalid_entry("sequence space exhausted"))?;
            previous = Some(entry);
        }
        if self.next_sequence != sequence {
            return Err(EmitterRestoreError::NextSequence {
                expected: sequence,
                actual: self.next_sequence,
            });
        }
        if self.rolling_hash != rolling_hash {
            return Err(EmitterRestoreError::RollingHash);
        }
        if self.category_counts != category_counts {
            return Err(EmitterRestoreError::CategoryCounts);
        }
        if let Some(last) = previous {
            if self.epoch < last.epoch {
                return Err(EmitterRestoreError::Epoch {
                    minimum: last.epoch.as_u64(),
                    actual: self.epoch.as_u64(),
                });
            }
        }

        // Rejections do not advance the ledger. Every successful emit must
        // have exactly one success event, in the same order and identity.
        let mut successful_entries = self.entries.iter();
        for (index, event) in self.events.iter().enumerate() {
            let invalid_event = |reason: &str| EmitterRestoreError::Events {
                index,
                reason: reason.to_string(),
            };
            if event.component != COMPONENT_NAME || event.event != "evidence_emit" {
                return Err(invalid_event("unexpected event producer or operation"));
            }
            match event.outcome.as_str() {
                "ok" => {
                    let entry = successful_entries
                        .next()
                        .ok_or_else(|| invalid_event("success has no corresponding entry"))?;
                    if event.error_code.is_some()
                        || event.trace_id != entry.trace_id
                        || event.decision_id != entry.decision_id
                        || event.policy_id != entry.policy_id
                    {
                        return Err(invalid_event("success contradicts its evidence entry"));
                    }
                }
                "rejected" if event.error_code.as_ref().is_some_and(|code| !code.is_empty()) => {}
                _ => return Err(invalid_event("invalid outcome or missing rejection reason")),
            }
        }
        if successful_entries.next().is_some() {
            return Err(EmitterRestoreError::Events {
                index: self.events.len(),
                reason: "evidence entry has no success event".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::mocks::{
        MockBudget, MockCx, decision_id_from_seed, policy_id_from_seed, trace_id_from_seed,
    };

    fn request(index: u64) -> EvidenceEmissionRequest {
        EvidenceEmissionRequest {
            category: if index % 2 == 0 {
                ActionCategory::DecisionContract
            } else {
                ActionCategory::ContainmentAction
            },
            action_name: "allow".into(),
            trace_id: trace_id_from_seed(1),
            decision_id: decision_id_from_seed(index + 1),
            policy_id: policy_id_from_seed(1),
            ts_unix_ms: 1000 + index,
            posterior: vec![1.0],
            expected_losses: BTreeMap::from([("allow".into(), 0.0)]),
            chosen_expected_loss: 0.0,
            calibration_score: 1.0,
            fallback_active: false,
            top_features: Vec::new(),
            witnesses: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    fn populated(count: u64) -> CanonicalEvidenceEmitter {
        let mut emitter = CanonicalEvidenceEmitter::new(EmitterConfig::default());
        emitter.set_epoch(SecurityEpoch::from_raw(3));
        let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(100));
        for index in 0..count {
            emitter.emit(&mut cx, &request(index)).unwrap();
        }
        emitter
    }

    fn assert_rejected(emitter: &CanonicalEvidenceEmitter) {
        assert!(!emitter.verify_chain_integrity());
        let json = serde_json::to_vec(emitter).unwrap();
        assert!(serde_json::from_slice::<CanonicalEvidenceEmitter>(&json).is_err());
    }

    fn reseal_entries(emitter: &mut CanonicalEvidenceEmitter) {
        let mut previous = None;
        for entry in &mut emitter.entries {
            entry.artifact_hash = entry.compute_artifact_hash().unwrap();
            entry.chain_hash = compute_chain_hash(previous.as_ref(), &entry.artifact_hash);
            previous = Some(entry.chain_hash);
        }
    }

    #[test]
    fn restart_then_append_is_identical_to_uninterrupted_emission() {
        for prefix in 0..=6 {
            let original = populated(prefix);
            let bytes = serde_json::to_vec(&original).unwrap();
            let mut restored: CanonicalEvidenceEmitter = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
            let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(100));
            for index in prefix..6 {
                restored.emit(&mut cx, &request(index)).unwrap();
            }
            let uninterrupted = populated(6);
            assert_eq!(restored.entries(), uninterrupted.entries());
            assert_eq!(restored.rolling_hash(), uninterrupted.rolling_hash());
            assert_eq!(restored.category_counts(), uninterrupted.category_counts());
            assert_eq!(restored.events(), uninterrupted.events());
            assert_eq!(restored.validate_integrity(), Ok(()));
        }
    }

    #[test]
    fn restore_rejects_forged_next_sequence_even_with_valid_entry_hashes() {
        for next in [0, 999, u64::MAX] {
            let mut emitter = populated(2);
            emitter.next_sequence = next;
            assert!(emitter.entries.iter().all(|entry| entry.verify_artifact_integrity()));
            assert!(matches!(
                emitter.validate_integrity(),
                Err(EmitterRestoreError::NextSequence { expected: 2, actual }) if actual == next
            ));
            assert_rejected(&emitter);
        }
    }

    #[test]
    fn restore_rejects_resealed_gaps_and_duplicate_sequences() {
        for sequence in [0, 99, u64::MAX] {
            let mut emitter = populated(2);
            emitter.entries[1].sequence = sequence;
            reseal_entries(&mut emitter);
            assert!(emitter.entries[1].verify_chain_link(Some(&emitter.entries[0])));
            assert!(matches!(
                emitter.validate_integrity(),
                Err(EmitterRestoreError::Sequence { expected: 1, .. })
            ));
            assert_rejected(&emitter);
        }
    }

    #[test]
    fn restore_rejects_rolling_hash_and_category_cache_tampering() {
        let mut emitter = populated(2);
        emitter.rolling_hash = ContentHash::compute(b"forged rolling hash");
        assert_eq!(emitter.validate_integrity(), Err(EmitterRestoreError::RollingHash));
        assert_rejected(&emitter);
        for count in [0, 2, u64::MAX] {
            let mut emitter = populated(2);
            emitter.category_counts.insert(ActionCategory::DecisionContract, count);
            assert_eq!(emitter.validate_integrity(), Err(EmitterRestoreError::CategoryCounts));
            assert_rejected(&emitter);
        }
        let mut emitter = populated(2);
        emitter.category_counts.insert(ActionCategory::Cancellation, 0);
        assert_rejected(&emitter);
    }

    #[test]
    fn restore_rejects_truncated_or_reordered_retained_entries() {
        let mut truncated = populated(3);
        truncated.entries.pop();
        assert_rejected(&truncated);
        let mut reordered = populated(3);
        reordered.entries.swap(0, 1);
        assert_rejected(&reordered);
    }

    #[test]
    fn restore_rejects_resealed_unsupported_schema_and_identity() {
        let mut schema = populated(1);
        schema.entries[0].schema_version = "evidence-v1".into();
        reseal_entries(&mut schema);
        assert_rejected(&schema);
        let mut identity = populated(1);
        identity.entries[0].entry_id = EvidenceEntryId::new("ev-forged");
        reseal_entries(&mut identity);
        assert_rejected(&identity);
    }

    #[test]
    fn restore_rejects_over_capacity_and_regressing_epochs() {
        let mut capacity = populated(2);
        capacity.config.buffer_capacity = 1;
        assert_rejected(&capacity);
        let mut current_epoch = populated(2);
        current_epoch.epoch = SecurityEpoch::from_raw(2);
        assert_rejected(&current_epoch);
        let mut history = populated(2);
        history.entries[1].epoch = SecurityEpoch::from_raw(2);
        reseal_entries(&mut history);
        assert_rejected(&history);
    }

    #[test]
    fn restore_rejects_missing_extra_and_contradictory_success_events() {
        let mut missing = populated(2);
        missing.events.pop();
        assert_rejected(&missing);
        let mut extra = populated(2);
        extra.events.push(extra.events[0].clone());
        assert_rejected(&extra);
        let mut reordered = populated(2);
        reordered.events.swap(0, 1);
        assert_rejected(&reordered);
        let mut contradiction = populated(2);
        contradiction.events[0].error_code = Some("buffer_full".into());
        assert_rejected(&contradiction);
    }

    #[test]
    fn legitimate_rejections_survive_restore_without_consuming_a_sequence() {
        let mut emitter = populated(1);
        let mut exhausted = MockCx::new(trace_id_from_seed(1), MockBudget::new(0));
        assert!(emitter.emit(&mut exhausted, &request(1)).is_err());
        let bytes = serde_json::to_vec(&emitter).unwrap();
        let mut restored: CanonicalEvidenceEmitter = serde_json::from_slice(&bytes).unwrap();
        let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(100));
        restored.emit(&mut cx, &request(1)).unwrap();
        assert_eq!(restored.entries()[1].sequence, 1);
        assert_eq!(restored.events().len(), 3);
        assert_eq!(restored.validate_integrity(), Ok(()));
    }

    #[test]
    fn epoch_regression_is_refused_before_spending_budget_and_can_recover() {
        let mut emitter = populated(1);
        let previous_entries = emitter.entries().to_vec();
        let previous_hash = *emitter.rolling_hash();
        emitter.set_epoch(SecurityEpoch::from_raw(2));
        let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(100));
        assert!(emitter.emit(&mut cx, &request(1)).is_err());
        assert_eq!(cx.budget().remaining_ms(), 100);
        assert_eq!(emitter.entries(), previous_entries);
        assert_eq!(*emitter.rolling_hash(), previous_hash);
        assert_eq!(emitter.events().last().unwrap().error_code.as_deref(), Some("epoch_regression"));
        emitter.set_epoch(SecurityEpoch::from_raw(4));
        emitter.emit(&mut cx, &request(1)).unwrap();
        assert_eq!(emitter.entries()[1].sequence, 1);
        assert_eq!(emitter.validate_integrity(), Ok(()));
    }

    #[test]
    fn empty_snapshot_requires_exact_genesis_state() {
        let emitter = populated(0);
        let bytes = serde_json::to_vec(&emitter).unwrap();
        assert!(serde_json::from_slice::<CanonicalEvidenceEmitter>(&bytes).is_ok());
        let mut forged = emitter;
        forged.rolling_hash = ContentHash::default();
        assert_rejected(&forged);
    }

    #[test]
    fn duplicate_snapshot_fields_are_rejected() {
        let bytes = serde_json::to_string(&populated(1)).unwrap();
        let duplicate = format!("{{\"next_sequence\":999,{}", &bytes[1..]);
        assert!(serde_json::from_str::<CanonicalEvidenceEmitter>(&duplicate).is_err());
    }
}
