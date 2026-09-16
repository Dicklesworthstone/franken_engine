//! Admission accounting for the live host-effect journal.
//!
//! The byte limit measures retained JSON payloads, not total allocator/RSS use.
//! Slot counts bound fixed per-entry overhead. Measurement borrows payloads and
//! stops at the limit; it never builds a second encoded copy of a large result.

use super::{
    HostEffectJournalEntry, HostEffectJournalError, HostEffectJournalRequest, HostIoOutcome,
    HostIoRequest, ProcessSpawnOutcome, ProcessSpawnRequest,
};
use serde::{Serialize, Serializer};
use std::io::{self, Write};

/// Lifetime limits for one journal, including all retained execution attempts.
/// Reusing a recording journal does not reset its retained-evidence budget.
/// Zero is a valid deny-all limit. This does not replace provider I/O limits or
/// the engine's heap budget, and does not bound caller-owned replay decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostEffectJournalLimits {
    pub max_entries: usize,
    pub max_encoded_bytes: usize,
}

impl Default for HostEffectJournalLimits {
    fn default() -> Self {
        Self {
            max_entries: 65_536,
            max_encoded_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
pub(super) struct JournalBudget {
    limits: HostEffectJournalLimits,
    retained_bytes: usize,
}

pub(super) struct Admission {
    pub(super) charge: usize,
    retained_after: usize,
}

impl JournalBudget {
    pub(super) fn new(limits: HostEffectJournalLimits) -> Self {
        Self {
            limits,
            retained_bytes: 0,
        }
    }

    pub(super) fn limits(&self) -> HostEffectJournalLimits {
        self.limits
    }

    pub(super) fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub(super) fn check_count(&self, count: usize) -> Result<(), HostEffectJournalError> {
        if count > self.limits.max_entries {
            return Err(HostEffectJournalError::Lifecycle {
                detail: format!(
                    "journal entry capacity exceeded (limit={})",
                    self.limits.max_entries
                ),
            });
        }
        Ok(())
    }

    /// Stage an exact replacement charge without mutating accounting. The
    /// caller holds the journal state/slot/budget locks until commit, and must
    /// leave both the old slot and accounting untouched on any refusal.
    pub(super) fn prepare_replacement<T: Serialize>(
        &self,
        previous_charge: usize,
        payload: &T,
    ) -> Result<Admission, HostEffectJournalError> {
        let retained = self
            .retained_bytes
            .checked_sub(previous_charge)
            .ok_or_else(|| HostEffectJournalError::Lifecycle {
                detail: "journal accounting does not cover its reservation".to_string(),
            })?;
        let available = self
            .limits
            .max_encoded_bytes
            .checked_sub(retained)
            .ok_or_else(|| HostEffectJournalError::Lifecycle {
                detail: "journal retained bytes exceed configured capacity".to_string(),
            })?;
        let mut counter = BoundedCounter {
            remaining: available,
            written: 0,
            exceeded: false,
        };
        if serde_json::to_writer(&mut counter, payload).is_err() {
            return Err(HostEffectJournalError::Lifecycle {
                detail: if counter.exceeded {
                    format!(
                        "journal byte capacity exceeded (limit={})",
                        self.limits.max_encoded_bytes
                    )
                } else {
                    "journal payload encoding failed".to_string()
                },
            });
        }
        // The counter admits only writes that fit in `available`, so addition
        // is bounded by max_encoded_bytes even at usize::MAX.
        Ok(Admission {
            charge: counter.written,
            retained_after: retained + counter.written,
        })
    }

    pub(super) fn commit(&mut self, admission: Admission) {
        self.retained_bytes = admission.retained_after;
    }
}

struct BoundedCounter {
    remaining: usize,
    written: usize,
    exceeded: bool,
}

impl Write for BoundedCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other("journal byte capacity exceeded"));
        }
        self.remaining -= bytes.len();
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) enum RequestRef<'a> {
    HostIo(&'a HostIoRequest),
    ProcessSpawn(&'a ProcessSpawnRequest),
}

impl Serialize for RequestRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::HostIo(request) => request.serialize(serializer),
            Self::ProcessSpawn(request) => request.serialize(serializer),
        }
    }
}

impl RequestRef<'_> {
    pub(super) fn into_owned(self) -> HostEffectJournalRequest {
        match self {
            Self::HostIo(request) => HostEffectJournalRequest::HostIo(request.clone()),
            Self::ProcessSpawn(request) => HostEffectJournalRequest::ProcessSpawn(request.clone()),
        }
    }

    pub(super) fn matches(self, owned: &HostEffectJournalRequest) -> bool {
        match (self, owned) {
            (Self::HostIo(actual), HostEffectJournalRequest::HostIo(expected)) => {
                actual == expected
            }
            (Self::ProcessSpawn(actual), HostEffectJournalRequest::ProcessSpawn(expected)) => {
                actual == expected
            }
            _ => false,
        }
    }

    pub(super) const fn family(self) -> &'static str {
        match self {
            Self::HostIo(_) => "host_io",
            Self::ProcessSpawn(_) => "process_spawn",
        }
    }

    pub(super) fn kind(self) -> &'static str {
        match self {
            Self::HostIo(request) => request.kind(),
            Self::ProcessSpawn(request) => request.kind(),
        }
    }
}

/// Same encoding as the owned entry, without cloning a provider result before
/// journal admission. The parity regression below pins this wire equivalence.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case", tag = "effect_family")]
pub(super) enum EntryRef<'a> {
    HostIo {
        request: &'a HostIoRequest,
        outcome: &'a HostIoOutcome,
    },
    ProcessSpawn {
        request: &'a ProcessSpawnRequest,
        outcome: &'a ProcessSpawnOutcome,
    },
}

impl<'a> EntryRef<'a> {
    pub(super) fn request(self) -> RequestRef<'a> {
        match self {
            Self::HostIo { request, .. } => RequestRef::HostIo(request),
            Self::ProcessSpawn { request, .. } => RequestRef::ProcessSpawn(request),
        }
    }

    pub(super) fn into_owned(self) -> HostEffectJournalEntry {
        match self {
            Self::HostIo { request, outcome } => HostEffectJournalEntry::HostIo {
                request: request.clone(),
                outcome: outcome.clone(),
            },
            Self::ProcessSpawn { request, outcome } => HostEffectJournalEntry::ProcessSpawn {
                request: request.clone(),
                outcome: outcome.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_effect_journal::{HostEffectJournalAttemptRecord, InMemoryHostEffectJournal};
    use crate::host_io::{HostIoError, HostIoResponse};
    use crate::process_spawn::{ProcessExit, ProcessLaunch, ProcessSpawnResponse, ProcessStdio};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn request() -> HostIoRequest {
        HostIoRequest::FsRead {
            path: "input.txt".into(),
        }
    }

    fn outcome() -> HostIoOutcome {
        Ok(HostIoResponse::FsRead {
            bytes: b"data".to_vec(),
        })
    }

    fn process_request() -> ProcessSpawnRequest {
        ProcessSpawnRequest::Run {
            launch: ProcessLaunch {
                executable: "/usr/bin/true".into(),
                argv: Vec::new(),
                env: BTreeMap::new(),
                cwd: None,
                shell: false,
                stdio: ProcessStdio::default(),
            },
            stdin: Vec::new(),
            timeout_millis: Some(100),
        }
    }

    fn limits(entries: usize, bytes: usize) -> HostEffectJournalLimits {
        HostEffectJournalLimits {
            max_entries: entries,
            max_encoded_bytes: bytes,
        }
    }

    fn entry_size() -> usize {
        serde_json::to_vec(&HostEffectJournalEntry::HostIo {
            request: request(),
            outcome: outcome(),
        })
        .unwrap()
        .len()
    }

    #[test]
    fn borrowed_entries_match_owned_wire_bytes_for_both_families_and_failures() {
        let request = request();
        for outcome in [
            outcome(),
            Err(HostIoError::Denied {
                reason: "denied\n\"quoted\"".into(),
            }),
        ] {
            let borrowed = EntryRef::HostIo {
                request: &request,
                outcome: &outcome,
            };
            assert_eq!(
                serde_json::to_vec(&borrowed).unwrap(),
                serde_json::to_vec(&borrowed.into_owned()).unwrap()
            );
        }
        let request = process_request();
        let outcome = Ok(ProcessSpawnResponse::Run {
            exit: ProcessExit {
                success: true,
                code: Some(0),
                signal: None,
            },
            stdout: vec![0, 127, 255],
            stderr: Vec::new(),
        });
        let borrowed = EntryRef::ProcessSpawn {
            request: &request,
            outcome: &outcome,
        };
        assert_eq!(
            serde_json::to_vec(&borrowed).unwrap(),
            serde_json::to_vec(&borrowed.into_owned()).unwrap()
        );
    }

    #[test]
    fn exact_byte_limit_allows_completion_and_replay_without_double_charging() {
        let journal = InMemoryHostEffectJournal::recording_with_limits(limits(1, entry_size()));
        journal.begin_execution().unwrap();
        journal.record_host_io(&request(), &outcome()).unwrap();
        assert_eq!(journal.retained_encoded_bytes(), entry_size());
        let entries = journal.finish_execution().unwrap();
        let replay = InMemoryHostEffectJournal::replaying_with_limits(
            entries.clone(),
            limits(1, entry_size()),
        )
        .unwrap();
        replay.begin_execution().unwrap();
        assert_eq!(replay.replay_host_io(&request()), Some(outcome()));
        assert_eq!(replay.finish_execution().unwrap(), entries);
    }

    #[test]
    fn denied_reservation_never_enters_the_transcript() {
        for policy in [limits(0, 10_000), limits(10, 0)] {
            let journal = InMemoryHostEffectJournal::recording_with_limits(policy);
            journal.begin_execution().unwrap();
            let error = journal.reserve_host_io(&request()).unwrap_err();
            assert!(journal.attempt_records().is_empty());
            assert_eq!(journal.retained_encoded_bytes(), 0);
            assert_eq!(journal.finish_execution(), Err(error));
        }
    }

    #[test]
    fn request_admission_obeys_exact_encoded_boundary() {
        let size = serde_json::to_vec(&request()).unwrap().len();
        for max_bytes in [size - 1, size] {
            let journal = InMemoryHostEffectJournal::recording_with_limits(limits(1, max_bytes));
            journal.begin_execution().unwrap();
            assert_eq!(
                journal.reserve_host_io(&request()).is_ok(),
                max_bytes == size
            );
            assert_eq!(
                journal.retained_encoded_bytes(),
                if max_bytes == size { size } else { 0 }
            );
        }
    }

    #[test]
    fn oversized_outcome_retains_a_hole_and_does_not_hide_later_completions() {
        let journal = InMemoryHostEffectJournal::recording_with_limits(limits(2, entry_size() * 2));
        journal.begin_execution().unwrap();
        let first = journal.reserve_host_io(&request()).unwrap();
        let second = journal.reserve_host_io(&request()).unwrap();
        let before = journal.retained_encoded_bytes();
        let large = Ok(HostIoResponse::FsRead {
            bytes: vec![255; entry_size() * 4],
        });
        let error = journal
            .complete_host_io(first, &request(), &large)
            .unwrap_err();
        assert_eq!(journal.retained_encoded_bytes(), before);
        journal
            .complete_host_io(second, &request(), &outcome())
            .unwrap();
        assert!(journal.attempt_entries().is_empty());
        assert!(matches!(
            journal.attempt_records().as_slice(),
            [
                HostEffectJournalAttemptRecord::Uncompleted { sequence: 0, .. },
                HostEffectJournalAttemptRecord::Completed { sequence: 1, .. }
            ]
        ));
        assert_eq!(journal.finish_execution(), Err(error));
    }

    #[test]
    fn process_rebinding_replaces_the_charge_instead_of_accumulating_it() {
        let original = process_request();
        let size = serde_json::to_vec(&original).unwrap().len();
        let journal = InMemoryHostEffectJournal::recording_with_limits(limits(1, size));
        journal.begin_execution().unwrap();
        let mut reservation = journal.reserve_process_spawn(&original).unwrap();
        for _ in 0..10 {
            reservation = journal
                .bind_prepared_process_spawn(reservation, &original)
                .unwrap();
            assert_eq!(journal.retained_encoded_bytes(), size);
        }
        let mut enlarged = original.clone();
        if let ProcessSpawnRequest::Run { stdin, .. } = &mut enlarged {
            *stdin = vec![42; 100];
        }
        let before = journal.attempt_records();
        assert!(
            journal
                .bind_prepared_process_spawn(reservation, &enlarged)
                .is_err()
        );
        assert_eq!(journal.retained_encoded_bytes(), size);
        assert_eq!(journal.attempt_records(), before);
    }

    #[test]
    fn replay_rejects_oversized_inputs_before_becoming_usable() {
        let entry = HostEffectJournalEntry::HostIo {
            request: request(),
            outcome: outcome(),
        };
        for policy in [limits(0, entry_size()), limits(1, entry_size() - 1)] {
            assert!(
                InMemoryHostEffectJournal::replaying_with_limits(vec![entry.clone()], policy)
                    .is_err()
            );
        }
    }

    #[test]
    fn concurrent_reservation_admission_cannot_overrun_the_entry_limit() {
        let journal = Arc::new(InMemoryHostEffectJournal::recording_with_limits(limits(
            3, 100_000,
        )));
        journal.begin_execution().unwrap();
        let reservations: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..12)
                .map(|_| {
                    let journal = Arc::clone(&journal);
                    scope.spawn(move || journal.reserve_host_io(&request()))
                })
                .collect();
            handles
                .into_iter()
                .filter_map(|handle| handle.join().unwrap().ok())
                .collect()
        });
        assert_eq!(reservations.len(), 3);
        for reservation in reservations {
            journal
                .complete_host_io(reservation, &request(), &outcome())
                .unwrap();
        }
        assert_eq!(journal.entries().len(), 3);
        assert_eq!(journal.retained_encoded_bytes(), entry_size() * 3);
        assert!(journal.finish_execution().is_err());
    }

    #[test]
    fn lifetime_budget_is_not_reset_between_recording_attempts() {
        let journal = InMemoryHostEffectJournal::recording_with_limits(limits(1, 100_000));
        journal.begin_execution().unwrap();
        journal.record_host_io(&request(), &outcome()).unwrap();
        let first = journal.finish_execution().unwrap();
        journal.begin_execution().unwrap();
        assert!(journal.reserve_host_io(&request()).is_err());
        assert_eq!(journal.entries(), first);
        assert_eq!(journal.retained_encoded_bytes(), entry_size());
    }

    #[test]
    fn rejected_measurement_does_not_mutate_accounting() {
        let mut budget = JournalBudget::new(limits(1, 20));
        let admission = budget.prepare_replacement(0, &"small").unwrap();
        budget.commit(admission);
        let before = budget.retained_bytes();
        assert!(
            budget
                .prepare_replacement(0, &"much too large a payload")
                .is_err()
        );
        assert!(budget.prepare_replacement(before + 1, &"x").is_err());
        assert_eq!(budget.retained_bytes(), before);
        let admission = budget.prepare_replacement(before, &"x").unwrap();
        budget.commit(admission);
        assert_eq!(budget.retained_bytes(), 3);
    }
}
