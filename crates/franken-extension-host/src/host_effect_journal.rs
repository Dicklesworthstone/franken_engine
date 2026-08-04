//! Globally ordered recording and replay for extension-host effects.
//!
//! Filesystem/network I/O and process creation retain separate provider traits,
//! capability types, and policies. This journal is the narrow shared layer that
//! commits their actual crossing order. Keeping two independent transcripts and
//! concatenating them after execution would forge the order of interleaved
//! effects and make replay weaker than the recorded run.

#![forbid(unsafe_code)]

use crate::host_io::{HostIoError, HostIoOutcome, HostIoRequest};
use crate::process_spawn::{ProcessSpawnError, ProcessSpawnOutcome, ProcessSpawnRequest};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Mutex;

/// One globally ordered extension-host effect and its exact typed outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "effect_family", deny_unknown_fields)]
pub enum HostEffectJournalEntry {
    HostIo {
        request: HostIoRequest,
        outcome: HostIoOutcome,
    },
    ProcessSpawn {
        request: ProcessSpawnRequest,
        outcome: ProcessSpawnOutcome,
    },
}

impl HostEffectJournalEntry {
    #[must_use]
    pub const fn family(&self) -> &'static str {
        match self {
            Self::HostIo { .. } => "host_io",
            Self::ProcessSpawn { .. } => "process_spawn",
        }
    }

    #[must_use]
    pub fn request_kind(&self) -> &'static str {
        match self {
            Self::HostIo { request, .. } => request.kind(),
            Self::ProcessSpawn { request, .. } => request.kind(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostEffectJournalMode {
    Record,
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEffectJournalError {
    Lifecycle {
        detail: String,
    },
    ReplayDivergence {
        index: usize,
        expected_family: String,
        expected_kind: String,
        live_family: String,
        live_kind: String,
    },
    UnusedReplaySuffix {
        index: usize,
        remaining: usize,
    },
}

impl fmt::Display for HostEffectJournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lifecycle { detail } => {
                write!(f, "host-effect journal lifecycle error: {detail}")
            }
            Self::ReplayDivergence {
                index,
                expected_family,
                expected_kind,
                live_family,
                live_kind,
            } => write!(
                f,
                "host-effect replay divergence at index {index}: expected {expected_family}:{expected_kind}, got {live_family}:{live_kind}"
            ),
            Self::UnusedReplaySuffix { index, remaining } => write!(
                f,
                "host-effect replay finished with {remaining} unused entries starting at index {index}"
            ),
        }
    }
}

impl std::error::Error for HostEffectJournalError {}

#[derive(Debug, Default)]
enum JournalState {
    #[default]
    Idle,
    Recording {
        start: usize,
    },
    Replaying {
        cursor: usize,
    },
    Finalized,
    Poisoned(HostEffectJournalError),
}

#[derive(Debug, Clone)]
enum JournalSlot {
    Reserved(HostEffectJournalRequest),
    Completed(HostEffectJournalEntry),
}

/// Exact request retained behind an opaque reservation. Completion must present
/// the same value, not merely another request in the same effect family.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostEffectJournalRequest {
    HostIo(HostIoRequest),
    ProcessSpawn(ProcessSpawnRequest),
}

impl HostEffectJournalRequest {
    const fn family(&self) -> &'static str {
        match self {
            Self::HostIo(_) => "host_io",
            Self::ProcessSpawn(_) => "process_spawn",
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::HostIo(request) => request.kind(),
            Self::ProcessSpawn(request) => request.kind(),
        }
    }

    fn matches_entry(&self, entry: &HostEffectJournalEntry) -> bool {
        match (self, entry) {
            (
                Self::HostIo(expected),
                HostEffectJournalEntry::HostIo {
                    request: actual, ..
                },
            ) => expected == actual,
            (
                Self::ProcessSpawn(expected),
                HostEffectJournalEntry::ProcessSpawn {
                    request: actual, ..
                },
            ) => expected == actual,
            _ => false,
        }
    }
}

/// Opaque proof that the journal accepted an effect crossing before the live
/// provider ran. Completing reservations out of order is safe: finalized
/// entries retain reservation (crossing) order rather than completion order.
#[derive(Debug)]
pub struct HostEffectJournalReservation {
    index: usize,
    request: HostEffectJournalRequest,
}

/// Exact-match, globally ordered transcript for one or more executions.
///
/// Recording journals may be reused; each execution returns only its appended
/// suffix. Replay journals are single-use and reject request mutation, family
/// reordering, and unused suffixes before evidence can be certified.
#[derive(Debug)]
pub struct InMemoryHostEffectJournal {
    mode: HostEffectJournalMode,
    entries: Mutex<Vec<JournalSlot>>,
    state: Mutex<JournalState>,
    attempt_entries: Mutex<Vec<HostEffectJournalEntry>>,
    attempt_record_start: Mutex<usize>,
}

impl InMemoryHostEffectJournal {
    #[must_use]
    pub fn recording() -> Self {
        Self {
            mode: HostEffectJournalMode::Record,
            entries: Mutex::new(Vec::new()),
            state: Mutex::new(JournalState::Idle),
            attempt_entries: Mutex::new(Vec::new()),
            attempt_record_start: Mutex::new(0),
        }
    }

    #[must_use]
    pub fn replaying(entries: Vec<HostEffectJournalEntry>) -> Self {
        Self {
            mode: HostEffectJournalMode::Replay,
            entries: Mutex::new(entries.into_iter().map(JournalSlot::Completed).collect()),
            state: Mutex::new(JournalState::Idle),
            attempt_entries: Mutex::new(Vec::new()),
            attempt_record_start: Mutex::new(0),
        }
    }

    pub fn begin_execution(&self) -> Result<(), HostEffectJournalError> {
        let mut state = self.state.lock().expect("host-effect journal state mutex");
        match &*state {
            JournalState::Idle => {
                self.attempt_entries
                    .lock()
                    .expect("host-effect attempt mutex")
                    .clear();
                *state = match self.mode {
                    HostEffectJournalMode::Record => {
                        let start = self
                            .entries
                            .lock()
                            .expect("host-effect journal mutex")
                            .len();
                        *self
                            .attempt_record_start
                            .lock()
                            .expect("host-effect attempt boundary mutex") = start;
                        JournalState::Recording { start }
                    }
                    HostEffectJournalMode::Replay => JournalState::Replaying { cursor: 0 },
                };
                Ok(())
            }
            JournalState::Poisoned(error) => Err(error.clone()),
            JournalState::Finalized => Err(HostEffectJournalError::Lifecycle {
                detail: "replay journal already finalized".to_string(),
            }),
            JournalState::Recording { .. } | JournalState::Replaying { .. } => {
                Err(HostEffectJournalError::Lifecycle {
                    detail: "execution already active".to_string(),
                })
            }
        }
    }

    /// In replay mode, consume the next exact host-I/O entry. Returning `Some`
    /// means the live provider must not run.
    pub fn replay_host_io(&self, request: &HostIoRequest) -> Option<HostIoOutcome> {
        if self.mode != HostEffectJournalMode::Replay {
            return None;
        }
        match self.consume_replay("host_io", request.kind(), |entry| {
            matches!(entry, HostEffectJournalEntry::HostIo { request: recorded, .. } if recorded == request)
        }) {
            Ok(HostEffectJournalEntry::HostIo { outcome, .. }) => Some(outcome),
            Ok(HostEffectJournalEntry::ProcessSpawn { .. }) => unreachable!("family checked"),
            Err(error) => Some(Err(HostIoError::Denied {
                reason: error.to_string(),
            })),
        }
    }

    pub fn reserve_host_io(
        &self,
        request: &HostIoRequest,
    ) -> Result<HostEffectJournalReservation, HostEffectJournalError> {
        self.reserve(HostEffectJournalRequest::HostIo(request.clone()))
    }

    pub fn complete_host_io(
        &self,
        reservation: HostEffectJournalReservation,
        request: &HostIoRequest,
        outcome: &HostIoOutcome,
    ) -> Result<(), HostEffectJournalError> {
        self.complete(
            reservation,
            HostEffectJournalEntry::HostIo {
                request: request.clone(),
                outcome: outcome.clone(),
            },
        )
    }

    pub fn record_host_io(
        &self,
        request: &HostIoRequest,
        outcome: &HostIoOutcome,
    ) -> Result<(), HostEffectJournalError> {
        let reservation = self.reserve_host_io(request)?;
        self.complete_host_io(reservation, request, outcome)
    }

    /// In replay mode, consume the next exact process entry. Returning `Some`
    /// means the live provider must not run.
    pub fn replay_process_spawn(
        &self,
        request: &ProcessSpawnRequest,
    ) -> Option<ProcessSpawnOutcome> {
        if self.mode != HostEffectJournalMode::Replay {
            return None;
        }
        match self.consume_replay("process_spawn", request.kind(), |entry| {
            matches!(entry, HostEffectJournalEntry::ProcessSpawn { request: recorded, .. } if recorded == request)
        }) {
            Ok(HostEffectJournalEntry::ProcessSpawn { outcome, .. }) => Some(outcome),
            Ok(HostEffectJournalEntry::HostIo { .. }) => unreachable!("family checked"),
            Err(error) => Some(Err(ProcessSpawnError::ReplayDivergence {
                index: replay_error_index(&error),
                live_kind: request.kind().to_string(),
                recorded_kind: replay_error_expected(&error),
            })),
        }
    }

    pub fn reserve_process_spawn(
        &self,
        request: &ProcessSpawnRequest,
    ) -> Result<HostEffectJournalReservation, HostEffectJournalError> {
        self.reserve(HostEffectJournalRequest::ProcessSpawn(request.clone()))
    }

    pub fn complete_process_spawn(
        &self,
        reservation: HostEffectJournalReservation,
        request: &ProcessSpawnRequest,
        outcome: &ProcessSpawnOutcome,
    ) -> Result<(), HostEffectJournalError> {
        self.complete(
            reservation,
            HostEffectJournalEntry::ProcessSpawn {
                request: request.clone(),
                outcome: outcome.clone(),
            },
        )
    }

    pub fn record_process_spawn(
        &self,
        request: &ProcessSpawnRequest,
        outcome: &ProcessSpawnOutcome,
    ) -> Result<(), HostEffectJournalError> {
        let reservation = self.reserve_process_spawn(request)?;
        self.complete_process_spawn(reservation, request, outcome)
    }

    pub fn finish_execution(&self) -> Result<Vec<HostEffectJournalEntry>, HostEffectJournalError> {
        let mut state = self.state.lock().expect("host-effect journal state mutex");
        let entries = self.entries.lock().expect("host-effect journal mutex");
        match &*state {
            JournalState::Recording { start } => {
                let slots =
                    entries
                        .get(*start..)
                        .ok_or_else(|| HostEffectJournalError::Lifecycle {
                            detail: "recording boundary exceeds journal length".to_string(),
                        })?;
                let current = match completed_entries(slots) {
                    Ok(current) => current,
                    Err(error) => {
                        *state = JournalState::Poisoned(error.clone());
                        return Err(error);
                    }
                };
                *state = JournalState::Idle;
                Ok(current)
            }
            JournalState::Replaying { cursor } if *cursor == entries.len() => {
                let current = match completed_entries(&entries) {
                    Ok(current) => current,
                    Err(error) => {
                        *state = JournalState::Poisoned(error.clone());
                        return Err(error);
                    }
                };
                *state = JournalState::Finalized;
                Ok(current)
            }
            JournalState::Replaying { cursor } => {
                let error = HostEffectJournalError::UnusedReplaySuffix {
                    index: *cursor,
                    remaining: entries.len().saturating_sub(*cursor),
                };
                *state = JournalState::Poisoned(error.clone());
                Err(error)
            }
            JournalState::Poisoned(error) => Err(error.clone()),
            JournalState::Finalized => Err(HostEffectJournalError::Lifecycle {
                detail: "replay journal already finalized".to_string(),
            }),
            JournalState::Idle => Err(HostEffectJournalError::Lifecycle {
                detail: "execution was not begun".to_string(),
            }),
        }
    }

    #[must_use]
    pub fn entries(&self) -> Vec<HostEffectJournalEntry> {
        self.entries
            .lock()
            .expect("host-effect journal mutex")
            .iter()
            .filter_map(|slot| match slot {
                JournalSlot::Completed(entry) => Some(entry.clone()),
                JournalSlot::Reserved(_) => None,
            })
            .collect()
    }

    /// Completed effects from the current or most recently failed execution
    /// attempt. Unlike `finish_execution`, this remains available after replay
    /// divergence, an unused suffix, or an incomplete recording reservation so
    /// callers can still issue failure receipts for the performed prefix.
    #[must_use]
    pub fn attempt_entries(&self) -> Vec<HostEffectJournalEntry> {
        self.attempt_entries
            .lock()
            .expect("host-effect attempt mutex")
            .clone()
    }

    fn consume_replay(
        &self,
        live_family: &str,
        live_kind: &str,
        matches_request: impl FnOnce(&HostEffectJournalEntry) -> bool,
    ) -> Result<HostEffectJournalEntry, HostEffectJournalError> {
        let mut state = self.state.lock().expect("host-effect journal state mutex");
        let cursor = match &*state {
            JournalState::Replaying { cursor } => *cursor,
            JournalState::Poisoned(error) => return Err(error.clone()),
            JournalState::Idle => {
                let error = HostEffectJournalError::Lifecycle {
                    detail: "replay attempted before begin_execution".to_string(),
                };
                *state = JournalState::Poisoned(error.clone());
                return Err(error);
            }
            JournalState::Finalized => {
                return Err(HostEffectJournalError::Lifecycle {
                    detail: "replay journal already finalized".to_string(),
                });
            }
            JournalState::Recording { .. } => {
                return Err(HostEffectJournalError::Lifecycle {
                    detail: "replay requested from a recording journal".to_string(),
                });
            }
        };
        let entries = self.entries.lock().expect("host-effect journal mutex");
        let Some(slot) = entries.get(cursor) else {
            let error = HostEffectJournalError::ReplayDivergence {
                index: cursor,
                expected_family: "end_of_transcript".to_string(),
                expected_kind: "end_of_transcript".to_string(),
                live_family: live_family.to_string(),
                live_kind: live_kind.to_string(),
            };
            *state = JournalState::Poisoned(error.clone());
            return Err(error);
        };
        let JournalSlot::Completed(entry) = slot else {
            let error = HostEffectJournalError::Lifecycle {
                detail: format!("replay entry {cursor} is incomplete"),
            };
            *state = JournalState::Poisoned(error.clone());
            return Err(error);
        };
        if !matches_request(entry) {
            let error = HostEffectJournalError::ReplayDivergence {
                index: cursor,
                expected_family: entry.family().to_string(),
                expected_kind: entry.request_kind().to_string(),
                live_family: live_family.to_string(),
                live_kind: live_kind.to_string(),
            };
            *state = JournalState::Poisoned(error.clone());
            return Err(error);
        }
        let entry = entry.clone();
        *state = JournalState::Replaying { cursor: cursor + 1 };
        self.attempt_entries
            .lock()
            .expect("host-effect attempt mutex")
            .push(entry.clone());
        Ok(entry)
    }

    fn reserve(
        &self,
        request: HostEffectJournalRequest,
    ) -> Result<HostEffectJournalReservation, HostEffectJournalError> {
        if self.mode != HostEffectJournalMode::Record {
            return Err(HostEffectJournalError::Lifecycle {
                detail: "record reservation requested from a replay journal".to_string(),
            });
        }
        let mut state = self.state.lock().expect("host-effect journal state mutex");
        if matches!(&*state, JournalState::Recording { .. }) {
            let mut entries = self.entries.lock().expect("host-effect journal mutex");
            let index = entries.len();
            entries.push(JournalSlot::Reserved(request.clone()));
            Ok(HostEffectJournalReservation { index, request })
        } else {
            let error = HostEffectJournalError::Lifecycle {
                detail: "record reservation attempted outside an active execution".to_string(),
            };
            *state = JournalState::Poisoned(error.clone());
            Err(error)
        }
    }

    fn complete(
        &self,
        reservation: HostEffectJournalReservation,
        entry: HostEffectJournalEntry,
    ) -> Result<(), HostEffectJournalError> {
        let mut state = self.state.lock().expect("host-effect journal state mutex");
        if !matches!(&*state, JournalState::Recording { .. }) {
            let error = HostEffectJournalError::Lifecycle {
                detail: "record completion attempted outside an active execution".to_string(),
            };
            *state = JournalState::Poisoned(error.clone());
            return Err(error);
        }
        let mut entries = self.entries.lock().expect("host-effect journal mutex");
        let Some(slot) = entries.get_mut(reservation.index) else {
            let error = HostEffectJournalError::Lifecycle {
                detail: format!("record reservation {} is missing", reservation.index),
            };
            *state = JournalState::Poisoned(error.clone());
            return Err(error);
        };
        if !matches!(slot, JournalSlot::Reserved(request)
            if request == &reservation.request && request.matches_entry(&entry))
        {
            let error = HostEffectJournalError::Lifecycle {
                detail: format!(
                    "record reservation {} does not match completion",
                    reservation.index
                ),
            };
            *state = JournalState::Poisoned(error.clone());
            return Err(error);
        }
        *slot = JournalSlot::Completed(entry);
        let start = *self
            .attempt_record_start
            .lock()
            .expect("host-effect attempt boundary mutex");
        let completed = entries
            .get(start..)
            .unwrap_or_default()
            .iter()
            .map_while(|slot| match slot {
                JournalSlot::Completed(entry) => Some(entry.clone()),
                JournalSlot::Reserved(_) => None,
            })
            .collect();
        *self
            .attempt_entries
            .lock()
            .expect("host-effect attempt mutex") = completed;
        Ok(())
    }
}

fn completed_entries(
    slots: &[JournalSlot],
) -> Result<Vec<HostEffectJournalEntry>, HostEffectJournalError> {
    slots
        .iter()
        .enumerate()
        .map(|(index, slot)| match slot {
            JournalSlot::Completed(entry) => Ok(entry.clone()),
            JournalSlot::Reserved(request) => Err(HostEffectJournalError::Lifecycle {
                detail: format!(
                    "effect reservation {index} ({}:{}) was not completed",
                    request.family(),
                    request.kind()
                ),
            }),
        })
        .collect()
}

fn replay_error_index(error: &HostEffectJournalError) -> usize {
    match error {
        HostEffectJournalError::ReplayDivergence { index, .. }
        | HostEffectJournalError::UnusedReplaySuffix { index, .. } => *index,
        HostEffectJournalError::Lifecycle { .. } => 0,
    }
}

fn replay_error_expected(error: &HostEffectJournalError) -> String {
    match error {
        HostEffectJournalError::ReplayDivergence {
            expected_family,
            expected_kind,
            ..
        } => format!("{expected_family}:{expected_kind}"),
        _ => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_io::{HostIoCapability, HostIoResponse};
    use crate::process_spawn::{
        ProcessExit, ProcessLaunch, ProcessSpawnCapability, ProcessSpawnResponse, ProcessStdio,
    };
    use std::collections::BTreeMap;

    fn fs_request() -> HostIoRequest {
        HostIoRequest::FsRead {
            path: "input.txt".to_string(),
        }
    }

    fn process_request() -> ProcessSpawnRequest {
        ProcessSpawnRequest::Run {
            launch: ProcessLaunch {
                executable: "/usr/bin/true".to_string(),
                argv: Vec::new(),
                env: BTreeMap::new(),
                cwd: Some("/".to_string()),
                shell: false,
                stdio: ProcessStdio::default(),
            },
            stdin: Vec::new(),
            timeout_millis: Some(100),
        }
    }

    fn fs_outcome() -> HostIoOutcome {
        Ok(HostIoResponse::FsRead {
            bytes: b"data".to_vec(),
        })
    }

    fn process_outcome() -> ProcessSpawnOutcome {
        Ok(ProcessSpawnResponse::Run {
            exit: ProcessExit {
                success: true,
                code: Some(0),
                signal: None,
            },
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }

    #[test]
    fn record_preserves_interleaved_effect_order() {
        let journal = InMemoryHostEffectJournal::recording();
        journal.begin_execution().unwrap();
        journal
            .record_host_io(&fs_request(), &fs_outcome())
            .unwrap();
        journal
            .record_process_spawn(&process_request(), &process_outcome())
            .unwrap();
        journal
            .record_host_io(&fs_request(), &fs_outcome())
            .unwrap();
        let entries = journal.finish_execution().unwrap();
        assert!(matches!(entries[0], HostEffectJournalEntry::HostIo { .. }));
        assert!(matches!(
            entries[1],
            HostEffectJournalEntry::ProcessSpawn { .. }
        ));
        assert!(matches!(entries[2], HostEffectJournalEntry::HostIo { .. }));
    }

    #[test]
    fn reservations_preserve_crossing_order_when_completion_reorders() {
        let journal = InMemoryHostEffectJournal::recording();
        journal.begin_execution().unwrap();
        let first = journal.reserve_host_io(&fs_request()).unwrap();
        let second = journal.reserve_process_spawn(&process_request()).unwrap();
        journal
            .complete_process_spawn(second, &process_request(), &process_outcome())
            .unwrap();
        assert!(
            journal.attempt_entries().is_empty(),
            "a later completion must not leapfrog an earlier reserved crossing"
        );
        journal
            .complete_host_io(first, &fs_request(), &fs_outcome())
            .unwrap();

        assert_eq!(journal.attempt_entries(), journal.entries());

        let entries = journal.finish_execution().unwrap();
        assert!(matches!(entries[0], HostEffectJournalEntry::HostIo { .. }));
        assert!(matches!(
            entries[1],
            HostEffectJournalEntry::ProcessSpawn { .. }
        ));
    }

    #[test]
    fn failed_recording_exposes_only_the_contiguous_completed_prefix() {
        let journal = InMemoryHostEffectJournal::recording();
        journal.begin_execution().unwrap();
        let _first = journal.reserve_host_io(&fs_request()).unwrap();
        let second = journal.reserve_process_spawn(&process_request()).unwrap();
        journal
            .complete_process_spawn(second, &process_request(), &process_outcome())
            .unwrap();

        assert!(journal.attempt_entries().is_empty());
        assert!(matches!(
            journal.finish_execution(),
            Err(HostEffectJournalError::Lifecycle { .. })
        ));
        assert!(journal.attempt_entries().is_empty());
    }

    #[test]
    fn reservation_rejects_same_kind_request_mutation() {
        let journal = InMemoryHostEffectJournal::recording();
        journal.begin_execution().unwrap();
        let reservation = journal.reserve_host_io(&fs_request()).unwrap();
        let mutated = HostIoRequest::FsRead {
            path: "different.txt".to_string(),
        };
        let error = journal
            .complete_host_io(reservation, &mutated, &fs_outcome())
            .unwrap_err();
        assert!(matches!(error, HostEffectJournalError::Lifecycle { .. }));
        assert_eq!(journal.finish_execution(), Err(error));
    }

    #[test]
    fn reservation_fails_before_any_provider_can_run_without_execution_boundary() {
        let journal = InMemoryHostEffectJournal::recording();
        let error = journal
            .reserve_process_spawn(&process_request())
            .unwrap_err();
        assert!(matches!(error, HostEffectJournalError::Lifecycle { .. }));
        assert!(journal.entries().is_empty());
    }

    #[test]
    fn finalization_rejects_an_uncompleted_effect_crossing() {
        let journal = InMemoryHostEffectJournal::recording();
        journal.begin_execution().unwrap();
        let _reservation = journal.reserve_host_io(&fs_request()).unwrap();
        let error = journal.finish_execution().unwrap_err();
        assert!(matches!(error, HostEffectJournalError::Lifecycle { .. }));
    }

    #[test]
    fn replay_rejects_family_reordering_before_live_effects() {
        let journal = InMemoryHostEffectJournal::replaying(vec![
            HostEffectJournalEntry::HostIo {
                request: fs_request(),
                outcome: fs_outcome(),
            },
            HostEffectJournalEntry::ProcessSpawn {
                request: process_request(),
                outcome: process_outcome(),
            },
        ]);
        journal.begin_execution().unwrap();
        assert!(matches!(
            journal.replay_process_spawn(&process_request()),
            Some(Err(ProcessSpawnError::ReplayDivergence { index: 0, .. }))
        ));
        assert!(journal.finish_execution().is_err());
    }

    #[test]
    fn replay_returns_exact_typed_outcomes_and_rejects_unused_suffix() {
        let entries = vec![
            HostEffectJournalEntry::HostIo {
                request: fs_request(),
                outcome: fs_outcome(),
            },
            HostEffectJournalEntry::ProcessSpawn {
                request: process_request(),
                outcome: process_outcome(),
            },
        ];
        let exact = InMemoryHostEffectJournal::replaying(entries.clone());
        exact.begin_execution().unwrap();
        assert_eq!(exact.replay_host_io(&fs_request()), Some(fs_outcome()));
        assert_eq!(
            exact.replay_process_spawn(&process_request()),
            Some(process_outcome())
        );
        assert_eq!(exact.finish_execution().unwrap(), entries);

        let unused = InMemoryHostEffectJournal::replaying(vec![
            HostEffectJournalEntry::HostIo {
                request: fs_request(),
                outcome: fs_outcome(),
            },
            HostEffectJournalEntry::ProcessSpawn {
                request: process_request(),
                outcome: process_outcome(),
            },
        ]);
        unused.begin_execution().unwrap();
        assert_eq!(unused.replay_host_io(&fs_request()), Some(fs_outcome()));
        assert!(matches!(
            unused.finish_execution(),
            Err(HostEffectJournalError::UnusedReplaySuffix {
                index: 1,
                remaining: 1
            })
        ));
        assert_eq!(unused.attempt_entries(), vec![unused.entries()[0].clone()]);
    }

    #[test]
    fn capability_types_stay_separate_across_the_shared_journal() {
        assert_eq!(HostIoCapability::FsRead.as_str(), "fs_read");
        assert_eq!(ProcessSpawnCapability::Spawn.as_str(), "process_spawn");
    }
}
