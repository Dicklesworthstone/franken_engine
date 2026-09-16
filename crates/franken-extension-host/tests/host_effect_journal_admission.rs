//! Real host-boundary regressions for bounded effect-journal admission.
//!
//! These compose the public journal protocol with SandboxedHostIo. They do
//! not claim to exercise the JavaScript interpreter or its policy lowering.

#![forbid(unsafe_code)]

use frankenengine_extension_host::host_effect_journal::{
    HostEffectJournalAttemptRecord, HostEffectJournalEntry, HostEffectJournalError,
    HostEffectJournalLimits, InMemoryHostEffectJournal,
};
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoError, HostIoOutcome, HostIoProvider, HostIoRequest, HostIoResponse,
    SandboxedHostIo,
};

fn limits(entries: usize, bytes: usize) -> HostEffectJournalLimits {
    HostEffectJournalLimits {
        max_entries: entries,
        max_encoded_bytes: bytes,
    }
}

// Public boundary protocol: a reservation must succeed before any live
// provider effect; a completion must succeed before an outcome is reportable.
fn dispatch(
    journal: &InMemoryHostEffectJournal,
    provider: &SandboxedHostIo,
    request: &HostIoRequest,
    capabilities: &[HostIoCapability],
) -> Result<HostIoOutcome, HostEffectJournalError> {
    if let Some(recorded) = journal.replay_host_io(request) {
        return Ok(recorded);
    }
    let reservation = journal.reserve_host_io(request)?;
    let outcome = provider.perform(request, capabilities);
    journal.complete_host_io(reservation, request, &outcome)?;
    Ok(outcome)
}

fn write_request(data: &[u8]) -> HostIoRequest {
    HostIoRequest::FsWrite {
        path: "result.bin".to_string(),
        data: data.to_vec(),
    }
}

#[test]
fn exhausted_entry_capacity_prevents_a_real_file_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
    let journal = InMemoryHostEffectJournal::recording_with_limits(limits(1, 4096));
    journal.begin_execution().unwrap();
    assert_eq!(
        dispatch(
            &journal,
            &provider,
            &write_request(b"kept"),
            &[HostIoCapability::FsWrite],
        )
        .unwrap(),
        Ok(HostIoResponse::FsWrite { bytes_written: 4 })
    );
    let prefix = journal.entries();
    let error = dispatch(
        &journal,
        &provider,
        &write_request(b"must not overwrite"),
        &[HostIoCapability::FsWrite],
    )
    .unwrap_err();
    assert!(error.to_string().contains("entry capacity exceeded"));
    assert_eq!(
        std::fs::read(directory.path().join("result.bin")).unwrap(),
        b"kept"
    );
    assert_eq!(journal.entries(), prefix);
    assert_eq!(journal.attempt_records().len(), 1);
    assert_eq!(journal.finish_execution(), Err(error));
}

#[test]
fn oversized_request_is_refused_before_a_real_file_is_created() {
    let directory = tempfile::tempdir().unwrap();
    let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
    let journal = InMemoryHostEffectJournal::recording_with_limits(limits(10, 64));
    journal.begin_execution().unwrap();
    let error = dispatch(
        &journal,
        &provider,
        &write_request(&[255; 512]),
        &[HostIoCapability::FsWrite],
    )
    .unwrap_err();
    assert!(error.to_string().contains("byte capacity exceeded"));
    assert!(!directory.path().join("result.bin").exists());
    assert!(journal.attempt_records().is_empty());
    assert_eq!(journal.retained_encoded_bytes(), 0);
    assert_eq!(journal.finish_execution(), Err(error));
}

#[test]
fn oversized_real_read_outcome_is_not_a_successful_complete_trace() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("input.bin"), [255; 8192]).unwrap();
    let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
    let journal = InMemoryHostEffectJournal::recording_with_limits(limits(4, 256));
    journal.begin_execution().unwrap();
    let request = HostIoRequest::FsRead {
        path: "input.bin".to_string(),
    };
    let error = dispatch(&journal, &provider, &request, &[HostIoCapability::FsRead]).unwrap_err();
    assert!(error.to_string().contains("byte capacity exceeded"));
    assert!(journal.entries().is_empty());
    assert!(matches!(
        journal.attempt_records().as_slice(),
        [HostEffectJournalAttemptRecord::Uncompleted { sequence: 0, .. }]
    ));
    assert!(
        dispatch(
            &journal,
            &provider,
            &write_request(b"must not execute after poison"),
            &[HostIoCapability::FsWrite],
        )
        .is_err()
    );
    assert!(!directory.path().join("result.bin").exists());
    assert_eq!(journal.finish_execution(), Err(error));
}

#[test]
fn bounded_replay_returns_recorded_bytes_without_repeating_real_effects() {
    let directory = tempfile::tempdir().unwrap();
    let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
    let requests = [
        write_request(b"original"),
        HostIoRequest::FsRead {
            path: "result.bin".to_string(),
        },
    ];
    let capabilities = [HostIoCapability::FsRead, HostIoCapability::FsWrite];
    let recording = InMemoryHostEffectJournal::recording_with_limits(limits(2, 4096));
    recording.begin_execution().unwrap();
    let outcomes: Vec<_> = requests
        .iter()
        .map(|request| dispatch(&recording, &provider, request, &capabilities).unwrap())
        .collect();
    assert_eq!(
        outcomes[1],
        Ok(HostIoResponse::FsRead {
            bytes: b"original".to_vec(),
        })
    );
    let entries = recording.finish_execution().unwrap();
    let encoded = serde_json::to_vec(&entries).unwrap();
    let exact_payload_limit = entries
        .iter()
        .map(|entry| serde_json::to_vec(entry).unwrap().len())
        .sum();

    // Either an accidental replay write or a live replay read will fail the
    // assertions below: the live disk must stay different from the transcript.
    std::fs::write(
        directory.path().join("result.bin"),
        b"changed outside replay",
    )
    .unwrap();
    let replay = InMemoryHostEffectJournal::replaying_with_limits(
        serde_json::from_slice(&encoded).unwrap(),
        limits(2, exact_payload_limit),
    )
    .unwrap();
    replay.begin_execution().unwrap();
    for (request, expected) in requests.iter().zip(outcomes) {
        assert_eq!(
            dispatch(&replay, &provider, request, &capabilities).unwrap(),
            expected
        );
    }
    assert_eq!(
        std::fs::read(directory.path().join("result.bin")).unwrap(),
        b"changed outside replay"
    );
    assert_eq!(
        serde_json::to_vec(&replay.finish_execution().unwrap()).unwrap(),
        encoded
    );
}

#[test]
fn real_provider_capability_denial_is_recorded_not_promoted_to_success() {
    let directory = tempfile::tempdir().unwrap();
    let provider = SandboxedHostIo::with_root(directory.path()).unwrap();
    let journal = InMemoryHostEffectJournal::recording_with_limits(limits(1, 4096));
    journal.begin_execution().unwrap();
    assert_eq!(
        dispatch(&journal, &provider, &write_request(b"denied"), &[]).unwrap(),
        Err(HostIoError::CapabilityMissing {
            capability: HostIoCapability::FsWrite,
        })
    );
    assert!(!directory.path().join("result.bin").exists());
    assert!(matches!(
        journal.finish_execution().unwrap().as_slice(),
        [HostEffectJournalEntry::HostIo {
            outcome: Err(HostIoError::CapabilityMissing { .. }),
            ..
        }]
    ));
}
