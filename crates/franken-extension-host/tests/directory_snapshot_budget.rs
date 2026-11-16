//! Real sandboxed directory snapshots honor the provider's existing byte cap.
//! Exercise the public filesystem and record/replay APIs without compiling
//! the provider's unrelated unit-test bodies.

#![forbid(unsafe_code)]
#![cfg(unix)]

use frankenengine_extension_host::host_io::{
    FsDirEntry, FsMetaResult, FsOperation, HostIoCapability, HostIoError, HostIoOutcome,
    HostIoProvider, HostIoRecorder, HostIoRequest, HostIoResponse, InMemoryHostIoTranscript,
    SandboxedHostIo,
};

fn request(path: &str, with_file_types: bool) -> HostIoRequest {
    HostIoRequest::FsMeta {
        operation: FsOperation::ReadDir,
        path: path.to_string(),
        arguments: vec![format!("with_file_types={with_file_types}")],
        data: Vec::new(),
    }
}

fn entry_bytes(with_file_types: bool) -> u64 {
    if with_file_types {
        std::mem::size_of::<FsDirEntry>() as u64
    } else {
        std::mem::size_of::<String>() as u64
    }
}

fn assert_budget_refusal(outcome: &HostIoOutcome) {
    assert!(
        matches!(outcome, Err(HostIoError::Io { detail })
            if detail.contains("readdir result") && detail.contains("exceeds byte limit")),
        "directory snapshot must fail as a whole: {outcome:?}"
    );
}

#[test]
fn decoded_names_and_entry_storage_fit_exactly_or_fail_as_a_whole() {
    let scratch = tempfile::tempdir().expect("sandbox root");
    std::fs::write(scratch.path().join("entry"), b"").unwrap();
    for with_file_types in [false, true] {
        let limit = entry_bytes(with_file_types) + 5;
        let provider = SandboxedHostIo::with_root_and_limit(scratch.path(), limit).unwrap();
        let outcome = provider.perform(&request(".", with_file_types), &[HostIoCapability::FsRead]);
        let expected = if with_file_types {
            FsMetaResult::DirEntries(vec![FsDirEntry {
                name: "entry".to_string(),
                is_file: true,
                is_directory: false,
                is_symbolic_link: false,
            }])
        } else {
            FsMetaResult::Strings(vec!["entry".to_string()])
        };
        assert_eq!(outcome, Ok(HostIoResponse::FsMeta { result: expected }));
        let limited = SandboxedHostIo::with_root_and_limit(scratch.path(), limit - 1).unwrap();
        assert_budget_refusal(
            &limited.perform(&request(".", with_file_types), &[HostIoCapability::FsRead]),
        );
    }
}

#[test]
fn many_short_names_cannot_bypass_the_directory_cap() {
    let scratch = tempfile::tempdir().expect("sandbox root");
    for index in 0..64 {
        std::fs::write(scratch.path().join(format!("{index:02x}")), b"").unwrap();
    }
    for with_file_types in [false, true] {
        // Filename bytes alone fit this limit; their retained entries do not.
        let provider = SandboxedHostIo::with_root_and_limit(scratch.path(), 128).unwrap();
        assert_budget_refusal(
            &provider.perform(&request(".", with_file_types), &[HostIoCapability::FsRead]),
        );
    }
}

#[test]
fn lossy_utf8_expansion_counts_toward_the_directory_cap() {
    use std::os::unix::ffi::OsStringExt;

    let scratch = tempfile::tempdir().expect("sandbox root");
    let filename = std::ffi::OsString::from_vec(vec![b'x', 0xff]);
    std::fs::write(scratch.path().join(filename), b"").unwrap();
    for with_file_types in [false, true] {
        let limited =
            SandboxedHostIo::with_root_and_limit(scratch.path(), entry_bytes(with_file_types) + 2)
                .unwrap();
        assert_budget_refusal(
            &limited.perform(&request(".", with_file_types), &[HostIoCapability::FsRead]),
        );
        let provider = SandboxedHostIo::with_root_and_limit(
            scratch.path(),
            entry_bytes(with_file_types) + "x\u{fffd}".len() as u64,
        )
        .unwrap();
        let outcome = provider
            .perform(&request(".", with_file_types), &[HostIoCapability::FsRead])
            .unwrap();
        match outcome {
            HostIoResponse::FsMeta {
                result: FsMetaResult::Strings(names),
            } => assert_eq!(names, ["x\u{fffd}"]),
            HostIoResponse::FsMeta {
                result: FsMetaResult::DirEntries(entries),
            } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, "x\u{fffd}");
                assert!(entries[0].is_file);
            }
            other => panic!("unexpected directory response: {other:?}"),
        }
    }
}

#[test]
fn empty_directories_fit_zero_and_a_refusal_does_not_poison_next_read() {
    let scratch = tempfile::tempdir().expect("sandbox root");
    std::fs::create_dir(scratch.path().join("empty")).unwrap();
    let provider = SandboxedHostIo::with_root_and_limit(scratch.path(), 0).unwrap();
    for with_file_types in [false, true] {
        assert_budget_refusal(
            &provider.perform(&request(".", with_file_types), &[HostIoCapability::FsRead]),
        );
        let expected = if with_file_types {
            FsMetaResult::DirEntries(Vec::new())
        } else {
            FsMetaResult::Strings(Vec::new())
        };
        assert_eq!(
            provider.perform(
                &request("empty", with_file_types),
                &[HostIoCapability::FsRead]
            ),
            Ok(HostIoResponse::FsMeta { result: expected })
        );
    }
}

#[test]
fn directory_success_and_budget_refusal_replay_after_the_tree_changes() {
    let scratch = tempfile::tempdir().expect("sandbox root");
    std::fs::write(scratch.path().join("a"), b"").unwrap();
    let provider =
        SandboxedHostIo::with_root_and_limit(scratch.path(), entry_bytes(false) + 1).unwrap();
    let read = request(".", false);
    let recording = InMemoryHostIoTranscript::recording();
    recording.begin_execution().unwrap();
    let success = provider.perform(&read, &[HostIoCapability::FsRead]);
    assert_eq!(
        success,
        Ok(HostIoResponse::FsMeta {
            result: FsMetaResult::Strings(vec!["a".to_string()]),
        })
    );
    recording.record(&read, &success);
    std::fs::write(scratch.path().join("b"), b"").unwrap();
    let refused = provider.perform(&read, &[HostIoCapability::FsRead]);
    assert_budget_refusal(&refused);
    recording.record(&read, &refused);
    let entries = recording.finish_execution().unwrap();
    std::fs::write(scratch.path().join("c"), b"").unwrap();
    let replay = InMemoryHostIoTranscript::replaying(entries.clone());
    replay.begin_execution().unwrap();
    assert_eq!(replay.replay(&read), Some(success));
    assert_eq!(replay.replay(&read), Some(refused));
    assert_eq!(replay.finish_execution().unwrap(), entries);
}
