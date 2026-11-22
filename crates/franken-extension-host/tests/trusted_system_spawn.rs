#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use frankenengine_extension_host::process_spawn::{
    NativeProcessSpawn, ProcessLaunch, ProcessSpawnCapability, ProcessSpawnError,
    ProcessSpawnPolicy, ProcessSpawnProvider, ProcessSpawnRequest, ProcessSpawnResponse,
    ProcessStdio,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn system_echo() -> PathBuf {
    [Path::new("/bin/echo"), Path::new("/usr/bin/echo")]
        .into_iter()
        .find(|path| path.is_file())
        .expect("installed system echo is required for native process integration")
        .to_path_buf()
}

fn run_request(executable: String) -> ProcessSpawnRequest {
    ProcessSpawnRequest::Run {
        launch: ProcessLaunch {
            executable,
            argv: vec![
                "secure".to_string(),
                "system".to_string(),
                "spawn".to_string(),
            ],
            env: BTreeMap::new(),
            cwd: None,
            shell: false,
            stdio: ProcessStdio::default(),
        },
        stdin: Vec::new(),
        timeout_millis: Some(5_000),
    }
}

fn assert_policy_code(error: &ProcessSpawnError, expected: &str) {
    match error {
        ProcessSpawnError::PolicyViolation { code, .. } => assert_eq!(code, expected),
        other => panic!("expected policy refusal {expected}, got {other:?}"),
    }
}

fn copy_echo(directory: &Path, name: &str, mode: u32) -> PathBuf {
    let executable = directory.join(name);
    std::fs::copy(system_echo(), &executable).expect("copy native executable fixture");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(mode))
        .expect("set fixture permissions");
    executable
}

#[test]
fn explicit_system_grant_runs_the_installed_echo_with_its_real_name() {
    let root = tempfile::tempdir().expect("working-directory jail");
    let mut policy = ProcessSpawnPolicy::jailed(root.path()).expect("native policy");
    let executable = policy
        .authorize_trusted_system_executable(system_echo())
        .expect("explicitly authorize protected system echo");
    assert!(policy.trusted_system_executables.contains(&executable));
    let provider = NativeProcessSpawn::new(policy).expect("install explicit system policy");
    let response = provider
        .perform(&run_request(executable), &[ProcessSpawnCapability::Spawn])
        .expect("execute the installed system image");
    let ProcessSpawnResponse::Run {
        exit,
        stdout,
        stderr,
    } = response
    else {
        panic!("expected a bounded process result");
    };
    assert!(exit.success, "system echo failed: {exit:?}; {stderr:?}");
    assert_eq!(stdout, b"secure system spawn\n");
    assert!(stderr.is_empty());
}

#[test]
fn default_policy_preserves_the_exact_legacy_wire_representation() {
    // Frozen pre-change representation: an empty compatibility grant must not
    // alter existing serialized policy bytes or the hashes/signatures of them.
    const LEGACY: &str = concat!(
        "{\"allowed_executables\":{},\"executable_aliases\":{},",
        "\"allow_shell\":false,\"shell_executable_alias\":null,",
        "\"allowed_env_keys\":[],\"fixed_env\":{},\"jailed_cwd_root\":\"\",",
        "\"limits\":{\"max_children\":4,\"max_executable_path_bytes\":4096,",
        "\"max_executable_bytes\":134217728,\"max_argv_count\":128,",
        "\"max_argv_bytes\":65536,\"max_env_count\":128,\"max_env_bytes\":65536,",
        "\"max_cwd_bytes\":4096,\"max_prelaunch_bytes\":131072,",
        "\"max_request_bytes\":16777216,\"max_stdin_bytes\":1048576,",
        "\"max_output_bytes\":4194304,\"max_runtime_millis\":30000},",
        "\"allowed_signals\":[\"terminate\",\"kill\"],",
        "\"allowed_stdio\":[\"pipe\",\"null\"]}"
    );
    let decoded: ProcessSpawnPolicy =
        serde_json::from_str(LEGACY).expect("legacy policy remains valid");
    assert_eq!(decoded, ProcessSpawnPolicy::default());
    assert!(decoded.trusted_system_executables.is_empty());
    assert_eq!(serde_json::to_string(&decoded).unwrap(), LEGACY);
}

#[test]
fn explicit_system_grant_changes_serialized_policy_identity() {
    let root = tempfile::tempdir().expect("policy jail");
    let mut policy = ProcessSpawnPolicy::jailed(root.path()).unwrap();
    let executable = policy.authorize_executable(system_echo()).unwrap();
    let original_grants = policy.allowed_executables.clone();
    let original_bytes = serde_json::to_vec(&policy).unwrap();
    let original_digest = Sha256::digest(&original_bytes);

    assert_eq!(
        policy
            .authorize_trusted_system_executable(system_echo())
            .unwrap(),
        executable,
    );
    assert_eq!(policy.allowed_executables, original_grants);
    let trusted_bytes = serde_json::to_vec(&policy).unwrap();
    assert_ne!(trusted_bytes, original_bytes);
    assert_ne!(Sha256::digest(&trusted_bytes), original_digest);
    let encoded = serde_json::to_value(&policy).unwrap();
    assert_eq!(encoded["trusted_system_executables"], json!([executable]));
    let round_trip: ProcessSpawnPolicy = serde_json::from_slice(&trusted_bytes).unwrap();
    assert_eq!(round_trip, policy);
}

#[test]
fn ordinary_reauthorization_removes_the_explicit_system_grant() {
    let root = tempfile::tempdir().expect("policy jail");
    let mut policy = ProcessSpawnPolicy::jailed(root.path()).unwrap();
    let executable = policy.authorize_executable(system_echo()).unwrap();
    let original = policy.clone();
    policy
        .authorize_trusted_system_executable(system_echo())
        .unwrap();
    assert!(policy.trusted_system_executables.contains(&executable));

    assert_eq!(
        policy.authorize_executable(system_echo()).unwrap(),
        executable
    );
    assert_eq!(policy, original);
    assert!(
        serde_json::to_value(&policy)
            .unwrap()
            .get("trusted_system_executables")
            .is_none()
    );
}

#[test]
fn trusted_alias_preserves_the_grant_and_invalid_alias_is_atomic() {
    let root = tempfile::tempdir().expect("alias policy jail");
    let mut policy = ProcessSpawnPolicy::jailed(root.path()).unwrap();
    let original = policy.clone();
    let error = policy
        .authorize_trusted_system_alias("invalid/alias", system_echo())
        .expect_err("invalid alias must be rejected before authorization");
    assert_policy_code(&error, "invalid_executable_alias");
    assert_eq!(policy, original);

    let executable = policy
        .authorize_trusted_system_alias("system-echo", system_echo())
        .expect("authorize a trusted alias in one operation");
    assert!(policy.trusted_system_executables.contains(&executable));
    assert_eq!(policy.executable_aliases["system-echo"], executable);
    let provider = NativeProcessSpawn::new(policy).unwrap();
    let prepared = provider
        .prepare_request(&run_request("system-echo".to_string()))
        .unwrap();
    let ProcessSpawnRequest::Run { launch, .. } = prepared else {
        panic!("alias preparation changed the operation");
    };
    assert_eq!(launch.executable, executable);
}

#[test]
fn writable_executable_cannot_gain_system_trust_or_partially_change_policy() {
    let root = tempfile::tempdir().expect("writable image fixture");
    let executable = copy_echo(root.path(), "writable-image", 0o777);
    let mut policy = ProcessSpawnPolicy::jailed(root.path()).unwrap();
    policy
        .authorize_trusted_system_executable(system_echo())
        .unwrap();
    let original = policy.clone();
    let error = policy
        .authorize_trusted_system_executable(&executable)
        .expect_err("a writable image cannot receive the trusted-system grant");
    assert_policy_code(&error, "trusted_system_executable_unprotected");
    assert_eq!(policy, original);
}

#[test]
fn readonly_image_in_a_writable_tree_is_not_a_protected_system_image() {
    let root = tempfile::tempdir().expect("writable ancestor fixture");
    let executable = copy_echo(root.path(), "readonly-image", 0o555);
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777))
        .expect("make the fixture ancestor writable");
    let mut policy = ProcessSpawnPolicy::jailed(root.path()).unwrap();
    let error = policy
        .authorize_trusted_system_executable(executable)
        .expect_err("read-only file permissions cannot authorize a writable tree");
    assert_policy_code(&error, "trusted_system_executable_unprotected");
    assert!(policy.allowed_executables.is_empty());
    assert!(policy.trusted_system_executables.is_empty());
}

#[test]
fn forged_serialized_grant_cannot_bypass_source_protection() {
    let root = tempfile::tempdir().expect("forged policy fixture");
    let executable = copy_echo(root.path(), "forged-system-image", 0o755);
    let mut policy = ProcessSpawnPolicy::jailed(root.path()).unwrap();
    let canonical = policy.authorize_executable(&executable).unwrap();
    let mut serialized = serde_json::to_value(&policy).unwrap();
    serialized["trusted_system_executables"] = json!([canonical]);
    let forged: ProcessSpawnPolicy = serde_json::from_value(serialized).unwrap();
    assert!(forged.trusted_system_executables.contains(&canonical));
    // A caller can construct or deserialize the public policy directly. The
    // native provider must enforce protection independently of the builder.
    let error = match NativeProcessSpawn::new(forged) {
        Err(error) => error,
        Ok(provider) => provider
            .perform(&run_request(canonical), &[ProcessSpawnCapability::Spawn])
            .expect_err("a forged compatibility grant must not execute"),
    };
    assert_policy_code(&error, "trusted_system_executable_unprotected");
}

#[test]
fn system_trust_does_not_replace_the_executable_digest_grant() {
    let root = tempfile::tempdir().expect("digest policy fixture");
    let mut policy = ProcessSpawnPolicy::jailed(root.path()).unwrap();
    let executable = policy
        .authorize_trusted_system_executable(system_echo())
        .unwrap();
    let digest = policy.allowed_executables.get_mut(&executable).unwrap();
    digest[0] ^= 1;
    let provider = NativeProcessSpawn::new(policy).expect("install structurally valid policy");
    let error = provider
        .perform(&run_request(executable), &[ProcessSpawnCapability::Spawn])
        .expect_err("the protected image must still match its authorized digest");
    assert_policy_code(&error, "executable_digest_mismatch");
}

#[test]
fn a_system_trust_entry_without_an_executable_grant_is_rejected() {
    let root = tempfile::tempdir().expect("missing digest grant fixture");
    let mut policy = ProcessSpawnPolicy::jailed(root.path()).unwrap();
    let executable = std::fs::canonicalize(system_echo()).unwrap();
    policy
        .trusted_system_executables
        .insert(executable.to_str().unwrap().to_string());
    assert!(matches!(
        NativeProcessSpawn::new(policy),
        Err(ProcessSpawnError::PolicyViolation { .. })
    ));
}

#[test]
fn system_grant_diagnostics_redact_paths() {
    let root = tempfile::tempdir().expect("diagnostic fixture");
    let executable = copy_echo(root.path(), "sensitive-system-image-path", 0o777);
    let secret = executable.to_str().unwrap();
    let mut policy = ProcessSpawnPolicy::jailed(root.path()).unwrap();
    let error = policy
        .authorize_trusted_system_executable(&executable)
        .unwrap_err();
    policy.trusted_system_executables.insert(secret.to_string());
    for diagnostic in [
        format!("{policy:?}"),
        format!("{error:?}"),
        error.to_string(),
    ] {
        assert!(!diagnostic.contains(secret));
        assert!(!diagnostic.contains("sensitive-system-image-path"));
    }
    // Redaction is diagnostic-only; the opt-in remains explicit in the policy
    // representation committed by an operator's hash or signature.
    assert_eq!(
        serde_json::to_value(&policy).unwrap()["trusted_system_executables"],
        json!([secret]),
    );
}
