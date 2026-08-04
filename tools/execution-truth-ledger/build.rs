#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct TierRSourceManifest {
    schema_version: &'static str,
    hash_algorithm: &'static str,
    identity_basis: &'static str,
    files: Vec<TierRSourceFile>,
}

#[derive(Serialize)]
struct TierRSourceFile {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Serialize)]
struct TierRBuildEnvironment {
    schema_version: &'static str,
    rustc_verbose_version: String,
    cargo_version: String,
    host: String,
    target: String,
    profile: String,
    opt_level: String,
    requested_toolchain: Option<String>,
    active_features: Vec<String>,
    build_flags_source: String,
    build_flags_sha256: String,
    builder_identity_source: String,
    builder_identity_sha256: Option<String>,
    source_manifest_sha256: String,
}

fn main() {
    let tool_root = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo supplies CARGO_MANIFEST_DIR"),
    );
    let repo_root = tool_root.join("../..");
    let core_root = repo_root.join("crates/franken-core");
    let extension_host_root = repo_root.join("crates/franken-extension-host");
    let engine_source_root = repo_root.join("crates/franken-engine/src");
    let mut inputs = vec![
        tool_root.join("build.rs"),
        tool_root.join("Cargo.toml"),
        tool_root.join("Cargo.lock"),
        repo_root.join("Cargo.toml"),
        repo_root.join("Cargo.lock"),
        core_root.join("Cargo.toml"),
        extension_host_root.join("Cargo.toml"),
        engine_source_root.join("execution_truth_ledger.rs"),
        engine_source_root.join("verification_coverage_contract.rs"),
        engine_source_root.join("bin/franken_execution_truth_ledger.rs"),
        engine_source_root.join("bin/franken_verification_coverage_contract.rs"),
    ];
    for optional in [
        repo_root.join("rust-toolchain.toml"),
        repo_root.join(".cargo/config.toml"),
    ] {
        if optional.is_file() {
            inputs.push(optional);
        }
    }
    collect_rust_sources(&tool_root.join("src"), &mut inputs);
    collect_rust_sources(&core_root.join("src"), &mut inputs);
    collect_rust_sources(&extension_host_root.join("src"), &mut inputs);
    inputs.sort();
    inputs.dedup();

    let canonical_repo = repo_root
        .canonicalize()
        .expect("canonicalize FrankenEngine repository root");
    let mut source_files = Vec::with_capacity(inputs.len());
    for path in inputs {
        let metadata = fs::symlink_metadata(&path)
            .unwrap_or_else(|error| panic!("inspect build input {}: {error}", path.display()));
        assert!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "Tier-R build input must be a regular non-symlink file: {}",
            path.display()
        );
        let canonical = path
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonicalize build input {}: {error}", path.display()));
        assert!(
            canonical.starts_with(&canonical_repo),
            "Tier-R build input escaped repository root: {}",
            canonical.display()
        );
        let relative = canonical
            .strip_prefix(&canonical_repo)
            .expect("checked repository prefix")
            .to_str()
            .expect("Tier-R build input paths must be UTF-8")
            .replace('\\', "/");
        let bytes = fs::read(&canonical)
            .unwrap_or_else(|error| panic!("read build input {}: {error}", canonical.display()));
        let digest = hex::encode(Sha256::digest(&bytes));
        source_files.push(TierRSourceFile {
            path: relative,
            bytes: u64::try_from(bytes.len()).expect("Tier-R build input length fits u64"),
            sha256: digest,
        });
        println!("cargo:rerun-if-changed={}", canonical.display());
    }

    let source_manifest = TierRSourceManifest {
        schema_version: "franken-engine.tier-r-source-manifest.v1",
        hash_algorithm: "sha256",
        identity_basis: "canonical-json-path-bytes-content-sha256-v1",
        files: source_files,
    };
    let mut manifest_bytes =
        serde_json::to_vec_pretty(&source_manifest).expect("serialize Tier-R source manifest");
    manifest_bytes.push(b'\n');
    let aggregate = hex::encode(Sha256::digest(&manifest_bytes));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    fs::write(
        out_dir.join("vcc_tier_r_source_manifest.json"),
        manifest_bytes,
    )
    .expect("write embedded Tier-R build-input manifest");

    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let rustc_verbose_version = command_version(&rustc, "-vV", "rustc");
    let cargo_version = command_version(&cargo, "-V", "cargo");
    let mut active_features: Vec<String> = env::vars()
        .filter_map(|(name, value)| {
            (name.starts_with("CARGO_FEATURE_") && value == "1").then_some(name)
        })
        .collect();
    active_features.sort();
    let (build_flags_source, build_flags) =
        if let Some(flags) = env::var_os("CARGO_ENCODED_RUSTFLAGS") {
            (
                "CARGO_ENCODED_RUSTFLAGS".to_string(),
                flags.to_string_lossy().into_owned(),
            )
        } else if let Some(flags) = env::var_os("RUSTFLAGS") {
            (
                "RUSTFLAGS".to_string(),
                flags.to_string_lossy().into_owned(),
            )
        } else {
            ("none".to_string(), String::new())
        };
    let builder_identity = env::var("RCH_WORKER_ID")
        .map(|identity| ("RCH_WORKER_ID".to_string(), identity))
        .or_else(|_| env::var("RCH_WORKER").map(|identity| ("RCH_WORKER".to_string(), identity)))
        .or_else(|_| env::var("HOSTNAME").map(|identity| ("HOSTNAME".to_string(), identity)))
        .ok();
    let build_environment = TierRBuildEnvironment {
        schema_version: "franken-engine.tier-r-build-environment.v1",
        rustc_verbose_version,
        cargo_version,
        host: env::var("HOST").expect("Cargo supplies HOST"),
        target: env::var("TARGET").expect("Cargo supplies TARGET"),
        profile: env::var("PROFILE").expect("Cargo supplies PROFILE"),
        opt_level: env::var("OPT_LEVEL").expect("Cargo supplies OPT_LEVEL"),
        requested_toolchain: env::var("RUSTUP_TOOLCHAIN").ok(),
        active_features,
        build_flags_source,
        build_flags_sha256: hex::encode(Sha256::digest(build_flags.as_bytes())),
        builder_identity_source: builder_identity
            .as_ref()
            .map_or_else(|| "unavailable".to_string(), |(source, _)| source.clone()),
        builder_identity_sha256: builder_identity
            .map(|(_, identity)| hex::encode(Sha256::digest(identity.as_bytes()))),
        source_manifest_sha256: aggregate.clone(),
    };
    let mut build_environment_bytes =
        serde_json::to_vec_pretty(&build_environment).expect("serialize Tier-R build environment");
    build_environment_bytes.push(b'\n');
    let build_environment_sha256 = hex::encode(Sha256::digest(&build_environment_bytes));
    fs::write(
        out_dir.join("vcc_tier_r_build_environment.json"),
        build_environment_bytes,
    )
    .expect("write embedded Tier-R build environment");
    println!("cargo:rustc-env=VCC_TIER_R_BUILD_SOURCE_SHA256={aggregate}");
    println!("cargo:rustc-env=VCC_TIER_R_BUILD_ENVIRONMENT_SHA256={build_environment_sha256}");
}

fn command_version(executable: &std::ffi::OsStr, argument: &str, label: &str) -> String {
    let output = Command::new(executable)
        .arg(argument)
        .output()
        .unwrap_or_else(|error| panic!("execute {label} version probe: {error}"));
    assert!(
        output.status.success(),
        "{label} version probe failed with {}",
        output.status
    );
    let stdout = String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("{label} version output is not UTF-8: {error}"));
    let version = stdout.trim();
    assert!(!version.is_empty(), "{label} version output is empty");
    version.to_string()
}

fn collect_rust_sources(directory: &Path, inputs: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read source directory {}: {error}", directory.display()))
        .collect::<Result<Vec<_>, _>>()
        .expect("read source directory entry");
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("inspect source {}: {error}", entry.path().display()));
        assert!(
            !file_type.is_symlink(),
            "Tier-R source tree contains symlink {}",
            entry.path().display()
        );
        if file_type.is_dir() {
            collect_rust_sources(&entry.path(), inputs);
        } else if file_type.is_file()
            && entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("rs")
        {
            inputs.push(entry.path());
        }
    }
}
