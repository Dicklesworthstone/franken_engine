//! Descriptor-pinned validation for an explicitly trusted system executable.
//!
//! This mode trusts privileged host administration and the backing filesystem.
//! It does not claim immutable bytes against either authority. Root ownership
//! and protected ancestors prevent an ordinary non-root writer from changing
//! the admitted image or replacing a component of its canonical pathname.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use super::*;
use rustix::fs::{Access, AtFlags, Mode, OFlags};
use std::io::Seek;
use std::os::unix::fs::MetadataExt;
use std::path::Component;

fn unprotected(detail: impl Into<String>) -> ProcessSpawnError {
    policy_error("trusted_system_executable_unprotected", detail)
}

fn check_directory(directory: &File) -> Result<(), ProcessSpawnError> {
    let metadata = directory
        .metadata()
        .map_err(|error| ProcessSpawnError::Io {
            operation: "inspect trusted system executable directory".to_string(),
            detail: error.to_string(),
        })?;
    // A POSIX ACL's effective group-class permissions are bounded by these
    // group mode bits, so a named-user ACL cannot grant write through this mask.
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(unprotected(
            "every executable directory must be root-owned and not group/other writable",
        ));
    }
    Ok(())
}

fn check_executable(file: &File) -> Result<std::fs::Metadata, ProcessSpawnError> {
    let metadata = file.metadata().map_err(|error| ProcessSpawnError::Io {
        operation: "inspect trusted system executable identity".to_string(),
        detail: error.to_string(),
    })?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(unprotected(
            "executable must be a root-owned regular file without group/other write permission",
        ));
    }
    if metadata.mode() & 0o6000 != 0 {
        return Err(policy_error(
            "trusted_system_executable_privileged",
            "setuid and setgid executables are not permitted",
        ));
    }
    // Presence is enough to refuse execution; never interpret capability
    // contents or allocate based on an untrusted attribute length. ERANGE also
    // establishes that an attribute exists and is larger than our fixed buffer.
    let mut capabilities = [0_u8; 64];
    match rustix::fs::fgetxattr(file, "security.capability", &mut capabilities) {
        Ok(_) | Err(rustix::io::Errno::RANGE) => {
            return Err(policy_error(
                "trusted_system_executable_privileged",
                "executables with file capabilities are not permitted",
            ));
        }
        Err(rustix::io::Errno::NODATA | rustix::io::Errno::OPNOTSUPP) => {}
        Err(error) => {
            return Err(unprotected(format!(
                "could not establish absence of executable file capabilities: {error}"
            )));
        }
    }
    Ok(metadata)
}

pub(super) fn open(
    executable: &Path,
    expected_digest: Option<&[u8; 32]>,
    maximum_bytes: u64,
    control: &dyn ProcessSpawnControl,
) -> Result<(File, [u8; 32]), ProcessSpawnError> {
    control.checkpoint()?;
    let mut components = executable.components();
    if components.next() != Some(Component::RootDir) {
        return Err(unprotected(
            "trusted system executable path must be canonical and absolute",
        ));
    }
    let mut components = components.peekable();
    let mut directory = rustix::fs::open("/", working_directory_flags(), Mode::empty())
        .map(File::from)
        .map_err(|error| ProcessSpawnError::Io {
            operation: "open trusted system executable root".to_string(),
            detail: error.to_string(),
        })?;
    check_directory(&directory)?;
    let name = loop {
        control.checkpoint()?;
        let Some(Component::Normal(name)) = components.next() else {
            return Err(unprotected(
                "trusted system executable path requires only normal components beneath root",
            ));
        };
        if components.peek().is_none() {
            break name;
        }
        directory = rustix::fs::openat(&directory, name, working_directory_flags(), Mode::empty())
            .map(File::from)
            .map_err(|error| ProcessSpawnError::Io {
                operation: "open trusted system executable directory".to_string(),
                detail: error.to_string(),
            })?;
        check_directory(&directory)?;
    };
    let mut file = rustix::fs::openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| ProcessSpawnError::Io {
        operation: "open trusted system executable identity".to_string(),
        detail: error.to_string(),
    })?;
    let metadata = check_executable(&file)?;
    enforce_limit("executable_bytes", metadata.len(), maximum_bytes)?;

    // Check the held source, including ACL and noexec restrictions. No mutable
    // caller pathname is reopened after the protected component walk.
    rustix::fs::accessat(
        rustix::fs::CWD,
        pinned_process_file_path(&file)?,
        Access::EXEC_OK,
        AtFlags::EACCESS,
    )
    .map_err(|error| ProcessSpawnError::Io {
        operation: "check executable execution permission".to_string(),
        detail: error.to_string(),
    })?;

    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut total_bytes = 0_u64;
    loop {
        control.checkpoint()?;
        let read = file
            .read(&mut buffer)
            .map_err(|error| ProcessSpawnError::Io {
                operation: "hash trusted system executable identity".to_string(),
                detail: error.to_string(),
            })?;
        if read == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        enforce_limit("executable_bytes", total_bytes, maximum_bytes)?;
        digest.update(&buffer[..read]);
    }
    control.checkpoint()?;
    let metadata = check_executable(&file)?;
    enforce_limit("executable_bytes", metadata.len(), maximum_bytes)?;
    let actual_digest: [u8; 32] = digest.finalize().into();
    if expected_digest.is_some_and(|expected| expected != &actual_digest) {
        return Err(policy_error(
            "executable_digest_mismatch",
            format!("digest changed for {}", executable.display()),
        ));
    }
    file.rewind().map_err(|error| ProcessSpawnError::Io {
        operation: "rewind trusted system executable identity".to_string(),
        detail: error.to_string(),
    })?;
    control.checkpoint()?;
    Ok((file, actual_digest))
}
