//! Positioned descriptor writes preserve the shared cursor and retained authority.
//!
//! The typed host request carries an optional canonical `position=` argument.
//! Absence retains the historical sequential shape; malformed or duplicate
//! positions never silently become sequential writes. Guest overloads must be
//! normalized before this boundary, not interpreted again by the host provider.

use super::{HostIoError, SandboxedHostIo};

fn invalid_position() -> HostIoError {
    HostIoError::Fs {
        code: "EINVAL".to_string(),
        detail: "file write position is invalid or outside the supported offset range".to_string(),
    }
}

pub(super) fn position_argument(arguments: &[String]) -> Result<Option<u64>, HostIoError> {
    let mut position = None;
    for argument in arguments {
        let Some(value) = argument.strip_prefix("position=") else {
            continue;
        };
        if position.is_some()
            || value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(invalid_position());
        }
        let value = value.parse::<u64>().map_err(|_| invalid_position())?;
        if value > i64::MAX as u64 {
            return Err(invalid_position());
        }
        position = Some(value);
    }
    Ok(position)
}

impl SandboxedHostIo {
    /// Write all bytes either sequentially or at an explicit file position.
    ///
    /// `Some(position)` uses descriptor-relative positional I/O and leaves the
    /// shared file cursor unchanged, including through provider clones. The
    /// held descriptor remains the target after renames or path replacement.
    /// Append descriptors retain the operating system's append semantics: on
    /// Linux an explicit position still appends, as with Node's `pwrite` path.
    /// No new file is opened and no seek/restore race is introduced.
    ///
    /// The per-request byte cap and signed file-offset range are checked before
    /// any write. Unknown, closed and non-writable descriptors return EBADF.
    /// A partial OS failure may already have written bytes; it is not rolled
    /// back or reported as success. Unsupported positional I/O fails explicitly.
    pub fn write_fd_at(
        &self,
        fd: u64,
        data: &[u8],
        position: Option<u64>,
    ) -> Result<u64, HostIoError> {
        let length = u64::try_from(data.len()).map_err(|_| HostIoError::Io {
            detail: "file write length is not representable".to_string(),
        })?;
        if length > self.max_bytes {
            return Err(HostIoError::Io {
                detail: format!(
                    "write of {length} bytes to fd {fd} exceeds the {}-byte cap",
                    self.max_bytes
                ),
            });
        }
        if let Some(position) = position {
            // A signed offset is what the OS consumes. Validate the complete
            // span before the first write so a retry cannot wrap or fall back.
            position
                .checked_add(length)
                .filter(|end| *end <= i64::MAX as u64)
                .ok_or_else(invalid_position)?;
        }
        self.with_fd_entry(fd, |entry| {
            if !entry.writable {
                return Err(HostIoError::Fs {
                    code: "EBADF".to_string(),
                    detail: format!("fd {fd} ({}) is not open for writing", entry.guest_path),
                });
            }
            if let Some(position) = position {
                #[cfg(unix)]
                {
                    std::os::unix::fs::FileExt::write_all_at(&entry.file, data, position)
                        .map_err(|error| Self::fs_error("pwrite", &entry.guest_path, error))?;
                }
                #[cfg(not(unix))]
                {
                    let _ = position;
                    return Err(Self::fs_not_implemented("pwrite"));
                }
            } else {
                std::io::Write::write_all(&mut entry.file, data)
                    .map_err(|error| Self::fs_error("write", &entry.guest_path, error))?;
            }
            Ok(length)
        })
    }
}
