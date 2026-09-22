//! WASI descriptor ownership over virtual streams and immutable input files.
//!
//! Numeric handles are guest-selected names, never OS descriptors or vector
//! offsets. A configured slot ceiling, not the largest handle, bounds storage.
//! Renumbering moves the object, cursor and attenuated rights together.
//! Closing a descriptor does not erase captured output or refund its quota.

use super::*;

pub(super) const NOTCAPABLE: i32 = 76;
pub(super) const NOTSUP: i32 = 58;
pub(super) const SPIPE: i32 = 70;
pub(super) const READ: u64 = 1 << 1;
pub(super) const SEEK: u64 = 1 << 2;
const SET_FLAGS: u64 = 1 << 3;
const TELL: u64 = 1 << 5;
const WRITE: u64 = 1 << 6;
pub(super) const PATH_OPEN: u64 = 1 << 13;
pub(super) const READDIR: u64 = 1 << 14;
pub(super) const PATH_FILESTAT: u64 = 1 << 18;
pub(super) const FILESTAT: u64 = 1 << 21;
pub(super) const FILE_RIGHTS: u64 = READ | SEEK | TELL | SET_FLAGS | FILESTAT;
pub(super) const DIRECTORY_RIGHTS: u64 = PATH_OPEN | PATH_FILESTAT | FILESTAT | READDIR;
const NONBLOCK: u16 = 4;
const CHARACTER_DEVICE: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stream {
    Input,
    Output,
    Error,
    File(usize),
    Directory(usize),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Descriptor {
    pub stream: Stream,
    pub rights: u64,
    pub inheriting: u64,
    pub flags: u16,
    pub cursor: u64,
    pub preopen: bool,
}

impl Descriptor {
    pub(super) fn new(stream: Stream, rights: u64) -> Self {
        Self {
            stream,
            rights,
            inheriting: 0,
            flags: 0,
            cursor: 0,
            preopen: false,
        }
    }
}

#[derive(Debug)]
pub(super) struct Table(Vec<Option<(u32, Descriptor)>>);

impl Table {
    pub(super) fn new() -> Self {
        Self(vec![
            Some((
                0,
                Descriptor::new(Stream::Input, READ | SET_FLAGS | FILESTAT),
            )),
            Some((
                1,
                Descriptor::new(Stream::Output, WRITE | SET_FLAGS | FILESTAT),
            )),
            Some((
                2,
                Descriptor::new(Stream::Error, WRITE | SET_FLAGS | FILESTAT),
            )),
        ])
    }

    pub(super) fn with_files(capacity: usize) -> Result<Self, WasiPreview1Error> {
        // Includes stdio and the root preopen. No guest operation grows slots.
        if !(4..=65_536).contains(&capacity) {
            return Err(WasiPreview1Error::InvalidString {
                field: "descriptor capacity (4..=65536)",
                index: 0,
            });
        }
        let mut table = Self::new();
        table
            .0
            .try_reserve_exact(capacity - 3)
            .map_err(|_| WasiPreview1Error::AllocationFailed)?;
        table.0.resize(capacity, None);
        let mut root = Descriptor::new(Stream::Directory(0), DIRECTORY_RIGHTS);
        root.inheriting = DIRECTORY_RIGHTS | FILE_RIGHTS;
        root.preopen = true;
        table.0[3] = Some((3, root));
        Ok(table)
    }

    /// Three stdio slots are covered by fixed dispatch work. Charge additional
    /// slot scans before inspecting any guest-selected handle.
    pub(super) fn charge(&self, caller: &mut WasmHostCaller<'_, '_>) -> IoResult<()> {
        caller.charge_work((self.0.len().saturating_sub(3) as u64) * 4)?;
        Ok(())
    }

    pub(super) fn vacant(&self, caller: &mut WasmHostCaller<'_, '_>) -> IoResult<(usize, u32)> {
        let slot = self
            .0
            .iter()
            .position(Option::is_none)
            .ok_or(IoFailure::Errno(33))?; // MFILE
        // A bounded search over at most N+1 names, never up to a guest's u32 fd.
        // Precharge the worst-case scans; this path cannot evade the VM budget.
        let n = self.0.len() as u64;
        caller.charge_work(n * (n + 1))?;
        let number = (0..=self.0.len() as u32)
            .find(|fd| self.index(*fd).is_err())
            .expect("N live slots cannot occupy N+1 distinct numbers");
        Ok((slot, number))
    }

    pub(super) fn insert(&mut self, slot: usize, fd: u32, descriptor: Descriptor) {
        debug_assert!(self.0[slot].is_none());
        self.0[slot] = Some((fd, descriptor));
    }

    pub(super) fn set_cursor(&mut self, fd: u32, cursor: u64) -> IoResult<()> {
        let index = self.index(fd)?;
        self.0[index]
            .as_mut()
            .expect("occupied descriptor")
            .1
            .cursor = cursor;
        Ok(())
    }

    pub(super) fn set_slot_cursor(&mut self, index: usize, cursor: u64) {
        self.0[index]
            .as_mut()
            .expect("occupied descriptor")
            .1
            .cursor = cursor;
    }

    pub(super) fn index(&self, fd: u32) -> IoResult<usize> {
        self.0
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|(number, _)| *number == fd))
            .ok_or(IoFailure::Errno(BADF))
    }

    pub(super) fn get(&self, fd: u32) -> IoResult<Descriptor> {
        Ok(self.0[self.index(fd)?].expect("occupied descriptor").1)
    }

    pub(super) fn readable(&self, fd: u32) -> IoResult<Descriptor> {
        let descriptor = self.get(fd)?;
        match descriptor.stream {
            Stream::Directory(_) => return Err(IoFailure::Errno(31)), // ISDIR
            Stream::Output | Stream::Error => return Err(IoFailure::Errno(BADF)),
            _ => {}
        }
        require_right(descriptor, READ)?;
        Ok(descriptor)
    }

    pub(super) fn writable(&self, fd: u32) -> IoResult<Stream> {
        let descriptor = self.get(fd)?;
        match descriptor.stream {
            Stream::Input => return Err(IoFailure::Errno(BADF)),
            Stream::File(_) | Stream::Directory(_) => return Err(IoFailure::Errno(NOTCAPABLE)),
            _ => {}
        }
        require_right(descriptor, WRITE)?;
        Ok(descriptor.stream)
    }

    fn close(&mut self, fd: u32) -> IoResult<()> {
        let index = self.index(fd)?;
        self.0[index] = None;
        Ok(())
    }

    fn renumber(&mut self, from: u32, to: u32) -> IoResult<()> {
        let source = self.index(from)?; // Validate even for from == to.
        if from == to {
            return Ok(());
        }
        let descriptor = self.0[source].expect("occupied descriptor").1;
        if let Ok(target) = self.index(to) {
            self.0[target] = None;
        }
        self.0[source] = Some((to, descriptor));
        Ok(())
    }
}

pub(super) fn require_right(descriptor: Descriptor, right: u64) -> IoResult<()> {
    if descriptor.rights & right != right {
        return Err(IoFailure::Errno(NOTCAPABLE));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Operation {
    Stat,
    FileStat,
    Close,
    Renumber,
    Rights,
    Flags,
    Seek,
    Tell,
    Prestat,
    PrestatName,
}

pub(super) fn install(
    imports: &mut WasmHostImports,
    streams: &Arc<Mutex<Streams>>,
    files: bool,
) -> Result<(), WasiPreview1Error> {
    use WasmValueType::{I32, I64};
    // Management is Builtin authority only. fd_read/fd_write independently
    // require FsRead/Console even after the guest changes numeric handles.
    for (name, params, operation) in [
        ("fd_fdstat_get", vec![I32, I32], Operation::Stat),
        ("fd_filestat_get", vec![I32, I32], Operation::FileStat),
        ("fd_close", vec![I32], Operation::Close),
        ("fd_renumber", vec![I32, I32], Operation::Renumber),
        (
            "fd_fdstat_set_rights",
            vec![I32, I64, I64],
            Operation::Rights,
        ),
        ("fd_fdstat_set_flags", vec![I32, I32], Operation::Flags),
        ("fd_seek", vec![I32, I64, I32, I32], Operation::Seek),
        ("fd_tell", vec![I32, I32], Operation::Tell),
        ("fd_prestat_get", vec![I32, I32], Operation::Prestat),
        (
            "fd_prestat_dir_name",
            vec![I32, I32, I32],
            Operation::PrestatName,
        ),
    ] {
        let mut required = BTreeSet::from([RuntimeCapability::Builtin]);
        if files
            && matches!(
                operation,
                Operation::Stat
                    | Operation::FileStat
                    | Operation::Seek
                    | Operation::Tell
                    | Operation::Prestat
                    | Operation::PrestatName
            )
        {
            // File sizes, names and cursors are filesystem observations too.
            required.insert(RuntimeCapability::FsRead);
        }
        let streams = Arc::clone(streams);
        imports.define(
            WASI_PREVIEW1_MODULE,
            name,
            WasmFunctionSignature {
                params,
                results: vec![I32],
            },
            required,
            1,
            move |caller, arguments| match execute(operation, caller, arguments, &streams) {
                Ok(()) => errno(SUCCESS),
                Err(IoFailure::Errno(code)) => errno(code),
                Err(IoFailure::Vm(error)) => Err(error),
            },
        )?;
    }
    Ok(())
}

fn execute(
    operation: Operation,
    caller: &mut WasmHostCaller<'_, '_>,
    arguments: &[WasmBoundaryValue],
    streams: &Mutex<Streams>,
) -> IoResult<()> {
    use WasmBoundaryValue::{I32, I64};
    caller.checkpoint()?;
    let mut streams = access(streams)?;
    streams.descriptors.charge(caller)?;
    match operation {
        Operation::Close => {
            let [fd] = words(arguments)?;
            streams.descriptors.close(fd)?;
        }
        Operation::Renumber => {
            let [from, to] = words(arguments)?;
            streams.descriptors.renumber(from, to)?;
        }
        Operation::Stat | Operation::FileStat => {
            let [fd, address] = words(arguments)?;
            let descriptor = streams.descriptors.get(fd)?;
            // WASI's memory32 records have explicit padding. Do not copy a host
            // Rust struct or leak its uninitialized padding into guest memory.
            let mut bytes = [0_u8; 64];
            let length = if matches!(operation, Operation::Stat) {
                bytes[0] = file_type(descriptor.stream);
                bytes[2..4].copy_from_slice(&descriptor.flags.to_le_bytes());
                bytes[8..16].copy_from_slice(&descriptor.rights.to_le_bytes());
                bytes[16..24].copy_from_slice(&descriptor.inheriting.to_le_bytes());
                24
            } else {
                require_right(descriptor, FILESTAT)?;
                bytes = filestat(descriptor.stream, streams.files.as_ref())?;
                64
            };
            if !valid_range(caller, address, length as u64) {
                return Err(IoFailure::Errno(FAULT));
            }
            caller.write_memory(address, &bytes[..length])?;
        }
        Operation::Rights => {
            let [I32(fd), I64(base), I64(inheriting)] = arguments else {
                return Err(IoFailure::Vm(
                    WasmHostError::trap("invalid WASI rights ABI").into(),
                ));
            };
            let index = streams.descriptors.index(*fd as u32)?;
            let (_, descriptor) = streams.descriptors.0[index]
                .as_mut()
                .expect("occupied descriptor");
            let base = *base as u64;
            let inheriting = *inheriting as u64;
            if inheriting & !descriptor.inheriting != 0 || base & !descriptor.rights != 0 {
                return Err(IoFailure::Errno(NOTCAPABLE));
            }
            descriptor.rights = base; // One-way attenuation, including to zero.
            descriptor.inheriting = inheriting;
        }
        Operation::Flags => {
            let [fd, flags] = words(arguments)?;
            let index = streams.descriptors.index(fd)?;
            let (_, descriptor) = streams.descriptors.0[index]
                .as_mut()
                .expect("occupied descriptor");
            require_right(*descriptor, SET_FLAGS)?;
            if flags & !0x1f != 0 {
                return Err(IoFailure::Errno(INVAL));
            }
            if flags & !u32::from(NONBLOCK) != 0 {
                return Err(IoFailure::Errno(NOTSUP));
            }
            descriptor.flags = flags as u16;
        }
        Operation::Seek => {
            let [I32(fd), I64(delta), I32(whence), I32(address)] = arguments else {
                return Err(IoFailure::Vm(
                    WasmHostError::trap("invalid WASI seek ABI").into(),
                ));
            };
            let fd = *fd as u32;
            let descriptor = streams.descriptors.get(fd)?;
            if (*whence as u32) > 2 {
                return Err(IoFailure::Errno(INVAL));
            }
            let Stream::File(index) = descriptor.stream else {
                return Err(IoFailure::Errno(SPIPE));
            };
            if *whence == 1 && *delta == 0 {
                if descriptor.rights & (SEEK | TELL) == 0 {
                    return Err(IoFailure::Errno(NOTCAPABLE));
                }
            } else {
                require_right(descriptor, SEEK)?;
            }
            let size = streams
                .files
                .as_ref()
                .ok_or(IoFailure::Errno(BADF))?
                .bytes(index)?
                .len() as u64;
            let base = match *whence {
                0 => 0,
                1 => descriptor.cursor,
                _ => size,
            };
            let next = i128::from(base) + i128::from(*delta);
            let next = u64::try_from(next).map_err(|_| IoFailure::Errno(INVAL))?;
            if !valid_range(caller, *address as u32, 8) {
                return Err(IoFailure::Errno(FAULT));
            }
            caller.write_memory(*address as u32, &next.to_le_bytes())?;
            streams.descriptors.set_cursor(fd, next)?;
        }
        Operation::Tell => {
            let [fd, address] = words(arguments)?;
            let descriptor = streams.descriptors.get(fd)?;
            if !matches!(descriptor.stream, Stream::File(_)) {
                return Err(IoFailure::Errno(SPIPE));
            }
            if descriptor.rights & (SEEK | TELL) == 0 {
                return Err(IoFailure::Errno(NOTCAPABLE));
            }
            if !valid_range(caller, address, 8) {
                return Err(IoFailure::Errno(FAULT));
            }
            caller.write_memory(address, &descriptor.cursor.to_le_bytes())?;
        }
        Operation::Prestat | Operation::PrestatName => {
            let fd = match arguments.first() {
                Some(I32(fd)) => *fd as u32,
                _ => return Err(IoFailure::Errno(INVAL)),
            };
            if !streams.descriptors.get(fd)?.preopen {
                return Err(IoFailure::Errno(BADF));
            }
            let name = &streams.files.as_ref().ok_or(IoFailure::Errno(BADF))?.mount;
            if matches!(operation, Operation::Prestat) {
                let [_, address] = words(arguments)?;
                if !valid_range(caller, address, 8) {
                    return Err(IoFailure::Errno(FAULT));
                }
                let mut bytes = [0; 8];
                bytes[4..8].copy_from_slice(&(name.len() as u32).to_le_bytes());
                caller.write_memory(address, &bytes)?;
            } else {
                let [_, address, length] = words(arguments)?;
                if (length as usize) < name.len() {
                    return Err(IoFailure::Errno(37));
                } // NAMETOOLONG
                if !valid_range(caller, address, u64::from(length)) {
                    return Err(IoFailure::Errno(FAULT));
                }
                caller.write_memory(address, name.as_bytes())?;
            }
        }
    }
    Ok(())
}

pub(super) fn file_type(stream: Stream) -> u8 {
    match stream {
        Stream::File(_) => 4,
        Stream::Directory(_) => 3,
        _ => CHARACTER_DEVICE,
    }
}

pub(super) fn filestat(stream: Stream, files: Option<&files::FileSystem>) -> IoResult<[u8; 64]> {
    let mut bytes = [0; 64];
    let (inode, size) = match stream {
        Stream::Input => (1, 0),
        Stream::Output => (2, 0),
        Stream::Error => (3, 0),
        Stream::File(index) => (
            (index as u64) + 4,
            files.ok_or(IoFailure::Errno(BADF))?.bytes(index)?.len() as u64,
        ),
        Stream::Directory(index) => ((index as u64) + 4, 0),
    };
    bytes[8..16].copy_from_slice(&inode.to_le_bytes());
    bytes[16] = file_type(stream);
    bytes[24..32].copy_from_slice(&1_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&size.to_le_bytes());
    Ok(bytes)
}
