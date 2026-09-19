//! WASI descriptor ownership over three virtual standard streams.
//!
//! Numeric handles are guest-selected names, never OS descriptors or vector
//! offsets. Renumbering moves a descriptor and its attenuated rights in a fixed
//! three-slot table, so even u32::MAX cannot cause allocation amplification.
//! Closing a descriptor does not erase captured output or refund its quota.

use super::*;

const NOTCAPABLE: i32 = 76;
const NOTSUP: i32 = 58;
const SPIPE: i32 = 70;
const READ: u64 = 1 << 1;
const SET_FLAGS: u64 = 1 << 3;
const WRITE: u64 = 1 << 6;
const FILESTAT: u64 = 1 << 21;
const NONBLOCK: u16 = 4;
const CHARACTER_DEVICE: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stream { Input, Output, Error }

#[derive(Debug, Clone, Copy)]
struct Descriptor { stream: Stream, rights: u64, flags: u16 }

#[derive(Debug)]
pub(super) struct Table([Option<(u32, Descriptor)>; 3]);

impl Table {
    pub(super) fn new() -> Self {
        Self([
            Some((0, Descriptor { stream: Stream::Input, rights: READ | SET_FLAGS | FILESTAT, flags: 0 })),
            Some((1, Descriptor { stream: Stream::Output, rights: WRITE | SET_FLAGS | FILESTAT, flags: 0 })),
            Some((2, Descriptor { stream: Stream::Error, rights: WRITE | SET_FLAGS | FILESTAT, flags: 0 })),
        ])
    }

    fn index(&self, fd: u32) -> IoResult<usize> {
        self.0.iter().position(|slot| slot.as_ref().is_some_and(|(number, _)| *number == fd))
            .ok_or(IoFailure::Errno(BADF))
    }

    fn get(&self, fd: u32) -> IoResult<Descriptor> {
        Ok(self.0[self.index(fd)?].expect("occupied descriptor").1)
    }

    pub(super) fn readable(&self, fd: u32) -> IoResult<()> {
        let descriptor = self.get(fd)?;
        if descriptor.stream != Stream::Input { return Err(IoFailure::Errno(BADF)); }
        require_right(descriptor, READ)
    }

    pub(super) fn writable(&self, fd: u32) -> IoResult<Stream> {
        let descriptor = self.get(fd)?;
        if descriptor.stream == Stream::Input { return Err(IoFailure::Errno(BADF)); }
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
        if from == to { return Ok(()); }
        let descriptor = self.0[source].expect("occupied descriptor").1;
        if let Ok(target) = self.index(to) { self.0[target] = None; }
        self.0[source] = Some((to, descriptor));
        Ok(())
    }
}

fn require_right(descriptor: Descriptor, right: u64) -> IoResult<()> {
    if descriptor.rights & right == 0 { return Err(IoFailure::Errno(NOTCAPABLE)); }
    Ok(())
}

#[derive(Clone, Copy)]
enum Operation { Stat, FileStat, Close, Renumber, Rights, Flags, Seek, Tell, Prestat, PrestatName }

pub(super) fn install(
    imports: &mut WasmHostImports,
    streams: &Arc<Mutex<Streams>>,
) -> Result<(), WasiPreview1Error> {
    use WasmValueType::{I32, I64};
    // Management is Builtin authority only. fd_read/fd_write independently
    // require FsRead/Console even after the guest changes numeric handles.
    for (name, params, operation) in [
        ("fd_fdstat_get", vec![I32, I32], Operation::Stat),
        ("fd_filestat_get", vec![I32, I32], Operation::FileStat),
        ("fd_close", vec![I32], Operation::Close),
        ("fd_renumber", vec![I32, I32], Operation::Renumber),
        ("fd_fdstat_set_rights", vec![I32, I64, I64], Operation::Rights),
        ("fd_fdstat_set_flags", vec![I32, I32], Operation::Flags),
        ("fd_seek", vec![I32, I64, I32, I32], Operation::Seek),
        ("fd_tell", vec![I32, I32], Operation::Tell),
        ("fd_prestat_get", vec![I32, I32], Operation::Prestat),
        ("fd_prestat_dir_name", vec![I32, I32, I32], Operation::PrestatName),
    ] {
        let streams = Arc::clone(streams);
        imports.define(WASI_PREVIEW1_MODULE, name,
            WasmFunctionSignature { params, results: vec![I32] },
            BTreeSet::from([RuntimeCapability::Builtin]), 1,
            move |caller, arguments| match execute(operation, caller, arguments, &streams) {
                Ok(()) => errno(SUCCESS),
                Err(IoFailure::Errno(code)) => errno(code),
                Err(IoFailure::Vm(error)) => Err(error),
            })?;
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
    // The provider owns no directories. libc preopen enumeration must learn
    // that absence, not receive a fabricated directory or ambient host path.
    if matches!(operation, Operation::Prestat | Operation::PrestatName) {
        return Err(IoFailure::Errno(BADF));
    }
    let mut streams = access(streams)?;
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
                bytes[0] = CHARACTER_DEVICE;
                bytes[2..4].copy_from_slice(&descriptor.flags.to_le_bytes());
                bytes[8..16].copy_from_slice(&descriptor.rights.to_le_bytes());
                // Inheriting rights remain zero: there are no child descriptors.
                24
            } else {
                require_right(descriptor, FILESTAT)?;
                let inode = match descriptor.stream { Stream::Input => 1_u64, Stream::Output => 2, Stream::Error => 3 };
                bytes[8..16].copy_from_slice(&inode.to_le_bytes());
                bytes[16] = CHARACTER_DEVICE;
                bytes[24..32].copy_from_slice(&1_u64.to_le_bytes());
                // Virtual device zero, no regular-file size, and unavailable
                // timestamps are zero. Metadata never exposes unread input.
                64
            };
            if !valid_range(caller, address, length as u64) { return Err(IoFailure::Errno(FAULT)); }
            caller.write_memory(address, &bytes[..length])?;
        }
        Operation::Rights => {
            let [I32(fd), I64(base), I64(inheriting)] = arguments else {
                return Err(IoFailure::Vm(WasmHostError::trap("invalid WASI rights ABI").into()));
            };
            let index = streams.descriptors.index(*fd as u32)?;
            let (_, descriptor) = streams.descriptors.0[index].as_mut().expect("occupied descriptor");
            let base = *base as u64;
            if *inheriting != 0 || base & !descriptor.rights != 0 {
                return Err(IoFailure::Errno(NOTCAPABLE));
            }
            descriptor.rights = base; // One-way attenuation, including to zero.
        }
        Operation::Flags => {
            let [fd, flags] = words(arguments)?;
            let index = streams.descriptors.index(fd)?;
            let (_, descriptor) = streams.descriptors.0[index].as_mut().expect("occupied descriptor");
            require_right(*descriptor, SET_FLAGS)?;
            if flags & !0x1f != 0 { return Err(IoFailure::Errno(INVAL)); }
            if flags & !u32::from(NONBLOCK) != 0 { return Err(IoFailure::Errno(NOTSUP)); }
            descriptor.flags = flags as u16;
        }
        Operation::Seek => {
            let [I32(fd), I64(_), I32(whence), I32(_)] = arguments else {
                return Err(IoFailure::Vm(WasmHostError::trap("invalid WASI seek ABI").into()));
            };
            streams.descriptors.get(*fd as u32)?;
            if (*whence as u32) > 2 { return Err(IoFailure::Errno(INVAL)); }
            return Err(IoFailure::Errno(SPIPE));
        }
        Operation::Tell => {
            let [fd, _] = words(arguments)?;
            streams.descriptors.get(fd)?;
            return Err(IoFailure::Errno(SPIPE));
        }
        Operation::Prestat | Operation::PrestatName => unreachable!("handled before descriptor access"),
    }
    Ok(())
}
