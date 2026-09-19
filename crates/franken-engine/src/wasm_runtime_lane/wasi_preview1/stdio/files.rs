//! Immutable, explicitly supplied files. No OS paths, links or ambient roots.
//!
//! Every directory descriptor is its own path-resolution boundary. Intermediate
//! components are traversed, not string-normalized past non-directories. File
//! data is immutable; each open descriptor owns its independent cursor/rights.

use super::*;
use super::descriptors::{
    Descriptor, Stream, DIRECTORY_RIGHTS, FILE_RIGHTS, NOTCAPABLE, NOTSUP,
    PATH_FILESTAT, PATH_OPEN, filestat, require_right,
};

const ILSEQ: i32 = 25;
const NAMETOOLONG: i32 = 37;
const NOENT: i32 = 44;
const NOTDIR: i32 = 54;
const ROFS: i32 = 69;

/// A private read-only tree, mounted at fd 3. The mount name is a guest label,
/// NEVER a host path. File keys must be canonical relative UTF-8 paths; parent
/// directories are created implicitly. Empty files and an empty root are valid.
/// There are no symlinks, devices, writable files or external filesystem calls.
#[derive(Debug, Clone)]
pub struct WasiReadOnlyFiles {
    pub mount_path: String,
    pub files: BTreeMap<String, Vec<u8>>,
    /// Includes the root, every implicit directory and every file.
    pub max_entries: usize,
    /// Total immutable file payload bytes. Path metadata is separately bounded
    /// by max_entries * max_path_bytes (plus bounded map/node overhead).
    pub max_bytes: usize,
    pub max_path_bytes: u32,
    /// Total slots including stdio and the root. Must be in 4..=65536. Slots
    /// are allocated before linking; path_open never allocates by a guest fd.
    pub max_open_descriptors: usize,
}

impl Default for WasiReadOnlyFiles {
    fn default() -> Self {
        Self {
            mount_path: "/data".into(), files: BTreeMap::new(),
            max_entries: 4096, max_bytes: 16 * 1024 * 1024,
            max_path_bytes: 4096, max_open_descriptors: 128,
        }
    }
}

#[derive(Debug)]
pub(super) struct Node {
    pub name: String,
    pub parent: usize,
    pub contents: Option<Arc<[u8]>>,
    pub children: BTreeMap<String, usize>,
}

#[derive(Debug)]
pub(super) struct FileSystem {
    pub mount: String,
    pub nodes: Vec<Node>,
    max_path_bytes: u32,
}

fn invalid_path(index: usize) -> WasiPreview1Error {
    WasiPreview1Error::InvalidString { field: "read-only filesystem path", index }
}

impl FileSystem {
    pub(super) fn build(config: WasiReadOnlyFiles) -> Result<Self, WasiPreview1Error> {
        limit("filesystem entries", 1, config.max_entries as u64)?;
        limit("filesystem paths", config.mount_path.len() as u64, u64::from(config.max_path_bytes))?;
        if config.mount_path.is_empty() || config.mount_path.contains('\0') { return Err(invalid_path(0)); }
        let bytes = config.files.values().fold(0_u64, |n, data| n.saturating_add(data.len() as u64));
        limit("read-only file bytes", bytes, config.max_bytes as u64)?;
        limit("filesystem entries", (config.files.len() as u64).saturating_add(1), config.max_entries as u64)?;
        let mut fs = Self { mount: config.mount_path, nodes: Vec::new(), max_path_bytes: config.max_path_bytes };
        fs.nodes.try_reserve_exact(1).map_err(|_| WasiPreview1Error::AllocationFailed)?;
        fs.nodes.push(Node { name: String::new(), parent: 0, contents: None, children: BTreeMap::new() });
        for (index, (path, contents)) in config.files.into_iter().enumerate() {
            limit("filesystem path bytes", path.len() as u64, u64::from(fs.max_path_bytes))?;
            if path.is_empty() || path.contains('\0')
                || path.split('/').any(|part| matches!(part, "" | "." | "..")) {
                return Err(invalid_path(index));
            }
            let mut current = 0;
            let mut parts = path.split('/').peekable();
            let mut contents = Some(contents);
            while let Some(part) = parts.next() {
                let last = parts.peek().is_none();
                if fs.nodes[current].contents.is_some() { return Err(invalid_path(index)); }
                if let Some(child) = fs.nodes[current].children.get(part).copied() {
                    // A configured file cannot replace an implicit directory.
                    if last { return Err(invalid_path(index)); }
                    current = child;
                } else {
                    limit("filesystem entries", fs.nodes.len() as u64 + 1, config.max_entries as u64)?;
                    fs.nodes.try_reserve(1).map_err(|_| WasiPreview1Error::AllocationFailed)?;
                    let child = fs.nodes.len();
                    fs.nodes.push(Node {
                        name: part.into(), parent: current,
                        contents: if last { Some(Arc::from(contents.take().expect("file payload"))) } else { None },
                        children: BTreeMap::new(),
                    });
                    fs.nodes[current].children.insert(part.into(), child);
                    current = child;
                }
            }
        }
        Ok(fs)
    }

    pub(super) fn bytes(&self, index: usize) -> IoResult<&Arc<[u8]>> {
        self.nodes.get(index).and_then(|node| node.contents.as_ref()).ok_or(IoFailure::Errno(BADF))
    }

    pub(super) fn object(&self, index: usize) -> Stream {
        if self.nodes[index].contents.is_some() { Stream::File(index) } else { Stream::Directory(index) }
    }

    fn lookup(&self, caller: &mut WasmHostCaller<'_, '_>, base: usize, address: u32, length: u32) -> IoResult<usize> {
        if length > self.max_path_bytes { return Err(IoFailure::Errno(NAMETOOLONG)); }
        if !valid_range(caller, address, u64::from(length)) { return Err(IoFailure::Errno(FAULT)); }
        // Bound UTF-8/component scans and ordered-map comparisons before reading
        // a guest path. Traversal uses borrowed components, no path-sized copies.
        let depth = self.nodes.len().max(1).ilog2() as u64 + 2;
        caller.charge_work(u64::from(length) * depth)?;
        let path = std::str::from_utf8(caller.read_memory(address, length)?)
            .map_err(|_| IoFailure::Errno(ILSEQ))?;
        if path.is_empty() { return Err(IoFailure::Errno(NOENT)); }
        if path.starts_with('/') { return Err(IoFailure::Errno(NOTCAPABLE)); }
        if path.contains('\0') { return Err(IoFailure::Errno(INVAL)); }
        let mut current = base;
        for part in path.split('/') {
            if self.nodes[current].contents.is_some() { return Err(IoFailure::Errno(NOTDIR)); }
            match part {
                "" | "." => {},
                ".." => {
                    if current == base { return Err(IoFailure::Errno(NOTCAPABLE)); }
                    current = self.nodes[current].parent;
                }
                name => current = *self.nodes[current].children.get(name).ok_or(IoFailure::Errno(NOENT))?,
            }
        }
        Ok(current)
    }
}

impl WasiPreview1Config {
    /// Supply a private, immutable filesystem alongside the existing bounded
    /// streams. Files/path operations and filesystem metadata require FsRead;
    /// descriptor management requires Builtin, and output still needs Console.
    /// These requirements do not grant capabilities or bypass module manifests.
    /// The old stdio-only factory remains filesystem-free.
    pub fn into_imports_with_read_only_files(
        self,
        granted: BTreeSet<RuntimeCapability>,
        stdin: Vec<u8>,
        streams: WasiStdioLimits,
        files: WasiReadOnlyFiles,
    ) -> Result<(WasmHostImports, WasiStdio), WasiPreview1Error> {
        self.stdio_imports(granted, stdin, streams, Some(files))
    }
}

#[derive(Clone, Copy)]
enum Operation { Open, Stat, Pread }

pub(super) fn install(
    imports: &mut WasmHostImports,
    streams: &Arc<Mutex<Streams>>,
    limits: &WasiStdioLimits,
) -> Result<(), WasiPreview1Error> {
    use WasmValueType::{I32, I64};
    for (name, params, operation) in [
        ("path_open", vec![I32, I32, I32, I32, I32, I64, I64, I32, I32], Operation::Open),
        ("path_filestat_get", vec![I32; 5], Operation::Stat),
        ("fd_pread", vec![I32, I32, I32, I64, I32], Operation::Pread),
    ] {
        let streams = Arc::clone(streams);
        let limits = limits.clone();
        imports.define(WASI_PREVIEW1_MODULE, name, WasmFunctionSignature { params, results: vec![I32] },
            BTreeSet::from([RuntimeCapability::FsRead]), 1,
            move |caller, args| match execute(operation, caller, args, &streams, &limits) {
                Ok(()) => errno(SUCCESS), Err(IoFailure::Errno(code)) => errno(code), Err(IoFailure::Vm(error)) => Err(error),
            })?;
    }
    Ok(())
}

fn execute(operation: Operation, caller: &mut WasmHostCaller<'_, '_>, args: &[WasmBoundaryValue],
    streams: &Mutex<Streams>, limits: &WasiStdioLimits) -> IoResult<()> {
    use WasmBoundaryValue::{I32, I64};
    caller.checkpoint()?;
    if matches!(operation, Operation::Pread) {
        let [I32(fd), I32(table), I32(count), I64(offset), I32(result)] = args else {
            return Err(IoFailure::Vm(WasmHostError::trap("invalid WASI pread ABI").into()));
        };
        return read_input(caller, [*fd as u32, *table as u32, *count as u32, *result as u32], streams, limits, Some(*offset as u64));
    }
    let mut streams = access(streams)?;
    streams.descriptors.charge(caller)?;
    let (fd, flags, address, length, out) = match operation {
        Operation::Open => {
            let [I32(fd), I32(flags), I32(address), I32(length), I32(_), I64(_), I64(_), I32(_), I32(out)] = args else {
                return Err(IoFailure::Vm(WasmHostError::trap("invalid WASI path_open ABI").into()));
            };
            (*fd as u32, *flags as u32, *address as u32, *length as u32, *out as u32)
        }
        Operation::Stat => { let [fd, flags, address, length, out] = words(args)?; (fd, flags, address, length, out) }
        Operation::Pread => unreachable!("handled before locking"),
    };
    if flags & !1 != 0 { return Err(IoFailure::Errno(INVAL)); }
    let directory = streams.descriptors.get(fd)?;
    let Stream::Directory(base) = directory.stream else { return Err(IoFailure::Errno(NOTDIR)); };
    require_right(directory, if matches!(operation, Operation::Open) { PATH_OPEN } else { PATH_FILESTAT })?;
    let width = if matches!(operation, Operation::Open) { 4 } else { 64 };
    if !valid_range(caller, out, width) { return Err(IoFailure::Errno(FAULT)); }
    let fs = streams.files.as_ref().ok_or(IoFailure::Errno(BADF))?;
    if matches!(operation, Operation::Stat) {
        let index = fs.lookup(caller, base, address, length)?;
        let bytes = filestat(fs.object(index), Some(fs))?;
        caller.write_memory(out, &bytes)?;
        return Ok(());
    }
    let [I32(_), I32(_), I32(_), I32(_), I32(oflags), I64(rights), I64(inheriting), I32(fdflags), I32(_)] = args else {
        unreachable!("checked open ABI");
    };
    let (oflags, fdflags) = (*oflags as u32, *fdflags as u32);
    if oflags & !15 != 0 || fdflags & !31 != 0 { return Err(IoFailure::Errno(INVAL)); }
    if oflags & (1 | 8) != 0 { return Err(IoFailure::Errno(ROFS)); } // CREAT / TRUNC
    if fdflags & !4 != 0 { return Err(IoFailure::Errno(NOTSUP)); }
    let (rights, inheriting) = (*rights as u64, *inheriting as u64);
    if (rights | inheriting) & !directory.inheriting != 0 { return Err(IoFailure::Errno(NOTCAPABLE)); }
    let index = fs.lookup(caller, base, address, length)?;
    let object = fs.object(index);
    if oflags & 2 != 0 && !matches!(object, Stream::Directory(_)) { return Err(IoFailure::Errno(NOTDIR)); }
    let supported = if matches!(object, Stream::Directory(_)) { DIRECTORY_RIGHTS } else { FILE_RIGHTS };
    if rights & !supported != 0 || (matches!(object, Stream::File(_)) && inheriting != 0) {
        return Err(IoFailure::Errno(NOTCAPABLE));
    }
    let (slot, number) = streams.descriptors.vacant(caller)?;
    // Publish the result before infallibly filling a preallocated slot. A known
    // bounds/work/recording refusal cannot leak a new hidden descriptor.
    caller.write_memory(out, &number.to_le_bytes())?;
    let mut descriptor = Descriptor::new(object, rights);
    descriptor.inheriting = inheriting;
    descriptor.flags = fdflags as u16;
    streams.descriptors.insert(slot, number, descriptor);
    Ok(())
}
