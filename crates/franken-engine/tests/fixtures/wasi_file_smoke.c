/* Rebuild with clang/wasm-ld (no libc or external engine bindings):
 * clang --target=wasm32 -Oz -nostdlib -fno-builtin \
 *   -Wl,--no-entry -Wl,--export=_start -Wl,--export-memory -Wl,--strip-all \
 *   -Wl,--initial-memory=131072 -Wl,--max-memory=131072 -Wl,-z,stack-size=16384 \
 *   -o wasi_file_smoke.wasm wasi_file_smoke.c
 * Input: private preopen fd 3 named /data, nested/input.bin with 1000 bytes
 * byte[i] = i mod 256. Output: the exact input on stdout, no stderr, exit 0.
 */
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long i64;
#define IMPORT(name) __attribute__((import_module("wasi_snapshot_preview1"), import_name(#name)))
struct iovec { void *base; u32 len; };
IMPORT(fd_prestat_get) int fd_prestat_get(u32, void *);
IMPORT(fd_prestat_dir_name) int fd_prestat_dir_name(u32, void *, u32);
IMPORT(fd_readdir) int fd_readdir(u32, void *, u32, u64, u32 *);
IMPORT(path_open) int path_open(u32, u32, const char *, u32, u32, u64, u64, u32, u32 *);
IMPORT(fd_read) int fd_read(u32, const struct iovec *, u32, u32 *);
IMPORT(fd_pread) int fd_pread(u32, const struct iovec *, u32, u64, u32 *);
IMPORT(fd_seek) int fd_seek(u32, i64, u32, u64 *);
IMPORT(fd_tell) int fd_tell(u32, u64 *);
IMPORT(fd_write) int fd_write(u32, const struct iovec *, u32, u32 *);
IMPORT(fd_close) int fd_close(u32);
IMPORT(proc_exit) __attribute__((noreturn)) void proc_exit(u32);

static void check(int condition, u32 code) { if (!condition) proc_exit(code); }
void _start(void) {
    u32 preopen[2], used, fd, read, written;
    u64 position;
    unsigned char buffer[1024];
    check(fd_prestat_get(3, preopen) == 0 && preopen[0] == 0 && preopen[1] == 5, 1);
    check(fd_prestat_dir_name(3, buffer, 5) == 0, 2);
    for (u32 i = 0; i < 5; ++i) check(buffer[i] == (unsigned char)"/data"[i], 3);
    check(fd_readdir(3, buffer, sizeof buffer, 0, &used) == 0 && used >= 24, 4);
    const u64 rights = (1ULL << 1) | (1ULL << 2) | (1ULL << 5) | (1ULL << 21);
    check(path_open(3, 1, "nested/input.bin", 16, 0, rights, 0, 0, &fd) == 0, 5);
    struct iovec part = {buffer, 3};
    check(fd_pread(fd, &part, 1, 1, &read) == 0 && read == 3, 6);
    check(buffer[0] == 1 && buffer[1] == 2 && buffer[2] == 3, 7);
    check(fd_tell(fd, &position) == 0 && position == 0, 8);
    check(fd_seek(fd, 0, 2, &position) == 0 && position == 1000, 9);
    check(fd_seek(fd, 0, 0, &position) == 0 && position == 0, 10);
    u32 total = 0;
    for (;;) {
        part.len = 257;
        check(fd_read(fd, &part, 1, &read) == 0 && read <= part.len, 11);
        if (read == 0) break;
        for (u32 i = 0; i < read; ++i) check(buffer[i] == (unsigned char)(total + i), 12);
        part.len = read;
        check(fd_write(1, &part, 1, &written) == 0 && written == read, 13);
        total += read;
    }
    check(total == 1000, 14);
    check(fd_close(fd) == 0, 15);
    proc_exit(0);
}
