/* Compiled guest fixture, no libc or host services outside explicit WASI.
 * Rebuild with:
 * clang --target=wasm32 -O1 -nostdlib -fno-builtin \
 *   -Wl,--no-entry -Wl,--export-memory -Wl,--strip-all \
 *   wasi_descriptor_smoke.c -o wasi_descriptor_smoke.wasm
 */
typedef unsigned u32;
typedef unsigned long long u64;
#define IMPORT(name) __attribute__((import_module("wasi_snapshot_preview1"), import_name(#name)))
IMPORT(fd_fdstat_get) extern u32 fd_fdstat_get(u32, void *);
IMPORT(fd_filestat_get) extern u32 fd_filestat_get(u32, void *);
IMPORT(fd_fdstat_set_rights) extern u32 fd_fdstat_set_rights(u32, u64, u64);
IMPORT(fd_renumber) extern u32 fd_renumber(u32, u32);
IMPORT(fd_close) extern u32 fd_close(u32);
IMPORT(fd_read) extern u32 fd_read(u32, const void *, u32, u32 *);
IMPORT(fd_write) extern u32 fd_write(u32, const void *, u32, u32 *);
IMPORT(proc_exit) extern void proc_exit(u32) __attribute__((noreturn));
struct fdstat { unsigned char type, pad; unsigned short flags; u32 pad2; u64 base, inheriting; };
struct iovec { void *data; u32 length; };
_Static_assert(sizeof(struct fdstat) == 24, "WASI fdstat layout");
_Static_assert(sizeof(struct iovec) == 8, "WASI iovec layout");
static void check(int ok, u32 code) { if (!ok) proc_exit(code); }
__attribute__((export_name("_start"))) void entry(void) {
    struct fdstat input, output;
    u64 stat[8];
    check(fd_fdstat_get(0, &input) == 0 && (input.base & 2), 10);
    check(fd_fdstat_get(1, &output) == 0 && (output.base & 64), 11);
    check(fd_filestat_get(1, stat) == 0, 12);
    /* Replacing stderr with stdout changes its handle, not its destination. */
    check(fd_renumber(1, 2) == 0, 13);
    check(fd_fdstat_get(1, &output) == 8, 14);
    char data[16];
    struct iovec io = { data, sizeof(data) };
    for (;;) {
        u32 read = 0, written = 0;
        check(fd_read(0, &io, 1, &read) == 0, 15);
        if (!read) break;
        io.length = read;
        check(fd_write(2, &io, 1, &written) == 0 && written == read, 16);
        io.length = sizeof(data);
    }
    /* Attenuation is permanent, even when descriptor identity is moved. */
    check(fd_fdstat_set_rights(0, 0, 0) == 0, 17);
    check(fd_fdstat_set_rights(0, input.base, input.inheriting) == 76, 18);
    check(fd_close(0) == 0 && fd_close(0) == 8, 19);
    check(fd_close(2) == 0, 20);
    proc_exit(0);
}
