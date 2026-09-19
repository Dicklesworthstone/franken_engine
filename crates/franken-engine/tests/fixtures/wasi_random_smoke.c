/* Freestanding compiled WASI command; no libc or runtime implementation.
 * Reproduce from the repository root with clang 17 or a compatible toolchain:
 * clang --target=wasm32 -nostdlib -Oz -Wl,--no-entry -Wl,--export=_start \
 *   -Wl,--export-memory -Wl,--initial-memory=131072 -Wl,--max-memory=131072 \
 *   -Wl,-z,stack-size=16384 -Wl,--strip-all \
 *   crates/franken-engine/tests/fixtures/wasi_random_smoke.c \
 *   -o crates/franken-engine/tests/fixtures/wasi_random_smoke.wasm
 */
typedef unsigned int u32;
struct iovec { const unsigned char *bytes; u32 length; };
__attribute__((import_module("wasi_snapshot_preview1"), import_name("random_get")))
extern int random_get(unsigned char *, u32);
__attribute__((import_module("wasi_snapshot_preview1"), import_name("fd_write")))
extern int fd_write(u32, const struct iovec *, u32, u32 *);
__attribute__((import_module("wasi_snapshot_preview1"), import_name("proc_exit"), noreturn))
extern void proc_exit(u32);

void _start(void) {
    unsigned char bytes[65];
    int error = random_get(bytes, sizeof(bytes));
    if (error) proc_exit((u32)error);
    const struct iovec output = { bytes, sizeof(bytes) };
    u32 written = 0;
    error = fd_write(1, &output, 1, &written);
    if (error || written != sizeof(bytes)) proc_exit(error ? (u32)error : 70);
}
