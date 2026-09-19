/* Freestanding command combining clocks, entropy, stdio and process exit.
 * Reproduce from the repository root with clang 17 or a compatible toolchain:
 * clang --target=wasm32 -nostdlib -Oz -Wl,--no-entry -Wl,--export=_start \
 *   -Wl,--export-memory -Wl,--initial-memory=131072 -Wl,--max-memory=131072 \
 *   -Wl,-z,stack-size=16384 -Wl,--strip-all \
 *   crates/franken-engine/tests/fixtures/wasi_clock_smoke.c \
 *   -o crates/franken-engine/tests/fixtures/wasi_clock_smoke.wasm
 */
typedef unsigned int u32;
typedef unsigned long long u64;
struct iovec { const void *bytes; u32 length; };
__attribute__((import_module("wasi_snapshot_preview1"), import_name("clock_res_get")))
extern int clock_res_get(u32, u64 *);
__attribute__((import_module("wasi_snapshot_preview1"), import_name("clock_time_get")))
extern int clock_time_get(u32, u64, u64 *);
__attribute__((import_module("wasi_snapshot_preview1"), import_name("random_get")))
extern int random_get(unsigned char *, u32);
__attribute__((import_module("wasi_snapshot_preview1"), import_name("fd_write")))
extern int fd_write(u32, const struct iovec *, u32, u32 *);
__attribute__((import_module("wasi_snapshot_preview1"), import_name("proc_exit"), noreturn))
extern void proc_exit(u32);

void _start(void) {
    u64 times[3];
    unsigned char random[16];
    int error = clock_res_get(1, &times[0]);
    if (error) proc_exit((u32)error);
    error = clock_time_get(1, ~(u64)0, &times[1]);
    if (error) proc_exit((u32)error);
    error = random_get(random, sizeof(random));
    if (error) proc_exit((u32)error);
    error = clock_time_get(1, 0, &times[2]);
    if (error) proc_exit((u32)error);
    if (!times[0] || times[2] < times[1]) proc_exit(29);
    const struct iovec output[2] = { { times, sizeof(times) }, { random, sizeof(random) } };
    u32 written = 0;
    error = fd_write(1, output, 2, &written);
    if (error || written != sizeof(times) + sizeof(random)) proc_exit(error ? (u32)error : 70);
}
