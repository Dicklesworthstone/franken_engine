# Linux system executables and immutable snapshots

Ubuntu's patched uutils checks that its utility name matches the real basename
reported by `/proc/self/exe`. An anonymous memfd reports a synthetic name ending
in ` (deleted)`, so preserving `argv[0]` alone cannot make those utilities work.
This is the Linux process-spawning blocker reported in issue #11.

The native provider offers two deliberately different authorizations:

| Authorization | Executed image | Trust after the launch-time digest check |
| --- | --- | --- |
| `authorize_executable` / `authorize_alias` | Sealed anonymous snapshot | Main-image bytes remain immutable, including against later source writes. |
| `authorize_trusted_system_executable` / `authorize_trusted_system_alias` | Held, authenticated, named system inode | Privileged host administration and the backing storage remain trusted. |

The immutable mode is still the default. Existing policies keep that behavior;
an empty trusted-system set is omitted from serialization, preserving the old
policy representation. A nonempty `trusted_system_executables` grant is serialized
alongside `allowed_executables`, so signing or hashing the complete policy covers
the additional trust decision. Each trusted path still requires an exact digest
entry. A request cannot choose or add this authority.

## Authorizing an Ubuntu system utility

The operator can explicitly authorize a protected system executable and its alias:

```rust
use frankenengine_extension_host::process_spawn::{NativeProcessSpawn, ProcessSpawnPolicy};

let mut policy = ProcessSpawnPolicy::jailed("/srv/my-service/work")?;
let canonical = policy.authorize_trusted_system_alias("echo", "/usr/bin/echo")?;
let provider = NativeProcessSpawn::new(policy)?;
```

Use an existing working directory appropriate for the service. The returned
canonical path and the authorized `echo` alias refer to the same grant; ambient
`PATH` lookup is never involved. If no alias is needed, call
`authorize_trusted_system_executable` directly.

The Linux validator walks from `/` through held directory descriptors without
following new symlinks. It requires the executable and every ancestor to be owned
by UID 0 and not writable by group or other users. These mode checks also reject
effective POSIX ACL write grants, because named-user and group ACL entries are
limited by the group-class mask. Setuid, setgid, and file-capability metadata are
rejected. Source execution permissions, including ACLs and `noexec` mounts, still
apply.

Every launch repeats those checks, hashes the same held executable descriptor
with the configured size bound and cancellation checkpoints, and compares the
digest with the policy. Exec uses that descriptor, preserving the real basename
without reopening a caller-controlled pathname. The cwd jail, capability gates,
environment policy, output/stdin limits, deadlines, and lifecycle cleanup remain
the same.

Calling `authorize_executable` or `authorize_alias` again selects immutable
authorization and clears a prior trusted-system grant for that path. Use the
trusted-system methods when adding or updating a named-system authorization.
These methods fail without mutating the policy if the source is unsuitable.

## Security boundary

Trusted-system authorization is **not an immutable snapshot guarantee**. It
explicitly trusts privileged host updates after authentication, including the
administration of a network-backed store or container image layers. Do not use
it for executable content controlled by an untrusted storage service, tenant,
package installer, or administrator. Root ownership and mode bits alone cannot
make an untrusted backing store immutable. The operator must trust that store,
just as the existing provider trusts the dynamic loader, shared libraries, and
other host resources used by a process.

Writable or tenant-controlled executables should keep immutable authorization.
That mode retains post-seal hashing, protection against in-place rewrites and
truncation, and rejection of mutation through descriptor aliases. A program that
requires a real filename needs a suitable trusted-system grant or a separately
provided immutable named-image facility; there is no automatic weaker retry.
FreeBSD continues to fail closed until its immutable-image backend is available.

An ordinary temporary copy is not a safe substitute: its owner can change its
mode and rewrite it. Relying solely on the kernel's usual executable write
exclusion is also insufficient on current Linux, where fanotify permission/HSM
handling can bypass that exclusion. The provider therefore does not use a
temporary-copy/ptrace workaround or reinterpret existing immutable policies.

## Regression coverage

The Linux workflow installs actual Ubuntu 26.04 uutils, first reproduces the old
sealed-memfd name failure, then runs the trusted-system integration tests and all
extension-host library tests as UID 1000. It also runs the core's native process
and child-cleanup tests against those installed utilities. The positive utility
case is required.
Separate immutable-mode tests still rewrite and truncate the authorized inode,
attempt writes and resizing through aliases, and check source execution
permissions and resource admission. Those fixtures use a standalone shell image
so the immutability assertions do not depend on multicall name dispatch.

References:

- [FrankenEngine issue #11](https://github.com/Dicklesworthstone/franken_engine/issues/11)
- [Ubuntu utility-name security patch](https://git.launchpad.net/ubuntu/+source/rust-coreutils/plain/debian/patches/require-utility-to-be-invoked-at-matching-path.patch?h=applied/ubuntu/devel)
- [Linux executable write denial and HSM exception](https://github.com/torvalds/linux/blob/master/include/linux/fs.h)
- [Linux fsnotify permission handling](https://github.com/torvalds/linux/blob/master/fs/notify/fsnotify.c)
