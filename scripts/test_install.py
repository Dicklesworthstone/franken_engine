#!/usr/bin/env python3
"""Installer regression tests; no network, compiler, or real release execution.

Runs the actual sourced installer functions with real tar/copy/rename operations.
Small shell executables are explicitly test payloads, not frankenctl binaries.
Transport and selected failure points are controlled at their shell boundaries.
Scratch trees are retained (and printed), never recursively removed.

Run: python3 scripts/test_install.py
Use FRANKEN_INSTALLER_UNDER_TEST to compare an unchanged installer.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

INSTALLER = Path(os.environ.get(
    "FRANKEN_INSTALLER_UNDER_TEST", Path(__file__).resolve().parents[1] / "install.sh"
)).resolve()
TEST_ROOT = Path(tempfile.mkdtemp(prefix="franken-install-tests-",
                                 dir=os.environ.get("FRANKEN_INSTALL_TEST_ROOT")))
OLD = b"#!/bin/sh\necho 'frankenctl 0.1.0'\n"
NEW = b"#!/bin/sh\necho 'frankenctl 0.2.0'\n"


class InstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=TEST_ROOT))
        self.dest = self.root / "install dir"
        self.dest.mkdir()
        self.work = self.root / "work"
        self.work.mkdir()
        self.old = self.dest / "frankenctl"
        self.old.write_bytes(OLD)
        self.old.chmod(0o755)
        self.candidate = self.root / "candidate"
        self.candidate.write_bytes(NEW)
        self.candidate.chmod(0o755)
        self.archive = self.root / "release.tar"
        self.make_archive({"pkg/frankenctl": NEW})

    def make_archive(self, entries: dict[str, bytes], *, corrupt: bool = False) -> None:
        with tarfile.open(self.archive, "w", format=tarfile.USTAR_FORMAT) as archive:
            for name, payload in entries.items():
                member = tarfile.TarInfo(name)
                member.mode = 0o755
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        if corrupt:
            # A genuine invalid second header AFTER a fully extractable payload.
            data = bytearray(self.archive.read_bytes())
            data[1024:1536] = b"X" * 512
            self.archive.write_bytes(data)

    def shell(self, body: str, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        for key in ("VERSION", "FRANKEN_ENGINE_REF", "BASH_ENV", "ENV"):
            environment.pop(key, None)
        environment.update({
            "INSTALLER": str(INSTALLER), "FIXTURE_ROOT": str(self.root),
            "FIXTURE_DEST": str(self.dest), "FIXTURE_WORK": str(self.work),
            "FIXTURE_CANDIDATE": str(self.candidate), "FIXTURE_ARCHIVE": str(self.archive),
            "HOME": str(self.root), "TMPDIR": str(self.root),
        })
        if env:
            environment.update(env)
        script = r'''
source "$INSTALLER"
# Never invoke the installer's recursive cleanup on test evidence.
trap - EXIT INT TERM
DEST_DIR="$FIXTURE_DEST"
WORK_DIR="$FIXTURE_WORK"
NO_GUM=1
HAS_GUM=0
''' + body
        result = subprocess.run(["bash", "-c", script], env=environment,
                                text=True, capture_output=True, timeout=15)
        (self.root / "stdout.txt").write_text(result.stdout)
        (self.root / "stderr.txt").write_text(result.stderr)
        return result

    def assert_refused(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Installed frankenctl", result.stdout)
        self.assertNotIn("unexpected fallback", result.stdout)
        self.assertEqual(self.old.read_bytes(), OLD, "failed update replaced the prior executable")

    def test_valid_archive_atomically_replaces_destination(self) -> None:
        inode = self.old.stat().st_ino
        result = self.shell('VERIFY=1; if extract_and_install "$FIXTURE_ARCHIVE"; then :; else exit 81; fi')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.old.read_bytes(), NEW)
        self.assertTrue(os.access(self.old, os.X_OK))
        self.assertNotEqual(self.old.stat().st_ino, inode)
        self.assertIn("Installed frankenctl", result.stdout)

    def test_partial_archive_extraction_failure_never_installs(self) -> None:
        self.make_archive({"pkg/frankenctl": NEW}, corrupt=True)
        result = self.shell('if extract_and_install "$FIXTURE_ARCHIVE"; then :; else echo "unexpected fallback"; fi')
        self.assert_refused(result)

    def test_multiple_binary_candidates_are_rejected(self) -> None:
        self.make_archive({"one/frankenctl": NEW, "two/frankenctl": NEW})
        self.assert_refused(self.shell('if extract_and_install "$FIXTURE_ARCHIVE"; then :; fi'))

    def test_archive_without_binary_cannot_reuse_previous_extraction(self) -> None:
        stale = self.work / "extract" / "frankenctl"
        stale.parent.mkdir()
        stale.write_bytes(NEW)
        stale.chmod(0o755)
        self.make_archive({"README": b"no executable"})
        self.assert_refused(self.shell('if extract_and_install "$FIXTURE_ARCHIVE"; then :; fi'))

    def test_failed_copy_does_not_touch_prior_executable(self) -> None:
        result = self.shell(r'''
install() { printf 'partial-copy' > "${@: -1}"; return 28; }
if install_binary "$FIXTURE_CANDIDATE"; then :; else echo 'unexpected fallback'; fi
''')
        self.assert_refused(result)

    def test_failed_rename_does_not_touch_prior_executable(self) -> None:
        result = self.shell(r'''
mv() { return 74; }
if install_binary "$FIXTURE_CANDIDATE"; then :; else echo 'unexpected fallback'; fi
''')
        self.assert_refused(result)

    def test_failed_destination_creation_is_fatal_even_in_conditional(self) -> None:
        blocker = self.root / "not-a-directory"
        blocker.write_text("obstruction")
        result = self.shell(r'''
DEST_DIR="$FIXTURE_ROOT/not-a-directory/bin"
if install_binary "$FIXTURE_CANDIDATE"; then :; else echo 'unexpected fallback'; fi
''')
        self.assert_refused(result)

    def test_directory_named_frankenctl_is_not_treated_as_install_directory(self) -> None:
        nested = self.root / "directory-dest" / "frankenctl"
        nested.mkdir(parents=True)
        result = self.shell(r'''
DEST_DIR="$FIXTURE_ROOT/directory-dest"
if install_binary "$FIXTURE_CANDIDATE"; then :; else echo 'unexpected fallback'; fi
''')
        self.assert_refused(result)
        self.assertEqual(list(nested.iterdir()), [])

    def test_failed_candidate_verification_preserves_previous_binary(self) -> None:
        self.candidate.write_text("#!/bin/sh\nexit 23\n")
        result = self.shell('VERIFY=1; if install_binary "$FIXTURE_CANDIDATE"; then :; fi')
        self.assert_refused(result)

    def test_existing_binary_failed_self_test_returns_failure(self) -> None:
        self.old.write_text("#!/bin/sh\nexit 23\n")
        result = self.shell('VERIFY=1; if self_test; then echo bad-success; fi')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("bad-success", result.stdout)

    def test_version_flag_fallback_remains_supported(self) -> None:
        self.candidate.write_text("#!/bin/sh\n[ \"$1\" = --version ] || exit 2\necho 'frankenctl 0.2.0'\n")
        result = self.shell('VERIFY=1; install_binary "$FIXTURE_CANDIDATE"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.old.read_bytes(), self.candidate.read_bytes())

    def test_binary_path_with_newlines_is_preserved(self) -> None:
        self.make_archive({"a\nb/frankenctl": NEW})
        result = self.shell('VERIFY=1; if extract_and_install "$FIXTURE_ARCHIVE"; then :; fi')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.old.read_bytes(), NEW)

    def release_fixture(self, *, checksum: str | None = None) -> str:
        checksum = checksum or hashlib.sha256(self.archive.read_bytes()).hexdigest()
        (self.root / "sidecar").write_text(checksum + "  release.tar\n")
        return r'''
TARGET=primary
TARGET_FALLBACK=fallback
download_file() {
  printf '%s\n' "$1" >> "$FIXTURE_ROOT/downloads"
  case "$1" in
    *.sigstore.json) return 22 ;;
    *.sha256) cp "$FIXTURE_ROOT/sidecar" "$2" ;;
    *) cp "$FIXTURE_ARCHIVE" "$2" ;;
  esac
}
# The signature-verification path has its own injected-failure test.
command_exists() { [ "$1" != cosign ] && command -v "$1" >/dev/null 2>&1; }
'''

    def test_checksum_verified_release_uses_real_archive_and_digest(self) -> None:
        result = self.shell(self.release_fixture() + 'VERIFY=1; if install_from_release v0.2.0; then :; fi')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.old.read_bytes(), NEW)
        self.assertIn("Checksum verified", result.stdout)

    def test_checksum_mismatch_cannot_fall_back(self) -> None:
        result = self.shell(self.release_fixture(checksum="0" * 64) + 'if install_from_release v0.2.0; then :; fi')
        self.assert_refused(result)
        self.assertNotIn("fallback", (self.root / "downloads").read_text())

    def test_verified_but_corrupt_archive_cannot_fall_back(self) -> None:
        self.make_archive({"pkg/frankenctl": NEW}, corrupt=True)
        result = self.shell(self.release_fixture() + 'if install_from_release v0.2.0; then :; fi')
        self.assert_refused(result)
        self.assertNotIn("fallback", (self.root / "downloads").read_text())

    def test_sigstore_failure_cannot_fall_back(self) -> None:
        result = self.shell(self.release_fixture() + r'''
command_exists() { command -v "$1" >/dev/null 2>&1; }
cosign() { return 1; }
download_file() {
  printf '%s\n' "$1" >> "$FIXTURE_ROOT/downloads"
  case "$1" in
    *.sigstore.json) printf '{}\n' > "$2" ;;
    *.sha256) cp "$FIXTURE_ROOT/sidecar" "$2" ;;
    *) cp "$FIXTURE_ARCHIVE" "$2" ;;
  esac
}
if install_from_release v0.2.0; then :; fi
''')
        self.assert_refused(result)
        self.assertNotIn("fallback", (self.root / "downloads").read_text())


    def source_fixture(self, *, missing_lock: bool = False) -> tuple[dict[str, str], str]:
        """Real local Git fetches; a declared Cargo double tests orchestration only."""
        origin = self.root / "origin"
        origin.mkdir()
        crate = origin / "crates/franken-engine"
        crate.mkdir(parents=True)
        (origin / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/franken-engine"]\n')
        (crate / "Cargo.toml").write_text('[package]\nname="frankenengine-engine"\nversion="0.2.0"\n')
        if not missing_lock:
            (origin / "Cargo.lock").write_text('version = 4\n# synthetic test lock\n')
        git_env = os.environ.copy()
        git_env.update({"GIT_CONFIG_NOSYSTEM": "1", "HOME": str(self.root)})

        def git(*args: str) -> str:
            return subprocess.check_output(
                ["git", "-c", "user.name=Installer Test", "-c", "user.email=test@example.invalid", *args],
                cwd=origin, env=git_env, text=True, stderr=subprocess.STDOUT,
            ).strip()

        git("init", "-b", "main")
        git("add", ".")
        git("commit", "-m", "tagged source fixture")
        selected = git("rev-parse", "HEAD")
        git("tag", "v0.2.0")
        (origin / "main-only").write_text("this is not the requested tag\n")
        git("add", ".")
        git("commit", "-m", "different main source")
        tools = self.root / "tools"
        tools.mkdir()
        cargo = tools / "cargo"
        cargo.write_text(r'''#!/usr/bin/env python3
# Test double: records admission inputs and emits Cargo-shaped JSON; no compiler.
import json, os, pathlib, sys
root = pathlib.Path(os.environ["FIXTURE_ROOT"])
cwd = pathlib.Path.cwd()
args = sys.argv[1:]
# Model Cargo's manifest-path behavior, not the process working directory:
# the original installer invoked Cargo from outside the checked-out source.
source = pathlib.Path(args[args.index("--manifest-path") + 1]).parent
(root / "cargo-receipt.json").write_text(json.dumps({
    "args": args, "cwd": str(cwd),
    "bypass": os.environ.get("RCH_CARGO_WRAPPER_BYPASS"),
    "target_dir": os.environ.get("CARGO_TARGET_DIR"),
    "rustc_wrapper": os.environ.get("RUSTC_WRAPPER"),
}))
if not args or args[0] != "build":
    sys.exit(19)
# Leave a plausible stale guessed-path executable. It must NEVER be selected.
stale = source / "target/release/frankenctl"
stale.parent.mkdir(parents=True, exist_ok=True)
stale.write_text("#!/bin/sh\necho stale-guessed-output\n")
stale.chmod(0o755)
actual = pathlib.Path(os.environ["CARGO_TARGET_DIR"]) / 'quoted"target/host-triple/release/frankenctl'
actual.parent.mkdir(parents=True, exist_ok=True)
actual.write_bytes(pathlib.Path(os.environ["FIXTURE_CANDIDATE"]).read_bytes())
actual.chmod(0o755)
mode = os.environ.get("FAKE_CARGO_MODE", "success")
if mode != "missing-artifact":
    print(json.dumps({"reason": "compiler-artifact", "manifest_path": str(source / "crates/franken-engine/Cargo.toml"),
      "target": {"name": "frankenctl", "kind": ["bin"]}, "profile": {"test": False}, "executable": str(actual)}))
print(json.dumps({"reason": "build-finished", "success": mode != "failure"}))
if mode == "failure":
    print("test admission refused build", file=sys.stderr)
    sys.exit(17)
''')
        cargo.chmod(0o755)
        env = {
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "CARGO_TARGET_DIR": str(self.root / "custom build cache"),
            "RUSTC_WRAPPER": "test-admission-wrapper",
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_KEY_0": "url." + origin.as_uri() + ".insteadOf",
            "GIT_CONFIG_VALUE_0": "https://github.com/Dicklesworthstone/franken_engine.git",
        }
        return env, selected

    def test_source_build_uses_reported_artifact_and_preserves_admission(self) -> None:
        import json
        env, selected = self.source_fixture()
        # Deliberately make the inherited admission setting distinguishable
        # from the old installer's unconditional BYPASS=1 assignment.
        env["RCH_CARGO_WRAPPER_BYPASS"] = "0"
        result = self.shell('SOURCE_REF=v0.2.0; VERIFY=1; if install_from_source; then :; fi', env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.old.read_bytes(), NEW)
        receipt = json.loads((self.root / "cargo-receipt.json").read_text())
        self.assertEqual(receipt["bypass"], "0")
        self.assertEqual(receipt["target_dir"], env["CARGO_TARGET_DIR"])
        self.assertEqual(receipt["rustc_wrapper"], env["RUSTC_WRAPPER"])
        self.assertEqual(receipt["cwd"], str(self.work / "source"))
        self.assertIn("--locked", receipt["args"])
        self.assertIn("--no-default-features", receipt["args"])
        self.assertIn("--message-format=json-render-diagnostics", receipt["args"])
        self.assertIn(selected, result.stdout)
        lock_sha = hashlib.sha256((self.work / "source/Cargo.lock").read_bytes()).hexdigest()
        self.assertIn(lock_sha, result.stdout)
        self.assertFalse((self.work / "source/main-only").exists(), "fetch must use the requested tag")

    def test_source_build_failure_is_fatal_even_with_a_stale_binary(self) -> None:
        env, _ = self.source_fixture()
        env["FAKE_CARGO_MODE"] = "failure"
        result = self.shell('SOURCE_REF=v0.2.0; if install_from_source; then :; else echo "unexpected fallback"; fi', env=env)
        self.assert_refused(result)
        self.assertIn("test admission refused build", result.stderr)

    def test_source_without_matching_artifact_cannot_install_guessed_output(self) -> None:
        env, _ = self.source_fixture()
        env["FAKE_CARGO_MODE"] = "missing-artifact"
        self.assert_refused(self.shell('SOURCE_REF=v0.2.0; if install_from_source; then :; fi', env=env))

    def test_source_without_lockfile_refuses_before_cargo(self) -> None:
        env, _ = self.source_fixture(missing_lock=True)
        self.assert_refused(self.shell('SOURCE_REF=v0.2.0; if install_from_source; then :; fi', env=env))
        self.assertFalse((self.root / "cargo-receipt.json").exists())

    def test_invalid_source_ref_refuses_before_cargo(self) -> None:
        env, _ = self.source_fixture()
        self.assert_refused(self.shell('SOURCE_REF=missing-ref; if install_from_source; then :; fi', env=env))
        self.assertFalse((self.root / "cargo-receipt.json").exists())

    def cargo_event(self, **changes: object) -> dict[str, object]:
        event: dict[str, object] = {
            "reason": "compiler-artifact", "manifest_path": str(self.root / "Cargo.toml"),
            "target": {"name": "frankenctl", "kind": ["bin"]},
            "profile": {"test": False}, "executable": str(self.candidate),
        }
        event.update(changes)
        return event

    def select_artifact(self, events: list[object], *, raw: str = "") -> subprocess.CompletedProcess[str]:
        import json
        (self.root / "messages").write_text(raw + "".join(json.dumps(event) + "\n" for event in events))
        return self.shell('cargo_built_executable "$FIXTURE_ROOT/messages" "$FIXTURE_ROOT/Cargo.toml"')

    def test_artifact_selection_accepts_cached_and_nonstandard_output(self) -> None:
        event = self.cargo_event(fresh=True)
        result = self.select_artifact([
            self.cargo_event(target={"name": "dependency", "kind": ["lib"]}, executable=None),
            event, {"reason": "build-finished", "success": True},
        ], raw="admission wrapper informational output\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(self.candidate))

    def test_artifact_selection_rejects_incomplete_or_wrong_builds(self) -> None:
        finished = {"reason": "build-finished", "success": True}
        cases = {
            "missing completion": [self.cargo_event()],
            "failed completion": [self.cargo_event(), {"reason": "build-finished", "success": False}],
            "no artifact": [finished],
            "wrong manifest": [self.cargo_event(manifest_path=str(self.root / "other/Cargo.toml")), finished],
            "test harness": [self.cargo_event(profile={"test": True}), finished],
            "wrong kind": [self.cargo_event(target={"name": "frankenctl", "kind": ["example"]}), finished],
            "missing executable": [self.cargo_event(executable=None), finished],
            "relative executable": [self.cargo_event(executable="target/release/frankenctl"), finished],
            "missing file": [self.cargo_event(executable=str(self.root / "absent")), finished],
            "unsafe path": [self.cargo_event(executable=str(self.candidate) + "\n"), finished],
            "two artifacts": [self.cargo_event(), self.cargo_event(executable=str(self.old)), finished],
            "two completions": [self.cargo_event(), finished, finished],
            "late artifact": [finished, self.cargo_event()],
        }
        for name, events in cases.items():
            with self.subTest(name=name):
                result = self.select_artifact(events)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(self.old.read_bytes(), OLD)

    def test_artifact_selection_rejects_malformed_json_and_non_executable_file(self) -> None:
        result = self.select_artifact([], raw='{not-json}\n')
        self.assertNotEqual(result.returncode, 0)
        self.candidate.chmod(0o644)
        result = self.select_artifact([self.cargo_event(), {"reason": "build-finished", "success": True}])
        self.assertNotEqual(result.returncode, 0)

    def test_source_ref_selection_respects_version_and_explicit_override(self) -> None:
        cases = [
            ("", {}, "main"),
            ("--version v0.2.0", {}, "v0.2.0"),
            ("--ref topic --version v0.2.0", {}, "topic"),
            ("--version v0.2.0 --ref topic", {}, "topic"),
            ("--version v0.2.0", {"FRANKEN_ENGINE_REF": "env-topic"}, "env-topic"),
            ("--ref topic", {"FRANKEN_ENGINE_REF": "env-topic"}, "topic"),
        ]
        for arguments, env, expected in cases:
            with self.subTest(arguments=arguments, env=env):
                result = self.shell(f'parse_args {arguments}; printf "%s\\n" "$SOURCE_REF"', env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)

    def main_harness(self) -> str:
        # Retain real argument handling, platform detection, workspace creation,
        # locking and preflight. Do not change shell rc/completion files.
        return r'''
install_completions() { :; }
maybe_add_path() { :; }
final_summary() { :; }
discover_latest_release_tag() { printf 'v0.2.0\n'; }
download_file() { return 22; }
install_from_source() { printf '%s\n' "$SOURCE_REF" > "$FIXTURE_ROOT/selected-ref"; }
'''

    def test_auto_fallback_keeps_discovered_release_instead_of_main(self) -> None:
        result = self.shell(self.main_harness() + 'main --force --dest "$FIXTURE_DEST"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "selected-ref").read_text().strip(), "v0.2.0")

    def test_auto_fallback_keeps_explicit_ref_override(self) -> None:
        result = self.shell(self.main_harness() + 'main --force --ref reviewed-commit --dest "$FIXTURE_DEST"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "selected-ref").read_text().strip(), "reviewed-commit")

    def test_release_only_missing_asset_never_compiles(self) -> None:
        result = self.shell(self.main_harness() + 'main --force --method release --version v0.2.0 --dest "$FIXTURE_DEST"')
        self.assert_refused(result)
        self.assertFalse((self.root / "selected-ref").exists())

    def test_offline_mode_needs_no_curl_and_performs_no_network(self) -> None:
        self.write_offline_checksum()
        result = self.shell(self.main_harness() + r'''
command_exists() { [ "$1" != curl ] && command -v "$1" >/dev/null 2>&1; }
main --force --offline "$FIXTURE_ARCHIVE" --verify --dest "$FIXTURE_DEST"
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.old.read_bytes(), NEW)
        self.assertFalse((self.root / "selected-ref").exists())

    def write_offline_checksum(self, text: str | None = None) -> None:
        if text is None:
            digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
            text = digest + "  " + self.archive.name + "\n"
        Path(str(self.archive) + ".sha256").write_text(text)

    def offline_install(self, *, before: str = "") -> subprocess.CompletedProcess[str]:
        result = self.shell(r'''
download_file() { echo forbidden-network >> "$FIXTURE_ROOT/network"; return 99; }
curl() { echo forbidden-network >> "$FIXTURE_ROOT/network"; return 99; }
cosign() { echo forbidden-network >> "$FIXTURE_ROOT/network"; return 99; }
OFFLINE_TARBALL="$FIXTURE_ARCHIVE"
VERIFY=1
''' + before + '\nif install_from_offline; then :; else echo "unexpected fallback"; fi')
        self.assertFalse((self.root / "network").exists(), "offline verification must stay local")
        return result

    def assert_no_extraction(self) -> None:
        self.assertEqual(list(self.work.glob("extract*")), [], "verification must precede tar")

    def test_offline_missing_checksum_refuses_before_extraction(self) -> None:
        self.assert_refused(self.offline_install())
        self.assert_no_extraction()

    def test_offline_wrong_checksum_refuses_before_extraction(self) -> None:
        self.write_offline_checksum("0" * 64 + "  release.tar\n")
        self.assert_refused(self.offline_install())
        self.assert_no_extraction()

    def test_offline_malformed_or_ambiguous_checksum_refuses(self) -> None:
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        for text in ["", "not-a-digest\n", "a" * 63 + "\n", "g" * 64 + "\n",
                     digest + "  first\n" + digest + "  second\n"]:
            with self.subTest(sidecar=text):
                self.write_offline_checksum(text)
                self.assert_refused(self.offline_install())
                self.assert_no_extraction()

    def test_offline_digest_tool_failure_cannot_look_like_verification(self) -> None:
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.write_offline_checksum()
        result = self.offline_install(before=f'compute_sha256() {{ printf "{digest}\\n"; return 74; }}')
        self.assert_refused(result)
        self.assert_no_extraction()

    def test_offline_checksum_detects_tampering_of_a_valid_archive(self) -> None:
        self.write_offline_checksum()
        # Both archives are valid. Only their payload differs, so tar success
        # cannot substitute for checksum verification.
        self.make_archive({"pkg/frankenctl": b"#!/bin/sh\necho tampered\n"})
        self.assert_refused(self.offline_install())
        self.assert_no_extraction()

    def test_offline_checksum_accepts_uppercase_crlf_without_network(self) -> None:
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest().upper()
        self.write_offline_checksum(digest + " *release.tar\r\n")
        result = self.offline_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.old.read_bytes(), NEW)
        self.assertIn("Checksum verified", result.stdout)

    def test_offline_checksum_handles_real_escaped_filename_sidecars(self) -> None:
        unusual = self.root / "archive\\name\nline.tar"
        unusual.write_bytes(self.archive.read_bytes())
        self.archive = unusual
        # Exercise the actual sha256sum escaped-record format, not a model.
        sidecar = subprocess.check_output(["sha256sum", str(self.archive)], text=True)
        self.assertTrue(sidecar.startswith("\\"))
        self.write_offline_checksum(sidecar)
        result = self.offline_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.old.read_bytes(), NEW)
        self.assertIn("Checksum verified", result.stdout)

    def test_offline_verified_archive_still_requires_candidate_startup(self) -> None:
        self.make_archive({"pkg/frankenctl": b"#!/bin/sh\nexit 23\n"})
        self.write_offline_checksum()
        self.assert_refused(self.offline_install())

    def test_offline_extracts_the_verified_snapshot_not_a_changed_original(self) -> None:
        original = self.archive.read_bytes()
        self.make_archive({"pkg/frankenctl": b"#!/bin/sh\necho substituted\n"})
        (self.root / "replacement.tar").write_bytes(self.archive.read_bytes())
        self.archive.write_bytes(original)
        self.write_offline_checksum()
        result = self.offline_install(before=r'''
tar() {
  cp "$FIXTURE_ROOT/replacement.tar" "$FIXTURE_ARCHIVE"
  command tar "$@"
}
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.archive.read_bytes(), original)
        self.assertEqual(self.old.read_bytes(), NEW, "only the verified snapshot may be installed")

    def test_offline_staging_copy_failure_preserves_previous_executable(self) -> None:
        self.write_offline_checksum()
        result = self.offline_install(before=r'''
cp() { printf partial-copy > "${@: -1}"; return 28; }
''')
        self.assert_refused(result)
        self.assert_no_extraction()

    def test_explicit_checksum_bypass_does_not_bypass_startup(self) -> None:
        self.make_archive({"pkg/frankenctl": b"#!/bin/sh\nexit 23\n"})
        self.assert_refused(self.offline_install(before="NO_CHECKSUM=1"))

    def test_explicit_no_verify_skips_both_checksum_and_sigstore(self) -> None:
        result = self.shell(r'''
NO_CHECKSUM=1
download_file() { echo forbidden-download >> "$FIXTURE_ROOT/network"; return 99; }
cosign() { echo forbidden-cosign >> "$FIXTURE_ROOT/network"; return 99; }
verify_checksum "$FIXTURE_ARCHIVE" unused
verify_sigstore "$FIXTURE_ARCHIVE" unused
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "network").exists())

    def test_online_multiple_checksum_records_cannot_trigger_fallback(self) -> None:
        setup = self.release_fixture()
        sidecar = self.root / "sidecar"
        sidecar.write_text(sidecar.read_text() * 2)
        self.assert_refused(self.shell(setup + 'if install_from_release v0.2.0; then :; fi'))
        self.assertNotIn("fallback", (self.root / "downloads").read_text())
        self.assert_no_extraction()



if __name__ == "__main__":
    print(f"Retained scratch and logs: {TEST_ROOT}", flush=True)
    unittest.main(verbosity=2)
