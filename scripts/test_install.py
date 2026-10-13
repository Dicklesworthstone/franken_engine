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


if __name__ == "__main__":
    print(f"Retained scratch and logs: {TEST_ROOT}", flush=True)
    unittest.main(verbosity=2)
