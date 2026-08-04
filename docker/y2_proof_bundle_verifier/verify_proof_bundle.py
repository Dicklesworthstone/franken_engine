#!/usr/bin/env python3
"""Third-party proof-bundle verifier (bd-cixqu.25.2, Track Y.2).

This is the *proof-checker* that runs inside the Y.2 docker image. It is a
standalone, independent re-implementation of the Y.1 recheck protocol
(`scripts/export_proof_bundle.sh`, schema ``franken-engine.proof-bundle.v1``).
It deliberately ships WITHOUT the FrankenEngine source tree so a third party
can verify a published proof bundle in a clean room.

The recheck is a pure function of the bundled proof source, so a verifier with
the same proof bytes recomputes the identical sha256 — independent of wall-clock
freshness or the engine build. Concretely, for every ``proof_source/*.proof.json``:

  1. recompute the canonical body hash
       sha256(canonical-json(proof without ``content_hash``))   (the "recomputed hash")
  2. integrity: the proof's declared ``content_hash`` must equal the recomputed
     hash (mutating a body without re-deriving the hash is detected here);
  3. schema:    ``schema_version`` must equal the pinned proof schema;
  4. verdict:   ``verdict`` must be ``proven``.

The bundle-level recheck digest is sha256 over the sorted JSON array of
``[claim_id, recomputed_hash, verdict]`` for every proof. It must equal BOTH the
bundled ``recheck_expected.sha256`` trust anchor AND the manifest's
``recheck_digest_sha256`` field.

Verification fails CLOSED: any missing/corrupt input, any tampered or
non-proven proof, any digest mismatch, or a bundle that declares itself
``incomplete`` yields a ``fail`` verdict and a non-zero exit code.

Usage:
    verify_proof_bundle.py verify-proof-bundle <bundle.tar.gz | bundle-dir> [--json-out PATH]
    verify_proof_bundle.py --help

Exit codes:
    0  bundle verified (verdict = pass)
    1  bundle failed verification (verdict = fail, fail-closed)
    2  CLI / environment error
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tarfile
import tempfile

VERDICT_SCHEMA = "franken-engine.proof-bundle-verifier-verdict.v1"
BUNDLE_SCHEMA = "franken-engine.proof-bundle.v1"
PROOF_SCHEMA = "franken-engine.theorem-backed-compiler.proof.v1"
COMPONENT = "y2_proof_bundle_verifier"


def _eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def canonical_body_hash(proof: dict) -> str:
    """Recompute a proof's content hash exactly as Y.1 export does."""
    body = {k: v for k, v in proof.items() if k != "content_hash"}
    enc = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(enc).hexdigest()


def _safe_extract_tar(tar_path: str, dest: str) -> None:
    """Extract a tar without honouring absolute paths or ``..`` traversal.

    The bundle is untrusted input. Python 3.12 ships the ``data`` extraction
    filter which rejects unsafe members; we also defensively validate every
    member resolves inside ``dest``.
    """
    with tarfile.open(tar_path, "r:*") as tar:
        members = tar.getmembers()
        dest_abs = os.path.realpath(dest)
        for member in members:
            target = os.path.realpath(os.path.join(dest, member.name))
            if target != dest_abs and not target.startswith(dest_abs + os.sep):
                raise ValueError(f"unsafe tar member escapes dest: {member.name!r}")
            if member.islnk() or member.issym():
                raise ValueError(f"link members are not allowed in bundle: {member.name!r}")
        try:
            tar.extractall(dest, filter="data")  # py>=3.12: reject unsafe members
        except TypeError:  # pragma: no cover - older python fallback
            tar.extractall(dest)


def _locate_bundle_root(extract_root: str) -> str | None:
    """Find the directory that holds bundle_manifest.json + recheck_expected.sha256."""
    candidates = [extract_root]
    try:
        for entry in sorted(os.listdir(extract_root)):
            full = os.path.join(extract_root, entry)
            if os.path.isdir(full):
                candidates.append(full)
    except OSError:
        return None
    for cand in candidates:
        if os.path.isfile(os.path.join(cand, "bundle_manifest.json")) and os.path.isfile(
            os.path.join(cand, "recheck_expected.sha256")
        ):
            return cand
    return None


def _fail(verdict: dict, reason: str) -> dict:
    verdict["verdict"] = "fail"
    verdict["reasons"].append(reason)
    return verdict


def verify_bundle(source: str) -> dict:
    """Verify a proof bundle (tar.gz or extracted dir). Returns a verdict dict."""
    verdict: dict = {
        "schema_version": VERDICT_SCHEMA,
        "component": COMPONENT,
        "bead_id": "bd-cixqu.25.2",
        "source": os.path.basename(source),
        "verdict": "pass",
        "reasons": [],
        "claim_count": 0,
        "proofs": [],
        "recomputed_recheck_digest": None,
        "expected_recheck_digest": None,
        "manifest_recheck_digest": None,
        "engine_source_present": False,
    }

    tmp = tempfile.mkdtemp(prefix="y2-verify-")
    try:
        if os.path.isdir(source):
            bundle_root = _locate_bundle_root(source)
        else:
            if not os.path.isfile(source):
                return _fail(verdict, f"bundle path not found: {source}")
            try:
                _safe_extract_tar(source, tmp)
            except Exception as exc:  # noqa: BLE001 - fail closed on any extract error
                return _fail(verdict, f"tar extraction failed (fail-closed): {exc}")
            bundle_root = _locate_bundle_root(tmp)

        if not bundle_root:
            return _fail(verdict, "incomplete bundle: bundle_manifest.json / recheck_expected.sha256 not found")

        # No engine-source leakage: a published bundle is proof-source only. A
        # bundle carrying Rust engine sources is malformed and rejected.
        for dirpath, _dirs, files in os.walk(bundle_root):
            for fname in files:
                if fname.endswith(".rs") or fname == "Cargo.toml" or fname == "lib.rs":
                    verdict["engine_source_present"] = True
                    _fail(verdict, f"engine source leaked into bundle: {os.path.join(dirpath, fname)}")

        manifest_path = os.path.join(bundle_root, "bundle_manifest.json")
        try:
            with open(manifest_path, encoding="utf-8") as fh:
                manifest = json.load(fh)
        except Exception as exc:  # noqa: BLE001
            return _fail(verdict, f"manifest unreadable (fail-closed): {exc}")

        if manifest.get("schema_version") != BUNDLE_SCHEMA:
            _fail(verdict, f"manifest schema mismatch: {manifest.get('schema_version')!r} != {BUNDLE_SCHEMA!r}")

        verdict["manifest_recheck_digest"] = manifest.get("recheck_digest_sha256")
        manifest_status = manifest.get("bundle_status")
        if manifest_status != "complete":
            _fail(verdict, f"manifest declares bundle_status={manifest_status!r} (not complete)")

        expected_file = os.path.join(bundle_root, "recheck_expected.sha256")
        try:
            with open(expected_file, encoding="utf-8") as fh:
                expected = fh.read().strip()
        except Exception as exc:  # noqa: BLE001
            return _fail(verdict, f"recheck_expected.sha256 unreadable (fail-closed): {exc}")
        verdict["expected_recheck_digest"] = expected

        proof_dir = os.path.join(bundle_root, "proof_source")
        if not os.path.isdir(proof_dir):
            return _fail(verdict, "incomplete bundle: proof_source/ directory missing")
        proof_files = sorted(
            os.path.join(proof_dir, f) for f in os.listdir(proof_dir) if f.endswith(".proof.json")
        )
        if not proof_files:
            return _fail(verdict, "incomplete bundle: no proof_source/*.proof.json")

        rows = []
        for path in proof_files:
            entry = {"file": os.path.basename(path)}
            try:
                with open(path, encoding="utf-8") as fh:
                    proof = json.load(fh)
            except Exception as exc:  # noqa: BLE001
                entry["integrity"] = "unparseable"
                verdict["proofs"].append(entry)
                _fail(verdict, f"proof unparseable (fail-closed): {os.path.basename(path)}: {exc}")
                continue
            claim_id = proof.get("claim_id", os.path.basename(path))
            stated = proof.get("verdict")
            declared = proof.get("content_hash")
            recomputed = canonical_body_hash(proof)
            intact = declared == recomputed
            schema_ok = proof.get("schema_version") == PROOF_SCHEMA
            proven = stated == "proven"
            entry.update(
                {
                    "claim_id": claim_id,
                    "stated_verdict": stated,
                    "content_hash": declared,
                    "recomputed_hash": recomputed,
                    "integrity": "intact" if intact else "tampered",
                    "schema_ok": schema_ok,
                    "proven": proven,
                }
            )
            verdict["proofs"].append(entry)
            if not intact:
                _fail(verdict, f"tampered proof (content_hash mismatch): {claim_id}")
            if not schema_ok:
                _fail(verdict, f"proof schema mismatch: {claim_id} schema={proof.get('schema_version')!r}")
            if not proven:
                _fail(verdict, f"proof not proven: {claim_id} verdict={stated!r}")
            rows.append((claim_id, recomputed, stated))

        verdict["claim_count"] = len(proof_files)
        if isinstance(manifest.get("claim_count"), int) and manifest["claim_count"] != len(proof_files):
            _fail(
                verdict,
                f"claim_count mismatch: manifest={manifest['claim_count']} proof_files={len(proof_files)}",
            )

        rows.sort()
        payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
        recomputed_digest = hashlib.sha256(payload).hexdigest()
        verdict["recomputed_recheck_digest"] = recomputed_digest

        if recomputed_digest != expected:
            _fail(
                verdict,
                f"recheck digest mismatch vs trust anchor: recomputed {recomputed_digest} != expected {expected}",
            )
        if verdict["manifest_recheck_digest"] not in (None, recomputed_digest):
            _fail(
                verdict,
                "recheck digest mismatch vs manifest: "
                f"recomputed {recomputed_digest} != manifest {verdict['manifest_recheck_digest']}",
            )

        if verdict["verdict"] == "pass":
            verdict["reasons"].append(
                f"verified {len(proof_files)} proofs intact+proven; recheck digest sha256:{recomputed_digest}"
            )
        return verdict
    finally:
        # Best-effort cleanup of the scratch extraction dir.
        for dirpath, dirs, files in os.walk(tmp, topdown=False):
            for f in files:
                try:
                    os.remove(os.path.join(dirpath, f))
                except OSError:
                    pass
            for d in dirs:
                try:
                    os.rmdir(os.path.join(dirpath, d))
                except OSError:
                    pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass


def _usage(stream=sys.stderr) -> None:
    print(
        "usage: verify_proof_bundle.py verify-proof-bundle <bundle.tar.gz|bundle-dir> [--json-out PATH]\n"
        "       verify_proof_bundle.py --help",
        file=stream,
    )


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        _usage(sys.stdout if argv[:1] in (["-h"], ["--help"]) else sys.stderr)
        return 0 if argv[:1] in (["-h"], ["--help"]) else 2
    if argv[0] != "verify-proof-bundle":
        _eprint(f"unknown mode: {argv[0]!r}")
        _usage()
        return 2
    if len(argv) < 2:
        _eprint("verify-proof-bundle requires a bundle path")
        _usage()
        return 2
    source = argv[1]
    json_out = None
    rest = argv[2:]
    i = 0
    while i < len(rest):
        if rest[i] == "--json-out" and i + 1 < len(rest):
            json_out = rest[i + 1]
            i += 2
        else:
            _eprint(f"unexpected argument: {rest[i]!r}")
            _usage()
            return 2

    verdict = verify_bundle(source)
    rendered = json.dumps(verdict, indent=2, sort_keys=True)
    print(rendered)
    if json_out:
        try:
            with open(json_out, "w", encoding="utf-8") as fh:
                fh.write(rendered + "\n")
        except OSError as exc:
            _eprint(f"could not write --json-out {json_out}: {exc}")
            return 2

    passed = verdict["verdict"] == "pass"
    _eprint(
        f"[{COMPONENT}] verdict={verdict['verdict']} "
        f"claims={verdict['claim_count']} "
        f"digest={verdict.get('recomputed_recheck_digest')}"
    )
    for reason in verdict["reasons"]:
        _eprint(f"[{COMPONENT}]   - {reason}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
