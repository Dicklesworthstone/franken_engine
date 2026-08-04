# Y.2 third-party proof-bundle verifier image (bd-cixqu.25.2, Track Y).
#
# The proof bundle IS the trust artifact: this image lets an external auditor
# re-check a published FrankenEngine proof bundle WITHOUT the FrankenEngine
# source tree. It therefore contains ONLY the standalone proof-checker
# (verify_proof_bundle.py) on a digest-pinned Python base — no engine source,
# no Cargo workspace, no Rust toolchain.
#
# The base image is pinned by digest so "builds reproducibly" survives upstream
# tag drift (Y.2 future-self note). The proof-checker uses only the Python
# standard library (hashlib, json, tarfile), so the build needs no apt/pip
# network step beyond the pinned base.
#
# Build context is docker/y2_proof_bundle_verifier/ (Dockerfile + verifier only),
# so the build cannot accidentally vacuum in engine source.

FROM python:3.12-slim@sha256:6c4dd321d176d61ea848dc8c73a4f7dbae8f70e0ee48bb411ea2f045b599fa8e

LABEL org.frankenengine.component="y2-proof-bundle-verifier"
LABEL org.frankenengine.bead="bd-cixqu.25.2"
LABEL org.frankenengine.track="Y"
LABEL org.frankenengine.bundle-schema="franken-engine.proof-bundle.v1"
LABEL org.frankenengine.description="Clean-room third-party verifier for FrankenEngine proof bundles; no engine source."

# Defense-in-depth: the verify container is ephemeral and never needs root.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin verifier

WORKDIR /verifier
COPY verify_proof_bundle.py /verifier/verify_proof_bundle.py

USER verifier

# The bundle is mounted read-only at /input; the verifier extracts to /tmp.
ENTRYPOINT ["python3", "/verifier/verify_proof_bundle.py"]
CMD ["--help"]
