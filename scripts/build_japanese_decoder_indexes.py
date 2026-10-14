#!/usr/bin/env python3
"""Build the runtime JIS table only from exact, pinned WHATWG index files.

Usage: python scripts/build_japanese_decoder_indexes.py /path/to/whatwg-encoding [--check]
No network, platform codec, or incumbent JavaScript engine supplies mappings.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

SOURCES = (
    ("index-jis0208.txt", "078394db64616dcbc4ed2925f789ba72206f23fc", 11104),
    ("index-jis0212.txt", "8a75fbcfd94037223b0fd750a90b0ab0f5315dde", 7211),
)
OUTPUT = Path(__file__).resolve().parents[1] / (
    "crates/franken-engine/src/baseline_interpreter/text_codec"
)


def table(path: Path, expected_blob: str, length: int) -> bytes:
    raw = path.read_bytes()
    actual = hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()
    if actual != expected_blob:
        raise ValueError(f"{path}: expected Git blob {expected_blob}, got {actual}")
    values = [0xFFFF] * length
    previous = -1
    for line in raw.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        pointer, scalar = int(fields[0]), int(fields[1], 16)
        if not previous < pointer < length:
            raise ValueError(f"{path}: unordered or out-of-range pointer {pointer}")
        if not 0 <= scalar < 0xFFFF or 0xD800 <= scalar <= 0xDFFF:
            raise ValueError(f"{path}: non-BMP, non-scalar or reserved mapping {scalar}")
        previous = pointer
        values[pointer] = scalar
    if previous != length - 1:
        raise ValueError(f"{path}: incomplete index")
    return struct.pack(f"<{length}H", *values)


def pack_unmapped_runs(raw: bytes) -> bytes:
    words = struct.unpack(f"<{len(raw) // 2}H", raw)
    packed = bytearray()
    cursor = 0
    while cursor < len(words):
        word = words[cursor]
        cursor += 1
        packed.extend(struct.pack("<H", word))
        if word == 0xFFFF:
            count = 1
            while cursor < len(words) and words[cursor] == 0xFFFF and count < 0xFFFF:
                count += 1
                cursor += 1
            packed.extend(struct.pack("<H", count))
    return bytes(packed)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    tables = [(name, table(args.sources / name, pin, length)) for name, pin, length in SOURCES]
    for name, raw in tables:
        output = pack_unmapped_runs(raw)
        path = OUTPUT / name.removeprefix("index-").replace(".txt", ".rle")
        if args.check:
            if path.read_bytes() != output:
                raise SystemExit(f"{path}: runtime table differs from pinned normative source")
        else:
            path.write_bytes(output)
        print(f"{path.name}: {len(output)} packed bytes; SHA-256 {hashlib.sha256(output).hexdigest()}")
    raw = b"".join(raw for _, raw in tables)
    print(f"{len(raw)} expanded bytes; SHA-256 {hashlib.sha256(raw).hexdigest()}")



if __name__ == "__main__":
    main()
