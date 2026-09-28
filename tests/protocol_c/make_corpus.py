"""Seed a libFuzzer corpus from golden vectors: make_corpus.py <vector-dir> <out>."""

import sys
from pathlib import Path

src, out = Path(sys.argv[1]), Path(sys.argv[2])
for name in ("frames.txt", "schema.txt"):
    for i, line in enumerate((src / name).read_text().splitlines()):
        (out / f"{name}-{i}").write_bytes(bytes.fromhex(line.split("|")[2]))
