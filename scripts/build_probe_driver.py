#!/usr/bin/env python3
"""Build the first GP106-on-XP dispatch probe from stock 368.81 nv4_mini.sys.

The patch changes only the architecture value returned for PCI device IDs in
the 0x1c00-0x1c3f range: NV136/GP106 becomes NV126/GM206.  It is deliberately
a falsifiable bring-up probe, not a claim that Pascal is register-compatible
with Maxwell.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pefile


STOCK_SHA256 = "cdb1f92a62fe4f36d9121d27fedd741c9a2c044df79d09dccd4fa492c80ca733"
GHIDRA_INSTRUCTION_VA = 0x00361631
EXPECTED = bytes.fromhex("b8 36 01 00 00")  # mov eax, 0x136
REPLACEMENT = bytes.fromhex("b8 26 01 00 00")  # mov eax, 0x126


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch_driver(source: Path, output: Path, manifest: Path) -> dict[str, object]:
    original = source.read_bytes()
    original_sha = sha256(original)
    if original_sha != STOCK_SHA256:
        raise ValueError(
            f"unexpected input SHA-256 {original_sha}; expected stock XP 368.81 {STOCK_SHA256}"
        )

    pe = pefile.PE(data=original, fast_load=False)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    target_rva = GHIDRA_INSTRUCTION_VA - image_base
    target_offset = pe.get_offset_from_rva(target_rva)
    actual = original[target_offset : target_offset + len(EXPECTED)]
    if actual != EXPECTED:
        raise ValueError(
            f"byte guard failed at file offset 0x{target_offset:x}: "
            f"got {actual.hex(' ')}, expected {EXPECTED.hex(' ')}"
        )

    patched = bytearray(original)
    patched[target_offset : target_offset + len(REPLACEMENT)] = REPLACEMENT

    patched_pe = pefile.PE(data=bytes(patched), fast_load=False)
    patched_pe.OPTIONAL_HEADER.CheckSum = patched_pe.generate_checksum()
    output.parent.mkdir(parents=True, exist_ok=True)
    patched_pe.write(str(output))
    final = output.read_bytes()

    result = {
        "schema_version": 1,
        "purpose": "GP106/NV136 architecture-dispatch probe using the existing GM206/NV126 path",
        "input": {"path": str(source), "sha256": original_sha, "size": len(original)},
        "output": {"path": str(output), "sha256": sha256(final), "size": len(final)},
        "patch": {
            "ghidra_va": f"0x{GHIDRA_INSTRUCTION_VA:08x}",
            "rva": f"0x{target_rva:x}",
            "file_offset": f"0x{target_offset:x}",
            "before": EXPECTED.hex(" "),
            "after": REPLACEMENT.hex(" "),
            "semantic_change": "PCI ID 0x1c00-0x1c3f: return 0x126 instead of 0x136",
        },
        "pe_checksum": f"0x{patched_pe.OPTIONAL_HEADER.CheckSum:08x}",
    }
    manifest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(patch_driver(args.source, args.output, args.manifest), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
