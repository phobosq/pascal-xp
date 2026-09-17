#!/usr/bin/env python3
import argparse, hashlib, json, re
from pathlib import Path
import pefile

PCI_RE = re.compile(rb"PCI\\VEN_10DE&DEV_([0-9A-Fa-f]{4})")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--out")
    args = ap.parse_args()

    path = Path(args.file)
    data = path.read_bytes()
    pe = pefile.PE(str(path), fast_load=False)

    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for mod in pe.DIRECTORY_ENTRY_IMPORT:
            imports.append({
                "module": mod.dll.decode(errors="replace"),
                "symbols": [
                    imp.name.decode(errors="replace") if imp.name else f"ordinal:{imp.ordinal}"
                    for imp in mod.imports
                ],
            })

    sections = [{
        "name": s.Name.rstrip(b"\0").decode(errors="replace"),
        "virtual_address": hex(s.VirtualAddress),
        "virtual_size": s.Misc_VirtualSize,
        "raw_size": s.SizeOfRawData,
        "entropy": round(s.get_entropy(), 4),
    } for s in pe.sections]

    pci_ids = sorted({m.group(1).decode().upper() for m in PCI_RE.finditer(data)})

    report = {
        "file": str(path), "size": len(data), "sha256": sha256_file(path),
        "machine": hex(pe.FILE_HEADER.Machine), "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "entry_point_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "sections": sections, "imports": imports, "nvidia_pci_device_ids": pci_ids,
    }

    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")

if __name__ == "__main__":
    main()
