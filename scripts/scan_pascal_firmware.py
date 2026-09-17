#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

KEYWORDS = [
    "acr", "fecs", "gpccs", "falcon", "ucode", "microcode",
    "pmu", "sec2", "grctx", "ctxsw", "bootloader"
]

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def find_all(haystack, needle):
    out = []
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx < 0:
            return out
        out.append(idx)
        start = idx + 1

def keyword_hits(data):
    results = []
    low = data.lower()
    for word in KEYWORDS:
        ascii_pat = word.encode("ascii")
        utf16_pat = word.encode("utf-16le")
        for enc, pat in (("ascii", ascii_pat), ("utf16le", utf16_pat)):
            for off in find_all(low, pat):
                results.append({"keyword": word, "encoding": enc, "offset": hex(off)})
    return sorted(results, key=lambda x: int(x["offset"], 16))

def signature_hits(data, sig_dir):
    results = []
    if not sig_dir:
        return results
    for path in sorted(Path(sig_dir).rglob("*")):
        if not path.is_file():
            continue
        sig = path.read_bytes()
        if len(sig) < 16:
            continue
        full = find_all(data, sig)
        prefixes = {}
        if not full:
            for n in (32, 64, 128, 256):
                if len(sig) >= n:
                    hits = find_all(data, sig[:n])
                    if hits:
                        prefixes[str(n)] = [hex(x) for x in hits]
        results.append({
            "name": path.name,
            "size": len(sig),
            "sha256": sha256_bytes(sig),
            "full_matches": [hex(x) for x in full],
            "prefix_matches": prefixes,
        })
    return results

def main():
    ap = argparse.ArgumentParser(description="Find Pascal/NVIDIA firmware clues in a driver binary")
    ap.add_argument("file")
    ap.add_argument("--signatures", help="Directory containing local reference firmware blobs")
    ap.add_argument("--out")
    args = ap.parse_args()

    path = Path(args.file)
    data = path.read_bytes()
    report = {
        "schema_version": 1,
        "file": str(path),
        "size": len(data),
        "sha256": sha256_bytes(data),
        "keyword_hits": keyword_hits(data),
        "signature_hits": signature_hits(data, args.signatures),
    }
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")

if __name__ == "__main__":
    main()
