#!/usr/bin/env python3
import argparse, hashlib, json
from pathlib import Path

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    root = Path(args.root)
    report = {"schema_version": 1, "artifacts": []}
    errors = []

    for artifact in manifest["artifacts"]:
        out_art = {k: v for k, v in artifact.items() if k != "files"}
        out_art["files"] = []
        for item in artifact["files"]:
            matches = list(root.rglob(item["path"]))
            if not matches:
                errors.append(f'{artifact["id"]}: missing {item["path"]}')
                continue
            if len(matches) > 1:
                errors.append(f'{artifact["id"]}: ambiguous {item["path"]}: {len(matches)} matches')
                continue
            p = matches[0]
            digest = sha256_file(p)
            expected = item.get("sha256")
            ok = expected is None or digest.lower() == expected.lower()
            out_art["files"].append({
                "path": str(p), "name": p.name, "size": p.stat().st_size,
                "sha256": digest, "expected_sha256": expected, "hash_ok": ok,
            })
            if not ok:
                errors.append(f'{artifact["id"]}: SHA256 mismatch for {item["path"]}')
        report["artifacts"].append(out_art)

    report["errors"] = errors
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    raise SystemExit(1 if errors else 0)

if __name__ == "__main__":
    main()
