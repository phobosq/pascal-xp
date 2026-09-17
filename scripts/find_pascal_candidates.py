#!/usr/bin/env python3
import argparse, json
from pathlib import Path

TERMS = [
    "GP106", "GP104", "GP102", "PASCAL", "FECS", "GPCCS", "ACR",
    "FALCON", "PMU", "SEC2", "PGRAPH", "PFIFO", "MMU", "CTXSW",
    "UCODE", "FIRMWARE", "10DE", "1C03"
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("facts")
    ap.add_argument("--out")
    args = ap.parse_args()

    data = json.loads(Path(args.facts).read_text(encoding="utf-8"))
    functions = {f["entry"]: f for f in data.get("functions", [])}
    hits = {}

    def add_hit(entry, reason, detail):
        if not entry:
            return
        rec = hits.setdefault(entry, {
            "function": functions.get(entry, {"entry": entry}),
            "reasons": []
        })
        rec["reasons"].append({"reason": reason, "detail": detail})

    for s in data.get("strings", []):
        matched = s.get("interesting_terms", [])
        if not matched:
            continue
        for xr in s.get("xrefs", []):
            fn = xr.get("function") or {}
            add_hit(fn.get("entry"), "string_xref", {
                "terms": matched,
                "string": s.get("value"),
                "string_address": s.get("address"),
                "xref_from": xr.get("from")
            })

    for sym in data.get("symbols", []):
        matched = sym.get("interesting_terms", [])
        if matched:
            add_hit(sym.get("address"), "symbol", {
                "terms": matched,
                "name": sym.get("name")
            })

    ranked = []
    for entry, rec in hits.items():
        score = 0
        for r in rec["reasons"]:
            score += 5 if r["reason"] == "string_xref" else 2
            detail_terms = r["detail"].get("terms", [])
            if any(t in detail_terms for t in ("GP106", "FECS", "GPCCS", "ACR", "PGRAPH")):
                score += 5
        rec["score"] = score
        ranked.append(rec)

    ranked.sort(key=lambda x: (-x["score"], x["function"].get("entry", "")))
    out = {
        "program": data.get("program"),
        "candidate_count": len(ranked),
        "candidates": ranked
    }
    text = json.dumps(out, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)

if __name__ == "__main__":
    main()
