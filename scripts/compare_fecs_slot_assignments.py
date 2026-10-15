#!/usr/bin/env python3
"""Rank structural XP/Win7 callback-table initializer analogues.

Offset matches alone do not establish FECS/GR object identity. The report is
hypothesis generation, not a patch manifest or an ABI-equivalence claim.
"""
import argparse
import json
import re
from pathlib import Path

SLOTS = (0x190, 0x1C8, 0x1D8, 0x1E8, 0x1F8)
# Ghidra decompilation may render 0x190 as decimal 400.
ASSIGN = re.compile(
    r"\*\(code\s*\*\*\)\(param_\d+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\)"
    r"\s*=\s*(FUN_[0-9a-fA-F]+|&LAB_[0-9a-fA-F]+)"
)

def describe(fn):
    code = fn.get("decompilation") or ""
    targets = {f"0x{offset:x}": [] for offset in SLOTS}
    for offset, target in ASSIGN.findall(code):
        value = int(offset, 0)
        if value in SLOTS:
            targets[f"0x{value:x}"].append(target)
    active = sum(bool(x) for x in targets.values())
    if active < 4:
        return None
    return {
        "entry": fn["entry"],
        "size": int(fn["size"]),
        "writes": int(fn.get("writes", 0)),
        "code_pointer_assignments": code.count("code **"),
        "slot_targets": targets,
        "matched_slot_count": active,
        "truncated_decompilation": bool(fn.get("decompilation_truncated")),
    }

def similarity(x, y):
    def ratio(a, b):
        return 1 - abs(a - b) / max(1, a, b)
    target_count_x = sum(map(len, x["slot_targets"].values()))
    target_count_y = sum(map(len, y["slot_targets"].values()))
    common = sum(bool(x["slot_targets"][s]) and bool(y["slot_targets"][s])
                 for s in x["slot_targets"])
    return round(
        0.45 * ratio(x["size"], y["size"])
        + 0.30 * ratio(x["code_pointer_assignments"], y["code_pointer_assignments"])
        + 0.15 * ratio(target_count_x, target_count_y)
        + 0.10 * common / len(SLOTS),
        6,
    )

def compare(xp, win7):
    left = [d for f in xp.get("selected_functions", []) if (d := describe(f))]
    right = [d for f in win7.get("selected_functions", []) if (d := describe(f))]
    scored = sorted(
        ((similarity(x, y), x, y) for x in left for y in right),
        key=lambda p: (-p[0], p[1]["entry"], p[2]["entry"]),
    )
    used_xp, used_win7, pairs = set(), set(), []
    for score, x, y in scored:
        if score < 0.85 or x["entry"] in used_xp or y["entry"] in used_win7:
            continue
        used_xp.add(x["entry"])
        used_win7.add(y["entry"])
        pairs.append({"structural_similarity": score, "xp": x, "win7": y})
    return {
        "schema_version": 1,
        "caveat": "Structural analogues only. Callback offsets are shared across unrelated structures; no FECS/GR ownership or GP106 reachability is established.",
        "xp_candidate_count": len(left),
        "win7_candidate_count": len(right),
        "pairs": pairs,
    }

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("xp", type=Path)
    ap.add_argument("win7", type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    report = compare(json.loads(args.xp.read_text()), json.loads(args.win7.read_text()))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print("FECS slot initializer analogues:", len(report["pairs"]))

if __name__ == "__main__":
    main()
