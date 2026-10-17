#!/usr/bin/env python3
"""Focused static FECS ucode dispatch comparison (XP / Win7 368.81).

Reports semantics only; neither class selection nor runtime execution is proven.
"""
import argparse
import json
import re
from pathlib import Path

PAIRS = [
    ("baseline", "00260170", "0037d8c0", "0x26bb9600"),
    ("variant", "002828f0", "00314c60", "0x60115600"),
]
PATS = {
    "preflight_at_0x58": r"\+\s*0x58\)\)\s*\(param_1",
    "firmware_callback_at_0x168": r"\+\s*0x168\)\)",
    "context_at_0x160": r"param_2\s*\+\s*0x160",
    "nested_context_at_0xf0": r"\+\s*0xf0",
    "flags_0x33c": r"\+\s*0x33c",
    "flags_0x345": r"\+\s*0x345",
    "result_0x404": r"\+\s*0x404",
    "context_flags_0x4ac": r"\+\s*0x4ac",
}

def fingerprint(code):
    v = {k: bool(re.search(pattern, code, re.I)) for k, pattern in PATS.items()}
    v["ucode_name"] = '"RMFecsSetUCode"' in code
    v["ucode_hdr_name"] = '"RMFecsSetUCodeHdr"' in code
    v["selector_present"] = bool(re.search(r">>\s*0xe\s*&\s*3", code))
    v["selector_offsets"] = sorted(set(re.findall(
        r"param_1\s*\+\s*(0x[0-9a-fA-F]+)\)\s*>>\s*0xe", code)))
    v["magic"] = sorted(set(x.lower() for x in re.findall(
        r"=\s*(0x[0-9a-fA-F]+)\s*;", code)
        if x.lower() in ("0x26bb9600", "0x60115600")))
    return v

def compare(xp, win7):
    by_side = {
        side: {row["entry"].lower(): row for row in src.get("functions", [])}
        for side, src in [("xp", xp), ("win7", win7)]
    }
    pairs = []
    for kind, a, b, magic in PAIRS:
        results = {}
        for side, entry in [("xp", a), ("win7", b)]:
            row = by_side[side].get(entry)
            results[side] = fingerprint(row.get("decompilation", "") if row else "")
        shared = (all(results["xp"][k] and results["win7"][k] for k in PATS)
                  and all(results["xp"][k] and results["win7"][k]
                          for k in ("ucode_name", "ucode_hdr_name")))
        same_magic = results["xp"]["magic"] == results["win7"]["magic"] == [magic]
        selector_same_presence = results["xp"]["selector_present"] == results["win7"]["selector_present"]
        pairs.append({
            "kind": kind, "xp": a, "win7": b,
            "static_common_operations_confirmed": shared and same_magic and selector_same_presence,
            "same_magic": same_magic,
            "xp_selector_offsets": results["xp"]["selector_offsets"],
            "win7_selector_offsets": results["win7"]["selector_offsets"],
            "xp_fingerprint": results["xp"], "win7_fingerprint": results["win7"],
        })
    return {
        "schema_version": 1, "pairs": pairs,
        "all_static_common_operations_confirmed": all(
            row["static_common_operations_confirmed"] for row in pairs),
        "runtime_gp106_selection_proven": False, "patch_candidate": False,
        "caveat": "Static FECS ucode code similarity does not establish runtime dispatch or GPU compatibility; differences in selector offsets can be struct layout.",
        "next_target": "Trace GP106 class selection and indirect firmware callback at +0x168.",
    }

def main():
    p = argparse.ArgumentParser()
    for name in ("xp", "win7", "out"):
        p.add_argument("--" + name, required=True)
    args = p.parse_args()
    data = compare(*(json.loads(Path(getattr(args, side)).read_text())
                     for side in ("xp", "win7")))
    Path(args.out).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"pairs": len(data["pairs"]),
                      "static_common_operations_confirmed": data["all_static_common_operations_confirmed"]}))

if __name__ == "__main__":
    main()
