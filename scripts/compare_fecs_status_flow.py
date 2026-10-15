#!/usr/bin/env python3
"""Compare paired FECS status-flow reports without asserting semantic equivalence."""
import argparse
import json
import re
from pathlib import Path

ROLES = ("primary", "alternate", "status")
PTR = re.compile(r"\b(param_[12])\s*\+\s*0x([0-9a-fA-F]+)")
INDIRECT = re.compile(r"\(\*\*\(code\s*\*\*\)\(param_2\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\)\)")
RETURN = re.compile(r"\breturn\s+([^;]+);")

def describe(item):
    code = item.get("decompilation") or ""
    fields = {"param_1": set(), "param_2": set()}
    for base, offset in PTR.findall(code):
        fields[base].add(int(offset, 16))
    return {
        "entry": item.get("entry"),
        "size": item.get("size"),
        "direct_call_count": len(item.get("calls", [])),
        "indirect_call_count": len(item.get("indirect_calls", [])),
        "return_instruction_count": len(item.get("return_sites", [])),
        "return_expressions": RETURN.findall(code),
        "param_1_offsets": sorted(fields["param_1"]),
        "param_2_offsets": sorted(fields["param_2"]),
        "param_2_callback_offsets": sorted({int(x, 0) for x in INDIRECT.findall(code)}),
        "decompilation_present": bool(code),
        "decompilation_truncated": item.get("decompilation_truncated", False),
    }

def compare(left, right):
    if left.get("platform") != "xp" or right.get("platform") != "win7":
        raise ValueError("expected XP report first, Win7 second")
    out = {"schema_version": 1, "source": "ExportFecsStatusFlow.py",
           "roles": {}, "caveats": [
               "Address and return-site differences do not prove behavioral differences.",
               "Offsets are decompiler observations, not verified structure definitions.",
               "No static report alone proves the origin of Windows Code 10."
           ]}
    for role in ROLES:
        a = left.get("functions", {}).get(role)
        b = right.get("functions", {}).get(role)
        if a is None or b is None:
            out["roles"][role] = {"missing": {"xp": a is None, "win7": b is None}}
            continue
        xp, win7 = describe(a), describe(b)
        out["roles"][role] = {
            "xp": xp, "win7": win7,
            "param_1_offsets_only_xp": sorted(set(xp["param_1_offsets"]) - set(win7["param_1_offsets"])),
            "param_1_offsets_only_win7": sorted(set(win7["param_1_offsets"]) - set(xp["param_1_offsets"])),
            "param_2_callback_offsets_common": sorted(set(xp["param_2_callback_offsets"]) & set(win7["param_2_callback_offsets"])),
            "same_direct_call_count": xp["direct_call_count"] == win7["direct_call_count"],
            "same_indirect_call_count": xp["indirect_call_count"] == win7["indirect_call_count"],
        }
    return out

def main():
    p = argparse.ArgumentParser()
    p.add_argument("xp")
    p.add_argument("win7")
    p.add_argument("--out", required=True)
    args = p.parse_args()
    xp = json.loads(Path(args.xp).read_text(encoding="utf-8"))
    win7 = json.loads(Path(args.win7).read_text(encoding="utf-8"))
    report = compare(xp, win7)
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Compared FECS status flow for: " + ", ".join(report["roles"]))

if __name__ == "__main__":
    main()
