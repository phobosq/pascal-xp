#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def by_key(items, key):
    out = {}
    for item in items:
        value = item.get(key)
        if value is not None:
            out.setdefault(value, []).append(item)
    return out


def main():
    ap = argparse.ArgumentParser(description="Compare two ExportProgramFacts JSON reports")
    ap.add_argument("left")
    ap.add_argument("right")
    ap.add_argument("--out")
    args = ap.parse_args()

    left = load(args.left)
    right = load(args.right)

    lf = by_key(left.get("functions", []), "name")
    rf = by_key(right.get("functions", []), "name")
    ls = {x.get("value") for x in left.get("strings", []) if x.get("value")}
    rs = {x.get("value") for x in right.get("strings", []) if x.get("value")}

    common_names = sorted(set(lf) & set(rf))
    function_deltas = []
    for name in common_names:
        # Keep the comparison conservative where duplicate names exist.
        if len(lf[name]) != 1 or len(rf[name]) != 1:
            continue
        a = lf[name][0]
        b = rf[name][0]
        if a.get("size") != b.get("size") or a.get("parameter_count") != b.get("parameter_count"):
            function_deltas.append({
                "name": name,
                "left_size": a.get("size"),
                "right_size": b.get("size"),
                "left_parameter_count": a.get("parameter_count"),
                "right_parameter_count": b.get("parameter_count"),
            })

    report = {
        "schema_version": 1,
        "left_program": left.get("program", {}),
        "right_program": right.get("program", {}),
        "summary": {
            "left_functions": len(left.get("functions", [])),
            "right_functions": len(right.get("functions", [])),
            "shared_unique_function_names": len(common_names),
            "left_strings": len(ls),
            "right_strings": len(rs),
            "shared_strings": len(ls & rs),
        },
        "functions_only_left": sorted(set(lf) - set(rf)),
        "functions_only_right": sorted(set(rf) - set(lf)),
        "function_shape_deltas": function_deltas,
        "strings_only_left": sorted(ls - rs),
        "strings_only_right": sorted(rs - ls),
        "shared_strings": sorted(ls & rs),
    }

    text = json.dumps(report, indent=2, sort_keys=True)
    print(text)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
