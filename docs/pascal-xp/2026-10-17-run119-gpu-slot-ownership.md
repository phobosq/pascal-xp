# Pascal XP 368.81 / Windows 7 368.81 — Driver analysis #119

Date: 2026-10-17. Source: [Driver analysis #119](https://github.com/phobosq/pascal-xp/actions/runs/39070773238), commit `c2ece01b1c3b2666cb6291f48ff9fb4cce60b699`. Static examination of SHA-validated XP and Windows 7 drivers; no NVIDIA binary or firmware included.

## Integrity and pipeline

All three jobs (XP, Win7, Compare) succeeded. The combined artifact `pascal-xp-focused-analysis-119` contains 38 entries: 37 parseable, nonempty JSON reports and one Markdown summary. ZIP CRC check passed. Both registration follow-up exports have no failed targets (XP 27/27, Win7 23/23). Descriptor owner chain comparator schema v2 is present. Python CI #144 succeeded on the same commit.

The descriptor owner comparison reports 7 XP registration wrappers and 12 Win7 wrappers in the bounded sample, with shared registration indices `0x32`, `0x33`, `0x37`, `0x38`. The separate follow-up comparator still matches 11/11 predicted counterpart indices; this is static index/header parity, **not** verified GP106 class identity or runtime dispatch.

## New Win7 GPU-slot ownership predicate

Newly included `FUN_001C4808` (88 bytes) was exported successfully. Its decompilation shows:

1. If the global active GPU bitmap `DAT_007E4588` is zero, return false.
2. Otherwise obtain a thread-associated value through `FUN_001BCA8C` and iterate the indexed slot range through `DAT_007E4594`.
3. For each slot whose bit is set in the argument mask, compare the stored slot owner `(&DAT_007E45A8)[index * 3]` with that thread-associated value. Any mismatch returns false; otherwise the function returns true.

`FUN_001BCA8C` (15 bytes) reads `SystemReserved1[0xF]` and writes the value to its output pointer; its precise Windows ABI meaning remains to be validated. `FUN_001C54F4` passes the active GPU bitmap to `FUN_001C4808`. Win7 GPU initialization caller `FUN_001A88E8` tests this wrapper before continuing. This refines the earlier generic bitmap hypothesis to a **slot-owner/context-consistency predicate**, not a demonstrated GPU architecture gate. A corresponding XP predicate has not yet been traced, so absence or incompatibility on XP is unproven.

## Registry ranking and report-generation defect

`xp_vs_win7_registry_global_consumers.json` has exactly one positive candidate on each side: XP `00117DB0`, Win7 `0023C050`. Both have `kind=known_registry_registration`; after applying `new_lookup_candidates()`, there are **zero new lookup consumers on both sides**. The summary JSON correctly stores the filtered lists.

The generated `analysis_summary.md` still labels the raw one-per-side count as a "registry global dispatch candidate" and has a missing comma in `scripts/summarize_analysis.py` between the XP NEW and Win7 raw f-strings, producing the malformed line `0- Win7 ...`. A minimal source fix is supplied separately; it is not claimed as committed.

## Conclusion

No new GP106 runtime divergence or patch candidate was demonstrated. Next bounded investigation: find an XP analogue for Win7 `001C4808` and trace the caller's status/ownership transition, rather than treating `SystemReserved1[0xF]` or the registration entry as evidence of a Pascal-specific gate. Keep the full Ghidra exports in CI artifacts, not this repository.
