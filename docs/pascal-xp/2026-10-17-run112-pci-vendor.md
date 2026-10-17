# Pascal XP 368.81 / Win7 368.81 — PCI vendor static parity follow-up

**Date:** 2026-10-17. **Source:** `phobosq/pascal-xp`, Driver analysis #112 (`39034143084`, commit `e4183c2ba1cfde2d0f76ed95aaf71e6faae476c9`). Input `xp_fecs_helper_callers.json`, `win7_fecs_helper_callers.json`, static Ghidra decompilation only. No driver patch, no repository write.

## Finding A: matching NVIDIA vendor enumeration helper

| | XP | Win7 |
|---|---|---|
| Function | `FUN_000C4980` | `FUN_0021CD04` |
| Function size (bytes) | 297 | 287 |
| GPU object field | `param_1+0x1EA8` | `param_1+0x1EB0` |
| Device-identifying field | `param_1+0xC62` | `param_1+0xC6A` |
| Registry root list | `DAT_0094B270+0x2370`, then `+0x518` | `DAT_007DA840+0x2378`, then `+0x518` |
| Per-list-entry vendor check | `*(short *)(entry+0x12)==0x10DE` | same |
| Per-list-entry device match | `*(short *)(entry+0x10)==DAT_00913230` | `==DAT_007693D0` |
| No matching devices | `0x25` | `0x25` |
| Device/limit mismatch | `0x4A` | `0x4A` |
| Match | `0`, output `_DAT_0091323E` | `0`, output `_DAT_007693DE` |

The two routines have matching count/filter/error behavior; the Win7 version has compiler security-cookie boilerplate and slightly different control flow. Normalized decompiler-text similarity is approximately 0.81 (heuristic, not formal equivalence). The recurring `+8` object-layout difference is consistent with earlier findings. **This is not a proof that GP106 is accepted:** the specific device selector is held in a data global, and this function has not been shown to be the first failure on a GP106 runtime path.

## Finding B: additional candidate PCI vendor/bridge helper pairs

- XP `FUN_003772A0` ↔ Win7 `FUN_00415150`: both check vendor `0x10DE` and compute vendor-dependent bitmasks. Function sizes 1715 / 1637 bytes, normalized text similarity ~0.89.
- XP `FUN_00378830` ↔ Win7 `FUN_004170FC`: both contain `0x10B5` with device `0x8747`, and `0x10DE` with device `0x01B3` or range `0x05B0..0x05BF` (Win7 tests this range via unsigned subtraction; XP via min/max). These appear to be bridge/switch-specific filters, not GP106 PCI IDs. Similarity ~0.41 due to structural and variable-layout differences; do not claim whole-function equivalence.

## Finding C: `0x1C03` Win7 occurrences are not GP106 PCI-ID checks

In 4,942 sampled Win7 FECS-helper caller decompilations, the literal `0x1C03` occurs in only four function bodies: `00311998`, `004EC8C8`, `004EDAF4`, `0059AF80`. Every observed occurrence is an **assignment to a local structure field** (`local_78[0]` or `local_70[0]`), with adjacent fields subsequently populated. None of these four occurrences is a comparison against a PCI device-ID field. Treat `0x1C03` as an unclassified structure/message tag in these occurrences, **not** as evidence of GP106 detection. There are zero `0x1C03` matches in the sampled XP FECS-helper callers; this does not prove absence in the whole XP binary.

## Evidence limits and next experiment

1. Neither `FUN_0009B570` (XP) nor `FUN_001CAE88` (Win7) has a standalone body in the #112 artifacts; their actual PCI/architecture-selection predicate remains unresolved.
2. `FUN_001C4EA4` and `FUN_001C54F4` also lack standalone bodies in the #112 artifacts, so lock/context hypothesis is not fully confirmed.
3. The actual GPU virtual `+0x90` target remains unresolved because the runtime vtable identity for GP106 is not established.

**Recommended focused export (only if write/export access is available):** standalone decompilation and direct call graph of XP `0009B570`, Win7 `001CAE88`, XP `0004F770`, Win7 `0019F478`, Win7 `001C4EA4`; plus data references to `DAT_00913230` / `DAT_007693D0`. Determine whether these vendor-counting helpers are reachable on the GP106 initialization path and where the first nonzero status originates. Do not patch until a GP106-specific divergence is established.