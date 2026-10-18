# Pascal XP 368.81 / Win7 368.81 — FECS selector provenance: RMInstLoc3 (run #126 re-audit)

Date: 2026-10-18 (CEST). Evidence: [Driver analysis #126](https://github.com/phobosq/pascal-xp/actions/runs/39080438535), `pascal-xp-focused-analysis-126`, SHA-validated original XP/Win7 368.81 inputs. This is a new **bounded data-provenance cross-check** of existing #126 exports, not a new CI analysis run. Examined `xp_fecs_helper_callers.json`, `win7_fecs_helper_callers.json`, and both `*_gp106_resource_wiring.json` reports. Only derived observations, not proprietary decompilation or firmware, are recorded here.

## New result: the eight-byte difference is a three-field relocation

The previously identified FECS selector offsets are not isolated numbers. A separate pair of registry-initialization functions reads the **same three named options** into consecutive 32-bit fields:

| Registry option | XP destination, `FUN_00065090` | Win7 destination, `FUN_001EA590` | Delta |
|---|---:|---:|---:|
| `RMInstLoc` | `param_1+0x2194` | `param_1+0x219C` | `+8` |
| `RMInstLoc2` | `param_1+0x2198` | `param_1+0x21A0` | `+8` |
| `RMInstLoc3` | `param_1+0x219C` | `param_1+0x21A4` | `+8` |

XP calls `FUN_000F0BF0` with each option name and its field address; Win7 calls `FUN_0021B3A0` analogously. On nonzero return from each option read, both sides set the corresponding field to zero. Both also inspect all three fields together and apply recognizable all-zero / sentinel-value handling (including `0x55555555`). In the exported functions the sentinel-derived summary flag is at XP `+0x21A4` versus Win7 `+0x21AC`, another `+8` relocation. These observations provide **direct evidence for the field identity and consistent layout shift**; they do not prove identical runtime registry values or that all objects reaching these functions have been type-verified.

The selector-bearing FECS pair previously identified as XP `FUN_002828F0` / Win7 `FUN_00314C60` reads the *third* field in that sequence and extracts `(RMInstLoc3 >> 14) & 3`, then writes a choice into the nested context's `+0x498/+0x4A0` fields. The `+8` offset change is therefore consistent with the named `RMInstLoc3` field moving with its two neighbors, **not evidence of an XP-specific erroneous selector offset**.

## Independent cross-check from the second selection path

The bounded exports also contain XP `FUN_00269740` and Win7 `FUN_002FDE74`, which select among the same respective three pointer-table targets (XP `DAT_0054BAB0`, `DAT_0054BAD0`, `DAT_0054BAD8`; Win7 `DAT_00622070`, `DAT_00622090`, `DAT_00622098`). In that *different* path, the selector is read from XP `+0x2194` versus Win7 `+0x219C` and uses `>> 20 & 3`, matching the **first** `RMInstLoc` field's relocation. This supports the interpretation that the registry option family feeds multiple selection paths. It does not prove identical firmware contents or that these functions run for GP106.

## Ordering, scope and patch decision

The FECS pair invokes its preflight and nested firmware callback `+0x168` **before** reading `RMInstLoc3`; a failure returned by either call cannot be explained by the later selector read *within that pair*. After callback success, the two-bit selector's four-way behavior matches the prior [post-callback audit](2026-10-18-run126-fecs-selector-postdispatch.md). This new evidence narrows the remaining question to **the runtime option values, the actual object reaching the callbacks, and the consumer of the selected table**.

Other #126 checks remain unchanged: descriptor owner-chain comparator has no ranked unmatched Win7 header; registration follow-up is 11/11; new registry-global lookup candidates are XP/Win7 0/0; Python CI #157 passed. These are static and CI checks, not a GP106 runtime trace.

**Next bounded experiment:** trace `RMInstLoc3` initialization into the exact GPU object passed to FECS dispatch, then resolve the nested context's `+0x168` callback producer and return status. A registry option name/offset match alone does not establish the callback target or a GP106-specific failure.

**Disposition:** `field_provenance=RMInstLoc3 (static)`, `layout_delta=+8 (three adjacent fields)`, `runtime_gp106_selection_proven=false`, `patch_candidate=false`. Do **not** patch the FECS selector offset or firmware tables on this evidence.
