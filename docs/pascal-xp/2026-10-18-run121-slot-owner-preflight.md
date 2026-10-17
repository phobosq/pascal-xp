# Pascal XP 368.81 / Windows 7 368.81 — Driver analysis #121: GPU slot-owner preflight

Date: 2026-10-18 (CEST). Source: [Driver analysis #121](https://github.com/phobosq/pascal-xp/actions/runs/39074225352), source commit `de88268d08fa4d797793b609f0762d2390a7d824`. This is a **static** comparison of SHA-validated driver inputs. No binary/firmware is included. No runtime GP106 branch or failure is demonstrated.

## Artifact integrity and reproducibility

All three jobs (XP, Win7, Compare) succeeded; Python CI #148 succeeded. The combined `pascal-xp-focused-analysis-121` ZIP contains 38 files: 37 valid JSON and one Markdown summary; ZIP CRC passed. All focused follow-up targets have `status=ok` (XP 27/27, Win7 23/23). The pipeline summary still reports 11/11 matching registration index/header pairs, seven matched OS helpers, and **zero new** registry class-lookup candidates (excluding the known registration functions). Run #121 was produced after documentation/CI changes; these counts are not evidence of newly discovered GP106 behavior.

## Targeted finding A: two Win7 ownership predicates use the same token source

`FUN_001BCA8C` (Win7, 15 bytes) writes `SystemReserved1[0xF]` to an output pointer. The precise Windows ABI interpretation of that slot is **not independently validated**.

- `FUN_001C4EA4` (34 bytes) compares the value returned through `FUN_001BCA8C` with the **single global** owner token `DAT_007E4BA8`. The Win7 GPU-init function `FUN_001C8754` returns `0x2F` if this predicate is false.
- `FUN_001C4808` (88 bytes) uses the **same** `FUN_001BCA8C` token source, but checks **per-slot** owner entries `(&DAT_007E45A8)[index*3]` for each bit selected by its mask, up to the bound `DAT_007E4594`. It also reads the active bitmap `DAT_007E4588`.

These are two different scopes of an apparent owner/context-consistency mechanism: global owner versus GPU-slot owners. The shared token source strengthens the *ownership* interpretation; it does **not** establish any PCI device-ID or GP106 architecture check.

## Targeted finding B: exact Boolean behavior of the Win7 slot predicate

The Ghidra decompilation of `FUN_001C4808(mask)` yields the following static truth table:

| Condition | `FUN_001C4808` result |
|---|---|
| `DAT_007E4588 == 0` | 0 |
| Active bitmap nonzero, any selected slot has a different owner token | 0 |
| Active bitmap nonzero, no selected slot has a different owner token | 1 |

In the last case, the predicate can be vacuously true if no bits are selected in the scanned range. The actual valid range/mask constraints remain unverified.

The wrapper `FUN_001C54F4` (11 bytes) passes `DAT_007E4588` to `FUN_001C4808`. **Decompiler typing caveat:** Ghidra declares this wrapper `void`, while Win7 caller `FUN_001A88E8` consumes its return value as a `char`. Therefore, forwarding of the callee's return register must be confirmed from the wrapper's **machine instructions** before the caller-level Boolean polarity is treated as proven.

**Conditional caller interpretation:** if `FUN_001C54F4` forwards the `FUN_001C4808` Boolean, then `FUN_001A88E8` calls it at entry and returns `false` when it evaluates nonzero. This would reject an already-owned set of active slots, consistent with a re-entrancy preflight, **not** a Pascal architecture gate. The wrapper prototype mismatch prevents elevating this to a confirmed machine-level interpretation.

## Targeted finding C: comparison with XP initialization

Win7 `FUN_001A88E8` performs its `FUN_001C54F4` preflight immediately after obtaining `root+0x180` and before registry-option processing. Its corresponding XP init routine `FUN_00056530` obtains `root+0x180` and then enters registry-option processing without a corresponding *visible early call at that position* in the bounded decompilation. This is a **local static control-flow difference**. It does not show that XP lacks equivalent protection elsewhere, nor that GP106 takes the Win7 branch.

Both downstream per-GPU initialization routines, XP `FUN_0009E0C0` and Win7 `FUN_001C8754`, continue to use `root+0x180`, `root+0x188`, and related object methods. The Win7 global-owner check can return `0x2F` before the resource query; no matching GP106 runtime status is available.

## Bounded next verification

1. Verify the 11-byte `FUN_001C54F4` wrapper's exact assembly and whether the result register survives the call/tail transfer. Do **not** trust the conflicting decompiler prototypes.
2. Locate the XP equivalent (if any) of the Win7 global/per-slot owner-token checks by comparing **dataflow and callers**, not only symbol/RVA proximity.
3. Only after obtaining runtime observations, tie the GPU-init entry, `0x2F`/early-`false` branches, and eventual GR/FECS `+0x168` receiver to a specific GP106 instance.

**Disposition:** no patch candidate; no NVIDIA binaries/firmware committed; static evidence only.
