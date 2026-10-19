# Pascal XP 368.81 / Win7 368.81 — FECS callback-slot writer alias audit (run #126 re-audit)

Date: 2026-10-19 (CEST). Source: [Driver analysis #126](https://github.com/phobosq/pascal-xp/actions/runs/39080438535), `pascal-xp-focused-analysis-126` artifact; specifically the SHA-validated XP/Win7 `*_fecs_helper_callers.json` exports, cross-checked with `*_gp106_resource_wiring.json`. This is a **new bounded re-audit of existing exports**, not a new driver-analysis run. The report contains derived metadata only, not proprietary driver bodies or firmware.

## Finding: `+0x168` alone is not a unique FECS callback identity

The FECS ucode functions XP `FUN_002828F0` and Win7 `FUN_00314C60` call through a nested context's indirect callback at `+0x168`, before reading the `RMInstLoc3` selector. A search for **writes to the same numeric offset** also finds two tightly matched XP/Win7 families of **bulk function-pointer slot initialization**:

| Property | XP | Win7 | Bounded cross-check |
|---|---|---|---|
| First slot-filler function | `FUN_000889F0` | `FUN_0020DC6C` | Both write **22 identical slot offsets** per indexed record, including `+0x168` |
| First family's base from registry-global-relative field | `DAT_0094B270+0x2348` | `DAT_007DA840+0x2350` | Field relocation `+8`; index stride `0x108` on both sides |
| First family's repeated target | `FUN_001C7870` | `FUN_0052858C` | Each side fills all 22 slots with one same-side target |
| Second slot-filler function | `FUN_0008F8A0` | `FUN_0020F554` | Both write **53 identical slot offsets** per indexed record, including `+0x168` |
| Second family's base from registry-global-relative field | `DAT_0094B270+0x2358` | `DAT_007DA840+0x2360` | Field relocation `+8`; index stride `0x1B8` on both sides |
| Second family's repeated target | `FUN_000B59C0` | `FUN_00323E5C` | Each side fills all 53 slots with one same-side target |

Each function checks the index against an upper bound of three and calls its platform's common helper on an out-of-range index (XP `000715D0`, Win7 `00199394`). The counts and exact offset-set matches were checked independently against the four exported function records; no inference from absolute function addresses was needed.

**Interpretation:** the same numeric `+0x168` offset occurs inside broad, indexed callback-table initialization. Those writers are **not evidence by themselves** that their slot is the nested `+0x168` callback actually invoked by FECS. The `+8` shift in the two registry-global-relative base fields is consistent between XP and Win7 but does not establish the identity of the pointed-to object. It is also not a reason to transplant callback targets between OSes.

## Other possible writers remain unproven

The bounded exports also contain a Win7 direct `+0x168` function-pointer writer at `FUN_0095B780` (target `FUN_001ACBD0`), and an XP conditional `+0x168` writer at `FUN_000E5D10` (target `FUN_00095400`). These are **separate candidate producers**, not an established XP/Win7 function pair or a demonstrated FECS callback implementation. The current exports do not establish that the FECS nested object aliases either candidate's destination.

Do not rank candidates solely by offset or proximity to the registry global: `+0x168` is shared by multiple structures and bulk initialization patterns.

## Structural filtering of the writer candidates

A further bounded inspection of the exported function bodies provides a **negative discriminator** for the two bulk slot-fillers, beyond their shared numeric `+0x168` slot:

- The 22-slot family indexes records with stride `0x108`, and its visible per-index writes span `+0x88` through `+0x180` relative to the array base (a `0xF8`-byte write window, including the scalar at `+0x88`).
- The 53-slot family indexes with stride `0x1B8`, and its visible per-index writes span `+0x80` through `+0x230` (a `0x1B0`-byte write window, including the scalar at `+0x80`).
- Both FECS selector-bearing functions use the *nested object* `*( *(param_2+0x160) + 0xF0 )`, and read its **direct function-pointer field** at `+0x168`. They also write fields as far as `+0x4AC` on that same nested object. The FECS object therefore has a substantially different **observed access footprint** from either indexed slot-filler record.

These facts **deprioritize** the bulk slot-fillers as FECS callback producers. The record strides are *not verified allocation sizes*, however, and a common numeric offset is neither an alias proof nor an absolute non-alias proof.

The two other offset-matching writers are likewise not a proven XP/Win7 pair. In XP `FUN_000E5D10`, the `+0x168` assignment to `FUN_00095400` is guarded by a check of the field at `+0x1A8` against `0x02FFFFFF`; the object is obtained from `*(param_1+8)`. In Win7 `FUN_0095B780`, the exported body writes `FUN_001ACBD0` directly to `param_1+0x168` as part of a large pointer-table initializer. **Conditional versus unconditional writes in two unpaired structures do not demonstrate an XP GP106 incompatibility.** Establish the exact nested-object identity and a matching producer before interpreting these as an OS-specific branch difference.

## Status and next bounded experiment

The existing #126 FECS comparator still confirms structural parity for both ucode function pairs; the descriptor-owner comparator has no ranked unmatched Win7 header; the registration follow-up remains 11/11 matched; new registry-global lookup candidates remain XP/Win7 0/0. [Python CI #159](https://github.com/phobosq/pascal-xp/actions/runs/39171745170) passed on the current documentation HEAD. No newer Driver analysis run has superseded #126 as of this audit.

**Next experiment:** trace the producer of the exact nested context `*(outer+0xF0)` passed to the FECS firmware call, resolve that object's callback-table address and its `+0x168` slot, then compare concrete callback targets and returned statuses between XP and Win7. Require object identity and GP106 reachability before treating any slot-writer difference as a patch candidate.

**Disposition:** `numeric_offset_aliasing=confirmed` (bounded static sample), `callback_target_resolved=false`, `gp106_runtime_divergence_proven=false`, `patch_candidate=false`. Do not modify NVIDIA driver bytes or firmware based on this offset-only evidence.
