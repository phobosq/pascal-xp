# Pascal XP 368.81 / Windows 7 368.81 — FECS ucode dispatch parity (run #126)

Date: 2026-10-18 CEST. Source: [Driver analysis #126](https://github.com/phobosq/pascal-xp/actions/runs/39080438535), code commit `cd81fe93ee500bda0f90a28c04dc391649df4993`. Evidence: `xp_vs_win7_fecs_ucode_dispatch.json`, `xp_gp106_resource_wiring.json`, `win7_gp106_resource_wiring.json`, and comparison/summary JSON in the **CI artifact** `pascal-xp-focused-analysis-126`. Original SHA-validated 368.81 driver inputs; only static derived observations are recorded here, not proprietary driver code.

## Two FECS ucode function pairs

| Role | XP RVA | Win7 RVA | Static result |
|---|---|---|---|
| Baseline FECS ucode | `00260170` | `0037D8C0` | Same fingerprint and `0x26BB9600` magic; no selector in either |
| Selector-bearing variant | `002828F0` | `00314C60` | Same fingerprint and `0x60115600` magic; selector present in both |

Both pairs contain the expected `RMFecsSetUCode` / `RMFecsSetUCodeHdr` string references and match the audit's bounded, regex-derived structural checks: preflight virtual call at `+0x58`, nested context `+0xF0`, indirect firmware callback `+0x168`, context `+0x160`, fields `+0x33C`/`+0x345`, result `+0x404`, and context flags `+0x4AC`. The comparator reports `all_static_common_operations_confirmed=true`. This **does not prove identical semantics, selected firmware, or GP106 runtime execution**.

The selector-bearing variants both extract a two-bit field with `>> 0xE & 3`, but the field is read at **XP `param_1+0x219C` versus Win7 `param_1+0x21A4`** (an eight-byte offset difference). Both variants also write a selected pointer at `+0x498`. The offset difference may simply reflect a changed object layout; it is **not a patch candidate** without proving object identity, field provenance, and a divergent runtime selection. The baseline pair does not contain this selector.

## Adjacent control flow and ownership

In the bounded FECS resource-wiring exports, both XP FECS functions call helper `000715D0`; both Win7 FECS functions call `00199394`. Those helpers have static references to the respective registry globals (XP `0094B270`, Win7 `007DA840`), but this is **not evidence** that either helper selects a GP106 class. The indirect callback at `+0x168` has not been resolved to a concrete target for a GP106 object.

The owner-chain comparator still shows **7 XP / 12 Win7 sampled registration wrappers**, four shared indices `0x32`, `0x33`, `0x37`, `0x38`, and **no ranked unmatched Win7 descriptor header** in this bounded sample. The independent registration follow-up reports **11/11 matched indices and header pointers**, without proving class identity. The GP106 constructor comparator has **zero two-sided FECS-proximity hypotheses** and **zero confirmed actionable pairs** (40 one-sided hypotheses only).

Registry-global scoring remains at one positive row per OS, **the already-known registration function** (XP `00117DB0`, Win7 `0023C050`). After `new_lookup_candidates()`, **new lookup candidates are 0/0**. The #126 generated Markdown summary displays these counts on separate lines; the previously reported missing-comma formatting defect is not present in the current source.

## Validation and next bounded investigation

[Driver analysis #126](https://github.com/phobosq/pascal-xp/actions/runs/39080438535) completed XP, Win7, and compare successfully, published all three expected artifacts, and saved both incremental report caches. [Python CI #154](https://github.com/phobosq/pascal-xp/actions/runs/39080438356) succeeded on the same source commit.

**Next experiment:** trace the object/vtable producer for the `+0x168` FECS firmware callback on both platforms, then trace the producer of the `+0x219C`/`+0x21A4` selector field and intersect with a proven GP106 class-selection path. Distinguish object-layout relocation from a real branch/firmware-selection difference, and trace any resulting failure status. Do not patch offsets or firmware tables on static similarity alone.

**Conclusion:** FECS dispatch *structural parity* is supported for two function pairs. `runtime_gp106_selection_proven=false` and `patch_candidate=false`; there is no demonstrated XP/Win7 GP106 failure divergence.
