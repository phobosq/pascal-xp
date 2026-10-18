# Pascal XP 368.81 / Win7 368.81 — FECS selector runs *after* firmware callback (run #126 re-audit)

Date: 2026-10-18 CEST. Source: [Driver analysis #126](https://github.com/phobosq/pascal-xp/actions/runs/39080438535), artifact `pascal-xp-focused-analysis-126`, especially `xp_gp106_resource_wiring.json` and `win7_gp106_resource_wiring.json`. This is a **new bounded control-flow re-audit of existing #126 evidence**, complementary to [the initial FECS parity report](2026-10-18-run126-fecs-ucode-dispatch.md). Both reports use the original SHA-validated 368.81 inputs; no driver or firmware bytes are included.

## New finding: error-path precedence

The selector-bearing functions — XP `FUN_002828F0` and Win7 `FUN_00314C60` — follow the same observable sequence in the bounded decompilations:

1. Call the receiver's indirect **preflight** at `+0x58`. A nonzero status exits the function before firmware dispatch or selector evaluation.
2. Write `0x60115600` to nested context `+0x4AC`, set `+0x33C/+0x345`, and reset two fields in the outer context.
3. Call the nested context's indirect **firmware callback** at `+0x168` with the FECS ucode names. A nonzero status exits immediately.
4. **Only on callback success**, clear nested `+0x404`, extract `(selector >> 14) & 3` from XP `param_1+0x219C` / Win7 `param_1+0x21A4`, and write nested `+0x4A0` and `+0x498`.

The ordering was checked independently for each side against the two exported function bodies. In both, the `+0x168` callback and its immediate nonzero-return guard precede the selector read.

**Implication:** within these two functions, the eight-byte selector-field offset difference **cannot cause the preflight or first `+0x168` callback to return an error**, because neither function reads the selector until after that callback succeeds. It could still affect **subsequent** behavior through the post-callback `+0x498/+0x4A0` state; this does not exclude selector reads elsewhere.

## Identical post-callback state machine

The following is the decompiled branch behavior, not a statement about firmware-table identity:

| Two-bit selector | `+0x4A0` | `+0x498` pointer in XP | `+0x498` pointer in Win7 |
|---|---:|---|---|
| `0` | `1` | `DAT_0054BAB0` | `DAT_00622070` |
| `1` | `0` | `DAT_0054BAD8` | `DAT_00622098` |
| `2` | `1` | `DAT_0054BAD8` | `DAT_00622098` |
| `3` | `1` | `DAT_0054BAD0` | `DAT_00622090` |

Both sets of three pointer targets have the same relative geometry: base, base+`0x20`, base+`0x28`. Selector values `1` and `2` share a pointer but differ at `+0x4A0`. Pointer-target contents and the semantics of this flag have **not** been verified; the targets must not be treated as interchangeable firmware images.

## Updated experiment priority

1. Resolve the actual object/vtable producer and target for nested-context callback `+0x168`, then trace its returned status. This is **upstream** of the observed selector read.
2. Independently identify writers of XP `+0x219C` / Win7 `+0x21A4` and consumers of nested `+0x498/+0x4A0`. Only if the **same proven GP106 object** reaches these fields can the eight-byte layout difference become an actionable hypothesis.
3. Correlate an observed GP106 failure with the **preflight**, **callback**, or **post-callback** stage. No such runtime observation is present.

## Cross-checks and disposition

The #126 descriptor-owner chain comparator has no ranked unmatched Win7 header, the registration follow-up is 11/11 matched, and new registry-global lookup candidates are XP/Win7 `0/0`. The existing generated Markdown summary has separate lines for these counts (the old missing-comma defect is already fixed). [Python CI #156](https://github.com/phobosq/pascal-xp/actions/runs/39093083926) is successful at the documentation HEAD as checked on 2026-10-18; it does not independently prove these new semantic observations.

**Conclusion:** callback-before-selector ordering and the four-case selector truth table are supported by both static exports. `runtime_gp106_selection_proven=false`, `patch_candidate=false`. Do **not** patch the selector offset or the FECS firmware tables on this evidence alone.
