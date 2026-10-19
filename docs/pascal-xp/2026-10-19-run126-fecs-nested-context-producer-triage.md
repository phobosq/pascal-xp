# FECS nested-context producer triage — bounded XP/Win7 368.81 audit

Date: 2026-10-19. Source: [Driver analysis #126](https://github.com/phobosq/pascal-xp/actions/runs/39080438535), artifact `pascal-xp-focused-analysis-126`, specifically `xp_fecs_helper_callers.json`, `win7_fecs_helper_callers.json` and the FECS comparator. This is a **new bounded re-audit of existing exported functions**, not a new disassembly run or a runtime GP106 trace. Only derived addresses, offsets and control-flow observations are retained here.

## Target identity and corroborating consumers

The FECS ucode routines access a two-hop object: `context = *(param_2 + 0x160)`, `nested = *(context + 0xF0)`. They call the function pointer at `nested+0x168` and access `nested+0x33C`, `+0x345`, `+0x404`, and `+0x4AC`. The #126 comparator pairs XP `00260170` with Win7 `0037D8C0` (baseline), and XP `002828F0` with Win7 `00314C60` (selector variant); static common operations are confirmed but callback target identity is not.

The same `+0x160 -> +0xF0` nested-object access is visible in two **additional, strongly aligned consumer shapes** in the bounded exports:

| XP consumer | Win7 consumer | Common behavior after the two-hop dereference |
|---|---|---|
| `00260320` | `0031517C` | Null check followed by an indirect call at `nested+0x170`, passing a third argument |
| `00260720` | `0037D774` | Check `nested+0x341`; on one branch call indirect `nested+0x250` and `nested+0x2B0`, then continue into platform-specific helpers |

The second pair also uses the same class-resource identifier `0x7EF3CB`, although its helper RVAs and some surrounding structure offsets differ. This is **positive structural evidence of a shared nested-context interface across FECS-adjacent consumers**, not evidence of the object's allocation site or the `+0x168` target.

## Concrete `+0xF0` producer candidates, not proven aliases

A bounded scan of the helper-caller decompilations found a small XP/Win7 **setter-shaped candidate pair**:

- XP `FUN_000ACF70(context, value)`: writes `*(context+0xF0)=value` after checking `context+0x58`, `+0x54`, and `+0x70`; also sets bit `0x10` in `context+8`.
- Win7 `FUN_001DF730(context, value)`: writes the same `+0xF0` field after checking `context+0x70`; the additional XP checks and flag write are **not** present in this short Win7 function.
- Visible bounded callers: XP `001268B0` invokes `000ACF70` using an object at `param_2+0x34F8`; Win7 `00201BDC`, `002771B4`, and `00278AB4` invoke `001DF730` with several caller-derived pointers, including null assignments. These caller sets have **not** been matched to the FECS context's producer.

A different Win7 candidate, `FUN_00353DD0`, explicitly assigns `*(param_3+0xF0)=param_3+0x3218` while constructing a large object; it also initializes `param_3+0x160`. This demonstrates an **embedded-object producer shape** for the same numeric offset, but no current xref connects that `param_3` to FECS's `*(param_2+0x160)`. It is not a verified counterpart to either setter.

**Key discriminator:** there are at least two plausible provenance patterns for a `+0xF0` pointer — external setter and embedded subobject. A matching field offset alone cannot distinguish them. The extra XP setter guards are **not** a patch candidate unless caller/object identity, GP106 reachability and a propagated failure are established.

## Cross-checks and next bounded export

The #126 descriptor-owner comparator reports no ranked unmatched Win7 descriptor header; registration follow-up remains 11/11 index/header matches (not full descriptor identity); registry-global consumer candidates add no new XP/Win7 lookup candidates (0/0). FECS comparator reports structural parity, and the generated summary retains `runtime_gp106_selection_proven=false`. [Python CI #165](https://github.com/phobosq/pascal-xp/actions/runs/39230419650) passed at HEAD `f33d38e`. None of these checks proves that a `+0xF0` writer feeds FECS.

Next **bounded experiment**, avoiding broad re-analysis:

1. Export incoming **machine-code xrefs and argument provenance** for XP `000ACF70`, Win7 `001DF730`, and Win7 `00353DD0`. Follow only call chains that also reach the FECS consumers above.
2. Resolve whether the first setter argument (or `00353DD0`'s `param_3`) is the same object as FECS's `*(param_2+0x160)`. Require a concrete allocation/field-store or alias chain, not matching offsets.
3. Only after that, read the actual `nested+0x168` assignment and compare target, preconditions and returned status on XP/Win7. A GP106-specific path remains to be demonstrated.

**Disposition:** `shared_nested_interface=static_supported`; `f0_producer_candidates=identified`; `f0_alias_to_fecs=unproven`; `callback_168_target=unresolved`; `gp106_runtime_divergence=unproven`; `patch_candidate=false`. No NVIDIA binaries or firmware were modified.
