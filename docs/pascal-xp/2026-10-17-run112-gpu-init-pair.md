# Pascal XP 368.81 vs Win7 368.81 — matched GPU initialization path

**Evidence:** GitHub `phobosq/pascal-xp`, Driver analysis #112 (run 39034143084, SHA `e4183c2ba1cfde2d0f76ed95aaf71e6faae476c9`), `xp_fecs_helper_callers.json`, `win7_fecs_helper_callers.json`, `xp_vs_win7_class_registry_lookup.json`, `xp_vs_win7_registry_global_consumers.json`. All three jobs SUCCESS. This is **static** reverse engineering, not proof of GP106 runtime selection or failure.

## Finding: XP counterpart of Win7 `0x001C8754` is XP `0x0009E0C0`

| Semantic operation | XP `0x0009E0C0` | Win7 `0x001C8754` |
|---|---|---|
| Global registry root | `DAT_0094B270` | `DAT_007DA840` |
| Global root object member | `+0x2338` | `+0x2340` |
| Root virtual class query | `root+0x90` with `&DAT_007EF3CB` | `root+0x90` with `0x7EF3CB` |
| Root virtual GPU getter | `root+0x188` | `root+0x188` |
| GPU index member | `gpu+0xC24` | `gpu+0xC2C` |
| GPU linked-list member | `gpu+0x1DF8` | `gpu+0x1E00` |
| GPU next member | `gpu+0x1E00` | `gpu+0x1E08` |
| GPU state flag | `gpu+0xC20` | `gpu+0xC28` |
| GPU callback | `gpu+0x90` | `gpu+0x90` |
| GPU licensed-feature storage | `gpu+0x26C4` | `gpu+0x26CC` |
| GPU post-init virtual table pointer | `gpu+0x1E20` | `gpu+0x1E28` |
| Post-init virtual method | `+0x418`, fallback `+0x410` | `+0x418`, fallback `+0x410` |
| On init error | free GPU, `root+0xB0`, cleanup; return nonzero | same sequence; return nonzero |

**Structural match:** The core root class-query and GPU initialization path exists in both binaries. Relevant object-member offsets consistently shift by `+8` in Win7. Both call the registry root's `+0x90` method without checking its return, then check later setup calls and the GPU object's *distinct* `+0x90` method.

## New, real static difference: Win7-only preflight

Win7 `0x001C8754` calls `FUN_001C4EA4()` **before** querying the registry resource. If it returns false, the function calls it again, triggers `FUN_00199394(0,1)` if false again, and returns status **`0x2F`**. XP `0x0009E0C0` proceeds directly to the root class query; no equivalent preflight occurs in this function. This difference is **not** evidence that XP is missing GP106 support: Win7's additional gate *rejects* a path that XP enters. The helper `FUN_001C4EA4` was **not** decompiled in available bounded reports, so its actual condition remains unknown.

## Caller propagation verified

- XP caller `0x00056530` calls `FUN_0009E0C0(...,&local_fc8)`; if the result is nonzero, it branches to `LAB_00056F2A` (common failure path). The GPU init path follows only after zero status.
- Win7 caller `0x001A88E8` calls `FUN_001C8754(...,local_1068)`; if nonzero, it sets diagnostic code `0x73C0000` and branches to `LAB_001A8CDA`. The prior check of `FUN_001C5408` maps nonzero to `0x7250000`.
- The two callers also contain OS-specific prechecks and parameter layouts; their different diagnostic encoding is **not** a GP106-specific divergence.

## Impact on previous hypotheses

1. Win7 `0x001C8754` **has a concrete XP counterpart** (`0x0009E0C0`), resolving the prior bounded-sample gap.
2. The hypothesis that XP lacks the `0x7EF3CB` registry-root GPU initialization path is **falsified** by this pair.
3. Neither binary checks the immediate return from root `+0x90`; downstream GPU-object setup and error propagation are structurally similar.
4. The previously observed `+8` object layout difference extends through this matched init path.
5. No GP106 runtime divergence or patch candidate is established.

## Focused next evidence needed

1. Decompile Win7 `FUN_001C4EA4` and resolve its boolean predicate, including whether it tests OS capabilities, registry readiness, or GPU-specific conditions.
2. Compare XP `FUN_0004F770` vs Win7 `FUN_0019F478` and the subsequent GPU `+0x90` implementation, then trace the *first* nonzero status under an observed GP106 runtime path.
3. Validate PCI device-ID/architecture selection on the caller path (`XP 0x00056530` vs Win7 `0x001A88E8`) before changing the XP binary.

**Operational note:** No new GitHub commits or driver binary patches were made in this investigation; all work here is read-only on downloaded CI artifacts.