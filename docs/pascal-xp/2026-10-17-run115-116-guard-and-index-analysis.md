# Pascal XP 368.81 / Windows 7 368.81 — Driver analysis #115–#116

Data: 2026-10-17. Source: GitHub Actions runs #115 (39064593635) and #116 (39066013310), both successful. Original XP `nv4_mini.sys` and Windows 7 `nvlddmkm.sys`; static analysis only.

## Target exports

| Platform | Address | Size | Meaning |
|---|---|---:|---|
| XP | `0009B470` | 20 bytes | Virtual dispatch through `DAT_0094B270 + 0xC0`, output pointer passed by parent `00056530` (`param_1+0x3C`). |
| Win7 | `001C8700` | 20 bytes | Same structural virtual dispatch through `DAT_007DA840 + 0xC0`, output pointer passed by `001A88E8` (`param_1+0x60`). |
| Win7 | `001C54F4` | 11 bytes | Thin wrapper around `001C4808(DAT_007E4588)`; `DAT_007E4588` is the active GPU-slot bitmap. |
| Win7 | `001C4EA4` | 34 bytes | `001BCA8C(local_res8); return DAT_007E4BA8 == local_res8[0]`; state/context owner identifier equality. |

All four `targets` have `status=ok` in the #116 `xp_registration_followup.json` / `win7_registration_followup.json` files. Ghidra emits the 20-byte wrappers as `void` and reports unresolved indirect jumps, but callers test their return values: **do not infer they actually return void**.

## Strongest new evidence: 0x2F is an ownership guard

Win7 `001C4D90` calls `001BCA8C(&DAT_007E4BA8)` after successful state acquisition, storing the current identifier. Win7 `001C4EC8` requires the matching owner and resets `DAT_007E4BA8` to `-1` on release. Both use `001C4EA4` and the status `0x2F` for invalid ownership/precondition. `001C8754` checks `001C4EA4` **before** its virtual resource query with class/resource ID `0x7EF3CB`; on failure, it returns `0x2F` before that query. Thus `0x2F` is strongly supported as a generic context-ownership error, not a demonstrated GP106 architecture gate.

## Other preflight stages

Win7 `001A88E8` checks `001C54F4` before allocating a GPU slot. This function passes the active GPU bitmap to `001C4808`; the precise predicate remains unknown until `001C4808` is exported. Win7 `001C50F0` returns `0x1F` for GPU index >31, `0x40` for an already occupied slot, `0x51` for allocation failure, and can propagate errors from `001C4860`, including `0x59` and `0x63` in its static paths. Win7 `001C5408` processes a GPU mask, invokes an object's virtual method, updates `DAT_007E458C` atomically and returns zero in its current decompilation.

XP `00056530` and Win7 `001A88E8` both call structurally equivalent index wrappers, followed by other mask/state helpers and GPU init (`0009E0C0` / `001C8754`). Win7 explicitly calls `001C50F0` for slot preparation; that is a control-flow difference, **not proof** that XP lacks equivalent logic in another helper.

## Conclusion and next bounded export

No evidence from #115/#116 ties any of these guards to a GP106-specific runtime failure. The two strongest next addresses are Win7 `001C4808` (actual bitmap predicate) and `001BCA8C` (source of current context/owner identifier). Add these two to `scripts/registration_followup_manifest.json` for the next run; do not expand beyond them or patch NVIDIA binaries without runtime evidence.

## Repository status

An attempted automated GitHub documentation/manifest commit was blocked by tool safety checks. No repository write was completed. The last verified `main` commit remains `4f5be05d20bf46c332a1078e23b5a83629397c46` (analysis #116).