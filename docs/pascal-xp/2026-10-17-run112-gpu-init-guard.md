# Pascal XP 368.81 / Win7 368.81 — GPU init guard follow-up

Data: **2026-10-17**. Input: GitHub Driver analysis #112 (run 39034143084, SHA `e4183c2ba1cfde2d0f76ed95aaf71e6faae476c9`), reports `xp_fecs_helper_callers.json`, `win7_fecs_helper_callers.json`. All conclusions are from **static decompilation**.

## 1. `FUN_001C4EA4` is probably a global RM lock-state predicate, not a GP106-specific hardware test

Within the **4,942 Win7 decompiled caller rows** in #112, `FUN_001C4EA4()` appears in **207 distinct functions**, of which **203** contain `0x2F` somewhere in their decompilation. `FUN_001C54F4()` appears in **163** distinct functions; **131** call both predicates. These counts are *sampled decompilation occurrences*, not whole-binary callgraph totals or proof of a particular return path.

The strongest evidence is the paired helper behavior:

- `FUN_001C4D90(param)` checks `FUN_001C4EA4()`: when false, it enters a resource/lock sequence involving `FUN_001BF7D0`, `FUN_001CBFBC(0)`, a ring buffer at `DAT_007E4BC0` and `DAT_007E4EB0`, and `FUN_001C3C64`. When true, it returns `0x2F` (after an assertion check).
- `FUN_001C4EC8()` requires `FUN_001C4EA4()` to be true, then invokes `FUN_001CBFBC(1)`, updates the same ring buffer, sets `DAT_007E4BA8=-1`, calls `FUN_001BF904` and returns zero. When false, it returns `0x2F`.
- Both helpers are called by **36** of the same decompiled Win7 wrapper functions; acquire-only=0, release-only=0. Example: `FUN_001A038C` does `FUN_001C4D90(0)` → `FUN_001C5578(0)` → driver work → `FUN_001C5588(0,0)` → `FUN_001C4EC8()`.
- The second pair `FUN_001C5578` / `FUN_001C5588` appears in **60** common wrapper functions (out of 62 and 61 respective sampled callers). This supports a nested lock/context model.

**Inference (medium confidence):** `FUN_001C4EA4()` probably tests whether an RM lock/context is currently held. Its exact implementation and predicate semantics remain unverified because #112 did **not** export that function's body. The `0x2F` result is consistent with a generic invalid-state/precondition failure, **not** yet with a GP106 failure.

## 2. GPU init path parity and guard placement

XP `FUN_0009E0C0` and Win7 `FUN_001C8754` both query resource `0x7EF3CB`, fetch the GPU object through root `+0x188`, execute preinit helper pairs and GPU virtual method `+0x90`, and propagate nonzero status. Win7 alone has `FUN_001C4EA4()` preflight returning `0x2F` on failure. Its generic lock usage above makes this a poor first candidate for an XP Pascal-enablement patch.

Their caller pair remains XP `FUN_00056530` / Win7 `FUN_001A88E8`. In XP the sequence before init includes `FUN_0009B570`, `FUN_0009B470` and `thunk_FUN_000C4B90`; Win7 uses `FUN_001CAE88`, `FUN_001C8700`, `FUN_001C50F0`, `thunk_FUN_0021BBF8` and an additional `FUN_001C5408` before GPU init. These are not yet demonstrated one-to-one equivalents. Both callers check the GPU-init return code and branch to failure handling.

Win7 `FUN_001C5408` iterates objects using `FUN_001C9D40`, invokes object virtual `+0x418` and ORs a mask into `DAT_007E458C`; this looks like a global resource/preparation step rather than a demonstrated PCI device-ID filter. No proof that its absence in XP blocks GP106.

## 3. Next targeted research (read-only until write restrictions are resolved)

1. Decompile `FUN_001C4EA4` and `FUN_001C54F4` to confirm lock ownership / execution context and establish precise `0x2F` semantics; prioritize verifying the acquire/release relationship above.
2. Compare XP `FUN_0004F770`, `FUN_000557E0`, `FUN_00055630` with Win7 `FUN_0019F478`, `FUN_001A95A8`, `FUN_001A93D4`; identify the earliest meaningful **nonzero return** in the same GPU-init stage.
3. Resolve architecture/device selection in XP `FUN_0009B570` versus Win7 `FUN_001CAE88`, and identify the actual PCI ID / GP106-specific conditional branch, not a class-resource constant.

**Blocked write:** Attempt to create a new focused Ghidra exporter through the GitHub connector was blocked by safety checks. No commit or new CI run was created. This report uses only existing artifacts. No NVIDIA binaries modified. **No runtime GP106 divergence established; no patch candidate.**