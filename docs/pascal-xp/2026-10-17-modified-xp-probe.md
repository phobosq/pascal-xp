# Focused RE: XP `FUN_0009B570`

## Provenance

- Source file: `nv4_mini_gp106_as_gm206_probe.sys`, a **modified** XP x64 probe owned by the user.
- SHA-256: `a94b56ea0b19dc786181dc392065437d7486045dd9350ed8e8a53d39d829fd63`.
- Expected official corpus XP SHA-256: `cdb1f92a62fe4f36d9121d27fedd741c9a2c044df79d09dccd4fa492c80ca733` — **does not match**.
- PE32+ x86-64 image base `0x10000`; function VA `0x9B570`, RVA `0x8B570`.
- `.pdata` RUNTIME_FUNCTION: start RVA `0x8B570`, end RVA `0x8B5D8`; confirms 104-byte boundary.

## What the assembly shows

1. Loads a context from root pointer `DAT_0094B270` at root `+0x2338`.
2. Loads a synchronization handle at context `+0x1F0`.
3. Calls `FUN_00073E10(handle, 0)`; returns immediately if its status is nonzero.
4. Scans up to 32 entries of stride `0xC`, starting at context `+0x70`, for the first entry whose first DWORD is `0xFFFFFFFF`.
5. Stores the incoming `ECX` identifier into that entry and clears its byte at `+4`.
6. Calls `FUN_00073E80(handle)` and returns zero even if all 32 entries were occupied.

**Interpretation:** strongly resembles registering an identifier in a synchronized 32-entry resource/context list. It is not visibly a PCI ID / GP106 architecture gate.

Neighbor function `FUN_0009B5E0` uses the same root/context/synchronization handle and clears a matching entry by restoring the `0xFFFFFFFF` sentinel. This strongly supports an add/remove pair.

## Critical limitation

This is independent assembly reconstruction on a **modified** probe, not a verified decompilation of the pristine binary. No byte-for-byte comparison of `0x9B570..0x9B5D8` against the original was available. The Win7 `FUN_001CAE88` body also remains unavailable because original `nvlddmkm.sys` was not mounted and GitHub #112 does not include this body. Thus the pair's equivalence is still unresolved.

## Available reproduction

- `xp_FUN_0009B570_disassembly.txt`: actual disassembly of the function.
- `xp_FUN_0009B570_reconstructed.c`: readable reconstruction, **not** a genuine Ghidra decompilation.
- `xp_FUN_0009B5E0_pair_disassembly.txt`: confirming neighboring inverse routine.
- `ExportGpuInitPreflightReadOnly.py`: Ghidra headless script for **both** original drivers, plus immediate callees and a few related functions (read-only).
- `README.txt`: commands and original input SHA values.

No GitHub commit, no driver patch, no binary included in the report bundle.