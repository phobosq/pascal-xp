# Pascal XP 368.81 / Win7 368.81 — focused class-resource comparison

Source: GitHub Driver analysis #108, run 39028858612, SHA ed477ff4e136, all three jobs SUCCESS. This note is a static reverse-engineering assessment; it does **not** prove a GP106 runtime branch or authorize a patch.

## Corrected interpretation of global consumer ranking

The current `scripts/compare_registry_global_consumers.py` matches textual `+ 400` and `+0x90` indiscriminately. Several scored entries are false positives:

- XP `0x00054B60`: `*(undefined4 *)(lVar2 + 400) = 1;` — a data write, not a virtual `+0x190` call.
- XP `0x0007C0D0`: `*(undefined4 *)(local_res18 + 400)` — a data read, not a virtual `+0x190` call.
- Win7 `0x001A5954`: `*(undefined4 *)(lVar2 + 400) = uVar3;` — a data write, not a virtual `+0x190` call.
- Win7 `0x001C8754`: genuine registry-root `+0x90` invocation, with resource `0x7EF3CB`. The later `lVar8 + 0x90` is a separate GPU-object method, not another root lookup. Root pointer alias `lVar4 = DAT_007DA840` is explicit.

The exporter examined 180 static references per binary (cap), covering 147 XP / 148 Win7 owners; it decompiled 57 functions per binary. These are bounded samples, **not** exhaustive absence proofs.

## Resource 0x7EF3CB registration parity

Both OS drivers explicitly register the same class-resource ID:

| Operation | XP 368.81 | Win7 368.81 |
|---|---|---|
| Dispatcher | `0x0005D820` | `0x001B757C` |
| Resource ID | `0x7EF3CB` | `0x7EF3CB` |
| Counter | `root+0x1D08` | `root+0x1D10` |
| First slot data | `root+0x1A90 + 0x10*n` | `root+0x1A98 + 0x10*n` |
| Second slot data | `root+0x1A94 + 0x10*n` | `root+0x1A9C + 0x10*n` |
| Slot pointer | `root+0x1A88 + 0x10*n` | `root+0x1A90 + 0x10*n` |
| Register helper | `FUN_00116D60` | `FUN_0023C384` |
| Link helper | `FUN_00069300` | `FUN_001E71D4` |

Each relevant field shifts **+8 bytes** from XP to Win7, consistent with an OS-specific object layout, not by itself a missing XP class registration. Both return success (zero) when the registration helper succeeds and propagate its nonzero status otherwise.

## Matched resource consumers

- XP `0x0049B9D0` ↔ Win7 `0x0053247C`: both access `0x7EF3CB`, resolve a resource object, use a `+0x680` field, and parse an object through the `param_1 + 0x1D8` virtual method. XP calls `FUN_000CA680(param_1,&DAT_007EF3CB)`; Win7 calls `FUN_0021BB10(param_1,0x7EF3CB)`.
- XP `0x004A1190` ↔ Win7 `0x005329E4`: both access the same resource, initialize an 0x88-byte local structure, call a virtual method `+0x468`, then `+0xB10`; they return 0 on success and propagate an error or 0xFFFF on failure.

These are strong static structural pairs, **not** proof of identical ABI or runtime behavior. They also disprove an inference that resource `0x7EF3CB` is absent from the XP binary just because it was not found in the bounded registry-global consumer sample.

## Next focused work

1. Fix consumer ranking to require actual indirect `(**(code **)(... + offset))` call expressions; resolve aliases of the registry root, and distinguish root `+0x90` from GPU-object `+0x90`. Add regression tests for the three false positives above.
2. Find XP counterpart of Win7 GPU-initialization `0x001C8754` (root `+0x90`, resource `0x7EF3CB`) by tracing callers of the root query method, not only bounded global xrefs. Do not infer absence from the 180-reference cap.
3. Once a matched initialization path is found, compare failure statuses from resource query, GPU-object `+0x90`, and the next registration steps. Tie any divergence to GP106 runtime selection before patching.

## Operational note

Attempt to commit the comparator correction via GitHub was blocked by tool safety checks. No code changes from this cycle were pushed; the analysis findings above are local and can be used in later cycles. Do not bypass safety checks.