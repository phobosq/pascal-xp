# XP counterpart search for Win7 slot-owner predicate (bounded audit)

Date: 2026-10-19. Inputs: committed reports for Driver analysis #115/#116, #119 and #121, and current `scripts/registration_followup_manifest.json`. This is an audit of *available textual evidence*, not a new Ghidra disassembly or a runtime experiment.

## Predicate signature

Win7 `FUN_001C4808(mask)` reads `DAT_007E4588` (active bitmap), `DAT_007E4594` (slot bound), and `(&DAT_007E45A8)[index*3]` (per-slot owner). It compares selected owners with a token obtained via `FUN_001BCA8C` from `SystemReserved1[0xF]`. Return is false if the active bitmap is zero or any selected slot mismatches, true otherwise. An empty selection in the scanned range can succeed vacuously. This is a structural matching signature, not a GP106 gate.

## Three targeted cross-checks

1. **Caller alignment:** Win7 `FUN_001A88E8` has an early `FUN_001C54F4` wrapper call after loading `root+0x180`, before registry options. XP `FUN_00056530` reaches registry processing without an equivalent call *at that position* in the bounded export. Both call structurally paired per-GPU initialization routines (`0009E0C0` / `001C8754`). Thus no direct XP counterpart is demonstrated at the aligned entry position; absence elsewhere is not established.
2. **Dataflow distinction:** Win7 `FUN_001C4EA4` compares a *global* token `DAT_007E4BA8`, whereas `001C4808` compares *per-slot* owner entries. Matching an XP global-owner comparison alone would not establish equivalence to `001C4808`. Require bitmap, bounded index, per-slot stride, selected-bit test, and token comparison together.
3. **Coverage audit:** The current XP focused-export manifest includes `00056530`, `0009E0C0`, and `0009B470` but has no targeted XP data-xref inventory for a slot bitmap/table or reverse caller graph. Therefore these exports cannot exhaustively identify a relocated/inlined XP predicate. Win7 `001C54F4` is decompiled as void despite its caller consuming a return value: verify machine instructions before asserting caller polarity.

## Disposition and next reproducible experiment

**XP counterpart: unresolved (not proven absent).** Next bounded export should collect XP references to the active-slot bitmap and owner-table candidates found from the XP GPU slot allocation/free helpers; for each referenced function capture direct callers, indexed-load stride, bit-test, and thread token provenance. Compare this signature with Win7 `001C4808`, not RVAs or names. Also export raw instructions for Win7 `001C54F4` to settle return-register forwarding. Record matched XP RVAs only when supported by concrete xrefs and instructions. No GP106 runtime proof and no NVIDIA binary changes.
