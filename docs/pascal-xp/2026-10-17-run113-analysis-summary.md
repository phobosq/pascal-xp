# Pascal XP automated analysis summary

- XP descriptor-parent owners: 7
- Win7 descriptor-parent owners: 14
- XP FECS table-root owners: 12
- Win7 FECS table-root owners: 9
- Ranked callback-shape pairs: 0
- Ranked GP106-like constructor pairs: 250
- Descriptor owner chains ranked: 0
- SEC2 audit classification: SEC2 security processor / firmware control, not demonstrated FECS/GPCCS/GR resource getter
- XP sampled FECS-root initializer/data links: 12
- Win7 sampled FECS-root initializer/data links: 9
- XP registry candidate lookup consumers: 32
- XP registry global dispatch candidates: 1
- Win7 registry global dispatch candidates: 1
- Win7 registry candidate lookup consumers: 34
- Registration index/header matches: 11/11
- Registration callback slot +0x4c8 parity: True
- Seven OS helper semantics paired XP/Win7: True
- Confirmed actionable constructor pairs: 0
- Two-sided static proximity hypotheses: 0
- One-sided static proximity hypotheses: 40

## Next actions
1. **Bounded class-registry global consumer decompilation identified candidate virtual dispatch.**
   - Verify actual class-selecting conditions, candidate PCI/GPU ties, and status propagation; generic RM_ASSERT is deprioritized.
1. **Static class-registry state consumers identified; actual GP106 class selection still unproven.**
   - Trace top bounded registry global-data consumers toward an observed class lookup/branch and propagated status. Do not equate class index with PCI device ID.
2. **Static owners were found around real FECS table roots.**
   - Intersect FECS table-root owners with GP106/GP10x registration and architecture-selection functions.

## Caveats
- Static DATA/CALL references do not prove GP106 runtime selection.
- Callback structural similarity is not ABI or ownership proof.
- Do not patch until a concrete GP106 path divergence is tied to a propagated failure status.