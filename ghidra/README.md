# Ghidra analysis

Planned headless pipeline:

1. Import XP `nv4_mini.sys` and Win7 `nvlddmkm.sys`.
2. Run standard auto-analysis.
3. Export function metadata, strings, xrefs, and references to candidate PCI/GPU tables.
4. Produce BinExport files for BinDiff.
5. Compare same-release XP/Win7 functions before comparing across driver versions.

Proprietary binaries stay outside the repository.
