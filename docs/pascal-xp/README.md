# Pascal XP 368.81 / Windows 7 368.81 — reverse-engineering reports

Historical research notes from 17 October 2026 for [phobosq/pascal-xp](https://github.com/phobosq/pascal-xp). Reports preserve their original findings and uncertainty. Treat these as **static evidence**, not proof that GP106 is selected or blocked at runtime.

## Reports

| Analysis | Source run | File |
|---|---|---|
| Class registry, 0x7EF3CB consumers and false positives | [#108](https://github.com/phobosq/pascal-xp/actions/runs/39028858612) | [Class resource](2026-10-17-run108-class-resource.md) |
| Matched XP/Win7 GPU initialization pair | [#112](https://github.com/phobosq/pascal-xp/actions/runs/39034143084) | [GPU init pair](2026-10-17-run112-gpu-init-pair.md) |
| Win7 RM lock/context guard hypothesis | #112 | [GPU init guard](2026-10-17-run112-gpu-init-guard.md) and [evidence JSON](2026-10-17-run112-win7-guard-evidence.json) |
| NVIDIA vendor enumeration and PCI ID false positives | #112 | [PCI vendor parity](2026-10-17-run112-pci-vendor.md) |
| Driver analysis generated summary | [#113](https://github.com/phobosq/pascal-xp/actions/runs/39055673968) | [Analysis summary](2026-10-17-run113-analysis-summary.md) |
| Win7 GPU init status paths 0x2F, 0x40, 0x51 | #113 | [Status paths](2026-10-17-run113-status-2f-40-51.md) |
| Win7 guards, GPU index wrappers and ownership state | [#115](https://github.com/phobosq/pascal-xp/actions/runs/39064593635), [#116](https://github.com/phobosq/pascal-xp/actions/runs/39066013310) | [Guard/index analysis](2026-10-17-run115-116-guard-and-index-analysis.md) |
| GPU-slot owner bitmap and registry ranking audit | [#119](https://github.com/phobosq/pascal-xp/actions/runs/39070773238) | [GPU-slot ownership](2026-10-17-run119-gpu-slot-ownership.md) |
| Independent analysis of a **modified XP probe**, not the original input | Separate local examination | [Probe analysis](2026-10-17-modified-xp-probe.md) |

## Important chronological corrections

- The #108 note identified Win7 GPU initialization at `FUN_001C8754` but could not find its XP counterpart within a bounded sample. #112 **found** XP `FUN_0009E0C0`; absence was never established.
- The modified-probe note explicitly lacks access to the pristine Win7 helper and warns that equivalence was unverified. #113 subsequently **confirmed with original SHA-validated binaries** that XP `FUN_0009B570` and Win7 `FUN_001CAE88` are 104-byte matching synchronized identifier-list insertions, **not** a demonstrated GP106 architecture gate.
- The #113 reports identify pre-resource-query failure conditions: Win7 slot preparation can return `0x40` (occupied slot) or `0x51` (allocation failure), while the `FUN_001C4EA4` preflight inside GPU initialization can return `0x2F`. These are static paths with **no proven runtime link to GP106**.
- No NVIDIA binaries, firmware images, or complete driver decompilation dumps are committed here.

## Baseline binary fingerprints used by CI

- Windows XP `nv4_mini.sys`: SHA-256 `cdb1f92a62fe4f36d9121d27fedd741c9a2c044df79d09dccd4fa492c80ca733`.
- Windows 7 `nvlddmkm.sys`: SHA-256 `629b14222fdaecc294d2d8fa372ce0ad6f76bbde13b6b4168977ef6e30d22562`.

The GitHub Actions source of truth is the [Driver analysis workflow](https://github.com/phobosq/pascal-xp/blob/main/.github/workflows/driver-analysis.yml).

## Incremental CI

- [Per-exporter incremental cache, dependencies, and on-demand Ghidra exporters](incremental-exporters.md) — phase 2.

- [Validated XP/Win7 report cache and compare-only mode](incremental-analysis.md) — fingerprinting, validation and fallback.

## Reporting workflow

- Commit each completed investigation report to `docs/pascal-xp/` and link it from this index; include the source Driver analysis run and clearly mark unproven hypotheses.
- If a GitHub write is blocked, provide the user with an exact, applicable unified diff and file path rather than only reporting the blocker. Do not attempt to circumvent safety checks.
