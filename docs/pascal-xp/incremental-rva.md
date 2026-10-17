# Phase 3: per-RVA registration follow-up cache

Cache now reuses individual RVA rows of the bounded registration_followup exporter, with an independently fingerprinted unit identity. The identity contains driver SHA-256, selected release/asset IDs, pinned Ghidra version/configuration, exporter code and argument recipe, but not the platform's focus-address list.

On a focus-list change the workflow verifies the previous cached registration JSON against its cache manifest, reuses only status=ok or status=too_large records, and passes a validated allowlisted selection file to the Ghidra exporter for missing addresses. decompile_failed and missing_function are retried. A merge recreates the original complete registration_followup JSON in current manifest order. Removal-only changes may need no Ghidra at all. Changed driver, exporter, toolchain or provenance must invalidate individual reuse.

The source manifest allows at most 256 unique eight-character hexadecimal addresses. Corrupted caches, duplicate records, unknown rows and incomplete merges fail closed. Temporary seeds/selection lists stay outside the published work/reports directory. Existing comparators and final JSON schema remain unchanged.

Cache metadata records a registration_unit_base only after the complete report passes integrity verification and sealing. Older phase-2 entries without this identity cannot reuse individual rows across a manifest change, so one initial rebuild is expected. All intermediate exports remain bounded; no binary, firmware, or Ghidra project is saved.

Tests: python -m unittest discover -s scripts -p test_registration_rva_cache.py -v. This phase reduces redundant per-RVA decompilation, but a nonempty selection still invokes full Ghidra import/auto-analysis. Actual speedup requires measuring completed Actions runs.
