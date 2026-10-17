# Incremental exporter caching — phase 2

The Driver analysis workflow now caches a validated complete **bundle with per-exporter fingerprints** for XP and Win7. GitHub cache still stores only allowed focused JSON, a source fingerprint text file and a manifest. It does not cache drivers or Ghidra projects.

The source of truth for the ordered exporter DAG is [scripts/driver_analysis_plan.json](../../scripts/driver_analysis_plan.json). [scripts/incremental_analysis.py](../../scripts/incremental_analysis.py) hashes for each output: platform; original driver SHA from the manifest; release/asset IDs; pinned Ghidra version and checksum; individual exporter script and its argument recipe; optional input manifest; and fingerprints of dependent exporters. A change to a comparator script does **not** invalidate Ghidra output. An upstream exporter change invalidates its dependent reports. An XP/Win7 identity change is scoped to that platform.

GitHub immutable cache key is derived from all exporter fingerprints. On a new key the restore action may retrieve the latest cache with the same platform prefix. The validator reuses only reports with matching exporter fingerprints and verified SHA-256 digests, then schedules missing exporters in dependency order. All twelve reports must exist and pass validation before saving the new bundle. Reused dependent inputs are materialized before the focused PyGhidra postScripts execute.

**Cache hit:** skip download and Ghidra, regenerate every comparator and summary. **Partial miss:** download hash-validated driver and launch one new Ghidra session with only the missing exporters; automatic PE import/analysis still incurs its normal cost. **Cold miss:** run all twelve exporters. Manual compare-only requires a full hit and fails without importing proprietary inputs if any report is stale or missing.

For safety and reproducibility, corrupted reusable cached data fails closed rather than being silently consumed. Cache is not an authoritative origin guarantee; only trusted workflows may create it. Caches may be evicted, resulting in a cold rebuild. GitHub cache scope and visibility rules still apply. The prior phase-1 cache prefix is separate, so first phase-2 run creates a new v2 bundle.

CI runs self-contained tests for cache hit/miss, dependency invalidation, corrupt checksums, manifest changes, platform isolation, deterministic argv generation, and whitelist enforcement. This phase does **not** yet cache individual RVA decompilations or full Ghidra project databases. Driver and firmware binaries remain excluded.
