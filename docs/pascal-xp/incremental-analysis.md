# Incremental Driver analysis cache — phase 1

The Driver analysis workflow uses a validated, per-platform **full-report cache**; this phase does not implement per-exporter or per-RVA caching.

## Modes and output contract

- Pushes changing ghidra scripts, Python scripts or the workflow run in automatic mode. An XP/Win7 cache hit avoids binary download, Ghidra installation and decompilation; cache misses perform the existing 12-exporter analysis.
- Manual workflow_dispatch with analysis_mode=auto also uses the cache. analysis_mode=compare-only demands valid caches for both XP and Win7, failing immediately on any miss without downloading driver binaries or launching Ghidra.
- Comparators, audits and the Markdown/JSON summary **always rerun** using current Python code. Existing focused-xp, focused-win7 and pascal-xp-focused-analysis artifact naming and contents are preserved.

## Cache identity and validation

scripts/analysis_cache.py fingerprints platform, manifest SHA-256 of original driver, selected release and asset IDs, pinned Ghidra version/ZIP digest, ghidra/*.py exporters, registration manifest, requirements.txt and driver-analysis.yml.

Only twelve whitelisted per-platform JSON reports, driver SHA-256 evidence text, and a checksum manifest are staged. Restore verifies platform, cache key/schema, filenames, sizes, JSON objects, original driver fingerprint and SHA-256 of each report. No NVIDIA binary, firmware, or Ghidra project is copied to Git or the cache.

A cache miss triggers analysis in auto mode and fails in compare-only. A corrupted restored hit fails closed: GitHub caches are immutable, so delete the bad cache entry or bump cache schema to rebuild. Pinned Ghidra: Ghidra_12.1.4_build, artifact ghidra_12.1.4_PUBLIC_20260921.zip, SHA-256 ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db.

JSONs may still include decompilation fragments. Do not put secrets in cache; use trusted workflows only. Phase 1 does not speed up actual cache misses.

concurrency.cancel-in-progress is disabled to avoid wasting an already running expensive analysis when a new push happens. GitHub may still coalesce pending runs; this is not strict FIFO.

## Regression checks

Run: python -m unittest discover -s scripts -p test_analysis_cache.py -v

Seven synthetic tests cover roundtrip, missing/corrupted/wrong-platform data, identity/config invalidation and malformed JSON. Expected first auto run: cache miss, Ghidra XP/Win7 and comparison. Expected next comparator-only change: validated XP/Win7 cache hits and fresh comparison without Ghidra. Actual speedup must be measured in Actions.

## Phase 2

See [incremental-exporters.md](incremental-exporters.md) for per-exporter fingerprints, dependent cache invalidation and selective headless postScripts. The phase-1 full-report cache is superseded by the separate v2 cache prefix.
