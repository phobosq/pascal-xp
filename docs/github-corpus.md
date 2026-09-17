# Supplying proprietary driver binaries to GitHub Actions

Do not commit NVIDIA driver binaries to the public repository.

The analysis workflow reads the two `.sys` files from a **Draft Release** in this repository. Draft release assets remain available for reuse while the workflow accesses them through the repository `GITHUB_TOKEN`.

## One-time upload

1. Open the repository on GitHub.
2. Go to **Releases**.
3. Choose **Draft a new release**.
4. Title/tag can be `corpus-36881`.
5. Upload exactly these assets:
   - `nv4_mini.sys` — from NVIDIA 368.81 Windows XP Professional x64.
   - `nvlddmkm.sys` — from NVIDIA 368.81 Windows 7 x64.
6. **Do not publish the release.** Keep it as a draft.

The corpus draft may remain in the repository permanently for repeated analysis runs.

## How the workflow locates the corpus

The workflow no longer depends on the draft release tag URL. Draft releases can use temporary `untagged-...` asset URLs even when `tag_name` is populated, so tag-based downloads are unreliable.

By default, the workflow scans releases and chooses the newest **draft** containing both required asset names.

You may optionally provide a numeric `release_id` to select a specific draft explicitly. The initial 368.81 corpus draft created for this project has release ID:

`390358348`

## Run the analysis

Go to:

**Actions -> Driver analysis -> Run workflow**

Normally leave `release_id` blank. The workflow will find the newest suitable draft automatically.

If automatic selection ever becomes ambiguous, enter:

`390358348`

The asset defaults remain:

- XP asset: `nv4_mini.sys`
- Win7 asset: `nvlddmkm.sys`

After completion, download the artifact named similar to:

`pascal-xp-36881-analysis-<run number>`

It contains only analysis output and hashes, not the original driver binaries.

## Expected reports

- `corpus_release.txt`
- `input_sha256.txt`
- `xp_pe.json`
- `win7_pe.json`
- `xp_firmware.json`
- `win7_firmware.json`
- `xp_program_facts.json`
- `win7_program_facts.json`
- `xp_vs_win7_program_facts.json`
- `xp_pascal_candidates.json`
- `win7_pascal_candidates.json`

## Safety behavior

Before artifact upload the workflow removes:

- the `.sys` input files,
- temporary Ghidra projects,
- the downloaded Ghidra distribution.

Only `work/reports/` is uploaded as the GitHub Actions artifact.
