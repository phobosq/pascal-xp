# Supplying proprietary driver binaries to GitHub Actions

Do not commit NVIDIA driver binaries to the public repository.

The analysis workflow reads the two `.sys` files from a **Draft Release** in this repository. Draft release assets are not exposed as normal public release downloads, while the workflow can access them using the repository `GITHUB_TOKEN`.

## One-time upload

1. Open the repository on GitHub.
2. Go to **Releases**.
3. Choose **Draft a new release**.
4. Create or enter tag: `corpus-36881`.
5. Title can be `Private analysis corpus 368.81`.
6. Upload exactly these assets (rename locally first if necessary):
   - `nv4_mini.sys` — from NVIDIA 368.81 Windows XP Professional x64 driver.
   - `nvlddmkm.sys` — from NVIDIA 368.81 Windows 7 x64 driver.
7. **Do not publish the release.** Save it as a draft.

The workflow deliberately refuses to consume a published release.

## Run the analysis

Go to:

**Actions -> Driver analysis -> Run workflow**

Defaults are already set to:

- corpus tag: `corpus-36881`
- XP asset: `nv4_mini.sys`
- Win7 asset: `nvlddmkm.sys`

After completion, download the artifact named similar to:

`pascal-xp-36881-analysis-<run number>`

It contains only analysis output and hashes, not the original driver binaries.

## Expected reports

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
