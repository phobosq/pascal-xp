# Pascal on Windows XP

Research project aimed at understanding and, if feasible, backporting NVIDIA Pascal (initial target: GeForce GTX 1060 / GP106) support to Windows XP using the last stable XP driver branch (368.81) and the matching Windows 7 368.81 driver as a donor/reference.

## Initial target

- GPU: GeForce GTX 1060 6 GB (GP106, common PCI ID `10DE:1C03`)
- Primary OS: Windows XP Professional x64 SP2
- Recipient driver: NVIDIA 368.81 for Windows XP x64
- Donor/reference driver: NVIDIA 368.81 for Windows 7 x64
- Control GPU: Maxwell, ideally GTX 960

## Immediate research questions

1. How far does GP106 get on XP x64 with only an INF modification?
2. Does XP `nv4_mini.sys` contain any dormant Pascal-specific code or data?
3. What hardware-facing Pascal initialization exists in the matching Win7 368.81 branch that is absent from XP?
4. Where do ACR / FECS / GPCCS / PGRAPH initialization paths diverge between Maxwell and Pascal?

## Repository policy

Do **not** commit NVIDIA proprietary driver binaries, firmware extracted from NVIDIA packages, or Microsoft SDK/WDK redistributables unless their licenses explicitly allow redistribution.

The repository stores manifests and hashes, analysis scripts, patches expressed against locally supplied originals, probe/test source code, and analysis reports.

## Layout

```text
corpus/       manifest templates; binaries stay local
scripts/      corpus preparation and static-analysis helpers
probe/        Windows XP runtime probe source
ghidra/       headless Ghidra scripts/configuration
reports/      generated reports
docs/         experiment notes and RE documentation
.github/      CI workflows
```

## Quick start

Python 3.10+ is recommended on the analysis workstation.

```bash
python -m pip install -r requirements.txt
python scripts/prepare_corpus.py --manifest corpus/manifest.example.json --root /path/to/local/driver/files --out work/corpus.json
python scripts/scan_pe.py /path/to/nv4_mini.sys
```

`prepare_corpus.py` does not download NVIDIA drivers. It inventories local files and verifies hashes when expected hashes are supplied.

## Experiment discipline

Each hardware experiment should answer one narrowly defined question and record exact input driver hashes, hardware IDs, OS build, modifications, runtime capability results, and logs/dumps.
