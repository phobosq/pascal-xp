#!/usr/bin/env python3
"""Validate and cache only public-focused, JSON-only XP/Win7 Ghidra reports.

No driver images, firmware, or Ghidra project databases are read or staged.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

CACHE_SCHEMA = 1
GHIDRA_TAG = 'Ghidra_12.1.4_build'
GHIDRA_ZIP_SHA256 = 'ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db'
EXPORTS = (
    'fecs_table_roots', 'fecs_descriptor_parents', 'gp106_resource_wiring',
    'gp106_constructor_patterns', 'gp106_constructor_ownership',
    'descriptor_owner_chains', 'focused_constructor_trace',
    'resource_override_wrappers', 'registration_followup',
    'class_registry_lookup', 'registry_global_consumers', 'fecs_helper_callers',
)
MAX_REPORT_SIZE = 32 * 1024 * 1024

def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def required_names(platform):
    if platform not in ('xp', 'win7'):
        raise ValueError('unknown platform')
    return tuple(f'{platform}_{name}.json' for name in EXPORTS)

def expected_driver_hash(platform, root=Path('.')):
    manifest = json.loads((Path(root) / 'scripts/registration_followup_manifest.json').read_text())
    return manifest['input_sha256'][platform]

def cache_key(platform, release_id, asset_id, root=Path('.')):
    root = Path(root)
    files = sorted((root / 'ghidra').glob('*.py'))
    files += [root / 'scripts/registration_followup_manifest.json',
              root / 'requirements.txt', root / '.github/workflows/driver-analysis.yml']
    fingerprint = {
        'schema': CACHE_SCHEMA, 'platform': platform,
        'driver_sha256': expected_driver_hash(platform, root),
        'release_id': str(release_id), 'asset_id': str(asset_id),
        'ghidra_tag': GHIDRA_TAG, 'ghidra_zip_sha256': GHIDRA_ZIP_SHA256,
        'sources': {str(p.relative_to(root)): sha256(p) for p in files},
    }
    return hashlib.sha256(json.dumps(fingerprint, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def inspect_reports(platform, folder, root=Path('.')):
    folder = Path(folder)
    names = (*required_names(platform), f'{platform}_input_sha256.txt')
    digests = {}
    for name in names:
        path = folder / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f'missing or unsafe report: {name}')
        if not (0 < path.stat().st_size <= MAX_REPORT_SIZE):
            raise ValueError(f'invalid report size: {name}')
        if name.endswith('.json'):
            data = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(data, dict) or not data:
                raise ValueError(f'invalid JSON object: {name}')
            if 'platform' in data and data['platform'] != platform:
                raise ValueError(f'wrong platform in {name}')
        else:
            recorded = path.read_text(encoding='utf-8').split()
            if len(recorded) != 2 or recorded[0].lower() != expected_driver_hash(platform, root):
                raise ValueError('source binary fingerprint mismatch')
            if Path(recorded[1]).name != ('nv4_mini.sys' if platform == 'xp' else 'nvlddmkm.sys'):
                raise ValueError('unexpected source binary name')
        digests[name] = sha256(path)
    return digests

def stage(platform, key, reports, cache, root=Path('.')):
    digests = inspect_reports(platform, reports, root)
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    # Cache only the whitelisted reports, never drivers or Ghidra projects.
    for name in digests:
        shutil.copyfile(Path(reports) / name, cache / name)
    (cache / 'cache_manifest.json').write_text(json.dumps({
        'cache_schema': CACHE_SCHEMA, 'platform': platform,
        'cache_key': key, 'files': digests,
    }, sort_keys=True, indent=2) + '\n', encoding='utf-8')

def restore(platform, key, cache, reports, root=Path('.')):
    cache = Path(cache)
    try:
        meta = json.loads((cache / 'cache_manifest.json').read_text(encoding='utf-8'))
        if meta.get('cache_schema') != CACHE_SCHEMA or meta.get('platform') != platform or meta.get('cache_key') != key:
            raise ValueError('cache identity mismatch')
        digests = inspect_reports(platform, cache, root)
        if digests != meta.get('files'):
            raise ValueError('cache report checksum mismatch')
        Path(reports).mkdir(parents=True, exist_ok=True)
        for name in digests:
            shutil.copyfile(cache / name, Path(reports) / name)
        return True, 'cache validated'
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeError) as exc:
        return False, str(exc)

def emit(name, value):
    line = f'{name}={value}\n'
    path = os.environ.get('GITHUB_OUTPUT')
    if path:
        with open(path, 'a', encoding='utf-8') as out:
            out.write(line)
    else:
        sys.stdout.write(line)

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='command', required=True)
    for command in ('key', 'restore', 'stage'):
        s = sub.add_parser(command)
        s.add_argument('--platform', choices=('xp', 'win7'), required=True)
        s.add_argument('--root', type=Path, default=Path('.'))
        if command == 'key':
            s.add_argument('--release-id', required=True)
            s.add_argument('--asset-id', required=True)
        else:
            s.add_argument('--key', required=True)
            s.add_argument('--cache-dir', type=Path, required=True)
            s.add_argument('--reports-dir', type=Path, required=True)
    a = p.parse_args()
    if a.command == 'key':
        emit('key', cache_key(a.platform, a.release_id, a.asset_id, a.root))
    elif a.command == 'stage':
        stage(a.platform, a.key, a.reports_dir, a.cache_dir, a.root)
        print(f'Validated {len(EXPORTS)} {a.platform} JSON reports for cache')
    else:
        valid, why = restore(a.platform, a.key, a.cache_dir, a.reports_dir, a.root)
        print(f'{a.platform} report cache: {why}')
        emit('valid', 'true' if valid else 'false')

if __name__ == '__main__':
    main()
