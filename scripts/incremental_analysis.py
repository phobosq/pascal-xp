#!/usr/bin/env python3
"""Per-exporter XP/Win7 cache planner; report-only cache, not Ghidra project caching."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

from analysis_cache import (
    GHIDRA_TAG, GHIDRA_ZIP_SHA256, MAX_REPORT_SIZE,
    expected_driver_hash, sha256,
)

SCHEMA = 2
PLAN = Path('scripts/driver_analysis_plan.json')
DRIVER_NAMES = {'xp': 'nv4_mini.sys', 'win7': 'nvlddmkm.sys'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def load_plan(root):
    raw = json.loads((Path(root) / PLAN).read_text(encoding='utf-8'))
    if raw['schema_version'] != 1 or len(raw['exporters']) != 12:
        raise ValueError('unexpected exporter plan')
    rows = raw['exporters']
    seen = set()
    for row in rows:
        name = row['id']
        if name in seen or '/' in name or not name.replace('_', '').isalnum():
            raise ValueError('duplicate/unsafe exporter ID')
        if any(dep not in seen for dep in row['depends_on']):
            raise ValueError('dependencies must precede dependent exporters')
        if not row['script'].startswith('Export') or '/' in row['script']:
            raise ValueError('unexpected exporter script')
        seen.add(name)
    return rows


def signatures(platform, release_id, asset_id, root=Path('.')):
    root = Path(root)
    rows = load_plan(root)
    identity = {
        'schema': SCHEMA, 'platform': platform,
        'driver': expected_driver_hash(platform, root),
        'release': str(release_id), 'asset': str(asset_id),
        'ghidra': GHIDRA_TAG, 'ghidra_sha': GHIDRA_ZIP_SHA256,
        'import_configuration': 'headless-autoanalysis-default-import-v1',
    }
    manifest = json.loads((root / 'scripts/registration_followup_manifest.json').read_text())
    manifest_hash = digest(manifest['platforms'][platform]['focus_addresses'])
    result = {}
    for row in rows:
        script_hash = sha256(root / 'ghidra' / row['script'])
        result[row['id']] = digest({
            'identity': identity, 'recipe': row, 'source': script_hash,
            'manifest': manifest_hash if row['id'] == 'registration_followup' else None,
            'upstream': {d: result[d] for d in row['depends_on']},
        })
    return result


def bundle_key(sigs):
    return digest({'schema': SCHEMA, 'signatures': sigs})


def report_name(platform, ident):
    return f'{platform}_{ident}.json'


def validate_json(path, platform):
    if not path.is_file() or path.is_symlink() or not (0 < path.stat().st_size <= MAX_REPORT_SIZE):
        raise ValueError(f'missing or invalid report file: {path.name}')
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or not data:
        raise ValueError(f'not a nonempty JSON object: {path.name}')
    if 'platform' in data and data['platform'] != platform:
        raise ValueError(f'wrong report platform: {path.name}')
    return sha256(path)


def validate_input(path, platform, root):
    text = path.read_text(encoding='utf-8').split()
    if len(text) != 2 or text[0].lower() != expected_driver_hash(platform, root):
        raise ValueError('binary fingerprint mismatch')
    if Path(text[1]).name != DRIVER_NAMES[platform]:
        raise ValueError('binary source filename mismatch')


def prepare(platform, sigs, cache_dir, reports_dir, plan_out, root=Path('.')):
    root = Path(root)
    cache_dir, reports_dir, plan_out = Path(cache_dir), Path(reports_dir), Path(plan_out)
    manifest_path = cache_dir / 'incremental_manifest.json'
    old = {}
    if manifest_path.is_file():
        old = json.loads(manifest_path.read_text(encoding='utf-8'))
        if old.get('schema') != SCHEMA or old.get('platform') != platform:
            raise ValueError('invalid cache metadata identity')
    reusable = []
    for name, signature in sigs.items():
        entry = old.get('entries', {}).get(name)
        if entry is None or entry.get('signature') != signature:
            continue
        src = cache_dir / report_name(platform, name)
        actual = validate_json(src, platform)
        if actual != entry.get('sha256'):
            raise ValueError(f'corrupted cached report: {name}')
        reusable.append(name)
    # No report is materialized until every candidate has passed validation.
    reports_dir.mkdir(parents=True, exist_ok=True)
    for name in reusable:
        shutil.copyfile(cache_dir / report_name(platform, name),
                        reports_dir / report_name(platform, name))
    sha_file = cache_dir / f'{platform}_input_sha256.txt'
    if sha_file.is_file() and reusable:
        validate_input(sha_file, platform, root)
        shutil.copyfile(sha_file, reports_dir / sha_file.name)
    missing = [ident for ident in sigs if ident not in reusable]
    plan_out.parent.mkdir(parents=True, exist_ok=True)
    plan_out.write_text(json.dumps({'platform': platform, 'missing': missing}, indent=2) + '\n')
    return missing


def build_argv(platform, plan_path, root=Path('.'), reports_dir=Path('work/reports')):
    rows = load_plan(root)
    plan = json.loads(Path(plan_path).read_text())
    if plan['platform'] != platform:
        raise ValueError('plan platform mismatch')
    missing = set(plan['missing'])
    if not missing.issubset({row['id'] for row in rows}):
        raise ValueError('unknown scheduled exporter')
    base = str(Path(reports_dir).resolve())
    tokens = []
    for row in rows:
        if row['id'] not in missing:
            continue
        tokens.extend(['-postScript', row['script']])
        for arg in row['args']:
            if arg == '{out}':
                tokens.append(base + '/' + report_name(platform, row['id']))
            elif arg == '{platform}':
                tokens.append(platform)
            elif arg == '{selection}':
                tokens.append(str(Path('work/rva/selection.json').resolve()))
            elif arg == '{manifest}':
                tokens.append(str((Path(root) / 'scripts/registration_followup_manifest.json').resolve()))
            elif arg.startswith('{report:') and arg.endswith('}'):
                tokens.append(base + '/' + report_name(platform, arg[8:-1]))
            else:
                raise ValueError('unknown exporter argument')
    return tokens


def seal(platform, sigs, reports_dir, cache_dir, root=Path('.')):
    reports_dir, cache_dir = Path(reports_dir), Path(cache_dir)
    entries = {}
    for name, sig in sigs.items():
        path = reports_dir / report_name(platform, name)
        entries[name] = {'signature': sig, 'sha256': validate_json(path, platform)}
    input_file = reports_dir / f'{platform}_input_sha256.txt'
    validate_input(input_file, platform, root)
    # Stage only whitelisted validated JSON and fingerprint, no binary/project.
    cache_dir.mkdir(parents=True, exist_ok=True)
    for name in entries:
        shutil.copyfile(reports_dir / report_name(platform, name),
                        cache_dir / report_name(platform, name))
    shutil.copyfile(input_file, cache_dir / input_file.name)
    (cache_dir / 'incremental_manifest.json').write_text(json.dumps({
        'schema': SCHEMA, 'platform': platform, 'entries': entries,
    }, sort_keys=True, indent=2) + '\n')


def emit(key, value):
    line = f'{key}={value}\n'
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as f:
            f.write(line)
    else:
        print(line, end='')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('command', choices=('key', 'prepare', 'args0', 'seal'))
    p.add_argument('--platform', required=True, choices=DRIVER_NAMES)
    p.add_argument('--release-id', required=True)
    p.add_argument('--asset-id', required=True)
    p.add_argument('--root', type=Path, default=Path('.'))
    p.add_argument('--cache-dir', type=Path, default=Path('work/cache'))
    p.add_argument('--reports-dir', type=Path, default=Path('work/reports'))
    p.add_argument('--plan-out', type=Path, default=Path('work/incremental_plan.json'))
    a = p.parse_args()
    sigs = signatures(a.platform, a.release_id, a.asset_id, a.root)
    if a.command == 'key':
        emit('key', bundle_key(sigs))
    elif a.command == 'prepare':
        missing = prepare(a.platform, sigs, a.cache_dir, a.reports_dir, a.plan_out, a.root)
        emit('need_ghidra', 'true' if missing else 'false')
        print(f'Reused {len(sigs)-len(missing)}/{len(sigs)} exporter reports')
    elif a.command == 'args0':
        sys.stdout.buffer.write(b''.join(x.encode() + b'\0' for x in
            build_argv(a.platform, a.plan_out, a.root, a.reports_dir)))
    else:
        seal(a.platform, sigs, a.reports_dir, a.cache_dir, a.root)


if __name__ == '__main__':
    main()
