#!/usr/bin/env python3
"""Incremental per-RVA reuse of the bounded registration_followup Ghidra export.

Only reuses verified rows from a cached, whitelisted JSON report. No binary,
firmware, Ghidra database or complete decompilation dump is stored.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys

from analysis_cache import GHIDRA_TAG, GHIDRA_ZIP_SHA256, expected_driver_hash, sha256
from incremental_analysis import digest, load_plan, report_name, validate_json

RVA_RE = re.compile(r'^[0-9a-fA-F]{8}$')
REUSABLE_STATUSES = ('ok', 'too_large')
VERSION = 1
CAVEAT = 'Static decompilation; not evidence of runtime GP106 dispatch.'


def targets(platform, root=Path('.')):
    data = json.loads((Path(root) / 'scripts/registration_followup_manifest.json').read_text(encoding='utf-8'))
    raw = data['platforms'][platform]['focus_addresses']
    if not isinstance(raw, list) or len(raw) > 256:
        raise ValueError('invalid focus list')
    rows = []
    for value in raw:
        if not isinstance(value, str) or not RVA_RE.fullmatch(value):
            raise ValueError('invalid registration RVA')
        rows.append(value.lower())
    if len(set(rows)) != len(rows):
        raise ValueError('duplicate registration RVA')
    return rows


def unit_signature(platform, release_id, asset_id, root=Path('.')):
    root = Path(root)
    row = next(x for x in load_plan(root) if x['id'] == 'registration_followup')
    return digest({
        'unit_cache_version': VERSION, 'platform': platform,
        'driver_sha256': expected_driver_hash(platform, root),
        'release_id': str(release_id), 'asset_id': str(asset_id),
        'ghidra': GHIDRA_TAG, 'ghidra_sha256': GHIDRA_ZIP_SHA256,
        'import_configuration': 'headless-autoanalysis-default-import-v1',
        'exporter_recipe': row, 'source_sha256': sha256(root / 'ghidra' / row['script']),
    })


def read_rows(path, platform):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if data.get('schema_version') != 1 or data.get('platform') != platform or not isinstance(data.get('targets'), list):
        raise ValueError('registration report schema/platform mismatch')
    found = {}
    for row in data['targets']:
        if not isinstance(row, dict):
            raise ValueError('malformed registration row')
        entry = row.get('entry')
        if not isinstance(entry, str) or not RVA_RE.fullmatch(entry):
            raise ValueError('invalid registration row RVA')
        key = entry.lower()
        if key in found:
            raise ValueError('duplicate registration row')
        if row.get('status') not in ('ok', 'too_large', 'missing_function', 'decompile_failed'):
            raise ValueError('unknown registration row status')
        if row['status'] in REUSABLE_STATUSES:
            if not isinstance(row.get('size'), int) or not isinstance(row.get('incoming'), list) or not isinstance(row.get('outgoing'), list):
                raise ValueError('missing registration row fields')
        found[key] = row
    return found


def render(platform, ordered, records):
    if set(records) != set(ordered):
        raise ValueError('registration report incomplete or unexpected')
    return {
        'schema_version': 1, 'platform': platform,
        'targets': [records[x] for x in ordered], 'caveat': CAVEAT
    }


def write_report(path, platform, ordered, records):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(render(platform, ordered, records), indent=2) + '\n', encoding='utf-8')


def prepare(platform, base_signature, cache_dir, reports_dir, plan_path, seed_path, selection_path, root=Path('.')):
    ordered = targets(platform, root)
    plan_path, seed_path, selection_path = Path(plan_path), Path(seed_path), Path(selection_path)
    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    if plan.get('platform') != platform or not isinstance(plan.get('missing'), list):
        raise ValueError('exporter plan invalid')
    missing_exporters = plan['missing']
    records = {}
    if 'registration_followup' in missing_exporters:
        cache_dir = Path(cache_dir)
        metadata = cache_dir / 'incremental_manifest.json'
        if metadata.is_file():
            meta = json.loads(metadata.read_text(encoding='utf-8'))
            if meta.get('registration_unit_base') == base_signature and meta.get('platform') == platform:
                cached = cache_dir / report_name(platform, 'registration_followup')
                digest_from_manifest = meta.get('entries', {}).get('registration_followup', {}).get('sha256')
                if not digest_from_manifest or validate_json(cached, platform) != digest_from_manifest:
                    raise ValueError('corrupted registration cache')
                rows = read_rows(cached, platform)
                records = {x: rows[x] for x in ordered if x in rows and rows[x]['status'] in REUSABLE_STATUSES}
    needed = [x for x in ordered if x not in records] if 'registration_followup' in missing_exporters else []
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    seed_path.write_text(json.dumps({'platform': platform, 'targets': list(records.values())}, indent=2) + '\n', encoding='utf-8')
    selection_path.write_text(json.dumps({'platform': platform, 'focus_addresses': needed}, indent=2) + '\n', encoding='utf-8')
    if 'registration_followup' in missing_exporters and not needed:
        write_report(Path(reports_dir) / report_name(platform, 'registration_followup'), platform, ordered, records)
        plan['missing'] = [x for x in missing_exporters if x != 'registration_followup']
        plan_path.write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    return {'need_ghidra': bool(plan['missing']), 'needs_seal': bool(missing_exporters),
            'has_delta': bool(needed), 'reused_rvas': len(records), 'new_rvas': len(needed)}


def merge(platform, seed_path, delta_path, output_path, root=Path('.')):
    ordered = targets(platform, root)
    seed = read_seed(seed_path, platform)
    delta = read_rows(delta_path, platform)
    if set(seed).intersection(delta):
        raise ValueError('duplicate RVA between cached and fresh records')
    records = dict(seed)
    records.update(delta)
    write_report(output_path, platform, ordered, records)
    return len(delta)


def read_seed(path, platform):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if data.get('platform') != platform:
        raise ValueError('registration seed platform mismatch')
    # Parse exactly the same record rules as an exported report.
    container = {'schema_version': 1, 'platform': platform, 'targets': data.get('targets')}
    # Avoid intermediate files and keep a single row validator.
    return parse_container(container, platform)


def parse_container(data, platform):
    if data.get('schema_version') != 1 or data.get('platform') != platform or not isinstance(data.get('targets'), list):
        raise ValueError('registration container invalid')
    found = {}
    for row in data['targets']:
        if not isinstance(row, dict) or not isinstance(row.get('entry'), str) or not RVA_RE.fullmatch(row['entry']):
            raise ValueError('registration entry invalid')
        key = row['entry'].lower()
        if key in found:
            raise ValueError('duplicate registration entry')
        if row.get('status') not in ('ok', 'too_large', 'missing_function', 'decompile_failed'):
            raise ValueError('unknown row status')
        found[key] = row
    return found


def stamp(platform, base_signature, cache_dir, reports_dir):
    report = Path(reports_dir) / report_name(platform, 'registration_followup')
    cached = Path(cache_dir) / report.name
    manifest = Path(cache_dir) / 'incremental_manifest.json'
    meta = json.loads(manifest.read_text(encoding='utf-8'))
    actual = validate_json(cached, platform)
    if actual != sha256(report) or meta.get('entries', {}).get('registration_followup', {}).get('sha256') != actual:
        raise ValueError('registration report changed since sealing')
    read_rows(report, platform)
    meta['registration_unit_base'] = base_signature
    manifest.write_text(json.dumps(meta, sort_keys=True, indent=2) + '\n', encoding='utf-8')


def emit(key, value):
    line = f'{key}={str(value).lower() if isinstance(value, bool) else value}\n'
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as f:
            f.write(line)
    else:
        sys.stdout.write(line)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('command', choices=('prepare', 'merge', 'stamp'))
    p.add_argument('--platform', choices=('xp', 'win7'), required=True)
    p.add_argument('--release-id', required=True)
    p.add_argument('--asset-id', required=True)
    p.add_argument('--root', type=Path, default=Path('.'))
    p.add_argument('--cache-dir', type=Path, default=Path('work/cache'))
    p.add_argument('--reports-dir', type=Path, default=Path('work/reports'))
    p.add_argument('--plan', type=Path, default=Path('work/exporters-plan.json'))
    p.add_argument('--seed', type=Path, default=Path('work/rva/seed.json'))
    p.add_argument('--selection', type=Path, default=Path('work/rva/selection.json'))
    a = p.parse_args()
    base = unit_signature(a.platform, a.release_id, a.asset_id, a.root)
    if a.command == 'prepare':
        result = prepare(a.platform, base, a.cache_dir, a.reports_dir,
                         a.plan, a.seed, a.selection, a.root)
        for key, value in result.items():
            emit(key, value)
    elif a.command == 'merge':
        count = merge(a.platform, a.seed,
                      a.reports_dir / report_name(a.platform, 'registration_followup'),
                      a.reports_dir / report_name(a.platform, 'registration_followup'), a.root)
        print(f'merged {count} newly analyzed RVAs')
    else:
        stamp(a.platform, base, a.cache_dir, a.reports_dir)


if __name__ == '__main__':
    main()
