#!/usr/bin/env python3
"""Audit static registration lifecycle parity in XP and Win7 368.81.

Static xrefs and semantic similarity do not prove GP106 runtime dispatch.
"""
import argparse
import json
import re
from pathlib import Path

SLOT = re.compile(r'\(param_1\s*\+\s*0x4c8\)\s*=\s*FUN_([0-9a-fA-F]+)')
PROC = re.compile(r'RtlInitUnicodeString\s*\([^,]+,\s*L"([^"]+)"\)')


def classify_helper(row):
    code = (row or {}).get('decompilation') or ''
    if 'RtlGetVersion(' in code and '0x11c' in code:
        return 'os_version'
    found = PROC.findall(code)
    if len(found) == 1 and 'MmGetSystemRoutineAddress(' in code:
        return 'resolve:' + found[0]
    if re.search(r'DAT_[0-9a-fA-F]+\s*=\s*param_1\s*;', code) and len(re.findall(r'DAT_[0-9a-fA-F]+\s*=\s*0\s*;', code)) == 3:
        return 'global_state_init'
    return None


def audit(manifest, xp, win7):
    targets = {
        side: {t['entry'].lower(): t for t in report.get('targets', [])}
        for side, report in [('xp', xp), ('win7', win7)]
    }
    installers = {'xp': '00108fd0', 'win7': '002369c8'}
    callbacks = {'xp': '000555d0', 'win7': '001a9ed0'}
    registration = {}
    for side, entry in installers.items():
        code = (targets[side].get(entry) or {}).get('decompilation') or ''
        assigned = SLOT.findall(code)
        registration[side] = {
            'installer': entry,
            'callback': callbacks[side],
            'slot': '0x4c8',
            'slot_assignment_confirmed': len(assigned) == 1 and assigned[0].lower().zfill(8) == callbacks[side],
            'decompilation_available': bool(code),
        }
    xp_callback = (targets['xp'].get('000555d0') or {}).get('decompilation') or ''
    registration['xp']['callback_invokes_registration_dispatcher'] = bool(
        re.search(r'\bFUN_000554a0\s*\(', xp_callback)
    )
    keys = {
        'xp': manifest['platforms']['xp'].get('post_registration_calls', []),
        'win7': manifest['platforms']['win7'].get('dispatcher_other_calls', []),
    }
    classified = {}
    for side, entries in keys.items():
        classified[side] = {}
        for entry in entries:
            semantic = classify_helper(targets[side].get(entry.lower()))
            if semantic:
                classified[side].setdefault(semantic, []).append(entry.lower())
    shared = sorted(set(classified['xp']) & set(classified['win7']))
    all_keys = sorted(set(classified['xp']) | set(classified['win7']))
    matches = [
        {'semantic': key, 'xp': classified['xp'].get(key, []),
         'win7': classified['win7'].get(key, []),
         'one_to_one': len(classified['xp'].get(key, [])) == 1 and len(classified['win7'].get(key, [])) == 1}
        for key in all_keys
    ]
    return {
        'schema_version': 1,
        'callback_registration': registration,
        'callback_slot_parity_confirmed': all(r['slot_assignment_confirmed'] for r in registration.values()),
        'post_registration': {
            'xp_count': len(keys['xp']),
            'win7_count': len(keys['win7']),
            'shared_semantics': shared,
            'semantic_pairs': matches,
            'semantic_parity_confirmed': len(shared) == 7
                and len(keys['xp']) == len(keys['win7']) == 7
                and all(r['one_to_one'] for r in matches),
        },
        'runtime_gp106_selection_proven': False,
        'patch_candidate': False,
        'caveat': 'Static callback/OS-helper similarity does not prove timing or branch equivalence, FECS/GPCCS/GR ownership, or GP106 runtime selection.',
    }


def main():
    parser = argparse.ArgumentParser()
    for name in ('manifest', 'xp', 'win7', 'out'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    manifest, xp, win7 = (
        json.loads(Path(getattr(args, name)).read_text())
        for name in ('manifest', 'xp', 'win7')
    )
    report = audit(manifest, xp, win7)
    Path(args.out).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({
        'callback_slot_parity': report['callback_slot_parity_confirmed'],
        'post_registration_semantic_parity': report['post_registration']['semantic_parity_confirmed'],
    }))


if __name__ == '__main__':
    main()
