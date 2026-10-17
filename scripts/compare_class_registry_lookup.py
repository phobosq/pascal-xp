#!/usr/bin/env python3
"""Rank bounded registry xrefs by provenance; static evidence is not GPU runtime dispatch."""
import argparse
import json
from pathlib import Path


def compact(report):
    reg = report.get('registration_function') or {}
    analysis = reg.get('analysis') or {}
    globals_seen = report.get('candidate_global_references', [])
    anchored = {row['address'].lower() for row in globals_seen
                if any(p.get('entry') == 'registry'
                       for p in row.get('producers', []))}
    helper_only = {row['address'].lower() for row in globals_seen
                   if row['address'].lower() not in anchored}
    # If old exports lack provenance, do not silently discard them.
    has_provenance = bool(globals_seen) and any(
        'producers' in row for row in globals_seen)
    ranked = []
    excluded = []
    for row in report.get('ranked_lookup_candidates', []):
        sites = len(set(row.get('xref_sites') or []))
        if not sites:
            continue
        addresses = {a.lower() for a in row.get('state_addresses', [])}
        rooted = sorted(addresses & anchored)
        other = sorted(addresses & helper_only)
        result = {
            'entry': row['entry'],
            'linked_registry_globals': rooted,
            'linked_helper_globals': other,
            'linked_state_variables': len(rooted) if has_provenance else len(addresses),
            'xref_sites': sites,
            'decompiled': row.get('status') == 'ok',
            'evidence_kind': 'registry_root_read_or_data_xref_only'
                             if rooted else 'callee_global_xref_only',
            'runtime_selected': False,
        }
        if has_provenance and not rooted:
            excluded.append(result)
        else:
            ranked.append(result)
    ranked.sort(key=lambda row: (-row['linked_state_variables'],
                                -row['xref_sites'], row['entry']))
    excluded.sort(key=lambda row: (-row['xref_sites'], row['entry']))
    incoming = reg.get('incoming') or []
    return {
        'registration_entry': report.get('registration_entry'),
        'registry_decompilation_status': analysis.get('status'),
        'registration_incoming_xrefs': len(incoming),
        'registration_call_xrefs': sum(
            'CALL' in str(row.get('type', '')).upper() for row in incoming),
        'bounded_child_count': len(report.get('direct_callees', [])),
        'candidate_global_count': len(globals_seen),
        'registry_root_global_addresses': sorted(anchored),
        'helper_only_global_addresses': sorted(helper_only),
        'candidate_consumer_count': len(ranked),
        'excluded_helper_only_consumer_count': len(excluded),
        'top_consumers': ranked[:12],
        'excluded_helper_only_consumers': excluded[:12],
        'provenance_available': has_provenance,
    }


def compare(xp, win7):
    return {
        'schema_version': 2, 'xp': compact(xp), 'win7': compact(win7),
        'runtime_gp106_selection_proven': False, 'patch_candidate': False,
        'caveat': ('Provenance separates globals accessed directly by the registration '
                   'function from unrelated globals referenced by its callees. '
                   'Static reads still do not prove GP106 runtime class selection.'),
    }


def main():
    p = argparse.ArgumentParser()
    for name in ('xp', 'win7', 'out'):
        p.add_argument('--' + name, required=True)
    args = p.parse_args()
    result = compare(json.loads(Path(args.xp).read_text()),
                     json.loads(Path(args.win7).read_text()))
    Path(args.out).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({side: {
        'registry_root_candidates': result[side]['candidate_consumer_count'],
        'helper_only_excluded': result[side]['excluded_helper_only_consumer_count']
    } for side in ('xp', 'win7')}))


if __name__ == '__main__':
    main()
