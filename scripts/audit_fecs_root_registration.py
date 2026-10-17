#!/usr/bin/env python3
"""Join sampled class-registration descriptors to table initializers.

The join is geometric, and registration indexes are NOT GPU PCI device IDs.
Unknown table roots are candidates, not automatically FECS-specific.
"""
import argparse
import json
import re
from pathlib import Path

REG = re.compile(r'\bFUN_[0-9a-fA-F]+\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*&(PTR|LAB)_[A-Za-z0-9_]+\s*\)\s*;', re.I)
XP_ROOT = re.compile(r'\bmemcpy\s*\(\s*param_2\s*,\s*&PTR_[A-Za-z0-9_]*?_([0-9a-fA-F]{8,16})\s*,', re.I)
WIN7_ROOT = re.compile(r'\*\s*param_2\s*=\s*PTR_[A-Za-z0-9_]*?_([0-9a-fA-F]{8,16})\s*;', re.I)
MAX_BLOCK = 0x290

def candidate_headers(chains):
    headers = []
    for owner in chains.get('owners', []):
        code = owner.get('decompilation') or ''
        if (owner.get('size') or 0) > 32:
            continue
        match = REG.search(code)
        if not match:
            continue
        for header in owner.get('headers', []):
            headers.append({'index': int(match.group(1), 0),
                            'header': int(header['address'], 16),
                            'wrapper': owner['entry'].lower()})
    return headers

def table_base(owner):
    code = owner.get('decompilation') or ''
    # Both pre-populated tables copied by XP and pointer writes in Win7 count.
    found = [(m.group(1), 'memcpy') for m in XP_ROOT.finditer(code)]
    found += [(m.group(1), 'explicit_ptr_writes') for m in WIN7_ROOT.finditer(code)]
    if len(found) != 1:
        return None, None
    return found[0][0].lower().zfill(8), found[0][1]

def audit(chains, roots):
    headers = candidate_headers(chains)
    known = {r['root'].lower().zfill(8): r.get('role') for r in roots.get('roots', [])}
    links, unresolved = [], []
    for owner in roots.get('owners', []):
        base, method = table_base(owner)
        refs = [r for r in owner.get('references', [])
                if r.get('type') == 'DATA' and r.get('section') == '.rdata']
        for ref in refs:
            site = int(ref['from'], 16)
            options = sorted((h for h in headers
                              if 0 <= site - h['header'] < MAX_BLOCK),
                             key=lambda h: (site - h['header'], h['index']))
            row = {'initializer': owner['entry'].lower(),
                   'source_site': ref['from'].lower(),
                   'table_base': base, 'initializer_method': method,
                   'in_previous_five_roots': bool(base and base in known),
                   'previously_assigned_root_role': known.get(base),
                   'runtime_selected': False}
            if not options:
                row['reason'] = 'no_sampled_registration_header_near_source'
                unresolved.append(row)
                continue
            h = options[0]
            row.update({'registration_index': h['index'],
                        'registration_wrapper': h['wrapper'],
                        'descriptor_header': '%08x' % h['header'],
                        'header_to_site_delta': site - h['header'],
                        'join_method': 'closest_preceding_sampled_header_under_0x290'})
            links.append(row)
    by_index = {}
    for row in links:
        by_index.setdefault('%02x' % row['registration_index'], []).append({
            'offset': row['header_to_site_delta'], 'table_base': row['table_base'],
            'initializer': row['initializer'],
            'known_root': row['in_previous_five_roots']})
    for index in by_index:
        by_index[index].sort(key=lambda r: r['offset'])
    return {
        'schema_version': 2, 'sampled_header_count': len(headers),
        'initializer_data_links': links,
        'unresolved_initializer_data_links': unresolved,
        'sampled_indices': by_index,
        'distinct_explicit_table_bases': sorted({r['table_base'] for r in links if r['table_base']}),
        'runtime_gp106_selection_proven': False, 'patch_candidate': False,
        'caveat': ('Nearest preceding header is geometric association only, not runtime selection. '
                   'Table bases outside the initial five roots are not assumed FECS. '
                   'XP memcpy and Win7 pointer writes are legitimate initialization.'),
    }

def main():
    p = argparse.ArgumentParser()
    for name in ('owner-chains', 'fecs-roots', 'out'):
        p.add_argument('--'+name, required=True)
    args = p.parse_args()
    result = audit(json.loads(Path(args.owner_chains).read_text()),
                   json.loads(Path(args.fecs_roots).read_text()))
    Path(args.out).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'linked': len(result['initializer_data_links']),
                      'unresolved': len(result['unresolved_initializer_data_links']),
                      'bases': len(result['distinct_explicit_table_bases'])}))

if __name__ == '__main__':
    main()
# dummy comment
