#!/usr/bin/env python3
"""Rank static class-registry-global users by dispatch evidence, not xref count.

Not evidence of GP106 runtime selection. Debug/assert routines are demoted.
"""
import argparse
import json
import re
from pathlib import Path

# Only a virtual CALL rooted in the registry global is evidence of its
# dispatch. A textual "+ 400" may be a plain struct field or stack offset.
CLASS_QUERY = re.compile(r'\b0xe803b6\b', re.I)
ERROR_ONLY = re.compile(r'Nvidia Release (?:RM_ASSERT|Debug Break)|DbgPrintEx\s*\(',re.I)
DEVICE_ID = re.compile(r'\b(?:0x1c[0-9a-f]{2}|0x1b[0-9a-f]{2})\b',re.I)

def direct_registry_call(code, registry_global, offset):
    if not registry_global:
        return False
    # Ghidra decompiler emits (**(code **)(DAT_xxxx + offset))(...)
    pattern=(r'\(\*\*\s*\(code\s*\*\*\)\s*\(\s*DAT_'
             +re.escape(registry_global)
             +r'\s*\+\s*'+offset+r'\s*\)\s*\)')
    return bool(re.search(pattern,code,re.I))

def indirect_registration_call(code, offset):
    # Registration stores the root in lVar2 and reuses it after the
    # +0x90 query. This alias is ONLY trusted for the known entry point.
    pattern=(r'\(\*\*\s*\(code\s*\*\*\)\s*\(\s*lVar2'
             +r'\s*\+\s*'+offset+r'\s*\)\s*\)')
    return bool(re.search(pattern,code,re.I))

def score_row(row, registration_entry, registry_global=None):
    code=row.get('decompilation') or ''
    if not code:
        return {'score':0,'kind':'undecompiled','positive_evidence':[]}
    signs=[]
    is_registration=row.get('entry')==registration_entry
    root_query=direct_registry_call(code,registry_global,r'0x90')
    # Do not treat the class resource constant alone as a registry call.
    if root_query and CLASS_QUERY.search(code):
        signs.append(('class_registration_resource_query',8))
    if root_query:
        signs.append(('class_query_virtual_method',3))
    lookup=(direct_registry_call(code,registry_global,r'(?:0x190|400)')
            or (is_registration and root_query
                and indirect_registration_call(code,r'(?:0x190|400)')))
    if lookup:
        signs.append(('class_lookup_virtual_method',5))
    slot=(direct_registry_call(code,registry_global,r'0x70')
          or (is_registration and root_query
              and indirect_registration_call(code,r'0x70')))
    if slot:
        signs.append(('registered_slot_pointer_access',2))
    # PCI-like constants elsewhere in a large decompilation are not evidence.
    if lookup and DEVICE_ID.search(code):
        signs.append(('potential_pci_device_value_unverified',1))
    if ERROR_ONLY.search(code):
        signs.append(('generic_rm_debug_assert_only',-10))
    score=sum(weight for _,weight in signs)
    kind='possible_lookup_or_dispatch' if score>=4 else 'other_global_user'
    if is_registration:kind='known_registry_registration'
    if ERROR_ONLY.search(code) and score<3:kind='generic_rm_debug_assert'
    return {'score':score,'kind':kind,
            'positive_evidence':[name for name,n in signs if n>0],
            'demoted_as_generic_debug':bool(ERROR_ONLY.search(code))}

def summarize(report):
    reg=report.get('registration_function')
    scored=[]
    for row in report.get('bounded_decompiled_owners',[]):
        scored.append({'entry':row['entry'],'status':row.get('status'),
            'reference_count':len(row.get('references',[])),
            **score_row(row,reg,report.get('registry_global'))})
    scored.sort(key=lambda item:(-item['score'],-item['reference_count'],item['entry']))
    return {'registration_function':reg,
            'global_address':report.get('registry_global'),
            'total_reference_owners':report.get('reference_owner_count',0),
            'decompiled_count':sum(x.get('status')=='ok' for x in scored),
            'positive_candidates':[r for r in scored if r['score']>=4][:12],
            'generic_debug_demoted':[r['entry'] for r in scored if r.get('kind')=='generic_rm_debug_assert'],
            'unclassified_xrefs':[r['entry'] for r in scored if r.get('kind')=='undecompiled'][:16],
            'all_scored':scored}

def new_lookup_candidates(side_report):
    """Exclude the known registry registration entry from new lookup hypotheses."""
    registry_entry = str(side_report.get('registration_function') or '').lower()
    return [row for row in side_report.get('positive_candidates', [])
            if row.get('kind') != 'known_registry_registration'
            and str(row.get('entry') or '').lower() != registry_entry]


def compare(xp,win7):
    return {'schema_version':1,'xp':summarize(xp),'win7':summarize(win7),
       'runtime_gp106_selection_proven':False,'patch_candidate':False,
       'caveat':'Heuristic static evidence only. A class resource ID or NVIDIA debug helper is not PCI GP106 execution; validate actual branches and status.'}

def main():
    parser=argparse.ArgumentParser()
    for n in ('xp','win7','out'):parser.add_argument('--'+n,required=True)
    args=parser.parse_args()
    result=compare(json.loads(Path(args.xp).read_text()),
                   json.loads(Path(args.win7).read_text()))
    Path(args.out).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({side:{'decompiled':result[side]['decompiled_count'],
                            'positive':len(result[side]['positive_candidates']),
                            'debug_demoted':len(result[side]['generic_debug_demoted'])}
                      for side in ('xp','win7')}))

if __name__=='__main__':
    main()
