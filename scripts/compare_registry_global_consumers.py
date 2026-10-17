#!/usr/bin/env python3
"""Rank static class-registry-global users by dispatch evidence, not xref count.

Not evidence of GP106 runtime selection. Debug/assert routines are demoted.
"""
import argparse
import json
import re
from pathlib import Path

VIRTUAL_INDEX = re.compile(r'\+\s*(?:0x190|400)\b', re.I)
CLASS_QUERY = re.compile(r'\b0xe803b6\b', re.I)
GET_SLOT = re.compile(r'\+\s*0x70\b', re.I)
METHOD_90 = re.compile(r'\+\s*0x90\b', re.I)
ERROR_ONLY = re.compile(r'Nvidia Release (?:RM_ASSERT|Debug Break)|DbgPrintEx\s*\(',re.I)
OTHER_VTABLE = re.compile(r'\+\s*(?:0x188|0x1a8)\b', re.I)
DEVICE_ID = re.compile(r'\b(?:0x1c[0-9a-f]{2}|0x1b[0-9a-f]{2})\b',re.I)

def score_row(row, registration_entry):
    code=row.get('decompilation') or ''
    if not code:
        return {'score':0,'kind':'undecompiled','positive_evidence':[]}
    signs=[]
    if CLASS_QUERY.search(code):
        signs.append(('class_registration_resource_query',8))
    if VIRTUAL_INDEX.search(code):
        signs.append(('class_lookup_virtual_method',5))
    if METHOD_90.search(code):
        signs.append(('class_query_virtual_method',3))
    if GET_SLOT.search(code):
        signs.append(('registered_slot_pointer_access',2))
    if OTHER_VTABLE.search(code):
        signs.append(('other_vtable_dispatch',1))
    if DEVICE_ID.search(code):
        signs.append(('potential_pci_device_value_unverified',1))
    if ERROR_ONLY.search(code):
        signs.append(('generic_rm_debug_assert_only',-10))
    score=sum(weight for _,weight in signs)
    kind='possible_lookup_or_dispatch' if score>3 else 'other_global_user'
    if row.get('entry')==registration_entry:kind='known_registry_registration'
    if ERROR_ONLY.search(code) and score<3:kind='generic_rm_debug_assert'
    return {'score':score,'kind':kind,'positive_evidence':[name for name,n in signs if n>0],
            'demoted_as_generic_debug':bool(ERROR_ONLY.search(code))}

def summarize(report):
    reg=report.get('registration_function')
    scored=[]
    for row in report.get('bounded_decompiled_owners',[]):
        scored.append({'entry':row['entry'],'status':row.get('status'),
            'reference_count':len(row.get('references',[])),
            **score_row(row,reg)})
    scored.sort(key=lambda item:(-item['score'],-item['reference_count'],item['entry']))
    return {'registration_function':reg,
            'global_address':report.get('registry_global'),
            'total_reference_owners':report.get('reference_owner_count',0),
            'decompiled_count':sum(x.get('status')=='ok' for x in scored),
            'positive_candidates':[r for r in scored if r['score']>=4][:12],
            'generic_debug_demoted':[r['entry'] for r in scored if r.get('kind')=='generic_rm_debug_assert'],
            'unclassified_xrefs':[r['entry'] for r in scored if r.get('kind')=='undecompiled'][:16],
            'all_scored':scored}

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
