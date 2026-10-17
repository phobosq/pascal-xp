#!/usr/bin/env python3
"""Compare sampled descriptor registration wrappers by explicit index, not shape."""
import argparse
import json
import re
from pathlib import Path

REG = re.compile(r'\bFUN_[0-9a-fA-F]+\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*&(PTR_[A-Za-z0-9_]+)\s*\)\s*;', re.I)

def classify(owner):
    code = owner.get('decompilation') or ''
    calls = [r for r in owner.get('outgoing', []) if 'CALL' in r.get('type','')]
    if owner.get('size', 0) > 32 or len(calls) != 1 or not owner.get('headers'):
        return None
    m = REG.search(code)
    if not m:
        return None
    body = code.split('{',1)[-1]
    if re.search(r'\b(if|switch|for|while)\s*\(',body):
        return None
    return {'entry':owner['entry'], 'registration_index':int(m.group(1),0),
            'pointer_symbol':m.group(2),
            'header_addresses':[h['address'] for h in owner['headers']],
            'matched_descriptor_sites':sorted({s for h in owner['headers'] for s in h.get('matched_descriptor_sites',[])}),
            'caller_entries':sorted({c['entry'] for c in owner.get('callers',[])})}

def dispatcher_summary(wrappers):
    counts={}
    for r in wrappers:
        for caller in r['caller_entries']:
            counts[caller]=counts.get(caller,0)+1
    return [{'entry':entry,'sampled_wrapper_calls':count} for entry,count in sorted(counts.items(),key=lambda t:(-t[1],t[0]))]

def compare(xp,w7):
    xr=[c for o in xp.get('owners',[]) if (c:=classify(o))]
    wr=[c for o in w7.get('owners',[]) if (c:=classify(o))]
    xi={r['registration_index']:r for r in xr}
    wi={r['registration_index']:r for r in wr}
    shared=sorted(xi.keys() & wi.keys())
    matched=[{'registration_index':i,'xp':xi[i],'win7':wi[i],
              'evidence':'same static registration index; class identity unverified'} for i in shared]
    excluded_xp=[o['entry'] for o in xp.get('owners',[]) if not classify(o)]
    excluded_w7=[o['entry'] for o in w7.get('owners',[]) if not classify(o)]
    return {'schema_version':2,'xp_owner_count':len(xp.get('owners',[])),
            'win7_owner_count':len(w7.get('owners',[])),
            'xp_registration_wrapper_count':len(xr),'win7_registration_wrapper_count':len(wr),
            'shared_registration_indices':shared,'matched_registration_wrappers':matched,
            'xp_only_registration_wrappers':[xi[i] for i in sorted(xi.keys()-wi.keys())],
            'win7_only_registration_wrappers':[wi[i] for i in sorted(wi.keys()-xi.keys())],
            'excluded_nonwrappers':{'xp':excluded_xp,'win7':excluded_w7},
            'registration_dispatchers':{'xp':dispatcher_summary(xr),'win7':dispatcher_summary(wr)},
            'ranked_unmatched_win7_headers':[],
            'gp106_runtime_selection_proven':False,'patch_candidate':False,
            'caveat':'FECS-descriptor sampling is incomplete; index differences do not prove missing GPU classes or GP106 runtime selection.'}

def main():
    p=argparse.ArgumentParser()
    for n in ('xp','win7','out'):p.add_argument('--'+n,required=True)
    a=p.parse_args()
    result=compare(json.loads(Path(a.xp).read_text()),json.loads(Path(a.win7).read_text()))
    Path(a.out).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('xp_registration_wrapper_count','win7_registration_wrapper_count','shared_registration_indices')}))
if __name__=='__main__':main()
