#!/usr/bin/env python3
"""Rank bounded registry lookup candidates; static xrefs are not runtime GP106."""
import argparse
import json
from pathlib import Path

def compact(report):
    reg=report.get('registration_function') or {}
    analysis=reg.get('analysis') or {}
    ranked=[]
    for row in report.get('ranked_lookup_candidates', []):
        sites=len(set(row.get('xref_sites') or []))
        if not sites:continue
        ranked.append({
            'entry':row['entry'],
            'linked_state_variables':len(set(row.get('state_addresses') or [])),
            'xref_sites':sites,
            'decompiled':row.get('status')=='ok',
            'evidence_kind':'read_or_data_xref_only',
            'runtime_selected':False})
    ranked.sort(key=lambda r:(-r['linked_state_variables'],
                              -r['xref_sites'],r['entry']))
    incoming=reg.get('incoming') or []
    return {
        'registration_entry':report.get('registration_entry'),
        'registry_decompilation_status':analysis.get('status'),
        'registration_incoming_xrefs':len(incoming),
        'registration_call_xrefs':sum('CALL' in str(r.get('type','')).upper() for r in incoming),
        'bounded_child_count':len(report.get('direct_callees', [])),
        'candidate_global_count':len(report.get('candidate_global_references', [])),
        'candidate_consumer_count':len(ranked),
        'top_consumers':ranked[:12],
    }

def compare(xp, win7):
    return {'schema_version':1,
            'xp':compact(xp),'win7':compact(win7),
            'runtime_gp106_selection_proven':False,'patch_candidate':False,
            'caveat':('Registry/global-state references are STATIC; '
                       'matching class registration indices do not identify PCI GPUs. '
                       'Trace actual lookup condition and propagated status.')}

def main():
    p=argparse.ArgumentParser()
    for name in ('xp','win7','out'):p.add_argument('--'+name,required=True)
    a=p.parse_args()
    result=compare(json.loads(Path(a.xp).read_text()),
                   json.loads(Path(a.win7).read_text()))
    Path(a.out).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'xp_candidates':result['xp']['candidate_consumer_count'],
                      'win7_candidates':result['win7']['candidate_consumer_count']}))

if __name__=='__main__':
    main()
