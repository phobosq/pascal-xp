#!/usr/bin/env python3
"""Verify focused registration counterparts; static index/pointer matches are not runtime GPU selection."""
import argparse,json,re
from pathlib import Path
REG=re.compile(r'\bFUN_[0-9a-fA-F]+\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*&PTR_([A-Za-z0-9_]+)\s*\)',re.I)
ADDRESS_SUFFIX=re.compile(r'([0-9a-fA-F]{8,16})$')
def fields(row):
    if row is None or row.get('status')!='ok':
        return {'status':row.get('status') if row else 'not_exported'}
    matches=REG.findall(row.get('decompilation') or '')
    if len(matches)!=1:return {'status':'not_unique_registration','registration_calls':len(matches)}
    idx,ptr=matches[0];m=ADDRESS_SUFFIX.search(ptr)
    return {'status':'registration','index':int(idx,0),'pointer_symbol':ptr,
            'pointer_address':m.group(1).lower().zfill(8) if m else None}
def compare(manifest,xp,win7):
    lookup={p:{r['entry'].lower():r for r in d.get('targets',[])} for p,d in [('xp',xp),('win7',win7)]}
    rows=[]
    for pred in manifest['predictions']:
        src=pred['observed_platform'];dst='win7' if src=='xp' else 'xp'
        entry=pred['predicted_other_wrapper'].lower()
        got=fields(lookup[dst].get(entry));idx=int(pred['observed_index'],16)
        header=pred.get('predicted_other_header','').lower().zfill(8)
        im=got.get('index')==idx if got['status']=='registration' else None
        hm=got.get('pointer_address')==header if got.get('pointer_address') and header else None
        rows.append({'observed_platform':src,'observed_wrapper':pred['observed_wrapper'],
                     'counterpart_platform':dst,'counterpart':entry,'expected_index':idx,
                     'expected_header':header,'counterpart_fields':got,'index_matches':im,
                     'header_pointer_matches':hm,'descriptor_identity_proven':False})
    helpers=[]
    for entry in manifest['platforms']['win7']['dispatcher_other_calls']:
        row=lookup['win7'].get(entry.lower())
        helpers.append({'entry':entry,'status':row.get('status') if row else 'not_exported',
                        'size':row.get('size') if row else None,
                        'decompilation_available':bool(row and row.get('decompilation')),
                        'outgoing_calls':sum('CALL' in r.get('type','').upper() for r in (row or {}).get('outgoing',[]))})
    return {'schema_version':2,'counterparts':rows,'total_counterparts':len(rows),
            'matched_indices':sum(r['index_matches'] is True for r in rows),
            'matched_header_pointers':sum(r['header_pointer_matches'] is True for r in rows),
            'unresolved_counterparts':[r['counterpart'] for r in rows if r['index_matches'] is not True or r['header_pointer_matches'] is not True],
            'win7_epilogue_helpers':helpers,'runtime_gp106_selection_proven':False,'patch_candidate':False,
            'caveat':'Matching indices/header pointers is static evidence, not descriptor identity or GP106 runtime selection.'}
def main():
    p=argparse.ArgumentParser()
    for n in ('manifest','xp','win7','out'):p.add_argument('--'+n,required=True)
    a=p.parse_args()
    r=compare(*[json.loads(Path(getattr(a,n)).read_text()) for n in ('manifest','xp','win7')])
    Path(a.out).write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({'indices':r['matched_indices'],'headers':r['matched_header_pointers'],
                      'total':r['total_counterparts'],'unresolved':len(r['unresolved_counterparts'])}))
if __name__=='__main__':main()
