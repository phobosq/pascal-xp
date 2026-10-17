#!/usr/bin/env python3
"""Compare FECS-adjacent descriptor reference-cell relative offsets; static evidence only."""
import argparse,json
from collections import defaultdict
from pathlib import Path

def signature_groups(report):
    rows=defaultdict(lambda:{'owners':set(),'site_deltas':set()})
    for site in report.get('descriptor_sites',[]):
        s=int(site['site'],16)
        for c in site.get('nearby_referenced_cells',[]):
            key=c['address']
            for r in c.get('references',[]):
                if r.get('function_owner'):
                    rows[key]['owners'].add(r['function_owner'])
                    rows[key]['site_deltas'].add(s-int(key,16))
    return [{'header':k,'owners':sorted(v['owners']),'offset_signature':sorted(v['site_deltas'])}
            for k,v in sorted(rows.items())]
def compare(xp,win7):
    x=signature_groups(xp);w=signature_groups(win7)
    x_by={tuple(a['offset_signature']) for a in x}
    w_by={tuple(a['offset_signature']) for a in w}
    return {'schema_version':1,'xp_cells':x,'win7_cells':w,
            'shared_offset_signatures':[list(z) for z in sorted(x_by&w_by)],
            'xp_only_offset_signatures':[list(z) for z in sorted(x_by-w_by)],
            'win7_only_offset_signatures':[list(z) for z in sorted(w_by-x_by)],
            'caveat':'Header cells may overlap multiple ±0x200 site windows. Owner counts are not class counts.'}
def main():
    p=argparse.ArgumentParser();p.add_argument('--xp',required=True);p.add_argument('--win7',required=True);p.add_argument('--out',required=True)
    a=p.parse_args();r=compare(json.loads(Path(a.xp).read_text()),json.loads(Path(a.win7).read_text()))
    Path(a.out).write_text(json.dumps(r,indent=2)+'\n')
    print({k:len(r[k]) for k in ['shared_offset_signatures','xp_only_offset_signatures','win7_only_offset_signatures']})
if __name__=='__main__':main()
