#!/usr/bin/env python3
"""Rank XP/Win7 descriptor header owner chains; static correspondence is not runtime proof."""
import argparse,json,re
from pathlib import Path
def features(x):
 code=x.get('decompilation') or ''
 incoming=x.get('incoming') or []; out=x.get('outgoing') or []
 cells=[c for h in x.get('headers',[]) for c in h.get('cells',[])]
 return {'size':x.get('size',0),'header_count':len(x.get('headers',[])),
 'incoming_code':sum(bool(r.get('owner')) for r in incoming),
 'incoming_data':sum(not r.get('owner') for r in incoming),
 'outgoing_calls':sum('CALL' in r.get('type','') for r in out),
 'outgoing_data':sum(r.get('type')=='DATA' for r in out),
 'scalar_nonzero':sum(int(c.get('u32','0'),16)!=0 for c in cells),
 'returns_header':bool(re.search(r'\breturn\s+(&|\(.*\*\))',code)),
 'contains_branch':bool(re.search(r'\b(if|switch)\s*\(',code)),
 'caller_count':len(x.get('callers',[]))}
def sim(a,b):
 fields=('size','header_count','incoming_code','incoming_data','outgoing_calls','outgoing_data','scalar_nonzero','caller_count')
 weights=(.15,.10,.10,.10,.15,.10,.10,.10)
 score=sum(w*(1-min(abs(a[k]-b[k])/max(a[k],b[k],1),1)) for k,w in zip(fields,weights))
 return round(score+.05*(a['returns_header']==b['returns_header'])+.05*(a['contains_branch']==b['contains_branch']),5)
def compare(xp,w7):
 out=[]
 for w in w7.get('owners',[]):
  wf=features(w); matches=[]
  for x in xp.get('owners',[]):
   xf=features(x);matches.append({'xp_entry':x['entry'],'score':sim(xf,wf),'xp_features':xf})
  matches.sort(key=lambda m:-m['score'])
  out.append({'win7_entry':w['entry'],'win7_features':wf,'best_xp_matches':matches[:3],
              'incoming_caller_entries':[c['entry'] for c in w.get('callers',[])],
              'header_addresses':[h['address'] for h in w.get('headers',[])],'needs_runtime_validation':True})
 out.sort(key=lambda r:(r['best_xp_matches'][0]['score'] if r['best_xp_matches'] else 0,-r['win7_features']['incoming_code']))
 return {'schema_version':1,'xp_owner_count':len(xp.get('owners',[])),'win7_owner_count':len(w7.get('owners',[])),
 'ranked_unmatched_win7_headers':out,'caveat':'Static ranking only, not patch evidence.'}
def main():
 p=argparse.ArgumentParser()
 for n in ('xp','win7','out'):p.add_argument('--'+n,required=True)
 a=p.parse_args();r=compare(json.loads(Path(a.xp).read_text()),json.loads(Path(a.win7).read_text()))
 Path(a.out).write_text(json.dumps(r,indent=2)+'\n')
 print(json.dumps({'xp':r['xp_owner_count'],'win7':r['win7_owner_count']}))
if __name__=='__main__':main()
