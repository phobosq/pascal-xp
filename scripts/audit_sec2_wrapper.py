#!/usr/bin/env python3
"""Classify Win7 0x4FAB14 wrapper from SEC2 registry-key and callback evidence."""
import argparse,json,re
from pathlib import Path
CALLBACKS={'005a1260':0x708,'005a13c4':0x710,'004fba94':0x718,'004fa748':0x720}
def audit(trace):
 t={x['entry']:x for x in trace.get('targets',[])}
 wrapper=(t.get('004fab14') or {}).get('decompilation') or ''
 settings=(t.get('004fb48c') or {}).get('decompilation') or ''
 present={k:bool(re.search(r'\+\s*0x%x\)\s*=\s*FUN_%s\b'%(off,k),wrapper)) for k,off in CALLBACKS.items()}
 keys=sorted(set(re.findall(r'"(Rm(?:DisableSec2|Sec2)[A-Za-z0-9]*)"',settings,re.I)))
 return {'wrapper':'004fab14','four_callback_writes':present,'sec2_registry_keys':keys,
 'sec2_settings_helper':'004fb48c','sec2_key_count':len(keys),
 'semantic_classification':'SEC2 security processor / firmware control, not demonstrated FECS/GPCCS/GR resource getter' if len(keys)>=3 and all(present.values()) else 'insufficient evidence',
 'runtime_gp106_selection_proven':False,'patch_candidate':False,
 'caveat':'Generic RM assertion/debug helpers do not establish FECS ownership.'}
def main():
 p=argparse.ArgumentParser();p.add_argument('--win7-trace',required=True);p.add_argument('--out',required=True)
 a=p.parse_args();r=audit(json.loads(Path(a.win7_trace).read_text()))
 Path(a.out).write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
if __name__=='__main__':main()
