#!/usr/bin/env python3
"""Rank XP/Win7 callback initializer analogues using callback function shapes.

All matches are structural hypotheses; not proof of FECS ownership or GP106 reachability.
"""
import argparse
import json
import re
from pathlib import Path

SLOTS = (0x190, 0x1c8, 0x1d8, 0x1e8, 0x1f8)
ASSIGN = re.compile(
    r"\*\((?:code|undefined[1248])\s*\*\*\)\(param_\d+\s*\+\s*(0x[0-9a-fA-F]+|\d+)\)"
    r"\s*=\s*(FUN_[0-9a-fA-F]+|&LAB_[0-9a-fA-F]+)"
)

def ratio(a, b):
    return 1 - abs(a-b) / max(1, a, b)

def index(report, facts):
    funcs = {f['entry'].lower(): f for f in facts['functions']}
    result = []
    for fn in report.get('selected_functions', []):
        slots = {f'0x{x:x}': [] for x in SLOTS}
        for off, target in ASSIGN.findall(fn.get('decompilation') or ''):
            val = int(off, 0)
            if val in SLOTS:
                addr = target.split('_')[-1].lower()
                fact = funcs.get(addr) if target.startswith('FUN_') else None
                slots[f'0x{val:x}'].append({
                    'target': target,
                    'size': fact.get('size') if fact else None,
                    'calls': len(fact.get('calls', [])) if fact else None,
                })
        if sum(bool(v) for v in slots.values()) >= 4:
            result.append({'entry': fn['entry'], 'size': fn['size'], 'slots': slots})
    return result

def pair(a, b):
    callback_pairs = []
    for slot in a['slots']:
        left = a['slots'][slot]
        right = b['slots'][slot]
        if len(left) != 1 or len(right) != 1:
            continue
        x, y = left[0], right[0]
        if x['size'] is None or y['size'] is None:
            continue
        callback_pairs.append({
            'slot': slot, 'xp_target': x['target'], 'win7_target': y['target'],
            'xp_size': x['size'], 'win7_size': y['size'],
            'size_similarity': round(ratio(x['size'], y['size']), 5),
            'call_similarity': round(ratio(x['calls'], y['calls']), 5),
        })
    if len(callback_pairs) < 3:
        return None
    avg_size = sum(x['size_similarity'] for x in callback_pairs)/len(callback_pairs)
    avg_calls = sum(x['call_similarity'] for x in callback_pairs)/len(callback_pairs)
    # A match on 3 slots cannot outrank an otherwise identical match on 5.
    score = (0.2*ratio(a['size'], b['size']) + 0.55*avg_size
             + 0.15*avg_calls + 0.10*len(callback_pairs)/len(SLOTS))
    return {'xp_entry': a['entry'], 'win7_entry': b['entry'],
            'shape_similarity': round(score, 6),
            'callback_pairs': callback_pairs,
            'comparable_slots': len(callback_pairs),
            'xp_initializer_size': a['size'], 'win7_initializer_size': b['size']}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('xp_assignments', type=Path)
    ap.add_argument('win7_assignments', type=Path)
    ap.add_argument('xp_facts', type=Path)
    ap.add_argument('win7_facts', type=Path)
    ap.add_argument('--out', required=True, type=Path)
    args=ap.parse_args()
    xp=index(json.loads(args.xp_assignments.read_text()), json.loads(args.xp_facts.read_text()))
    win7=index(json.loads(args.win7_assignments.read_text()), json.loads(args.win7_facts.read_text()))
    ranked=sorted((p for x in xp for y in win7 if (p:=pair(x,y)) is not None),
                  key=lambda p:(-p['shape_similarity'],p['xp_entry'],p['win7_entry']))
    used_xp=set(); used_win7=set(); matched=[]
    for p in ranked:
        if p['xp_entry'] in used_xp or p['win7_entry'] in used_win7:
            continue
        matched.append(p)
        used_xp.add(p['xp_entry']);used_win7.add(p['win7_entry'])
    output={'schema_version':1,
            'caveat':'Callback function-size and direct-call-count similarities are structural hints only; no FECS/GR ownership, GP106 path, or ABI equivalence is established.',
            'xp_candidates':len(xp),'win7_candidates':len(win7),
            'ranked_pairs':matched}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(output,indent=2)+'\n')
    print('ranked pairs',len(matched))

if __name__=='__main__':main()
