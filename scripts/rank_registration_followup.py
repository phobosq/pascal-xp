#!/usr/bin/env python3
"""Rank unresolved registration followups using positive semantic evidence."""
import argparse,json
from pathlib import Path
def rank(manifest,helper_report):
    helpers={r.get('entry'):r for r in helper_report.get('callers',[])}
    targets=[]
    for p in manifest['predictions']:
        dst='win7' if p['observed_platform']=='xp' else 'xp'
        targets.append({'priority':1,'platform':dst,'entry':p['predicted_other_wrapper'],
                        'kind':'counterpart_registration_wrapper',
                        'question':'Does decompilation confirm same index and descriptor pointer?',
                        'evidence':'dispatcher CALL target present; semantics unverified'})
    for platform,entry in [('xp','000555d0'),('win7','002369c8')]:
        targets.append({'priority':2,'platform':platform,'entry':entry,'kind':'registration_upstream',
                        'question':'Does caller perform equivalent OS or GR initialization?',
                        'evidence':'static reference, not runtime selection proof'})
    for entry in manifest['platforms']['win7']['dispatcher_other_calls']:
        code=(helpers.get(entry) or {}).get('decompilation') or ''
        if entry=='001bd760' and 'RtlGetVersion' in code and '0x11c' in code:
            kind='os_version_probe';priority=4
            question='Find homologous XP OS-version initialization elsewhere.'
            evidence='RtlGetVersion and 0x11c version buffer; not FECS-specific'
        else:
            kind='unclassified_epilogue_helper';priority=3
            question='Identify side effects and OS/GR relevance.'
            evidence='unconditional post-registration call'
        targets.append({'priority':priority,'platform':'win7','entry':entry,'kind':kind,
                        'question':question,'evidence':evidence})
    targets.sort(key=lambda x:(x['priority'],x['platform'],x['entry']))
    return {'schema_version':1,'ranked_targets':targets,
            'known_non_fecs_epilogue':[x['entry'] for x in targets if x['kind']=='os_version_probe'],
            'gp106_runtime_selection_proven':False,'patch_candidate':False,
            'caveat':'OS-version helper is not FECS divergence. Remaining helpers require decompilation.'}
def main():
    p=argparse.ArgumentParser()
    for n in ('manifest','helper-report','out'):p.add_argument('--'+n,required=True)
    a=p.parse_args()
    r=rank(json.loads(Path(a.manifest).read_text()),json.loads(Path(a.helper_report).read_text()))
    Path(a.out).write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({'targets':len(r['ranked_targets']),'non_fecs':r['known_non_fecs_epilogue']}))
if __name__=='__main__':main()
