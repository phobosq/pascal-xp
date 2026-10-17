#!/usr/bin/env python3
"""Rank unresolved registration followups using positive semantic evidence."""
import argparse,json
from pathlib import Path
def rank(manifest,helper_report):
    helpers={r.get('entry'):r for r in helper_report.get('win7_epilogue_helpers',[])}
    targets=[]
    for p in manifest['predictions']:
        dst='win7' if p['observed_platform']=='xp' else 'xp'
        counterpart = next((r for r in helper_report.get('counterparts',[])
                            if r.get('counterpart') == p['predicted_other_wrapper']), {})
        verified = counterpart.get('index_matches') is True and counterpart.get('header_pointer_matches') is True
        targets.append({'priority':6 if verified else 1,'platform':dst,'entry':p['predicted_other_wrapper'],
                        'kind':'static_registration_wrapper_confirmed' if verified else 'counterpart_registration_wrapper',
                        'question':'Trace runtime GPU class selection' if verified else 'Confirm index and descriptor pointer',
                        'evidence':'index/header pointer matched statically; runtime unverified' if verified else 'dispatcher CALL target present; semantics unverified'})
    for platform,entry in [('xp','000555d0'),('win7','002369c8')]:
        targets.append({'priority':2,'platform':platform,'entry':entry,'kind':'registration_upstream',
                        'question':'Does caller perform equivalent OS or GR initialization?',
                        'evidence':'static reference, not runtime selection proof'})
    for entry in manifest['platforms']['win7']['dispatcher_other_calls']:
        h=helpers.get(entry) or {}
        semantic=h.get('semantic_class','unclassified')
        if semantic in ('os_version_probe','processor_group_api_resolver','global_state_init'):
            kind=semantic;priority=5
            question='No GPU follow-up unless later evidence links this OS glue to GP106 selection.'
            evidence='classified by focused decompilation as Windows compatibility/global initialization'
        else:
            kind='unclassified_epilogue_helper';priority=3
            question='Identify side effects and OS/GR relevance.'
            evidence='unconditional post-registration call'
        targets.append({'priority':priority,'platform':'win7','entry':entry,'kind':kind,
                        'question':question,'evidence':evidence})
    targets.sort(key=lambda x:(x['priority'],x['platform'],x['entry']))
    return {'schema_version':1,'ranked_targets':targets,
            'known_non_fecs_epilogue':[x['entry'] for x in targets if x['kind'] in ('os_version_probe','processor_group_api_resolver','global_state_init')],
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
