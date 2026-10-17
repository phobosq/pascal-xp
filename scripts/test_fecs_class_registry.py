"""Regression tests: static descriptor-table joins and bounded registry xrefs."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from audit_fecs_root_registration import audit,table_base
from compare_class_registry_lookup import compare,compact

class ClassRegistryTests(unittest.TestCase):
    def test_xp_table_memcpy(self):
        self.assertEqual(table_base({'decompilation':'memcpy(param_2,&PTR_FUN_005eeef0,0x90);'}),
                         ('005eeef0','memcpy'))
    def test_win7_pointer_writes(self):
        self.assertEqual(table_base({'decompilation':'*param_2 = PTR_FUN_00ce7470;'}),
                         ('00ce7470','explicit_ptr_writes'))
    def test_ambiguous_bases_remain_unclassified(self):
        self.assertEqual(table_base({'decompilation':'memcpy(param_2,&PTR_FUN_005eeef0,0x90);'
                                     'memcpy(param_2,&PTR_FUN_005eef80,0x90);'}),(None,None))
    def test_static_geometric_join(self):
        owners={'owners':[{'entry':'00234c44','size':17,
             'decompilation':'FUN_0023c050(0x17,&PTR_LAB_00650ed0);',
             'headers':[{'address':'00650ed0'}]}]}
        roots={'roots':[],'owners':[{'entry':'0093ccc0',
            'decompilation':'*param_2 = PTR_FUN_00ce7470;',
            'references':[{'from':'00651048','type':'DATA','section':'.rdata'}]}]}
        out=audit(owners,roots)
        self.assertEqual(len(out['initializer_data_links']),1)
        row=out['initializer_data_links'][0]
        self.assertEqual((row['registration_index'],row['header_to_site_delta']),(0x17,0x178))
        self.assertEqual(row['table_base'],'00ce7470')
        self.assertFalse(row['in_previous_five_roots'])
        self.assertFalse(out['runtime_gp106_selection_proven'])
        self.assertFalse(out['patch_candidate'])
    def test_missing_header_unresolved_not_absent(self):
        out=audit({'owners':[]},{'roots':[],'owners':[{'entry':'1',
            'decompilation':'*param_2 = PTR_FUN_00ce7470;',
            'references':[{'from':'00651048','type':'DATA','section':'.rdata'}]}]})
        self.assertEqual(len(out['unresolved_initializer_data_links']),1)
        self.assertFalse(out['patch_candidate'])
    def test_registry_xrefs_deduplicated_and_limited(self):
        r={'registration_entry':'00117db0',
           'registration_function':{'analysis':{'status':'ok'},
              'incoming':[{'type':'UNCONDITIONAL_CALL'},{'type':'DATA'}]},
           'candidate_global_references':[{'address':'00900120'}],
           'ranked_lookup_candidates':[{'entry':'00001111',
               'xref_sites':['abc','def','abc'],'state_addresses':['a','b'],
               'status':'ok'},
             {'entry':'00002222','xref_sites':[],'state_addresses':['a'],'status':'ok'}]}
        out=compact(r)
        self.assertEqual((out['candidate_consumer_count'],out['registration_call_xrefs']),(1,1))
        self.assertEqual(out['top_consumers'][0]['xref_sites'],2)
        self.assertEqual(out['top_consumers'][0]['linked_state_variables'],2)
        self.assertFalse(out['top_consumers'][0]['runtime_selected'])
    def test_root_vs_callee_global_provenance(self):
        r={'registration_entry':'00117db0',
           'registration_function':{'incoming':[],'analysis':{'status':'ok'}},
           'candidate_global_references':[
               {'address':'0094b270','producers':[{'entry':'registry'}]},
               {'address':'0094b298','producers':[{'entry':'000715d0'}]}],
           'ranked_lookup_candidates':[
               {'entry':'00054490','xref_sites':['x','y'],
                'state_addresses':['0094b270'],'status':'ok'},
               {'entry':'000716c0','xref_sites':['a','b','c'],
                'state_addresses':['0094b298'],'status':'ok'},
               {'entry':'00072380','xref_sites':['m','n'],
                'state_addresses':['0094b270','0094b298'],'status':'ok'}]}
        out=compact(r)
        self.assertEqual(out['registry_root_global_addresses'],['0094b270'])
        self.assertEqual(out['helper_only_global_addresses'],['0094b298'])
        self.assertEqual(out['candidate_consumer_count'],2)
        self.assertEqual(out['excluded_helper_only_consumer_count'],1)
        self.assertEqual(out['excluded_helper_only_consumers'][0]['entry'],'000716c0')
        self.assertEqual({x['entry'] for x in out['top_consumers']},
                         {'00054490','00072380'})
        self.assertFalse(out['top_consumers'][0]['runtime_selected'])

    def test_callee_only_provenance_never_proves_lookup(self):
        out=compact({'registration_entry':'0023c050',
            'candidate_global_references':[
                {'address':'007da7d4','producers':[{'entry':'00199394'}]}],
            'ranked_lookup_candidates':[{'entry':'00197ae8',
                'xref_sites':['a'],'state_addresses':['007da7d4']} ]})
        self.assertTrue(out['provenance_available'])
        self.assertEqual(out['candidate_consumer_count'],0)
        self.assertEqual(out['excluded_helper_only_consumer_count'],1)

    def test_no_runtime_classification_from_static_xrefs(self):
        out=compare({}, {})
        self.assertFalse(out['runtime_gp106_selection_proven'])
        self.assertFalse(out['patch_candidate'])

if __name__=='__main__':
    unittest.main()
