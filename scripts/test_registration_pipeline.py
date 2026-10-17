"""Self-contained deterministic regression tests for focused registration reports."""
import unittest
from compare_registration_followup import compare,fields
from rank_registration_followup import rank
class TestRegistrationPipeline(unittest.TestCase):
    def setUp(self):
        self.manifest={'predictions':[{'observed_platform':'xp','observed_index':'0x32',
            'observed_wrapper':'000ebcc0','predicted_other_wrapper':'00234dd4',
            'predicted_other_header':'00654210'}],
            'platforms':{'win7':{'dispatcher_other_calls':['001bd760','001bd9ec']}}}
        self.row={'entry':'00234dd4','status':'ok',
            'decompilation':'void FUN_00234dd4(void){FUN_00123456(0x32,&PTR_LAB_00654210);}',
            'outgoing':[]}
    def test_unique_registration(self):
        d=fields(self.row)
        self.assertEqual((d['index'],d['pointer_address']),(0x32,'00654210'))
    def test_index_and_pointer_match(self):
        r=compare(self.manifest,{'targets':[]},{'targets':[self.row]})
        self.assertEqual((r['matched_indices'],r['matched_header_pointers']),(1,1))
        self.assertEqual(r['unresolved_counterparts'],[])
        self.assertFalse(r['patch_candidate'])
    def test_header_mismatch_not_patch(self):
        self.row['decompilation']=self.row['decompilation'].replace('00654210','00654220')
        r=compare(self.manifest,{'targets':[]},{'targets':[self.row]})
        self.assertEqual(r['matched_indices'],1)
        self.assertEqual(r['matched_header_pointers'],0)
        self.assertEqual(r['unresolved_counterparts'],['00234dd4'])
        self.assertFalse(r['runtime_gp106_selection_proven'])
    def test_missing_is_unresolved(self):
        r=compare(self.manifest,{'targets':[]},{'targets':[]})
        self.assertEqual(r['matched_indices'],0)
        self.assertEqual(len(r['unresolved_counterparts']),1)
    def test_duplicate_registration_unresolved(self):
        self.row['decompilation']+=self.row['decompilation']
        self.assertEqual(fields(self.row)['status'],'not_unique_registration')
    def test_rank_helpers_without_semantics(self):
        r=rank(self.manifest,{'callers':[]})
        self.assertEqual(len(r['ranked_targets']),5)
        self.assertEqual(r['known_non_fecs_epilogue'],[])
        self.assertFalse(r['patch_candidate'])
    def test_rank_os_version_with_evidence(self):
        r=rank(self.manifest,{'callers':[{'entry':'001bd760',
            'decompilation':'RtlGetVersion(...); memset(...,0,0x11c);'}]})
        self.assertEqual(r['known_non_fecs_epilogue'],['001bd760'])
if __name__=='__main__':unittest.main()
