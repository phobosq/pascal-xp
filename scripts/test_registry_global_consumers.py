"""Deterministic tests for class-registry consumer evidence ranking."""
import unittest
from compare_registry_global_consumers import compare,score_row,summarize

class RegistryConsumerTests(unittest.TestCase):
    def test_debug_break_is_demoted(self):
        row={'entry':'000716c0','decompilation':
             'DbgPrintEx(0,0,0,0,"NVRM-RC: Nvidia Release Debug Break");'}
        out=score_row(row,'00117db0','0094b270')
        self.assertLess(out['score'],0)
        self.assertEqual(out['kind'],'generic_rm_debug_assert')
    def test_registration_dispatch_is_positive(self):
        row={'entry':'00117db0','decompilation':
          '(**(code **)(DAT_0094b270+0x90))(DAT_0094b270,0xe803b6,param_1);'
          'lVar2=(**(code **)(lVar2+400))(lVar2,param_1);'
          'puVar3=(undefined8 *)(**(code **)(lVar2+0x70))(lVar2);'}
        out=score_row(row,'00117db0','0094b270')
        self.assertGreaterEqual(out['score'],18)
        self.assertEqual(out['kind'],'known_registry_registration')
    def test_runtime_stays_unproven(self):
        sample={'registry_global':'0094b270','registration_function':'00117db0',
            'reference_owner_count':2,'bounded_decompiled_owners':[
                {'entry':'000716c0','status':'ok',
                 'decompilation':'DbgPrintEx(0,0,0,0,"Nvidia Release Debug Break");',
                 'references':[{'source':'1'}]*4},
                {'entry':'00117db0','status':'ok',
                 'decompilation':'(**(code **)(DAT_0094b270+0x90))(DAT_0094b270,0xe803b6); (**(code **)(lVar2+400))(lVar2);',
                 'references':[{'source':'2'}]}]}
        out=compare(sample,sample)
        self.assertFalse(out['patch_candidate'])
        self.assertFalse(out['runtime_gp106_selection_proven'])
        self.assertEqual(out['xp']['positive_candidates'][0]['entry'],'00117db0')
        self.assertEqual(out['xp']['generic_debug_demoted'],['000716c0'])
    def test_plain_struct_offsets_are_not_class_dispatch(self):
        # Real run #108 false positives: +400 is a stored field, while
        # +0x188 is an unrelated virtual method on the same global.
        xp={'entry':'00054b60','decompilation':
            '*(undefined4 *)(lVar2 + 400) = 1;'
            'lVar6 = (**(code **)(DAT_0094b270 + 0x188))(DAT_0094b270,param_1);'
            '(**(code **)(lVar7 + 0x1a8))(lVar6);'}
        out=score_row(xp,'00117db0','0094b270')
        self.assertEqual(out['score'],0)
        self.assertEqual(out['kind'],'other_global_user')
        self.assertEqual(out['positive_evidence'],[])
    def test_foreign_virtual_90_is_not_registry_query(self):
        win7={'entry':'001c8754','decompilation':
              '(**(code **)(lVar4 + 0x90))(lVar4,0x7ef3cb,param_1);'
              '(**(code **)(DAT_007da840 + 0x188))(DAT_007da840,param_1);'}
        out=score_row(win7,'0023c050','007da840')
        self.assertEqual(out['score'],0)
        self.assertEqual(out['positive_evidence'],[])
    def test_unrooted_resource_constant_is_not_sufficient(self):
        row={'entry':'00012345','decompilation':'FUN_00000000(0xe803b6);'}
        out=score_row(row,'00117db0','0094b270')
        self.assertEqual(out['score'],0)
    def test_empty_report(self):
        out=summarize({})
        self.assertEqual(out['positive_candidates'],[])
        self.assertEqual(out['decompiled_count'],0)
if __name__=='__main__':
    unittest.main()
