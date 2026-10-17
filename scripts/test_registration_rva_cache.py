"""Synthetic per-RVA cache tests. No Ghidra or NVIDIA binaries."""
import json
from pathlib import Path
import tempfile
import unittest
from incremental_analysis import prepare as exporter_prepare, seal as exporter_seal, signatures, report_name, build_argv
from registration_rva_cache import prepare, merge, stamp, targets, unit_signature, read_rows

class RvaCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        for d in ('scripts','ghidra'):
            (self.root/d).mkdir()
        entries=[{'id':'registration_followup','script':'ExportRegistrationFollowup.py',
                  'args':['{manifest}','{out}','{platform}','{selection}'],'depends_on':[]}]
        entries += [{'id':'test_%d'%i,'script':'ExportOther%d.py'%i,'args':['{out}','{platform}'],
                     'depends_on':[]} for i in range(11)]
        (self.root/'scripts/driver_analysis_plan.json').write_text(json.dumps({'schema_version':1,'exporters':entries}))
        for e in entries:
            (self.root/'ghidra'/e['script']).write_text('source')
        self.addresses=['001c4808','001bca8c']
        self.manifest={'input_sha256':{'xp':'a'*64,'win7':'b'*64},
                       'platforms':{'xp':{'focus_addresses':self.addresses[:]},'win7':{'focus_addresses':[]}}}
        self.write_manifest()
        self.orig=self.root/'original'
        self.orig.mkdir()
        for i in range(11):
            (self.orig/('xp_test_%d.json'%i)).write_text(json.dumps({'platform':'xp','value':i}))
        self.write_export(self.orig,[self.row(x) for x in self.addresses])
        (self.orig/'xp_input_sha256.txt').write_text('a'*64+'  work/drivers/nv4_mini.sys\n')
        self.cache=self.root/'cache'
        self.report=self.root/'fresh'
        self.plan=self.root/'work/plan.json'
        self.seed=self.root/'work/rva/seed.json'
        self.selector=self.root/'work/rva/selection.json'
        self.base=unit_signature('xp','1','2',self.root)
        self.original_signatures=signatures('xp','1','2',self.root)

    def write_manifest(self):
        (self.root/'scripts/registration_followup_manifest.json').write_text(json.dumps(self.manifest))

    def row(self,entry,status='ok'):
        return {'entry':entry,'status':status,'size':5,
                'decompilation':'synthetic','incoming':[],'outgoing':[]}

    def write_export(self,dest,rows):
        dest.mkdir(parents=True,exist_ok=True)
        (dest/report_name('xp','registration_followup')).write_text(
            json.dumps({'schema_version':1,'platform':'xp','targets':rows,'caveat':'synthetic'}))

    def seal_baseline(self):
        exporter_seal('xp',self.original_signatures,self.orig,self.cache,self.root)
        stamp('xp',self.base,self.cache,self.orig)

    def plan_current(self):
        sigs=signatures('xp','1','2',self.root)
        exporter_prepare('xp',sigs,self.cache,self.report,self.plan,self.root)
        return sigs

    def prepare_current(self,base=None):
        return prepare('xp',self.base if base is None else base,self.cache,self.report,
                       self.plan,self.seed,self.selector,self.root)

    def test_cold_miss(self):
        self.plan_current()
        r=self.prepare_current()
        self.assertEqual((r['reused_rvas'],r['new_rvas']),(0,2))
        self.assertTrue(r['need_ghidra'])

    def test_addition_reuses_existing_rows(self):
        self.seal_baseline()
        self.manifest['platforms']['xp']['focus_addresses'].append('001c54f4')
        self.write_manifest()
        new_sigs=self.plan_current()
        r=self.prepare_current()
        self.assertEqual((r['reused_rvas'],r['new_rvas']),(2,1))
        self.assertEqual(json.loads(self.selector.read_text())['focus_addresses'],['001c54f4'])
        argv=build_argv('xp',self.plan,self.root,self.report)
        self.assertIn(str(Path('work/rva/selection.json').resolve()),argv)
        self.write_export(self.report,[self.row('001c54f4')])
        merge('xp',self.seed,self.report/'xp_registration_followup.json',
              self.report/'xp_registration_followup.json',self.root)
        self.assertEqual(list(read_rows(self.report/'xp_registration_followup.json','xp')),
                         ['001c4808','001bca8c','001c54f4'])
        exporter_seal('xp',new_sigs,self.report,self.cache,self.root)
        stamp('xp',self.base,self.cache,self.report)

    def test_removal_reuses_all_without_ghidra(self):
        self.seal_baseline()
        self.manifest['platforms']['xp']['focus_addresses']=['001bca8c']
        self.write_manifest()
        self.plan_current()
        r=self.prepare_current()
        self.assertFalse(r['need_ghidra'])
        self.assertFalse(r['has_delta'])
        self.assertEqual(json.loads(self.plan.read_text())['missing'],[])
        self.assertEqual(list(read_rows(self.report/'xp_registration_followup.json','xp')),['001bca8c'])

    def test_decompile_failure_retried(self):
        self.write_export(self.orig,[self.row(self.addresses[0],'decompile_failed'),self.row(self.addresses[1])])
        self.seal_baseline()
        self.manifest['platforms']['xp']['focus_addresses'].append('001c54f4')
        self.write_manifest()
        self.plan_current()
        self.assertEqual((self.prepare_current()['new_rvas']),2)

    def test_wrong_semantic_signature_invalidates_all(self):
        self.seal_baseline()
        self.manifest['platforms']['xp']['focus_addresses'].append('001c54f4')
        self.write_manifest()
        self.plan_current()
        self.assertEqual(self.prepare_current('incorrect')['new_rvas'],3)

    def test_cache_tamper_fails_closed(self):
        self.seal_baseline()
        self.manifest['platforms']['xp']['focus_addresses'].append('001c54f4')
        self.write_manifest()
        self.plan_current()
        (self.cache/'xp_registration_followup.json').write_text('{"platform":"xp","tamper":true}')
        with self.assertRaisesRegex(ValueError,'corrupted registration cache'):
            self.prepare_current()

    def test_merge_duplicate_fails(self):
        self.seed.parent.mkdir(parents=True,exist_ok=True)
        self.seed.write_text(json.dumps({'platform':'xp','targets':[self.row(self.addresses[0])]}))
        self.write_export(self.report,[self.row(x) for x in self.addresses])
        with self.assertRaisesRegex(ValueError,'duplicate RVA'):
            merge('xp',self.seed,self.report/'xp_registration_followup.json',
                  self.report/'xp_registration_followup.json',self.root)

    def test_duplicate_manifest_fails(self):
        self.manifest['platforms']['xp']['focus_addresses'].append(self.addresses[0])
        self.write_manifest()
        with self.assertRaisesRegex(ValueError,'duplicate registration RVA'):
            targets('xp',self.root)

    def test_cache_stamp_integrity(self):
        self.seal_baseline()
        (self.cache/'xp_registration_followup.json').write_text('{"fake":true}')
        with self.assertRaisesRegex(ValueError,'changed since sealing'):
            stamp('xp',self.base,self.cache,self.orig)

if __name__=='__main__':
    unittest.main()
