"""Per-exporter incremental analysis tests without Ghidra or NVIDIA binaries."""
import json
from pathlib import Path
import tempfile
import unittest

from incremental_analysis import (
    build_argv, bundle_key, load_plan, prepare, report_name, seal, signatures
)


class IncrementalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for d in ('ghidra', 'scripts'):
            (self.root / d).mkdir()
        self.plan = {'schema_version': 1, 'exporters': [
            {'id': 'fecs_descriptor_parents', 'script': 'ExportParents.py',
             'args': ['{out}', '{platform}'], 'depends_on': []},
            {'id': 'descriptor_owner_chains', 'script': 'ExportChains.py',
             'args': ['{report:fecs_descriptor_parents}', '{out}', '{platform}'],
             'depends_on': ['fecs_descriptor_parents']},
            {'id': 'registration_followup', 'script': 'ExportFollowup.py',
             'args': ['{manifest}', '{out}', '{platform}'], 'depends_on': []},
        ]}
        # Validation of twelve entries is intentionally strict in production.
        self.plan['exporters'] += [
            {'id': f'test_export_{i}', 'script': f'ExportOther{i}.py',
             'args': ['{out}', '{platform}'], 'depends_on': []}
            for i in range(9)]
        (self.root / 'scripts/driver_analysis_plan.json').write_text(json.dumps(self.plan))
        (self.root / 'scripts/registration_followup_manifest.json').write_text(
            json.dumps({'input_sha256': {'xp': 'a'*64, 'win7': 'b'*64},
                        'platforms': {'xp': {'focus_addresses': ['0001']},
                                      'win7': {'focus_addresses': []}}}))
        for e in self.plan['exporters']:
            (self.root / 'ghidra' / e['script']).write_text('script\n')
        self.sigs = signatures('xp', '1', '2', self.root)
        self.reports = self.root / 'reports'
        self.reports.mkdir()
        for ident in self.sigs:
            (self.reports / report_name('xp', ident)).write_text(
                json.dumps({'platform': 'xp', 'exporter': ident}))
        (self.reports / 'xp_input_sha256.txt').write_text(
            'a'*64+'  work/drivers/nv4_mini.sys\n')
        self.cache = self.root / 'cache'
        self.out = self.root / 'restored'
        self.planfile = self.root / 'plan.json'

    def test_full_miss_then_complete_hit(self):
        self.assertEqual(12, len(prepare('xp', self.sigs, self.cache, self.out,
                                          self.planfile, self.root)))
        seal('xp', self.sigs, self.reports, self.cache, self.root)
        self.assertEqual([], prepare('xp', self.sigs, self.cache, self.out,
                                      self.planfile, self.root))
        self.assertEqual(len(list(self.out.glob('*.json'))), 12)

    def test_one_exporter_changed_keeps_other_eleven(self):
        seal('xp', self.sigs, self.reports, self.cache, self.root)
        (self.root / 'ghidra/ExportOther0.py').write_text('new script\n')
        newer = signatures('xp', '1', '2', self.root)
        missing = prepare('xp', newer, self.cache, self.out, self.planfile, self.root)
        self.assertEqual(missing, ['test_export_0'])
        self.assertEqual(len(list(self.out.glob('*.json'))), 11)

    def test_dependencies_invalidate_transitively(self):
        seal('xp', self.sigs, self.reports, self.cache, self.root)
        (self.root / 'ghidra/ExportParents.py').write_text('changed\n')
        newer = signatures('xp', '1', '2', self.root)
        missing = prepare('xp', newer, self.cache, self.out, self.planfile, self.root)
        self.assertEqual(missing, ['fecs_descriptor_parents', 'descriptor_owner_chains'])

    def test_manifest_change_only_followup(self):
        seal('xp', self.sigs, self.reports, self.cache, self.root)
        path = self.root / 'scripts/registration_followup_manifest.json'
        data = json.loads(path.read_text())
        data['platforms']['xp']['focus_addresses'].append('1234')
        path.write_text(json.dumps(data))
        newer = signatures('xp', '1', '2', self.root)
        self.assertEqual(['registration_followup'],
                         prepare('xp', newer, self.cache, self.out, self.planfile, self.root))

    def test_bad_sha_rejected_without_materializing(self):
        seal('xp', self.sigs, self.reports, self.cache, self.root)
        (self.cache / 'xp_descriptor_owner_chains.json').write_text('{"tamper":true}')
        with self.assertRaisesRegex(ValueError, 'corrupted cached report'):
            prepare('xp', self.sigs, self.cache, self.out, self.planfile, self.root)
        self.assertFalse(self.out.exists())

    def test_comparator_change_does_not_invalidate(self):
        key = bundle_key(self.sigs)
        (self.root / 'scripts/compare_registry_global_consumers.py').write_text('changed\n')
        self.assertEqual(key, bundle_key(signatures('xp', '1', '2', self.root)))

    def test_argv_respects_order_and_paths(self):
        self.planfile.write_text(json.dumps({'platform':'xp',
            'missing':['descriptor_owner_chains', 'registration_followup']}))
        tokens = build_argv('xp', self.planfile, self.root, self.reports)
        self.assertEqual(tokens.count('-postScript'), 2)
        self.assertEqual(tokens[1], 'ExportChains.py')
        self.assertIn(str(self.reports / 'xp_fecs_descriptor_parents.json'), tokens)
        self.assertIn(str((self.root / 'scripts/registration_followup_manifest.json').resolve()), tokens)

    def test_change_input_id_invalidates_all(self):
        self.assertNotEqual(self.sigs, signatures('xp','1','3',self.root))
        self.assertNotEqual(self.sigs, signatures('win7','1','2',self.root))

    def test_validate_schema_and_order(self):
        rows = load_plan(self.root)
        self.assertEqual(len(rows),12)
        self.plan['exporters'][0]['depends_on']=['descriptor_owner_chains']
        (self.root / 'scripts/driver_analysis_plan.json').write_text(json.dumps(self.plan))
        with self.assertRaisesRegex(ValueError,'dependencies must precede'):
            load_plan(self.root)

    def test_cache_contains_only_whitelist(self):
        seal('xp', self.sigs, self.reports, self.cache, self.root)
        files={p.name for p in self.cache.iterdir()}
        self.assertEqual(len(files),14)
        self.assertNotIn('nv4_mini.sys',files)


if __name__=='__main__':
    unittest.main()
