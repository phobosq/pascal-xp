"""Self-contained deterministic cache tests; no binaries or Ghidra."""
import json
from pathlib import Path
import tempfile
import unittest
from analysis_cache import EXPORTS, cache_key, inspect_reports, restore, stage

class AnalysisCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ('scripts', 'ghidra', '.github/workflows'):
            (self.root / directory).mkdir(parents=True)
        self.manifest = {'input_sha256': {'xp': 'a' * 64, 'win7': 'b' * 64}}
        (self.root / 'scripts/registration_followup_manifest.json').write_text(json.dumps(self.manifest))
        (self.root / 'requirements.txt').write_text('pefile\n')
        (self.root / '.github/workflows/driver-analysis.yml').write_text('workflow: 1\n')
        (self.root / 'ghidra/ExportFoo.py').write_text('print(1)\n')
        self.reports = self.root / 'reports'
        self.reports.mkdir()
        self.key = cache_key('xp', '10', '20', self.root)
        for name in EXPORTS:
            (self.reports / f'xp_{name}.json').write_text(json.dumps({'platform': 'xp', 'name': name}))
        (self.reports / 'xp_input_sha256.txt').write_text('a' * 64 + '  work/drivers/nv4_mini.sys\n')
        self.cache = self.root / 'cache'

    def test_hit_roundtrip_and_no_proprietary_copy(self):
        stage('xp', self.key, self.reports, self.cache, self.root)
        names = {p.name for p in self.cache.iterdir()}
        self.assertEqual(len(names), len(EXPORTS) + 2)
        self.assertNotIn('nv4_mini.sys', names)
        valid, _ = restore('xp', self.key, self.cache, self.root / 'restored', self.root)
        self.assertTrue(valid)
        self.assertEqual(inspect_reports('xp', self.root / 'restored', self.root),
                         inspect_reports('xp', self.reports, self.root))

    def test_missing_cache_is_a_miss(self):
        valid, _ = restore('xp', self.key, self.root / 'missing', self.root / 'out', self.root)
        self.assertFalse(valid)

    def test_corrupt_cache_is_rejected(self):
        stage('xp', self.key, self.reports, self.cache, self.root)
        (self.cache / 'xp_fecs_table_roots.json').write_text('{"platform":"xp","tampered":true}')
        valid, why = restore('xp', self.key, self.cache, self.root / 'out', self.root)
        self.assertFalse(valid)
        self.assertIn('checksum', why)
        self.assertFalse((self.root / 'out').exists())

    def test_wrong_platform_or_key_is_rejected(self):
        stage('xp', self.key, self.reports, self.cache, self.root)
        self.assertFalse(restore('win7', self.key, self.cache, self.root / 'out', self.root)[0])
        self.assertFalse(restore('xp', 'wrong', self.cache, self.root / 'out', self.root)[0])

    def test_only_analysis_inputs_invalidate(self):
        before = cache_key('xp', '10', '20', self.root)
        (self.root / 'scripts/compare_registry_global_consumers.py').write_text('updated\n')
        self.assertEqual(before, cache_key('xp', '10', '20', self.root))
        (self.root / 'ghidra/ExportFoo.py').write_text('updated\n')
        self.assertNotEqual(before, cache_key('xp', '10', '20', self.root))

    def test_binary_identity_and_config_invalidate(self):
        self.assertNotEqual(self.key, cache_key('xp', '10', '21', self.root))
        self.assertNotEqual(self.key, cache_key('xp', '11', '20', self.root))
        self.assertNotEqual(self.key, cache_key('win7', '10', '20', self.root))
        self.manifest['input_sha256']['xp'] = 'c' * 64
        (self.root / 'scripts/registration_followup_manifest.json').write_text(json.dumps(self.manifest))
        self.assertNotEqual(self.key, cache_key('xp', '10', '20', self.root))

    def test_reject_missing_or_malformed_json(self):
        (self.reports / 'xp_fecs_table_roots.json').unlink()
        with self.assertRaisesRegex(ValueError, 'missing'):
            stage('xp', self.key, self.reports, self.cache, self.root)
        (self.reports / 'xp_fecs_table_roots.json').write_text('null')
        with self.assertRaisesRegex(ValueError, 'invalid JSON object'):
            stage('xp', self.key, self.reports, self.cache, self.root)

if __name__ == '__main__':
    unittest.main()
