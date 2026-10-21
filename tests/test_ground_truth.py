"""benchmarks/ground_truth.py: the matching rule that turns findings into recall."""
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load():
    spec = importlib.util.spec_from_file_location('ground_truth', ROOT / 'benchmarks' / 'ground_truth.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GroundTruthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gt = load()

    def test_a_a_label_needs_its_path_and_its_cwe_family(self):
        label = {'path': 'routes/login.ts', 'cwe': [89]}
        self.assertTrue(self.gt.matches(label, {'path': 'routes/login.ts', 'cwe_ids': ['CWE-89: SQL Injection']}))
        self.assertFalse(self.gt.matches(label, {'path': 'routes/login.ts', 'cwe_ids': ['CWE-79']}))
        self.assertFalse(self.gt.matches(label, {'path': 'routes/search.ts', 'cwe_ids': ['CWE-89']}))

    def test_b_globs_and_secret_labels(self):
        self.assertTrue(self.gt.matches({'path': 'src/lessons/xxe/**', 'cwe': [611]},
                                        {'path': 'src/lessons/xxe/a/B.java', 'cwe_ids': ['CWE-611']}))
        self.assertTrue(self.gt.matches({'path': 'lib/insecurity.ts', 'cwe': [798], 'secret': True},
                                        {'path': 'lib/insecurity.ts', 'tool': 'gitleaks', 'cwe_ids': []}))

    def test_c_every_label_is_well_formed(self):
        spec = json.loads((ROOT / 'benchmarks' / 'ground_truth.json').read_text(encoding='utf-8'))['projects']
        self.assertTrue(any(p.get('clean') for p in spec.values()))
        for name, project in spec.items():
            self.assertTrue(project['repo'].startswith('https://github.com/'), name)
            for label in project['labels']:
                self.assertTrue(label['cwe'] and all(isinstance(c, int) for c in label['cwe']), label)
                self.assertFalse(label['path'].startswith('/') or '..' in label['path'], label)


if __name__ == '__main__':
    unittest.main()
