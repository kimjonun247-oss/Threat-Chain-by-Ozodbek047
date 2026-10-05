"""CWE -> OWASP map generation (setup_cwe.py) and the taxonomy loader.

The map has a hand-verified baseline in zanjir/taxonomy.py and an optional refresh
from MITRE's catalog (scanner-rules/cwe-owasp.json). These tests cover the regex
parser (no expat needed), its guards against a changed or truncated catalog, and
that taxonomy loads a valid generated map but ignores a corrupt one.
"""
import json
import tempfile
import unittest
from pathlib import Path

import setup_cwe
from zanjir import taxonomy


def catalog(members_by_id, version='4.20'):
    """A minimal CWE catalog XML with the given {category_id: [cwe,...]}."""
    blocks = []
    for cid, members in members_by_id.items():
        rows = ''.join(f'<Has_Member CWE_ID="{m}" View_ID="1400"/>' for m in members)
        blocks.append(f'<Category ID="{cid}" Name="OWASP cat {cid}" Status="Incomplete">'
                      f'<Summary>x</Summary><Relationships>{rows}</Relationships></Category>')
    return (f'<?xml version="1.0"?><Weakness_Catalog Version="{version}">'
            f'<Categories>{"".join(blocks)}</Categories></Weakness_Catalog>')


FULL = {cid: [base, base + 1] for cid, base in zip(setup_cwe.CATEGORIES, range(100, 1100, 100))}


class ParseTests(unittest.TestCase):
    def test_parses_all_ten_categories(self):
        mapping = setup_cwe.parse_map(catalog(FULL), min_count=2)
        # Every category contributes its members under its own A0x code.
        self.assertEqual(set(mapping.values()), set(setup_cwe.CATEGORIES.values()))
        self.assertEqual(len(mapping), 20)
        first_id = next(iter(setup_cwe.CATEGORIES))
        self.assertEqual(mapping[100], setup_cwe.CATEGORIES[first_id])

    def test_missing_category_raises(self):
        short = dict(FULL)
        short.pop(1445)  # drop A10
        with self.assertRaises(ValueError):
            setup_cwe.parse_map(catalog(short), min_count=2)

    def test_empty_category_raises(self):
        empty = dict(FULL)
        empty[1440] = []
        with self.assertRaises(ValueError):
            setup_cwe.parse_map(catalog(empty), min_count=2)

    def test_truncated_download_is_rejected(self):
        # Shape is complete but far fewer CWEs than a real catalog -> rejected.
        with self.assertRaises(ValueError):
            setup_cwe.parse_map(catalog(FULL), min_count=100)

    def test_overlap_keeps_first_category(self):
        overlap = {cid: [base] for cid, base in zip(setup_cwe.CATEGORIES, range(100, 1100, 100))}
        first_id, second_id = list(setup_cwe.CATEGORIES)[:2]
        overlap[second_id] = overlap[second_id] + [100]  # 100 already in the first category
        mapping = setup_cwe.parse_map(catalog(overlap), min_count=1)
        self.assertEqual(mapping[100], setup_cwe.CATEGORIES[first_id])


class LoaderTests(unittest.TestCase):
    def write(self, obj):
        path = Path(tempfile.mkdtemp()) / 'cwe-owasp.json'
        path.write_text(json.dumps(obj), encoding='utf-8')
        return path

    def test_valid_generated_map_is_loaded(self):
        good = {'map': {str(i): 'A%02d' % ((i % 10) + 1) for i in range(1, 160)}}
        loaded = taxonomy._load_generated_owasp_map(self.write(good))
        self.assertIsNotNone(loaded)
        self.assertEqual(set(loaded.values()), set(taxonomy.OWASP_TOP10_2025))
        self.assertEqual(loaded[1], 'A02')

    def test_too_small_map_is_ignored(self):
        small = {'map': {str(i): 'A%02d' % ((i % 10) + 1) for i in range(1, 20)}}
        self.assertIsNone(taxonomy._load_generated_owasp_map(self.write(small)))

    def test_bad_codes_are_ignored(self):
        bad = {'map': {str(i): 'XX' for i in range(1, 160)}}
        self.assertIsNone(taxonomy._load_generated_owasp_map(self.write(bad)))

    def test_missing_file_is_ignored(self):
        self.assertIsNone(taxonomy._load_generated_owasp_map(Path('/no/such/cwe-owasp.json')))


class BaselineTests(unittest.TestCase):
    def test_baseline_is_well_formed(self):
        # The hand-verified baseline must stay a complete, well-coded map.
        self.assertEqual(set(taxonomy.CWE_TO_OWASP.values()), set(taxonomy.OWASP_TOP10_2025))
        self.assertTrue(all(isinstance(k, int) for k in taxonomy.CWE_TO_OWASP))
        self.assertGreaterEqual(len(taxonomy.CWE_TO_OWASP), 200)


if __name__ == '__main__':
    unittest.main()
