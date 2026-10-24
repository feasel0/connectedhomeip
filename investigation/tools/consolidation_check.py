import argparse
from collections import Counter
import hashlib
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def catalog_rows(text):
    rows = []
    classification = mechanism = ''
    current = None
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith('## '):
            classification = line[3:]
        elif line.startswith('### '):
            mechanism = line[4:]
        match = re.match(r'#### Failure ([0-9a-f]{16}): (.*)', line)
        if match:
            current = {'id': match[1], 'description': match[2],
                       'classification': classification, 'mechanism': mechanism,
                       'line': number, 'resolution': None}
            rows.append(current)
        elif current is not None and current['resolution'] is None:
            resolution = re.match(r'- Resolution: \*\*(FIXED|OPEN)\*\*', line)
            if resolution:
                current['resolution'] = resolution[1]
    assert len({row['id'] for row in rows}) == len(rows), 'Duplicate original failure ID'
    assert all(row['resolution'] is not None for row in rows), 'Missing original resolution'
    return rows


def check_catalog(source, destination=None):
    original = catalog_rows(source.read_text())
    assert len(original) == 158
    assert Counter(row['resolution'] for row in original) == {'FIXED': 80, 'OPEN': 78}
    if destination is not None:
        result = catalog_rows(destination.read_text())
        expected = {row['id']: (row['resolution'], row['classification'], row['description']) for row in original}
        actual = {row['id']: (row['resolution'], row['classification'], row['description']) for row in result}
        assert actual == expected, 'Historical identity/outcome/classification changed'
    print(f'PASS: 158 original failure IDs, 80 mapped mechanisms, 78 OPEN; source SHA256 {hashlib.sha256(source.read_bytes()).hexdigest()}')


class CatalogTests(unittest.TestCase):
    def test_individual_identity_and_classification(self):
        rows = catalog_rows('## 2. Methodology\n### OPEN: Scan\n#### Failure 0123456789abcdef: run 1\n- Resolution: **OPEN**.\n')
        self.assertEqual(rows[0]['id'], '0123456789abcdef')
        self.assertEqual(rows[0]['classification'], '2. Methodology')
        self.assertEqual(rows[0]['resolution'], 'OPEN')

    def test_duplicate_rejected(self):
        text = '#### Failure 0123456789abcdef: run\n- Resolution: **OPEN**.\n'
        with self.assertRaises(AssertionError):
            catalog_rows(text + text)

    def test_missing_resolution_rejected(self):
        with self.assertRaises(AssertionError):
            catalog_rows('#### Failure 0123456789abcdef: run\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['self-test', 'catalog'])
    parser.add_argument('--source', type=Path, default=ROOT / 'pr539-failure-evidence/FAILURES.md')
    parser.add_argument('--destination', type=Path)
    options = parser.parse_args()
    if options.action == 'self-test':
        unittest.main(argv=[__file__])
    else:
        check_catalog(options.source, options.destination)
