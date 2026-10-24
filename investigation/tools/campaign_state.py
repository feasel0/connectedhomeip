import argparse
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import time
import unittest
import uuid
from pathlib import Path


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def approved_matrix(path):
    cells = []
    pattern = re.compile(r'^\| ([WTBD][1-4]) \| `(TC_[A-Za-z_0-9]+)` \| (\d+) \| (CORE|GATED) \| 0 \| 0 \| 0 \| 0 \|')
    for line in path.read_text().splitlines():
        match = pattern.match(line)
        if match:
            topology, case, target, tier = match.groups()
            cells.append({'topology': topology, 'case': case, 'target': int(target),
                          'minimum': 10, 'tier': tier, 'state': 'GATED'})
    if len(cells) != 88 or len({(cell['topology'], cell['case']) for cell in cells}) != 88:
        raise ValueError('Approved candidate matrix must have exactly 88 unique rows')
    if sum(cell['target'] for cell in cells) != 1110:
        raise ValueError('Approved target total changed')
    if sum(cell['target'] for cell in cells if cell['tier'] == 'CORE') != 710:
        raise ValueError('Approved core target total changed')
    return cells


def atomic(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    text = document if isinstance(document, str) else json.dumps(document, indent=2, sort_keys=True) + '\n'
    with temporary.open('x') as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def connection(root, readonly=False):
    if readonly:
        database = sqlite3.connect('file:' + str(root / 'campaign.sqlite') + '?mode=ro', uri=True, timeout=10)
    else:
        database = sqlite3.connect(root / 'campaign.sqlite', timeout=10)
        database.execute('PRAGMA journal_mode=WAL')
        database.execute('PRAGMA synchronous=FULL')
        database.execute('PRAGMA foreign_keys=ON')
    database.row_factory = sqlite3.Row
    return database


def initialize(root, plan, mode='PREPARATION'):
    cells = approved_matrix(plan)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    campaign = 'weekend-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:12]
    manifest = {'schema': 1, 'campaign_id': campaign, 'plan_sha256': digest(plan),
                'source_manifest': None, 'cells': cells, 'launch_authorized': True,
                'hardware_admitted': False, 'differentials_enabled': False,
                'global_gates': {}, 'duration_seconds': 172800, 'checkpoint_seconds': 86400,
                'cleanup_margin_seconds': 600}
    atomic(root / 'preparation.json', manifest)
    database = connection(root)
    database.executescript('''
        CREATE TABLE campaign(id TEXT PRIMARY KEY, plan_hash TEXT NOT NULL, mode TEXT NOT NULL,
            manifest_hash TEXT, state TEXT NOT NULL, started REAL, deadline REAL,
            checkpoint_done INTEGER NOT NULL DEFAULT 0, last_progress REAL NOT NULL,
            boot_id TEXT, disposition TEXT NOT NULL);
        CREATE TABLE cells(id TEXT PRIMARY KEY, topology TEXT NOT NULL, test_case TEXT NOT NULL,
            tier TEXT NOT NULL, target INTEGER NOT NULL, minimum INTEGER NOT NULL,
            state TEXT NOT NULL, gate_reason TEXT NOT NULL,
            UNIQUE(topology,test_case));
        CREATE TABLE attempts(id TEXT PRIMARY KEY, cell_id TEXT NOT NULL REFERENCES cells(id),
            replaces_id TEXT REFERENCES attempts(id), state TEXT NOT NULL, unit TEXT,
            identity TEXT, created REAL NOT NULL, ended REAL, evidence TEXT,
            integrity TEXT NOT NULL DEFAULT 'PARTIAL');
        CREATE TABLE iterations(id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL REFERENCES attempts(id),
            ordinal INTEGER NOT NULL, native_outcome TEXT NOT NULL,
            invocation_outcome TEXT NOT NULL, integrity TEXT NOT NULL,
            receipt_hash TEXT, classification INTEGER, signature TEXT,
            UNIQUE(attempt_id,ordinal));
        CREATE TABLE transitions(sequence INTEGER PRIMARY KEY, wall REAL NOT NULL,
            entity TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL);
        CREATE TABLE ownership(resource TEXT PRIMARY KEY, attempt_id TEXT NOT NULL,
            identity TEXT NOT NULL, acquired REAL NOT NULL, released REAL);
        CREATE TABLE health(sequence INTEGER PRIMARY KEY, wall REAL NOT NULL,
            host TEXT NOT NULL, document TEXT NOT NULL);
        CREATE TABLE recoveries(id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL,
            operation TEXT NOT NULL, outcome TEXT NOT NULL, evidence TEXT NOT NULL);
    ''')
    with database:
        database.execute('INSERT INTO campaign(id,plan_hash,mode,state,last_progress,disposition) VALUES(?,?,?,?,?,?)',
                 (campaign, digest(plan), mode, 'PREPARING', time.time(), 'Prelaunch gates not satisfied'))
        for cell in cells:
            identifier = cell['topology'] + '/' + cell['case'] + '/' + digest(plan)[:16]
            database.execute('INSERT INTO cells VALUES(?,?,?,?,?,?,?,?)',
                             (identifier, cell['topology'], cell['case'], cell['tier'], cell['target'],
                              cell['minimum'], 'GATED', 'Source/fixture/supervision qualification pending'))
        database.execute('INSERT INTO transitions(wall,entity,kind,detail) VALUES(?,?,?,?)',
                         (time.time(), campaign, 'PREPARATION_INITIALIZED', json.dumps({'executed': 0})))
    database.close()
    return campaign


def record_outcome(database, attempt_id, ordinal, outcome, receipt_hash, integrity='COMPLETE', signature=None):
    if outcome not in {'PASS', 'FAIL'} or ordinal < 1 or not re.fullmatch(r'[0-9a-f]{64}', receipt_hash):
        raise ValueError('Invalid native outcome/ordinal/receipt hash')
    identifier = attempt_id + '/' + str(ordinal)
    existing = database.execute('SELECT * FROM iterations WHERE id=?', (identifier,)).fetchone()
    if existing:
        if (existing['native_outcome'], existing['receipt_hash'], existing['integrity']) != (outcome, receipt_hash, integrity):
            raise ValueError('Conflicting receipt cannot rewrite an original outcome')
        return False
    database.execute('INSERT INTO iterations VALUES(?,?,?,?,?,?,?,?,?)',
                     (identifier, attempt_id, ordinal, outcome, 'STARTED', integrity, receipt_hash,
                      6 if outcome == 'FAIL' else None, signature,))
    return True


def status(root):
    database = connection(root, readonly=True)
    try:
        campaign = dict(database.execute('SELECT * FROM campaign').fetchone())
        cells = [dict(row) for row in database.execute('SELECT * FROM cells ORDER BY topology,test_case')]
        counts = dict(database.execute('SELECT native_outcome,COUNT(*) FROM iterations GROUP BY native_outcome').fetchall())
        attempts = [dict(row) for row in database.execute('SELECT * FROM attempts ORDER BY created')]
        by_cell = {row['cell_id']: dict(row) for row in database.execute(
            "SELECT a.cell_id,COUNT(i.id) AS executed,"
            "COALESCE(SUM(i.native_outcome='PASS'),0) AS passed,"
            "COALESCE(SUM(i.native_outcome='FAIL'),0) AS failed "
            'FROM attempts a LEFT JOIN iterations i ON i.attempt_id=a.id GROUP BY a.cell_id')}
        for cell in cells:
            block_states = [row['state'] for row in attempts if row['cell_id'] == cell['id']]
            cell.update({key: by_cell.get(cell['id'], {}).get(key, 0) for key in ['executed', 'passed', 'failed']})
            cell.update(launched_blocks=len(block_states), incomplete_blocks=block_states.count('INCOMPLETE'),
                blocked_blocks=block_states.count('BLOCKED'),
                unexecuted=max(0, cell['target'] - cell['executed']))
        return {'campaign': campaign, 'cells': cells, 'attempts': attempts,
                'planned_cells': len(cells), 'planned_target': sum(cell['target'] for cell in cells),
            'admitted_cells': sum(cell['state'] == 'ADMITTED' for cell in cells),
            'launched_blocks': len(attempts), 'incomplete_blocks': sum(row['state'] == 'INCOMPLETE' for row in attempts),
            'blocked_blocks': sum(row['state'] == 'BLOCKED' for row in attempts),
            'unexecuted_target': sum(cell['unexecuted'] for cell in cells),
                'executed': sum(counts.values()), 'passed': counts.get('PASS', 0), 'failed': counts.get('FAIL', 0),
                'remaining_seconds': max(0, campaign['deadline'] - time.time()) if campaign['deadline'] else None}
    finally:
        database.close()


def render(root, visible):
    document = status(root)
    campaign = document['campaign']
    text = ('# Weekend Campaign Live Summary\n\n'
            f"Campaign: {campaign['id']}; mode: {campaign['mode']}\n\nState: **{campaign['state']}**\n\n"
            f"Disposition: {campaign['disposition']}\n\n"
            f"Candidate cells: {document['planned_cells']}; target: {document['planned_target']}; "
            f"executed: {document['executed']}; PASS: {document['passed']}; FAIL: {document['failed']}\n\n"
            f"Admitted cells: {document['admitted_cells']}; launched blocks: {document['launched_blocks']}; "
            f"incomplete blocks: {document['incomplete_blocks']}; unexecuted target: {document['unexecuted_target']}\n\n"
            f"Last progress: {campaign['last_progress']}; deadline: {campaign['deadline']}\n\n"
            'Historical 158/80/78 and synthetic qualifications are separate.\n\n'
            '| Topology | Case | Target | Executed | PASS | FAIL | Incomplete Blocks | Unexecuted | State | Gate |\n'
            '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |\n')
    for cell in document['cells']:
        text += (f"| {cell['topology']} | {cell['test_case']} | {cell['target']} | {cell['executed']} | {cell['passed']} | "
                 f"{cell['failed']} | {cell['incomplete_blocks']} | {cell['unexecuted']} | {cell['state']} | {cell['gate_reason']} |\n")
    atomic(root / 'status.json', document)
    atomic(root / 'LIVE_SUMMARY.md', text)
    atomic(visible, text)


class StateTests(unittest.TestCase):
    def test_approved_matrix(self):
        cells = approved_matrix(Path(__file__).resolve().parents[1] / 'WEEKEND_MATRIX_PLAN_2026-10-24.md')
        self.assertEqual(len(cells), 88)
        self.assertEqual(sum(cell['minimum'] for cell in cells if cell['tier'] == 'CORE'), 480)
        self.assertTrue(all(cell['state'] == 'GATED' for cell in cells))

    def test_zero_initial_hardware_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'new'
            initialize(root, Path(__file__).resolve().parents[1] / 'WEEKEND_MATRIX_PLAN_2026-10-24.md')
            document = status(root)
            self.assertEqual((document['executed'], document['passed'], document['failed']), (0, 0, 0))
            self.assertIsNone(document['campaign']['deadline'])

    def test_receipt_replay_and_conflicting_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'new'
            initialize(root, Path(__file__).resolve().parents[1] / 'WEEKEND_MATRIX_PLAN_2026-10-24.md')
            database = connection(root)
            cell = database.execute('SELECT id FROM cells LIMIT 1').fetchone()['id']
            with database:
                database.execute('INSERT INTO attempts(id,cell_id,state,created) VALUES(?,?,?,?)',
                                 ('attempt-one', cell, 'RUNNING', time.time()))
                self.assertTrue(record_outcome(database, 'attempt-one', 1, 'FAIL', 'a' * 64))
                self.assertFalse(record_outcome(database, 'attempt-one', 1, 'FAIL', 'a' * 64))
                with self.assertRaises(ValueError):
                    record_outcome(database, 'attempt-one', 1, 'PASS', 'b' * 64)
            database.close()
            document = status(root)
            self.assertEqual((document['executed'], document['failed']), (1, 1))
            observed = next(row for row in document['cells'] if row['id'] == cell)
            self.assertEqual((observed['executed'], observed['failed'], observed['passed'], observed['launched_blocks']), (1, 1, 0, 1))
            self.assertEqual(observed['unexecuted'], observed['target'] - 1)


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['self-test', 'initialize', 'status', 'render'])
    parser.add_argument('--root', type=Path)
    parser.add_argument('--plan', type=Path, default=Path(__file__).resolve().parents[1] / 'WEEKEND_MATRIX_PLAN_2026-10-24.md')
    parser.add_argument('--visible', type=Path)
    arguments = parser.parse_args()
    if arguments.action == 'self-test':
        unittest.main(argv=[__file__])
    elif arguments.action == 'initialize':
        print(initialize(arguments.root, arguments.plan))
    elif arguments.action == 'status':
        print(json.dumps(status(arguments.root), indent=2))
    else:
        render(arguments.root, arguments.visible)
