import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import campaign_service as service
import campaign_state as ledger
import campaign_native


PLAN = Path(__file__).resolve().parents[1] / 'WEEKEND_MATRIX_PLAN_2026-10-24.md'


def settings(behaviors, **options):
    rows = ledger.approved_matrix(PLAN)
    cells = []
    for index, behavior in enumerate(behaviors):
        row = rows[index]
        cells.append({'id': row['topology'] + '/' + row['case'] + '/' + ledger.digest(PLAN)[:16],
                      'behavior': behavior, 'seconds': 0.2, 'timeout_seconds': 10})
    return dict(mode='synthetic', cells=cells, duration_seconds=30, checkpoint_seconds=15, **options)


def wait_for(condition, timeout=30):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = condition()
        if result:
            return result
        threading.Event().wait(0.1)
    raise TimeoutError('Bounded lifecycle proof did not reach required state')


def terminal(root):
    document = ledger.status(root)
    return document if document['campaign']['state'] in service.FINAL else None


class ServiceTests(unittest.TestCase):
    def test_hardware_limits_cannot_inherit_synthetic_short_timeout(self):
        document = {'duration_seconds': 172800, 'checkpoint_seconds': 86400, 'cleanup_margin_seconds': 300,
                    'cells': [{'id': 'cell', 'estimated_seconds': 100, 'timeout_seconds': 10}],
                    'native_profile': {'cell': {'baseline': 'pristine-upstream', 'requested_iterations': 10,
                                                'native_timeout_seconds': 1200}}}
        with self.assertRaises(ValueError):
            service.validate_hardware_limits(document)
        document['cells'][0]['timeout_seconds'] = 1500
        service.validate_hardware_limits(document)
        document['native_profile']['cell']['requested_iterations'] = 1
        with self.assertRaises(ValueError):
            service.validate_hardware_limits(document)

    def test_operational_failure_stops_owned_worker_before_terminal_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'run'
            service.prepare(root, PLAN, settings(['PASS']))
            document = ledger.status(root)
            attempt_root = root / 'attempts' / 'owned'
            attempt_root.mkdir(parents=True)
            ledger.atomic(attempt_root / 'identity.json', {'invocation_id': 'matching'})
            database = ledger.connection(root)
            with database:
                database.execute('INSERT INTO attempts(id,cell_id,state,unit,created) VALUES(?,?,?,?,?)',
                                 ('owned', document['cells'][0]['id'], 'RUNNING', 'owned.service', time.time()))
            database.close()
            state = {'MainPID': '123', 'InvocationID': 'matching', 'ActiveState': 'active', 'SubState': 'running'}
            with patch.object(service, 'unit_status', return_value=state), patch.object(service, 'control') as control:
                service.fail_closed(root, ValueError('Frozen manifest changed'))
                control.assert_called_once_with('stop', 'owned.service')
            result = ledger.status(root)
            self.assertEqual(result['campaign']['state'], 'BLOCKED')
            self.assertEqual(result['attempts'][0]['state'], 'INCOMPLETE')
            self.assertEqual(result['passed'], 0)

    def test_native_outcome_requires_completed_iteration_records(self):
        document = {'test_summary_record': {'total_number_of_iterations': 10,
                    'number_of_iterations_completed': 1, 'number_of_iterations_passed': 0,
                    'number_of_iterations_failed': 1}, 'list_of_iteration_records': [
                    {'iteration_number': 1, 'iteration_data': {'iteration_tc_execution_data': {
                        'iteration_begin_time': '2026-10-24T10:00:00Z',
                        'iteration_end_time': '2026-10-24T10:00:01Z', 'iteration_result': 'FAIL'}}}]}
        self.assertEqual(campaign_native.native_outcomes(document, 10)[0]['outcome'], 'FAIL')
        document['test_summary_record']['number_of_iterations_passed'] = 1
        with self.assertRaises(ValueError):
            campaign_native.native_outcomes(document, 10)

    def test_native_duplicate_id_rejected(self):
        document = {'test_summary_record': {'total_number_of_iterations': 10},
                    'list_of_iteration_records': [{'iteration_number': 1}, {'iteration_number': 1}]}
        with self.assertRaises(ValueError):
            campaign_native.native_outcomes(document, 10)

    def test_native_in_progress_is_not_pass(self):
        document = {'test_summary_record': {'total_number_of_iterations': 10,
                    'number_of_iterations_completed': 0, 'number_of_iterations_passed': 0,
                    'number_of_iterations_failed': 0}, 'list_of_iteration_records': [
                    {'iteration_number': 1, 'iteration_data': {'iteration_tc_execution_data': {
                        'iteration_begin_time': '2026-10-24T10:00:00Z', 'iteration_result': 'PASS'}}}]}
        self.assertEqual(campaign_native.native_outcomes(document, 10), [])

    def test_manifest_and_program_are_frozen(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'run'
            service.prepare(root, PLAN, settings(['PASS']))
            self.assertEqual(service.configuration(root)['mode'], 'synthetic')
            program = root / 'program/campaign_state.py'
            program.write_text(program.read_text() + '\n')
            with self.assertRaises(ValueError):
                service.configuration(root)

    def test_preparation_does_not_start_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'run'
            service.prepare(root, PLAN, settings(['PASS']))
            document = ledger.status(root)
            self.assertEqual(document['campaign']['state'], 'PREPARED')
            self.assertIsNone(document['campaign']['started'])
            self.assertIsNone(document['campaign']['deadline'])

    def test_hardware_refused_without_complete_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'run'
            configuration = settings(['PASS'])
            configuration['mode'] = 'hardware'
            configuration['duration_seconds'] = 172800
            configuration['cells'][0].pop('behavior')
            service.prepare(root, PLAN, configuration)
            with self.assertRaises(ValueError):
                service.configuration(root)
            self.assertEqual(ledger.status(root)['executed'], 0)

    def test_synthetic_results_cannot_enter_hardware_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            configuration = settings(['PASS'])
            configuration['mode'] = 'hardware'
            configuration['duration_seconds'] = 172800
            with self.assertRaises(ValueError):
                service.prepare(Path(directory) / 'run', PLAN, configuration)

    def test_prune_refuses_uncommitted_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'run'
            service.prepare(root, PLAN, settings(['PASS']))
            database = ledger.connection(root)
            cell = database.execute('SELECT id FROM cells LIMIT 1').fetchone()['id']
            with database:
                database.execute('INSERT INTO attempts(id,cell_id,state,created,integrity) VALUES(?,?,?,?,?)',
                                 ('unverified', cell, 'PASS', time.time(), 'COMPLETE'))
            database.close()
            with self.assertRaises(ValueError):
                service.prune(root)


def qualify(base):
    base.mkdir(mode=0o700, parents=True, exist_ok=False)
    roots = []
    results = {}

    def create(name, configuration, launcher_crash=False):
        root = base / name
        service.prepare(root, PLAN, configuration)
        roots.append(root)
        command = [sys.executable, '-B', str(root / 'program/campaign_service.py'), 'start', '--root', str(root)]
        if launcher_crash:
            code = ('import os,signal,subprocess; subprocess.run(' + repr(command)
                    + ',check=True,stdin=subprocess.DEVNULL); os.kill(os.getpid(),signal.SIGKILL)')
            result = subprocess.run([sys.executable, '-B', '-c', code], stdin=subprocess.DEVNULL, timeout=25)
            if result.returncode != -signal.SIGKILL:
                raise AssertionError('Launching process was not actually killed')
        else:
            subprocess.run(command, check=True, stdin=subprocess.DEVNULL, timeout=25)
        return root

    try:
        configuration = settings(['PASS', 'FAIL', 'PASS'])
        configuration['cells'][0]['seconds'] = 5
        root = create('crash-and-progress', configuration, launcher_crash=True)

        def worker_ready():
            document = ledger.status(root)
            if not document['attempts']:
                return None
            path = root / 'attempts' / document['attempts'][0]['id'] / 'identity.json'
            return document if path.exists() else None

        before = wait_for(worker_ready)
        coordinator = service.names(root)[0]
        old = service.unit_status(coordinator)
        worker_before = service.unit_status(before['attempts'][0]['unit'])
        pid = int(old['MainPID'])
        cgroup = Path('/proc/' + str(pid) + '/cgroup').read_text()
        parent_line = next(line for line in Path('/proc/' + str(pid) + '/status').read_text().splitlines()
                           if line.startswith('PPid:'))
        parent_pid = parent_line.split()[1]
        parent = Path('/proc/' + parent_pid + '/comm').read_text().strip()
        if parent != 'systemd' or coordinator not in cgroup:
            raise AssertionError('Coordinator is not owned by the independent user manager')
        service.control('kill', '--kill-who=main', '--signal=SIGKILL', coordinator)
        wait_for(lambda: service.unit_status(coordinator).get('InvocationID') not in {'', old['InvocationID']})
        after = wait_for(lambda: terminal(root))
        if after['campaign']['state'] != 'COMPLETE' or [row['state'] for row in after['attempts']] != ['PASS', 'FAIL', 'PASS']:
            raise AssertionError('Crash reconciliation or ordinary-failure continuation failed')
        if before['campaign']['deadline'] != after['campaign']['deadline']:
            raise AssertionError('Restart changed original deadline')
        if after['attempts'][0]['id'] != before['attempts'][0]['id']:
            raise AssertionError('Restart changed or replayed original attempt')
        if json.loads(after['attempts'][0]['identity'])['invocation_id'] != worker_before['InvocationID']:
            raise AssertionError('Independent worker was replaced after coordinator crash')
        results.update(A={'result': 'PASS', 'root': str(root), 'executed': after['executed']},
                       B={'result': 'PARTIAL', 'proof': 'Launching process SIGKILL proved; real SSH disconnect pending'},
                       C={'result': 'PASS', 'proof': 'Actual launcher SIGKILL, systemd parent and separate manager cgroup',
                          'scope': 'IDE-independent lifecycle proved; the shared VS Code instance was not terminated',
                          'cgroup': cgroup, 'manager_pid': parent_pid},
                       D={'result': 'PASS', 'original_attempt': before['attempts'][0]['id'], 'worker_adopted': True},
                       E={'result': 'PASS', 'outcomes': ['PASS', 'FAIL', 'PASS']},
                       H={'result': 'PASS', 'deadline_before': before['campaign']['deadline'],
                          'deadline_after': after['campaign']['deadline']})
        fresh = subprocess.run([sys.executable, '-B', str(root / 'program/campaign_service.py'), 'status', '--root', str(root)],
                               capture_output=True, text=True, check=True, timeout=15, stdin=subprocess.DEVNULL)
        if json.loads(fresh.stdout)['ledger']['executed'] != 3:
            raise AssertionError('Fresh-process ledger read failed')
        results['L'] = {'result': 'PASS', 'proof': 'Fresh process read committed outcomes after launch process died'}
        service.prune(root)
        for attempt in after['attempts']:
            directory = root / 'attempts' / attempt['id']
            if not (directory / 'receipt.json').exists() or (directory / 'detail.log').exists() != (attempt['state'] != 'PASS'):
                raise AssertionError('Success/failure retention violated')
        results['K'] = {'result': 'PASS', 'proof': 'Only detail with committed valid PASS receipt deleted; FAIL retained'}

        configuration = settings(['HANG'])
        configuration['cells'][0]['timeout_seconds'] = 2
        root = create('worker-hang', configuration)
        after = wait_for(lambda: terminal(root))
        directory = root / 'attempts' / after['attempts'][0]['id']
        if after['campaign']['state'] != 'BLOCKED' or after['attempts'][0]['state'] != 'INCOMPLETE':
            raise AssertionError('Hung worker was not blocked/incomplete')
        if not (directory / 'watchdog.json').exists() or not (directory / 'detail.log').exists():
            raise AssertionError('Watchdog failed to preserve hang evidence')
        results['F'] = {'result': 'PASS', 'root': str(root), 'proof': 'Independent watchdog detected/stopped owned hang'}

        safety = []
        for behavior in ['OWNERSHIP_FAILURE', 'CAPTURE_FAILURE']:
            root = create(behavior.lower(), settings([behavior, 'PASS']))
            after = wait_for(lambda: terminal(root))
            if after['campaign']['state'] != 'BLOCKED' or len(after['attempts']) != 1:
                raise AssertionError('Safety fault did not block next admission')
            safety.append(str(root))
        results['G'] = {'result': 'PASS', 'roots': safety}

        configuration = settings(['HANG'])
        root = create('manifest-failure', configuration)
        wait_for(lambda: any((root / 'attempts' / row['id'] / 'identity.json').exists()
                             for row in ledger.status(root)['attempts']))
        manifest_path = root / 'manifest.json'
        ledger.atomic(manifest_path, manifest_path.read_text() + '\n')
        after = wait_for(lambda: terminal(root))
        if after['campaign']['state'] != 'BLOCKED' or after['passed'] != 0:
            raise AssertionError('Manifest failure did not fail closed')
        for attempt in after['attempts']:
            wait_for(lambda: service.unit_status(attempt['unit']).get('MainPID') in {'0', '', None})
            if attempt['state'] != 'INCOMPLETE':
                raise AssertionError('Admission exception did not close owned worker conservatively')
        results['G']['manifest_failure_root'] = str(root)

        configuration = settings(['PASS', 'PASS'])
        configuration['duration_seconds'] = 3
        configuration['checkpoint_seconds'] = 1
        configuration['cells'][0].update(seconds=8, estimated_seconds=0.1, timeout_seconds=20)
        root = create('clock-thresholds', configuration)
        after = wait_for(lambda: terminal(root))
        if after['campaign']['state'] != 'CLOSED' or not after['campaign']['checkpoint_done'] or len(after['attempts']) != 1:
            raise AssertionError('Compressed checkpoint/deadline closeout failed')
        if after['attempts'][0]['state'] != 'INCOMPLETE' or after['passed'] != 0:
            raise AssertionError('Interrupted threshold worker was counted as PASS')
        results['I'] = {'result': 'PASS', 'root': str(root), 'proof': 'Compressed 24h/48h thresholds; controlled incomplete closeout'}
        results['J'] = {'result': 'NOT_RUN', 'proof': 'Real remote ownership/disconnect proof pending'}
    finally:
        ledger.atomic(base / 'qualification-results.json', results)
        for root in roots:
            for attempt in ledger.status(root)['attempts']:
                service.control('stop', attempt['unit'], check=False)
            for unit in service.names(root):
                service.control('stop', unit, check=False)
        ledger.atomic(base / 'qualification-results.json', results)
    return results


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['self-test', 'qualify'])
    parser.add_argument('--root', type=Path)
    options = parser.parse_args()
    if options.action == 'self-test':
        unittest.main(argv=[__file__])
    else:
        print(json.dumps(qualify(options.root), indent=2))
