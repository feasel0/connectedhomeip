import argparse
import fcntl
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
import campaign_remote_worker as remote


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
    def test_versioned_xml_assets_are_verified_through_the_pinned_manifest_before_native_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            xml = root / 'cluster.xml'
            xml.write_text('<cluster/>')
            manifest = root / 'xml-manifest.json'
            ledger.atomic(manifest, {str(xml): ledger.digest(xml)})
            profile = {'source_hashes': {str(manifest): ledger.digest(manifest)}, 'asset_manifest': str(manifest)}
            campaign_native.verify_profile_sources(profile)
            xml.write_text('<changed/>')
            with self.assertRaisesRegex(ValueError, 'XML asset'):
                campaign_native.verify_profile_sources(profile)

    def test_incomplete_native_block_preserves_both_outcomes_and_quarantines_only_qualified_cell(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger.atomic(root / 'request.json', {'attempt_id': 'owned'})
            ledger.atomic(root / 'identity.json', {'worker': 'owned'})
            document = {'test_summary_record': {'total_number_of_iterations': 10,
                'number_of_iterations_completed': 2, 'number_of_iterations_passed': 1, 'number_of_iterations_failed': 1},
                'list_of_iteration_records': [{'iteration_number': ordinal, 'iteration_data': {'iteration_tc_execution_data': {
                    'iteration_begin_time': 'start', 'iteration_end_time': 'end', 'iteration_result': outcome}}}
                    for ordinal, outcome in [(1, 'PASS'), (2, 'FAIL')]]}
            ledger.atomic(root / 'summary.json', document)
            profile = {'baseline': 'pristine-upstream', 'requested_iterations': 10, 'capture_id': 'owned-test-capture',
                'source_hashes': {str(root / 'summary.json'): ledger.digest(root / 'summary.json')},
                'rf_lock': str(root / 'rf.lock'), 'argv': [sys.executable, '-B', '-c',
                    'import threading;threading.Event().wait(0.2)'], 'native_timeout_seconds': 10,
                'summary_glob': 'summary.json', 'incomplete_resources': ['cell:owned']}
            with patch.object(campaign_native, 'hook', return_value={}):
                result = campaign_native.execute_guarded(profile, root, threading.Event())
            self.assertEqual(result['outcome'], 'INCOMPLETE')
            self.assertEqual([row['outcome'] for row in result['iterations']], ['PASS', 'FAIL'])
            self.assertEqual(result['quarantined_resources'], ['cell:owned'])
            self.assertTrue(result['cleanup_complete'])
            self.assertEqual(result['unexecuted'], 8)
            complete = root / 'complete'
            complete.mkdir(mode=0o700)
            ledger.atomic(complete / 'request.json', {'attempt_id': 'complete'})
            ledger.atomic(complete / 'identity.json', {'worker': 'owned'})
            document['test_summary_record']['total_number_of_iterations'] = 2
            ledger.atomic(complete / 'summary.json', document)
            profile.update(requested_iterations=2, source_hashes={str(complete / 'summary.json'):
                ledger.digest(complete / 'summary.json')}, argv=[sys.executable, '-B', '-c',
                    'import sys,threading;threading.Event().wait(0.2);sys.exit(1)'])
            with patch.object(campaign_native, 'hook', return_value={}):
                result = campaign_native.execute_guarded(profile, complete, threading.Event(), qualification=True)
            self.assertEqual(result['outcome'], 'FAIL')
            self.assertTrue(result['complete_block'])

    def test_production_admission_reuses_only_the_unlaunched_original_unowned_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'campaign'
            original = ledger.initialize(root, PLAN)
            options = settings(['PASS'])
            options.update(mode='hardware', duration_seconds=172800)
            options['cells'][0].pop('behavior')
            options['cells'][0]['target_iterations'] = 15
            service.prepare(root, PLAN, options)
            document = ledger.status(root)
            self.assertEqual(document['campaign']['id'], original)
            self.assertIsNone(document['campaign']['started'])
            self.assertEqual(document['executed'], 0)
            with self.assertRaisesRegex(ValueError, 'unlaunched'):
                service.prepare(root, PLAN, options)

    def test_native_success_capture_retention_compiles_and_uses_only_verified_closed_segments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger.atomic(root / 'capture-evidence.json', {'integrity_complete': True, 'capture': {'state': 'stopped'},
                'closed_segments': {'/var/lib/lab-resource-helper/runs/dut-mdns--owned/packets/capture.pcapng': 'a' * 64}})
            profile = {'capture_access': ['verified-ssh'], 'capture_id': 'owned', 'dut_machine_id': 'verified-dut'}
            def reply(transport, code):
                compile(code, '<real-generated-capture-retention>', 'exec')
                self.assertEqual(transport['remote_access'], ['verified-ssh'])
                self.assertIn('dut-mdns--owned', code)
                self.assertIn('st_nlink==1', code)
                return {'all_absent': True}
            with patch.object(campaign_native, 'remote_json', side_effect=reply):
                campaign_native.retain_native_success(profile, root)
            self.assertTrue(json.loads((root / 'capture-retention.json').read_text())['all_absent'])

    def test_hardware_preparation_rejects_stretch_target_not_in_approved_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            options = settings(['PASS'])
            options['mode'] = 'hardware'
            options['duration_seconds'] = 172800
            options['cells'][0].pop('behavior')
            options['cells'][0]['target_iterations'] = 30
            with self.assertRaisesRegex(ValueError, 'approved plan'):
                service.prepare(Path(directory) / 'campaign', PLAN, options)

    def test_success_retention_resumes_without_requiring_already_deleted_raw_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger.atomic(root / 'receipt.json', {'outcome': 'PASS'})
            ledger.atomic(root / 'remaining.log', 'closed raw detail')
            plan = {'receipt_hash': ledger.digest(root / 'receipt.json'), 'bytes': 31, 'deletions': [
                {'file': 'already-deleted.log', 'sha256': 'a' * 64},
                {'file': 'remaining.log', 'sha256': ledger.digest(root / 'remaining.log')}]}
            service.finish_retention(root, plan)
            self.assertFalse((root / 'remaining.log').exists())
            self.assertTrue(json.loads((root / 'retention-complete.json').read_text())['all_absent'])

    def test_hardware_scheduler_finishes_all_minimums_before_stretch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'campaign'
            options = settings(['PASS', 'PASS'])
            service.prepare(root, PLAN, options)
            options['mode'] = 'hardware'
            for cell in options['cells']:
                cell.update(target_iterations=15, stretch_estimated_seconds=20)
            options['native_profile'] = {cell['id']: {'stretch_profile': {'requested_iterations': 5}}
                                        for cell in options['cells']}
            database = ledger.connection(root)
            first, second = options['cells']
            with database:
                database.execute('INSERT INTO attempts(id,cell_id,state,created) VALUES(?,?,?,?)',
                                 ('first-minimum', first['id'], 'PASS', time.time()))
                for ordinal in range(1, 11):
                    ledger.record_outcome(database, 'first-minimum', ordinal, 'PASS', 'a' * 64)
            selected = service.next_block(database, options)
            self.assertEqual((selected['id'], selected['block_phase']), (second['id'], 'minimum'))
            with database:
                database.execute('INSERT INTO attempts(id,cell_id,state,created) VALUES(?,?,?,?)',
                                 ('second-minimum', second['id'], 'FAIL', time.time()))
                for ordinal in range(1, 11):
                    ledger.record_outcome(database, 'second-minimum', ordinal, 'FAIL', 'b' * 64)
            selected = service.next_block(database, options)
            self.assertEqual((selected['id'], selected['block_phase']), (first['id'], 'stretch'))
            self.assertEqual(selected['estimated_seconds'], 20)
            database.close()

    def test_native_success_pruning_retains_receipts_and_summaries_but_deletes_closed_raw_detail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'campaign'
            service.prepare(root, PLAN, settings(['PASS']))
            database = ledger.connection(root)
            cell = database.execute("SELECT id FROM cells WHERE state='ADMITTED'").fetchone()[0]
            attempt = root / 'attempts/closed-success';attempt.mkdir(parents=True)
            ledger.atomic(attempt / 'detail.log', 'closed native detail')
            ledger.atomic(attempt / 'native.private.log', 'private raw log')
            ledger.atomic(attempt / 'summary.json', {'passed': 1})
            ledger.atomic(attempt / 'receipt.json', {'outcome': 'PASS', 'cleanup_complete': True,
                'detail_hash': ledger.digest(attempt / 'detail.log'), 'artifacts': {
                    filename: ledger.digest(attempt / filename) for filename in ['native.private.log', 'summary.json']}})
            with database:
                database.execute('INSERT INTO attempts(id,cell_id,state,unit,created,integrity) VALUES(?,?,?,?,?,?)',
                                 ('closed-success', cell, 'PASS', 'owned-unit', time.time(), 'COMPLETE'))
                ledger.record_outcome(database, 'closed-success', 1, 'PASS', ledger.digest(attempt / 'receipt.json'))
            database.close()
            with patch.object(service, 'unit_status', return_value={'MainPID': '0', 'SubState': 'exited'}):
                service.prune(root)
            self.assertFalse((attempt / 'native.private.log').exists())
            self.assertFalse((attempt / 'detail.log').exists())
            self.assertTrue((attempt / 'summary.json').exists())
            self.assertTrue((attempt / 'receipt.json').exists())
            self.assertTrue(json.loads((attempt / 'retention-complete.json').read_text())['all_absent'])

    def test_remote_native_handoff_compiles_and_preserves_partial_outcomes_after_worker_closure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = root / 'remote-template.json'
            ledger.atomic(template, {name: ['/usr/bin/true', '{remote_profile}'] for name in
                ['argv', 'before', 'capture_start', 'capture_health', 'capture_stop', 'recovery', 'after']})
            ledger.atomic(root / 'request.json', {'attempt_id': 'owned-attempt', 'rf_owner': {'machine_id': 'pi'}})
            ledger.atomic(root / 'identity.json', {'worker': 'ubuntu-owner'})
            summary = {'test_summary_record': {'total_number_of_iterations': 10, 'number_of_iterations_completed': 1,
                'number_of_iterations_passed': 1, 'number_of_iterations_failed': 0}, 'list_of_iteration_records': [
                {'iteration_number': 1, 'iteration_data': {'iteration_tc_execution_data': {
                    'iteration_begin_time': 'start', 'iteration_end_time': 'end', 'iteration_result': 'PASS'}}}]}
            profile = {'source_hashes': {str(template): ledger.digest(template)}, 'remote_root': '/private/remote',
                'remote_template': str(template), 'remote_program': '/private/program', 'native_timeout_seconds': 60,
                'controller_machine_id': 'pi', 'requested_iterations': 10, 'summary_glob': 'remote-summary/summary.json'}
            def remote_reply(profile, code):
                compile(code, '<real-generated-remote-snippet>', 'exec')
                if 'queue(' in code:
                    return {'state': 'RESERVED'}
                return {'job': {'state': 'INCOMPLETE', 'live': False, 'child_live': False, 'cleanup_closed': True},
                        'summary': summary, 'native_receipt': {'outcome': 'INCOMPLETE', 'cleanup_complete': True}}
            with patch.object(campaign_native, 'remote_json', side_effect=remote_reply):
                result = campaign_native.execute_remote(profile, root, threading.Event(), True)
            self.assertTrue(result['remote_worker_stopped'])
            self.assertEqual(result['iterations'][0]['outcome'], 'PASS')
            self.assertTrue((root / 'iteration-receipts/00001.json').exists())

    def test_native_guard_does_not_call_capture_stop_before_capture_was_requested(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(campaign_native, 'execute', side_effect=campaign_native.NativeResourceError('fixture unavailable')), \
                    patch.object(campaign_native, 'hook', return_value={}) as hook:
                result = campaign_native.execute_guarded({'failure_resources': ['fixture:wifi']}, root, threading.Event())
            self.assertEqual(result['failure_domain'], 'resource')
            self.assertTrue(result['cleanup_complete'])
            self.assertEqual([call.args[1] for call in hook.call_args_list], ['after'])

    def test_remote_native_transport_compiles_code_and_refuses_nonzero_exit(self):
        result = subprocess.CompletedProcess([], 1, stdout='', stderr='private transport failure')
        with patch.object(campaign_native.subprocess, 'run', return_value=result):
            with self.assertRaises(campaign_native.NativeResourceError):
                campaign_native.remote_json({'remote_access': ['/usr/bin/false']}, 'print("safe")')

    def test_native_hook_distinguishes_resource_failures_from_integrity_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = {'before': ['/usr/bin/false']}
            result = subprocess.CompletedProcess([], 1, stdout='', stderr='NativeResourceError: unreachable fixture')
            with patch.object(campaign_native.subprocess, 'run', return_value=result):
                with self.assertRaises(campaign_native.NativeResourceError):
                    campaign_native.hook(profile, 'before', root, [])
            result.stderr = 'ValueError: changed immutable source'
            with patch.object(campaign_native.subprocess, 'run', return_value=result):
                with self.assertRaises(ValueError):
                    campaign_native.hook(profile, 'before', root, [])

    def test_isolated_infrastructure_failure_quarantines_only_affected_cells(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'qualification'
            options = settings(['PASS', 'PASS'])
            service.prepare(root, PLAN, options)
            first, second = options['cells']
            first['resources'] = ['controller:pi']
            second['resources'] = ['controller:ubuntu']
            options['native_profile'] = {first['id']: {'failure_resources': ['controller:pi']}}
            database = ledger.connection(root)
            with database:
                database.execute('INSERT INTO attempts(id,cell_id,state,created) VALUES(?,?,?,?)',
                                 ('broken-pi', first['id'], 'INCOMPLETE', time.time()))
                attempt = database.execute("SELECT * FROM attempts WHERE id='broken-pi'").fetchone()
                service.isolate_failure(database, attempt, options, {'failure_domain': 'resource',
                    'cleanup_complete': True, 'quarantined_resources': ['controller:pi']})
            self.assertFalse(service.unsafe_attempt(database))
            self.assertEqual(database.execute('SELECT state FROM cells WHERE id=?', (first['id'],)).fetchone()[0], 'QUARANTINED')
            self.assertEqual(database.execute('SELECT state FROM cells WHERE id=?', (second['id'],)).fetchone()[0], 'ADMITTED')
            with database:
                service.isolate_failure(database, attempt, options, {'failure_domain': 'integrity', 'cleanup_complete': True})
            self.assertTrue(service.unsafe_attempt(database))
            database.close()

    def test_native_wifi_capture_rejects_packet_loss_and_rotation_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = {'source_hashes': {}, 'capture_id': 'owned-capture'}
            broker = {'capture': {'profile': 'dut-mdns', 'run_id': 'owned-capture', 'state': 'stopped',
                                 'child_exit_codes': [0], 'error': None}}
            evidence = {'free_bytes': 12 * 1024 ** 3, 'file_count': 1, 'bytes': 1024,
                        'closed_segments': {'segment': 'a' * 64}, 'drop_counts': [0], 'packet_counts': [3]}
            with patch.object(campaign_native, 'fixture_json', side_effect=[broker, evidence]):
                self.assertTrue(campaign_native.wifi_hook(profile, root, 'capture_stop')['integrity_complete'])
            with patch.object(campaign_native, 'fixture_json', side_effect=[broker, evidence]) as query:
                campaign_native.wifi_hook(profile, root, 'capture_stop')
                program = query.call_args_list[1].args[1][-1]
            import re
            expression = re.search(r're.findall\(r"(Packets received/dropped[^\"]+)"', program).group(1)
            self.assertEqual(re.findall(expression, "Packets received/dropped on interface 'wlan0': 1132/0 (pcap:0/dumpcap:0)"), ['0'])
            self.assertEqual(re.findall(expression, "Packets received/dropped on interface 'wlan0': 1132/184 (pcap:184/dumpcap:0)"), ['184'])
            with patch.object(campaign_native, 'fixture_json', side_effect=[broker, dict(evidence, drop_counts=[1])]):
                with self.assertRaisesRegex(ValueError, 'packet loss'):
                    campaign_native.wifi_hook(profile, root, 'capture_stop')
            with patch.object(campaign_native, 'fixture_json', side_effect=[broker, dict(evidence, closed_segments={})]):
                with self.assertRaisesRegex(ValueError, 'pre-overwrite'):
                    campaign_native.wifi_hook(profile, root, 'capture_stop')

    def test_partial_native_iterations_are_durable_and_cannot_be_rewritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger.atomic(root / 'request.json', {'attempt': 'bounded-control'})
            ledger.atomic(root / 'identity.json', {'worker': 'independent-service'})
            profile = {'requested_iterations': 10, 'summary_glob': 'qa/summary.json'}
            document = {'test_summary_record': {'total_number_of_iterations': 10,
                'number_of_iterations_completed': 1, 'number_of_iterations_passed': 1, 'number_of_iterations_failed': 0},
                'list_of_iteration_records': [{'iteration_number': 1, 'iteration_data': {'iteration_tc_execution_data': {
                    'iteration_begin_time': '2026-10-25T20:00:00', 'iteration_end_time': '2026-10-25T20:00:05',
                    'iteration_result': 'PASS'}}}]}
            ledger.atomic(root / 'qa/summary.json', document)
            outcomes = campaign_native.snapshot_iterations(profile, root)
            self.assertEqual([(row['ordinal'], row['outcome']) for row in outcomes], [(1, 'PASS')])
            receipt = root / 'iteration-receipts/00001.json'
            original = ledger.digest(receipt)
            (root / 'qa/summary.json').write_text('{')
            self.assertEqual(campaign_native.snapshot_iterations(profile, root), [])
            self.assertEqual(ledger.digest(receipt), original)
            document['test_summary_record'].update(number_of_iterations_passed=0, number_of_iterations_failed=1)
            document['list_of_iteration_records'][0]['iteration_data']['iteration_tc_execution_data']['iteration_result'] = 'FAIL'
            ledger.atomic(root / 'qa/summary.json', document)
            with self.assertRaisesRegex(ValueError, 'changed after durable publication'):
                campaign_native.snapshot_iterations(profile, root)

    def test_native_qualification_has_separate_bounded_ledger_without_faking_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'qualification'
            cell = settings(['PASS'])['cells'][0]
            cell.pop('behavior')
            profile = {'baseline': 'pristine-upstream', 'requested_iterations': 1, 'native_timeout_seconds': 60}
            service.prepare(root, PLAN, {'mode': 'qualification', 'cells': [cell], 'duration_seconds': 300,
                                        'native_profile': {cell['id']: profile}})
            document = service.configuration(root)
            self.assertEqual(document['mode'], 'qualification')
            self.assertNotIn('gates', document)
            self.assertEqual(ledger.status(root)['executed'], 0)
            with self.assertRaisesRegex(ValueError, 'whole minimum block'):
                campaign_native.execute(profile, root, threading.Event())
            with self.assertRaisesRegex(ValueError, 'immutable loaded-source'):
                campaign_native.execute(profile, root, threading.Event(), qualification=True)

    def test_global_rf_reservation_survives_restart_and_requires_exact_closed_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'ledger'
            campaign = ledger.initialize(root, PLAN)
            owner = {'campaign_id': campaign, 'attempt_id': 'first', 'worker': 'remote-job-first',
                     'machine_id': 'controller-pi', 'boot_id': 'original-boot'}
            contender = dict(owner, attempt_id='second', worker='ubuntu-worker', machine_id='ubuntu')
            database = ledger.connection(root)
            ledger.reserve_resources(database, ['rf:lab'], owner)
            database.close()
            database = ledger.connection(root)
            ledger.reserve_resources(database, ['rf:lab'], owner)
            with self.assertRaisesRegex(ValueError, 'positive reconciliation'):
                ledger.reserve_resources(database, ['rf:lab', 'otbr:ubuntu'], contender)
            self.assertIsNone(database.execute("SELECT * FROM ownership WHERE resource='otbr:ubuntu'").fetchone())
            closure = {'owner': owner, 'worker_stopped': False, 'fixture_ready': True, 'capture_closed': True}
            with self.assertRaisesRegex(ValueError, 'closure required'):
                ledger.release_resources(database, ['rf:lab'], owner, closure)
            closure['worker_stopped'] = True
            with self.assertRaises(ValueError):
                ledger.release_resources(database, ['rf:lab'], contender, dict(closure, owner=contender))
            ledger.release_resources(database, ['rf:lab'], owner, closure)
            ledger.reserve_resources(database, ['rf:lab'], contender)
            self.assertEqual(database.execute("SELECT attempt_id FROM ownership WHERE resource='rf:lab'").fetchone()[0], 'second')
            database.close()

    def test_shared_resource_guard_distinguishes_oom_from_counter_reset(self):
        previous = {'free_bytes': 12 * 1024 ** 3, 'ram_bytes': 1024 ** 3, 'boot_id': 'same', 'oom_kills': 3}
        current = dict(previous, oom_kills=4)
        self.assertEqual(ledger.health_violation(current, previous), 'new-host-oom-kill')
        current['boot_id'] = 'new'
        self.assertIsNone(ledger.health_violation(current, previous))
        current['free_bytes'] = 7 * 1024 ** 3
        self.assertEqual(ledger.health_violation(current, previous), 'disk-reserve')

    def test_shared_rf_lease_can_be_exclusive_on_read_only_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            lease = Path(directory) / 'rf.lock'
            lease.touch()
            with lease.open('r') as owner, lease.open('r') as contender:
                fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_fixture_smoke_refuses_host_tmp_alias_before_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tmp').symlink_to('/tmp', target_is_directory=True)
            with patch.dict(os.environ, HOME=str(root / 'home')):
                with self.assertRaisesRegex(ValueError, 'namespace required before imports'):
                    campaign_native.fixture_smoke({}, root)

    def test_smoke_capture_rejects_wrong_owner_and_retains_failed_closure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger.atomic(root / 'capture-request.json', {})
            profile = {'capture_profile': 'dut-mdns', 'capture_id': 'reserved'}
            reply = {'capture': {'profile': 'dut-mdns', 'run_id': 'different', 'state': 'stopped', 'child_exit_codes': [0]}}
            with patch.object(campaign_native, 'hook', return_value=reply):
                with self.assertRaises(ValueError):
                    campaign_native.close_smoke_capture(profile, root)
                reply['capture']['run_id'] = 'reserved'
                reply['capture']['child_exit_codes'] = [1]
                with self.assertRaises(ValueError):
                    campaign_native.close_smoke_capture(profile, root)
                self.assertFalse((root / 'capture-closed.json').exists())
                reply['capture']['child_exit_codes'] = [0]
                campaign_native.close_smoke_capture(profile, root)
            with patch.object(campaign_native, 'hook') as hook:
                campaign_native.close_smoke_capture(profile, root)
                hook.assert_not_called()

    def test_smoke_external_close_stops_fixture_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(campaign_native, 'hook', return_value={'no_live_dut': True}) as hook, \
                    patch.object(campaign_native, 'close_smoke_capture') as capture:
                campaign_native.close_smoke_fixture({}, root)
                campaign_native.close_smoke_fixture({}, root)
            hook.assert_called_once_with({}, 'fixture_stop', root, ['no_live_dut'])
            self.assertEqual(capture.call_count, 2)
            self.assertTrue((root / 'fixture-closed.json').exists())

    def test_smoke_external_close_attempts_capture_after_fixture_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(campaign_native, 'hook', side_effect=ValueError('Fixture still live')), \
                    patch.object(campaign_native, 'close_smoke_capture') as capture:
                with self.assertRaisesRegex(ValueError, 'Fixture still live'):
                    campaign_native.close_smoke_fixture({}, root)
            capture.assert_called_once_with({}, root)
            self.assertFalse((root / 'fixture-closed.json').exists())

    def test_dut_external_close_refuses_host_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tmp').mkdir()
            with self.assertRaisesRegex(ValueError, 'exact private single-user namespace'):
                campaign_native.stop_smoke_dut(root, Path('/usr/bin/true'), '0' * 64)

    def test_smoke_requires_explicit_hashed_paa_store(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = {'paa_trust_store': str(root), 'source_hashes': {}}
            with self.assertRaisesRegex(ValueError, 'PAA certificates'):
                campaign_native.smoke_trust_store(profile)
            certificate = root / 'root.der'
            certificate.write_bytes(b'public-test-certificate')
            with self.assertRaisesRegex(ValueError, 'PAA certificates'):
                campaign_native.smoke_trust_store(profile)
            profile['source_hashes'][str(certificate)] = ledger.digest(certificate)
            self.assertEqual(campaign_native.smoke_trust_store(profile), str(root))

    def test_dut_external_close_signals_only_private_namespace_process(self):
        from campaign_isolation import isolated_command

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = ('import json,subprocess,sys;from pathlib import Path;sys.path.insert(0,' +
                    repr(str(Path(__file__).parent)) + ');import campaign_native as native;'
                    'from campaign_state import digest;process=subprocess.Popen(["/usr/bin/sleep","60"]);'
                    'result=native.stop_smoke_dut(Path(' + repr(str(root)) + '),Path("/usr/bin/sleep"),'
                    'digest(Path("/usr/bin/sleep")));assert result["pids"]==[process.pid];'
                    'assert process.wait(timeout=5)==-15;print(json.dumps(result))')
            process = subprocess.run(isolated_command(root, [], [sys.executable, '-B', '-c', code]),
                                     capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertTrue(json.loads(process.stdout)['no_live_dut'])

    def test_shared_host_health_records_pressure_and_oom_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = ledger.host_health(Path(directory))
        self.assertGreater(sample['ram_bytes'], 0)
        self.assertGreater(sample['free_bytes'], 0)
        self.assertEqual(len(sample['load_average']), 3)
        self.assertEqual(set(sample['pressure']), {'cpu', 'memory', 'io'})
        self.assertTrue(sample['oom_kills'] is None or sample['oom_kills'] >= 0)

    def test_remote_watchdog_removes_schedule_only_after_both_owners_are_dead(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger.atomic(root / 'request.json', {'attempt_id': 'closed', 'profile': {}})
            ledger.atomic(root / 'child-identity.json', {'pid': 123})
            with patch.object(remote, 'status', return_value={'state': 'PASS', 'live': False}), \
                    patch.object(remote, 'live', return_value=False), patch.object(remote, 'cron_entry') as cron:
                remote.job_watch(root)
                cron.assert_called_once_with(root, 'closed', False)
            self.assertFalse((root / 'watchdog-stop.json').exists())

    def test_remote_cleanup_runs_real_command_once_after_closure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = Path(__file__).resolve()
            ledger.atomic(root / 'request.json', {'profile': {'cleanup_argv': [sys.executable, '-c', 'print("closed")'],
                'source_hashes': {str(source): ledger.digest(source)}}})
            self.assertTrue(remote.job_cleanup(root))
            self.assertTrue(remote.job_cleanup(root))
            self.assertEqual(len(list(root.glob('cleanup-attempt-*.json'))), 1)
            self.assertTrue((root / 'cleanup-closed.json').exists())

    def test_remote_cleanup_failure_is_bounded_and_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = Path(__file__).resolve()
            ledger.atomic(root / 'request.json', {'profile': {'cleanup_argv': ['/usr/bin/false'],
                'source_hashes': {str(source): ledger.digest(source)}}})
            for _ in range(4):
                self.assertFalse(remote.job_cleanup(root))
            self.assertEqual(len(list(root.glob('cleanup-attempt-*.json'))), 3)
            self.assertTrue((root / 'cleanup-exhausted.json').exists())
            self.assertFalse((root / 'cleanup-closed.json').exists())

    def test_remote_watchdog_retains_schedule_until_cleanup_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger.atomic(root / 'request.json', {'attempt_id': 'pending'})
            ledger.atomic(root / 'child-identity.json', {'pid': 123})
            with patch.object(remote, 'status', return_value={'state': 'INCOMPLETE', 'live': False}), \
                    patch.object(remote, 'live', return_value=False), patch.object(remote, 'job_cleanup', return_value=False), \
                    patch.object(remote, 'cron_entry') as cron:
                remote.job_watch(root)
                cron.assert_not_called()

    def test_remote_watchdog_closes_orphan_before_removing_schedule(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ledger.atomic(root / 'request.json', {'attempt_id': 'owned'})
            ledger.atomic(root / 'child-identity.json', {'pid': 123, 'deadline': time.time() + 60})
            with patch.object(remote, 'status', return_value={'state': 'INCOMPLETE', 'live': False}), \
                    patch.object(remote, 'live', return_value=True), patch.object(remote.os, 'getpgid', return_value=123), \
                    patch.object(remote.os, 'killpg') as kill, patch.object(remote, 'cron_entry') as cron:
                remote.job_watch(root)
                kill.assert_called_once_with(123, signal.SIGTERM)
                cron.assert_not_called()

    def test_fixture_smoke_refuses_host_native_paths_before_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tmp').mkdir()
            with self.assertRaisesRegex(ValueError, 'namespace required before imports'):
                campaign_native.fixture_smoke({}, root)

    def test_remote_queue_rejects_unbounded_or_changed_program_before_cron(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'job'
            machine = Path('/etc/machine-id').read_text().strip()
            profile = {'kind': 'build', 'timeout_seconds': 172801, 'argv': ['/usr/bin/true'],
                       'source_hashes': {str(Path(__file__)): ledger.digest(Path(__file__))}}
            with patch.object(remote, 'cron_entry') as cron:
                with self.assertRaises(ValueError):
                    remote.queue(root, machine, 'owned-build', profile)
                profile['timeout_seconds'] = 60
                profile['source_hashes'][str(Path(__file__))] = '0' * 64
                with self.assertRaises(ValueError):
                    remote.queue(root, machine, 'owned-build', profile)
                cron.assert_not_called()
            self.assertFalse(root.exists())

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
            configuration['cells'][0]['target_iterations'] = 15
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
