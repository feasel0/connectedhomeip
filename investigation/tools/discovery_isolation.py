import argparse
import fcntl
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


def discovery_matches(expected: int, advertised: int, short: bool) -> bool:
    if not 0 <= expected < 4096 or not 0 <= advertised < 4096:
        raise ValueError('Discriminators must be 12-bit integers')
    return expected >> 8 == advertised >> 8 if short else expected == advertised


def require_closed_campaign(root: Path, proc: Path = Path('/proc')) -> None:
    owner = json.loads((root / 'runs/combined-nordic-ubuntu-TC_RT_2_1-100/owner.json').read_text())
    status = proc / str(owner['pid']) / 'stat'
    try:
        ticks = status.read_text().rsplit(')', 1)[1].split()[19]
    except FileNotFoundError:
        ticks = None
    if ticks == str(owner['start_ticks']):
        raise RuntimeError('Protected commissioning campaign still owns its original process')
    try:
        finished = json.loads((root / 'finished.json').read_text())['result']
        endurance = json.loads((root / 'endurance.json').read_text())
        external = json.loads((root / 'external-closeout.json').read_text())
    except (OSError, ValueError, KeyError) as error:
        raise RuntimeError('Protected campaign closure is unverified') from error
    if finished != endurance:
        raise RuntimeError('Campaign finalization records disagree')
    records = finished['records']
    requested = finished['requested']
    if (finished['status'] != 'CLOSED' or finished['process_exit'] != 0
            or finished['interruption'] is not None or finished.get('capture_errors')
            or not finished['same_process'] or requested != 100
            or [row['iteration'] for row in records] != list(range(1, requested + 1))
            or any(row['outcome'] not in ('PASS', 'FAIL') for row in records)):
        raise RuntimeError('Campaign did not close with complete native accounting')
    passed = sum(row['outcome'] == 'PASS' for row in records)
    failed = sum(row['outcome'] == 'FAIL' for row in records)
    actual = (requested, len(records), passed, failed, 0)
    if tuple(finished[key] for key in ('requested', 'executed', 'passed', 'failed', 'unexecuted')) != actual:
        raise RuntimeError('Campaign native counts disagree')
    if (tuple(external[key] for key in ('requested', 'completed', 'passed', 'failed', 'unexecuted_or_interrupted')) != actual
            or external['interruption'] is not None
            or external['accepted_native_records'] != records):
        raise RuntimeError('External closeout disagrees with native accounting')


def require_fixture_idle(root: Path) -> None:
    fixture = root.parent / 'nordic-fixture.lock'
    with fixture.open('r+') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('Nordic fixture lock has an active owner') from error
        uart = Path('/dev/serial/by-id/usb-SEGGER_J-Link_001050208117-if00')
        if not uart.exists():
            raise RuntimeError('Expected Nordic UART is absent')
        owners = subprocess.run(['fuser', str(uart)], capture_output=True, text=True, timeout=10)
        if owners.returncode != 1 or owners.stdout.strip() or owners.stderr.strip():
            raise RuntimeError('Nordic UART is owned or its ownership could not be verified')
        listeners = subprocess.check_output(['ss', '-H', '-ltn'], text=True, timeout=10)
        if any(line.split()[3].rsplit(':', 1)[-1] in ('57728', '57828')
                for line in listeners.splitlines()):
            raise RuntimeError('An existing Nordic fixture relay is listening')
        units = subprocess.check_output(['systemctl', 'list-units', '--all', '--plain', '--no-legend',
            '--state=active,activating,deactivating', 'rt21-endurance-20261016.service',
            'rt21-closeout-20261016.service', 'lab-resource-capture@thread-lab--*.service'],
            text=True, timeout=15)
        if units.strip():
            raise RuntimeError('Protected campaign or local capture services still own resources')
        user_units = subprocess.check_output(['systemctl', '--user', 'list-units', '--all', '--plain', '--no-legend',
            '--state=active,activating,deactivating', 'rt21-endurance-20261016.service',
            'rt21-closeout-20261016.service'], text=True, timeout=15)
        if user_units.strip():
            raise RuntimeError('A campaign user service still owns the fixture')
        captures = [path for path in Path('/proc').glob('[0-9]*/comm')
            if path.exists() and path.read_text().strip() in ('dumpcap', 'btmon', 'tcpdump')]
        if captures:
            raise RuntimeError('A capture process remains active; ownership must be resolved')


class IsolationTest(unittest.TestCase):
    def test_observed_collision_changes_with_filter_width_only(self):
        self.assertTrue(discovery_matches(3840, 4021, short=True))
        self.assertFalse(discovery_matches(3840, 4021, short=False))
        self.assertTrue(discovery_matches(3840, 3840, short=False))

    def test_different_short_discriminator_does_not_match(self):
        self.assertFalse(discovery_matches(3840, 3839, short=True))
        self.assertEqual(sum(discovery_matches(3840, value, short=True) for value in range(4096)), 256)

    def test_invalid_discriminator_is_rejected(self):
        with self.assertRaises(ValueError):
            discovery_matches(3840, 4096, short=True)

    def make_campaign(self, root, exited, active):
        campaign = root / 'campaign'
        owner = campaign / 'runs/combined-nordic-ubuntu-TC_RT_2_1-100/owner.json'
        owner.parent.mkdir(parents=True)
        owner.write_text(json.dumps({'pid': 123, 'start_ticks': '456'}))
        (campaign / 'current.json').write_text(json.dumps({'process_exit': exited}))
        records = [{'iteration': number, 'outcome': 'FAIL' if number == 75 else 'PASS'} for number in range(1, 101)]
        final = {'requested': 100, 'executed': 100, 'passed': 99, 'failed': 1,
            'unexecuted': 0, 'process_exit': 0, 'interruption': None, 'same_process': True,
            'status': 'CLOSED', 'capture_errors': [], 'records': records}
        (campaign / 'finished.json').write_text(json.dumps({'result': final}))
        (campaign / 'endurance.json').write_text(json.dumps(final))
        (campaign / 'external-closeout.json').write_text(json.dumps({'requested': 100,
            'completed': 100, 'passed': 99, 'failed': 1, 'unexecuted_or_interrupted': 0,
            'interruption': None, 'accepted_native_records': records}))
        proc = root / 'proc'
        if active:
            status = proc / '123/stat'
            status.parent.mkdir(parents=True)
            status.write_text('123 (native (controller)) ' + ' '.join(['S'] + ['0'] * 18 + ['456']))
        return campaign, proc

    def test_active_process_blocks_even_if_summary_claims_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, proc = self.make_campaign(Path(directory), 0, True)
            with self.assertRaisesRegex(RuntimeError, 'original process'):
                require_closed_campaign(campaign, proc)

    def test_missing_process_without_exit_is_not_closure(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, proc = self.make_campaign(Path(directory), None, False)
            (campaign / 'finished.json').unlink()
            with self.assertRaisesRegex(RuntimeError, 'closure is unverified'):
                require_closed_campaign(campaign, proc)

    def test_closed_process_allows_followup(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, proc = self.make_campaign(Path(directory), 1, False)
            require_closed_campaign(campaign, proc)

    def test_completed_campaign_ignores_stale_running_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, proc = self.make_campaign(Path(directory), None, False)
            require_closed_campaign(campaign, proc)

    def test_inconsistent_finalization_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, proc = self.make_campaign(Path(directory), None, False)
            path = campaign / 'endurance.json'
            final = json.loads(path.read_text())
            final['passed'] = 100
            path.write_text(json.dumps(final))
            with self.assertRaisesRegex(RuntimeError, 'finalization records disagree'):
                require_closed_campaign(campaign, proc)

    def test_external_closeout_cannot_hide_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, proc = self.make_campaign(Path(directory), None, False)
            path = campaign / 'external-closeout.json'
            final = json.loads(path.read_text())
            final['passed'], final['failed'] = 100, 0
            path.write_text(json.dumps(final))
            with self.assertRaisesRegex(RuntimeError, 'External closeout disagrees'):
                require_closed_campaign(campaign, proc)

    def test_incomplete_native_ledger_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, proc = self.make_campaign(Path(directory), None, False)
            final = json.loads((campaign / 'endurance.json').read_text())
            final['records'].pop()
            (campaign / 'endurance.json').write_text(json.dumps(final))
            (campaign / 'finished.json').write_text(json.dumps({'result': final}))
            with self.assertRaisesRegex(RuntimeError, 'complete native accounting'):
                require_closed_campaign(campaign, proc)

    def test_fixture_lock_owner_blocks_followup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'nordic-fixture.lock').touch()
            with (root / 'nordic-fixture.lock').open('r+') as owner:
                fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(RuntimeError, 'active owner'):
                    require_fixture_idle(root / 'campaign')

    def test_capture_service_blocks_followup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'nordic-fixture.lock').touch()
            with patch.object(Path, 'exists', return_value=True), patch.object(subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], 1, '', '')), patch.object(subprocess,
                    'check_output', side_effect=['', 'lab-resource-capture@thread-lab--active.service']):
                with self.assertRaisesRegex(RuntimeError, 'capture services'):
                    require_fixture_idle(root / 'campaign')

    def test_uart_owner_blocks_followup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'nordic-fixture.lock').touch()
            with patch.object(Path, 'exists', return_value=True), patch.object(subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], 0, '123', '')):
                with self.assertRaisesRegex(RuntimeError, 'UART is owned'):
                    require_fixture_idle(root / 'campaign')

    def test_user_service_blocks_followup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'nordic-fixture.lock').touch()
            with patch.object(Path, 'exists', return_value=True), patch.object(subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], 1, '', '')), patch.object(subprocess,
                    'check_output', side_effect=['', '', 'rt21-endurance-20261016.service']):
                with self.assertRaisesRegex(RuntimeError, 'user service'):
                    require_fixture_idle(root / 'campaign')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--protected-run', type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    if arguments.self_test:
        unittest.main(argv=[__file__])
        return
    if arguments.protected_run is None:
        parser.error('--protected-run is required')
    try:
        require_closed_campaign(arguments.protected_run)
        require_fixture_idle(arguments.protected_run)
    except (OSError, ValueError, KeyError, IndexError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({'launch_allowed': False, 'reason': str(error)}))
        raise SystemExit(2)
    command = arguments.command
    if command[:1] == ['--']:
        command = command[1:]
    print(json.dumps({'launch_allowed': True,
        'scope': 'protected campaign closure and local fixture idle; remote/discovery preflight still required'}), flush=True)
    if command:
        sys.exit(subprocess.run(command, check=False).returncode)


if __name__ == '__main__':
    main()
