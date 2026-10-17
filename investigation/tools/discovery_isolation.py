import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


def discovery_matches(expected: int, advertised: int, short: bool) -> bool:
    if not 0 <= expected < 4096 or not 0 <= advertised < 4096:
        raise ValueError('Discriminators must be 12-bit integers')
    return expected >> 8 == advertised >> 8 if short else expected == advertised


def require_closed_campaign(root: Path, proc: Path = Path('/proc')) -> None:
    owner = json.loads((root / 'runs/combined-nordic-ubuntu-TC_RT_2_1-100/owner.json').read_text())
    current = json.loads((root / 'current.json').read_text())
    status = proc / str(owner['pid']) / 'stat'
    try:
        ticks = status.read_text().rsplit(')', 1)[1].split()[19]
    except FileNotFoundError:
        ticks = None
    if ticks == str(owner['start_ticks']):
        raise RuntimeError('Protected commissioning campaign still owns its original process')
    if current.get('process_exit') is None:
        raise RuntimeError('Protected campaign closure is unverified')


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
            with self.assertRaisesRegex(RuntimeError, 'closure is unverified'):
                require_closed_campaign(campaign, proc)

    def test_closed_process_allows_followup(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign, proc = self.make_campaign(Path(directory), 1, False)
            require_closed_campaign(campaign, proc)


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
    except (OSError, ValueError, KeyError, IndexError, RuntimeError) as error:
        print(json.dumps({'launch_allowed': False, 'reason': str(error)}))
        raise SystemExit(2)
    command = arguments.command
    if command[:1] == ['--']:
        command = command[1:]
    print(json.dumps({'launch_allowed': True, 'scope': 'protected campaign closure only'}), flush=True)
    if command:
        sys.exit(subprocess.run(command, check=False).returncode)


if __name__ == '__main__':
    main()
