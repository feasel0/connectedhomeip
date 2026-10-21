"""Check proposed endpoint policies against the existing capture helper offline."""

import argparse
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def main() -> None:
    """Validate policy, fixed capture commands and operator execution without root."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('existing_lab_capture', args.helper)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    document = json.loads(Path(__file__).with_name('dnssd-endpoint-profiles.json').read_text())

    class EndpointPolicyTests(unittest.TestCase):
        def test_policies_use_existing_configuration_validator(self):
            for role, host in document['hosts'].items():
                config = host['configuration']
                with self.subTest(role=role), patch.object(helper, 'trusted'), \
                        patch.object(helper.Path, 'read_text', side_effect=[json.dumps(config), config['machine_id']]):
                    self.assertEqual(helper.configuration(), config)

        def test_profiles_capture_exact_endpoint_interfaces(self):
            expected = {'dut': ('dut-mdns', ['wlan0']), 'controller': ('controller-mdns', ['eth0', 'wlan0'])}
            for role, (name, interfaces) in expected.items():
                profile = document['hosts'][role]['configuration']['profiles'][name]
                with self.subTest(role=role):
                    self.assertEqual(profile['interfaces'], interfaces)
                    self.assertIsNone(profile['hci_index'])
                    self.assertIsNone(profile['recovery_unit'])
                    commands = helper.capture_commands(profile, Path('/protected/run'))
                    self.assertEqual(len(commands), 1)
                    kind, command = commands[0]
                    self.assertEqual(kind, 'dumpcap')
                    expected_command = ['/usr/bin/dumpcap', '-q']
                    for interface in interfaces:
                        expected_command.extend(['-i', interface])
                    expected_command.extend(['-b', 'filesize:65536', '-b', 'files:16',
                                             '-w', '/protected/run/packets/capture.pcapng'])
                    self.assertEqual(command, expected_command)

        def test_controller_hci_policy_is_preserved(self):
            config = document['hosts']['controller']['configuration']
            self.assertEqual(config['profiles']['controller-hci'], {
                'interfaces': [], 'hci_index': 0, 'recovery_unit': 'bluetooth.service'})

        def test_host_mismatch_is_rejected(self):
            config = document['hosts']['dut']['configuration']
            with patch.object(helper, 'trusted'), \
                    patch.object(helper.Path, 'read_text', side_effect=[json.dumps(config), 'different-host']), \
                    self.assertRaises(PermissionError):
                helper.configuration()

        def test_verify_uses_operator_identity_and_each_interface(self):
            profile = document['hosts']['controller']['configuration']['profiles']['controller-mdns']
            account = SimpleNamespace(pw_name='operator', pw_uid=1234, pw_gid=2345)
            with patch.object(helper.shutil, 'disk_usage', return_value=SimpleNamespace(free=3 * 1024 ** 3)), \
                    patch.object(helper, 'trusted'), patch.object(helper.os, 'getgrouplist', return_value=[2345]), \
                    patch.object(helper.subprocess, 'check_output', return_value='1. eth0\n2. wlan0\n') as execute:
                helper.verify_profile(profile, account)
                self.assertEqual(execute.call_args.kwargs['user'], 1234)
                self.assertEqual(execute.call_args.kwargs['extra_groups'], [2345])
                execute.return_value = '1. eth0\n'
                with self.assertRaisesRegex(RuntimeError, 'wlan0'):
                    helper.verify_profile(profile, account)

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EndpointPolicyTests))
    raise SystemExit(not result.wasSuccessful())


if __name__ == '__main__':
    main()
