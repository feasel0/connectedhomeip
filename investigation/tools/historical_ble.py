"""Account for historical BLE outcomes using value-free original evidence."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import unittest

from trace_lifecycle import HEADER, save


CATALOG = Path(__file__).resolve().parents[1] / 'pr539-failure-evidence/catalog.json'
LABELS = {
    'adapter_unavailable': 'BLE adapter unavailable',
    'incorrect_state': 'Incorrect state',
    'scan_started': 'ChipDeviceScanner has started scanning',
    'scan_start_failed': 'Failed to initiate BLE scan start',
    'scan_stop_failed': 'Failed to initiate BLE scan stop',
    'device_found': 'CHIP Device found',
    'ble_connected': 'BLE connection established',
    'ble_connect_failed': 'BLE connection failed',
    'pase_established': 'PASE session established',
}


def markers(line: str) -> dict:
    """Return fixed labels and typed identities, never arbitrary log text."""
    result = {}
    labels = [name for name, text in LABELS.items() if text.lower() in line.lower()]
    if labels:
        result['labels'] = labels
    for key, pattern in {
        'adapter_paths': r'/org/bluez/hci\d+',
        'dbus_errors': r'org\.bluez\.Error\.[A-Za-z]+',
        'codes': r'CHIP Error (0x[0-9a-fA-F]{8})',
        'sources': r'([A-Za-z0-9_]+\.cpp):(\d+)',
    }.items():
        matches = re.findall(pattern, line)
        if matches:
            result[key] = matches
    header = HEADER.search(line)
    if header and int(header[6], 16) == 0 and int(header[7], 16) in (32, 33, 34, 35, 36):
        result['pase_header'] = {'direction': header[1], 'exchange': int(header[2]), 'session': int(header[4]),
            'counter': int(header[5]), 'opcode': int(header[7], 16)}
    return result


def scan(path: Path) -> dict:
    """Hash an original and retain only allowlisted marker fields."""
    digest = hashlib.sha256()
    rows = []
    with path.open('rb') as stream:
        for number, encoded in enumerate(stream, 1):
            digest.update(encoded)
            fields = markers(encoded.decode(errors='replace'))
            if fields:
                rows.append({'line': number, **fields})
    return {'path': str(path), 'sha256': digest.hexdigest(), 'events': rows}


def controller_indexes(value) -> list[int]:
    """Extract only the BLE index from structured invocation argv arrays."""
    found = []
    if isinstance(value, dict):
        for item in value.values():
            found.extend(controller_indexes(item))
    elif isinstance(value, list):
        if '--ble-controller' in value:
            found.append(int(value[value.index('--ble-controller') + 1]))
        else:
            for item in value:
                found.extend(controller_indexes(item))
    return found


def local_phase(logs: list[dict]) -> str:
    """Distinguish an observed failure stage from an unproven primary cause."""
    events = [event for log in logs for event in log['events']]
    if any('adapter_unavailable' in event.get('labels', []) for event in events):
        return 'LOCAL_ADAPTER_UNAVAILABLE'
    for log in logs:
        timed_out = False
        for event in log['events']:
            if ('BLEManagerImpl.cpp', '937') in map(tuple, event.get('sources', [])) and '0x00000032' in event.get('codes', []):
                timed_out = True
            if timed_out and 'org.bluez.Error.InProgress' in event.get('dbus_errors', []):
                return 'SCAN_TIMEOUT_BEFORE_STOP_ERROR'
    return 'UNRESOLVED_LOCAL_PHASE'


def analyze() -> None:
    """Produce exact ID accounting without automatically assigning root causes."""
    failures = json.loads(CATALOG.read_text())['failures']
    selected = [row for row in failures if row['signature'] in ('pase-incorrect-state', 'ble-discovery-empty')]
    assert len(selected) == 66 and len({row['id'] for row in selected}) == 66
    assert Counter(row['signature'] for row in selected) == {'pase-incorrect-state': 55, 'ble-discovery-empty': 11}
    results = []
    for failure in selected:
        invocation = Path(failure['run']) / 'invocation-private.json'
        indexes = controller_indexes(json.loads(invocation.read_text()))
        assert len(indexes) == 1, (failure['id'], indexes)
        logs = [scan(Path(path)) for path in failure['logs']]
        events = [event for log in logs for event in log['events']]
        results.append({'id': failure['id'], 'signature': failure['signature'], 'iteration': failure['iteration'],
            'run': failure['run'], 'configured_index': indexes[0],
            'invocation_sha256': hashlib.sha256(invocation.read_bytes()).hexdigest(), 'logs': logs,
            'marker_counts': dict(Counter(label for event in events for label in event.get('labels', []))),
            'dbus_errors': dict(Counter(error for event in events for error in event.get('dbus_errors', []))),
            'pase_headers': sum('pase_header' in event for event in events),
            'adapter_paths': sorted({path for event in events for path in event.get('adapter_paths', [])}),
            'actual_hci_traffic': None, 'actual_hardware_identity': None,
            'local_phase': local_phase(logs), 'root_cause': 'UNRESOLVED',
            'disposition': 'OPEN_PENDING_PROVENANCE'})
    document = {'outcomes': results, 'native_outcomes_changed': False,
        'local_phase_counts': dict(Counter(row['local_phase'] for row in results)),
        'index_counts': dict(Counter(row['configured_index'] for row in results))}
    assert document['local_phase_counts'] == {'SCAN_TIMEOUT_BEFORE_STOP_ERROR': 44,
        'UNRESOLVED_LOCAL_PHASE': 11, 'LOCAL_ADAPTER_UNAVAILABLE': 11}, document['local_phase_counts']
    assert all(row['signature'] == 'ble-discovery-empty' for row in results
        if row['local_phase'] == 'UNRESOLVED_LOCAL_PHASE')
    save('historical-ble-accounting.json', document)
    groups = []
    for run in sorted({row['run'] for row in results}):
        rows = [row for row in results if row['run'] == run]
        groups.append({'run': run, 'count': len(rows), 'ids': [row['id'] for row in rows],
            'configured_indexes': sorted({row['configured_index'] for row in rows}),
            'marker_counts': dict(sum((Counter(row['marker_counts']) for row in rows), Counter())),
            'dbus_errors': dict(sum((Counter(row['dbus_errors']) for row in rows), Counter())),
            'pase_headers': sum(row['pase_headers'] for row in rows),
            'adapter_paths': sorted({path for row in rows for path in row['adapter_paths']})})
    print(json.dumps({'index_counts': document['index_counts'], 'local_phase_counts': document['local_phase_counts'],
        'groups': groups}, indent=2))


class EvidenceTest(unittest.TestCase):
    def test_no_secret_or_arbitrary_text_export(self):
        self.assertEqual(markers('Session key = DO_NOT_EXPORT'), {})
        row = markers('Failed to initiate BLE scan start: org.bluez.Error.NotReady secret=DO_NOT_EXPORT')
        self.assertEqual(row, {'labels': ['scan_start_failed'], 'dbus_errors': ['org.bluez.Error.NotReady']})
        self.assertNotIn('DO_NOT_EXPORT', json.dumps(row))

    def test_configured_index_is_not_hardware_proof(self):
        self.assertEqual(controller_indexes({'argv': ['python', '--ble-controller', '0', '--passcode', 'DO_NOT_EXPORT']}), [0])
        self.assertEqual(controller_indexes({'unrelated': 'hci1'}), [])

    def test_only_explicit_pase_headers(self):
        self.assertNotIn('pase_header', markers('PASESession.cpp:99: Incorrect state'))
        row = markers('<<< E:8i S:0 M:12 Type 0000:20 PBKDFParamRequest')
        self.assertEqual(row['pase_header']['opcode'], 32)

    def test_stop_error_requires_prior_timeout_in_same_log(self):
        timeout = markers('BLEManagerImpl.cpp:937: CHIP Error 0x00000032')
        stop = markers('Failed to stop discovery: org.bluez.Error.InProgress')
        self.assertEqual(local_phase([{'events': [timeout, stop]}]), 'SCAN_TIMEOUT_BEFORE_STOP_ERROR')
        self.assertEqual(local_phase(json.loads(json.dumps([{'events': [timeout, stop]}]))), 'SCAN_TIMEOUT_BEFORE_STOP_ERROR')
        self.assertEqual(local_phase([{'events': [stop, timeout]}]), 'UNRESOLVED_LOCAL_PHASE')
        self.assertEqual(local_phase([{'events': [timeout]}, {'events': [stop]}]), 'UNRESOLVED_LOCAL_PHASE')
        self.assertEqual(local_phase([{'events': [markers('BLE adapter unavailable')]}]), 'LOCAL_ADAPTER_UNAVAILABLE')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('self-test', 'analyze'))
    action = parser.parse_args().action
    if action == 'self-test':
        unittest.main(argv=[__file__])
    else:
        analyze()
