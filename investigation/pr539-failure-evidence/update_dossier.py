import argparse
import ctypes
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
HISTORY = Path('/home/feasel/qa-mar6/pr539-full-testing-20261011')
FOLLOWUP = Path('/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011')
ARCHIVE = FOLLOWUP / 'failure-preservation'
UNIT = 'pr539-failure-dossier.service'
READ_CONTINUATION = 'rt12-read-integration-v9-all-five'
READ_RETRY = 'rt12-read-integration-v10-all-five'
CATEGORIES = ('Probably Due to PR539', 'Probably Due to Current Testing Methodology',
              'Pre-Existing Test Harness Problems', 'Pre-Existing SDK Problems',
              'Cannot Classify With Confidence')
KNOWLEDGE = {
    'pase-incorrect-state': (1, 'Ubuntu BLE fixture: PASE IncorrectState',
        '55 original/baseline/recovery outcomes. BlueZ StopDiscovery InProgress and absent controller BLE ACL traffic; baseline reproduces. The final fixture inspection found the controller at hci1/index 1 while older runs selected absent hci0. Corrected commissioning cases pass. This favors setup, not proof of a particular BlueZ or SDK defect.',
        'Inspect the indexed capture and adapter-selection provenance before drawing SDK conclusions.'),
    'ble-discovery-empty': (1, 'Ubuntu BLE fixture: empty discovery',
        '11 original/recovery outcomes. Original RT2_1 could not discover Matter BLE; recovery still reported adapter unavailable. The RCP dongle is not the controller adapter. Later stage-selection discovery failures have a different cause and are separate.',
        'Correlate HCI coverage and native controller index against the exact failed source/configuration.'),
    'bulk-write-verification': (2, 'Valve DefaultOpenLevel constraint generation',
        'Positive-write generation ignored live LevelStep; odd generated values were rejected with ConstraintError on step-2 DUTs. The verifier counted constraint skips as failures and described a readback mismatch. Baseline reproduces. PR547 fixes generation without suppressing all rejected writes; smoke plus ten iterations passed.',
        'Review live LevelStep, generated candidate, write status and verifier skip reason in each indexed log.'),
    'multi-admin-subscription-verification': (2, 'Valve subscription verification',
        'Same LevelStep/ConstraintError mechanism as bulk writes, repeated across secondary controllers. The independent per-controller map also had a pre-existing aliasing defect; it is not established as the cause of these particular failures.',
        'Separate invalid positive writes from subscription-cache or controller-map defects.'),
    'multi-admin-read-mismatch': (2, 'Cross-controller comparison of non-equivalent reads',
        'Original failures name Identify DataVersion or ScenesManagement FabricSceneInfo. Reads are non-atomic and fabrics legitimately expose different scene records. Actual comparator methods reproduce false positives with stable positive controls. Do not ignore all attributes or all data versions by name.',
        'Compare actual SDK DataVersion metadata, compressed fabric identities and stable shared paths separately.'),
    'multi-admin-cleanup-timeout': (4, 'Concurrent read timeout replaced by cleanup timeout',
        'Three original Pi-DUT outcomes: concurrent reads time out before unpairing also times out, replacing the primary error with TestCaseExit. The separate 2026-10-16 Ubuntu/Wi-Fi matched check reproduces this failure family on upstream and the five-PR snapshot. Exact harness/SDK/fixture ownership and the original Pi-controller attribution remain unresolved; the PR548 diagnostics fix does not repair transport timeouts.',
        'Preserve the primary read error when cleanup fails; investigate full-load concurrency/subscriptions and SDK/fixture ownership. The Pi-controller cell still needs matched attribution.'),
    'Valve constraint': (2, 'Valve verification in corrected Ubuntu/Nordic rerun',
        'The corrected adapter rerun still rejects positive Valve writes/subscription verification. These belong to the separate pre-existing constraint-generation investigation, not the repaired PR539 readiness hook. Preserve the exact per-iteration status and generated value; case name alone is insufficient for future attribution.',
        'Verify DefaultOpenLevel/LevelStep and ConstraintError in the retained controller log.'),
    'read comparison': (2, 'Read comparison in corrected Ubuntu/Nordic rerun',
        'Concurrent-read comparison still fails after fixture correction. The original comparator wrongly requires identical metadata and fabric-scoped/live values. Attribution is likely harness; packet-level decoding has not established every individual changed value.',
        'Locate the mismatch attribute labels and compare with PR548 focused controls.'),
    'verified metadata/fabric scenes': (2, 'Five verified corrected-rerun metadata/scene comparisons',
        'The five identified Ubuntu/Nordic failures contain 15 logged comparison paths: Identify.DataVersion and, in iteration 2, ScenesManagement.FabricSceneInfo. Exact original log lines were extracted on 2026-10-17 without exporting values. PR548 handles actual SDK metadata identity and typed cross-fabric scene lists; this resolves the recorded predicates, not hypothetical later comparisons.',
        'Preserve the original FAILs and exact deciding paths; full-load native timeouts remain separate.'),
    'SecurePairing callback selection': (2, 'Unreachable SecurePairing reset target',
        'Original callback-fix campaign iteration 8 selected SecurePairing start but no callback reset occurred; commissioning completed and later BLE discovery was empty. Exact-source continuation iteration 3 selected completion and the target-observation guard failed. AutoCommissioner advances to ReadCommissioningInfo without either selected SecurePairing notification; stage IDs match. PR550 now excludes this stage in both modes and still fails missing/nonmatching target observations.',
        'Keep start/completion selection, callback event and actual reset observation distinct. Validate current v3 without synthetic unreachable callbacks.'),
    'IdentifyTime': (2, 'Read smoke v1: IdentifyTime',
        'A live countdown changes between reads. The initial metadata/fabric fix was incomplete. PR548 now bounds time-sensitive values by the measured monotonic read window rather than requiring equality.', 'Check bounded decrement and invalid-domain controls.'),
    'UTCTime': (2, 'Read smoke v2: UTCTime',
        'UTC/local time and uptime are advancing observations. PR548 uses the real asyncio.gather read window and validates domains; earlier snapshot remains a failed hardware smoke.', 'Review elapsed-time bounds and unchanged-value controls.'),
    'DeviceLoadStatus': (2, 'Read smoke v3: DeviceLoadStatus',
        'DeviceLoadStruct is an observation, not necessarily identical cross-controller state. Per-fabric and global counts need different treatment. Earlier snapshot was an incomplete harness repair.', 'Review SDK struct/domain controls and stable shared-value checks.'),
    'Thread counters/UpTime': (2, 'Read smoke v4: Thread counters and uptime',
        'Traffic counters advance during the test. PR548 explicitly handles 20 traffic counters and uptime while retaining strict error-counter checks.', 'Do not blanket-relax all diagnostic counters.'),
    'NeighborTable/RouteTable': (2, 'Read smoke v5: Thread neighbor/route tables',
        'Live observations changed. Typed domains and observation fields need validation, but stable topology must remain strict. No Thread dataset change or firmware workaround was used.', 'Separate live measurements from actual neighbor/route topology changes.'),
    'fabric-filtered ACL': (2, 'Read smoke v6: AccessControl ACL',
        'Native Read defaults fabricFiltered=True. Different compressed fabrics expose different ACL entries. PR548 validates typed ACL lists across fabrics; same-fabric equality, missing paths and shared values remain strict.', 'Verify actual fabric identity and AccessControlEntryStruct shape.'),
    'fabric-filtered Fabrics': (2, 'Read smoke v7: OperationalCredentials Fabrics',
        'Fabric-filtered FabricDescriptorStruct lists differ across fabrics. Seven new controls reproduced the gap; 49 tests pass after the repair. Read v8 failed at a different attribute, NOCs.', 'Keep same-fabric equality, SupportedFabrics, path presence and malformed table checks.'),
    'fabric-filtered NOCs': (2, 'Read smoke v8: OperationalCredentials NOCs',
        'The closed smoke compared one typed NOC entry for fabric index 2 against one for fabric index 3, with no decode failure. Native Read defaults fabricFiltered=True and the SDK list encoder filters entries to the accessing fabric. The unchanged PR548 comparator rejects typed differing cross-fabric NOC lists but accepts identical lists in a CPU control. This is a likely incomplete pre-existing harness repair, not a demonstrated PR539 readiness or SDK failure.',
        'Add a local typed cross-fabric NOC comparison with malformed-list, decode-failure, missing-path, shared-value and same-fabric controls; do not ignore the whole credentials cluster. Existing physical failure remains preserved.'),
    'CurrentFabricIndex': (2, 'Read v9: OperationalCredentials CurrentFabricIndex',
        'All ten v9 iterations failed at requesting-fabric indexes, with 30 identified comparisons. PR548 validates indexes in 1-254 and permits differences only across compressed fabric identities. The corrected v10 snapshot passed ten iterations; the fix was subsequently published.',
        'No remaining fix for this identified mechanism; preserve the ten original FAIL outcomes.'),
    'BlueZ subscription': (1, 'Offline BLE-Wi-Fi a02: subscription failure',
        'A real commissioning smoke failed in the BLE/BlueZ path. Fixture service configuration and cached unpaired-peer state were repaired. Exact native-versus-BlueZ root cause is unproved.', 'Inspect HCI, BlueZ services and commissioner/DUT logs together.'),
    'GATT service discovery': (1, 'Offline BLE-Wi-Fi GATT failures',
        'a03 and a05-a08 could not discover valid Matter GATT services. a08 did not actually apply the intended single-ATT configuration because its launcher failed open. Later corrected fixture passed 22 final-source cycles. This does not prove the specific root cause of every historical GATT failure.', 'Verify exported peer services, ServicesResolved, effective daemon arguments and HCI events.'),
    'operational discovery/IPv6 timeout': (1, 'Offline BLE-Wi-Fi operational timeout',
        'a04/a09 passed PASE/provisioning before operational discovery timeout; a10 lacked expected IPv6 link-local behavior. Temporary RA/address-generation repairs were restored at closeout. Pi2 does not need Ethernet.', 'Correlate provisioning, actual IPv6 addresses, DNS-SD and CASE establishment rather than repeating BLE pairing.'),
    'unclassified': (4, 'New failure: attribution pending',
        'Newly observed outcome. No inherited diagnosis is assigned solely from its test-case name. Raw exception and trace remain private in the linked evidence.',
        'Investigate after batch closeout in the requested category order; classify only with deciding evidence.')}
READ_SIGNATURES = ('IdentifyTime', 'UTCTime', 'DeviceLoadStatus', 'Thread counters/UpTime',
                   'NeighborTable/RouteTable', 'fabric-filtered ACL', 'fabric-filtered Fabrics')
READ_PHASE_SIGNATURES = dict(zip(
    ('rt12-read-integration', *[f'rt12-read-integration-v{number}' for number in range(2, 8)]), READ_SIGNATURES))
VERIFIED_FAILURES = {'137a000b88bfd888': ('fabric-filtered NOCs', (
    (FOLLOWUP / 'rt12-read-integration-v8/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/console.log', 453255),))}
VERIFIED_FAILURES.update(dict.fromkeys((
    '10438225351291f9', '549bca9c2b00dccf', '5012de0fddd0dad1', 'afadff143e413fec', '114e6dc16ee6ae6e',
    '5a52ea1bd1faa282', 'c30adfc582b73690', 'af630d00669fe2f8', '8d82396f140d172f', '59fa1859d905f3db'),
    ('CurrentFabricIndex', ())))
for verified_id, verified_iteration, verified_lines in (
        ('2dc88704967e9345', 1, (780854, 780857, 780859)),
        ('6ec3f8548b8a83e9', 2, (778955, 778958, 778960)),
        ('0d6bf96729f5927d', 3, (780082, 780084, 780086)),
        ('81d2781f125d012e', 8, (777552, 777555, 777557)),
        ('bb57845dfbe57338', 9, (777203, 777206, 777208))):
    verified_run = 'pr539-nordic-ubuntu-TC_RT_1_2-' + ('1' if verified_iteration == 1 else '10')
    verified_log = FOLLOWUP / 'ubuntu-nordic-final/runs' / verified_run / 'logs/MatterTest/ble-thread'
    verified_stamp = '10-12-2026_00-57-57-717' if verified_iteration == 1 else '10-12-2026_01-03-17-134'
    verified_time = {1: '00-59-10', 2: '01-07-05', 3: '01-11-01', 8: '01-24-53', 9: '01-28-44'}[verified_iteration]
    verified_log = verified_log / verified_stamp / 'TC_RT_1_2' / str(verified_iteration) / (
        f'controller_log_iteration_{verified_iteration}_2026-10-12_{verified_time}.log')
    VERIFIED_FAILURES[verified_id] = ('verified metadata/fabric scenes',
                                      tuple((verified_log, number) for number in verified_lines))
RESOLUTIONS = {
    'bulk-write-verification': 'PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.',
    'multi-admin-subscription-verification': 'PR547 `6e93374`: fixes the identified LevelStep/ConstraintError mechanism, not the independent controller-map aliasing concern.',
    'Valve constraint': 'PR547 `6e93374`: step-aligned positive Valve writes; retained negative controls still reject invalid values.',
    'multi-admin-read-mismatch': 'PR548 `a550450` includes SDK metadata identity and validated fabric-dependent scene comparison; unrelated shared values remain strict.',
    'verified metadata/fabric scenes': 'PR548 `a550450`: actual SDK DataVersion metadata and typed fabric-dependent scene comparison; all 15 observed paths attributed and 107 focused tests pass. Original FAIL outcomes remain unchanged.',
    'SecurePairing callback selection': 'PR550 `2b0feed`: excludes unreachable SecurePairing targets in both modes and propagates callback reset failures; use with PR549 ownership.',
    'IdentifyTime': 'PR548 `a550450`: validated countdown drift bounded by the measured read window.',
    'UTCTime': 'PR548 `a550450`: validated advancing clocks and uptime bounded by the measured read window.',
    'DeviceLoadStatus': 'PR548 `a550450`: typed/domain-checked device-load observations rather than blanket equality.',
    'Thread counters/UpTime': 'PR548 `a550450`: explicit traffic-counter domains and measured uptime drift; error counters remain strict.',
    'NeighborTable/RouteTable': 'PR548 `9a003ab`, retained in `a550450`: validate live fields and compare stable membership/topology without order dependence; physical multi-entry churn remains untested.',
    'fabric-filtered ACL': 'PR548 `a550450`: validate typed fabric-filtered ACLs while preserving same-fabric equality and path checks.',
    'fabric-filtered Fabrics': 'PR548 `a550450`: validate typed fabric-filtered descriptor lists; shared attributes remain strict.',
    'fabric-filtered NOCs': 'PR548 `e0b6f61`, retained in `a550450`: typed cross-fabric NOCs and scene decode-failure checks; negative regressions pass.',
    'CurrentFabricIndex': 'PR548 `7b75e7b`, retained in `a550450`: validate indexes and compare according to fabric identity; v10 passed 10/10.',
}


def atomic_json(path, document):
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')
    os.replace(temporary, path)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(hashlib, 'file_digest') else stream_digest(stream)


def stream_digest(stream):
    hashed = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        hashed.update(block)
    return hashed.hexdigest()


def preserve(path, manifest, archive):
    key = str(path.resolve())
    before = path.stat()
    if key in manifest:
        previous = manifest[key]
        if (before.st_size, before.st_mtime_ns) != (previous['size'], previous['mtime_ns']):
            raise RuntimeError('Preserved original changed: ' + key)
        if not Path(previous['copy']).is_file():
            raise RuntimeError('Preserved copy missing: ' + key)
        return
    objects = archive / 'objects'
    objects.mkdir(parents=True, exist_ok=True, mode=0o700)
    available = shutil.disk_usage(archive).free
    if available < before.st_size + 2 * 1024 ** 3:
        raise RuntimeError('Insufficient disk reserve to preserve: ' + key)
    descriptor, name = tempfile.mkstemp(prefix='evidence-', dir=objects)
    os.close(descriptor)
    temporary = Path(name)
    try:
        shutil.copyfile(path, temporary)
        copied_hash = digest(temporary)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RuntimeError('Evidence still changing; defer preservation: ' + key)
        if copied_hash != digest(path):
            raise RuntimeError('Copy integrity mismatch: ' + key)
        destination = objects / copied_hash
        if destination.exists():
            if digest(destination) != copied_hash:
                raise RuntimeError('Archive integrity mismatch: ' + str(destination))
        else:
            os.replace(temporary, destination)
        destination.chmod(0o400)
        manifest[key] = {'sha256': copied_hash, 'size': after.st_size, 'mtime_ns': after.st_mtime_ns,
                         'copy': str(destination)}
    finally:
        temporary.unlink(missing_ok=True)


def exception_message(record):
    exception = record.get('exception') or {}
    if isinstance(exception, str):
        exception = json.loads(exception)
    return exception.get('exception_msg', '')


def new_signature(record):
    message = exception_message(record)
    if 'SecurePairing' in message and ('not' in message or 'target' in message):
        return 'SecurePairing callback selection'
    if 'DefaultOpenLevel' in message and 'ConstraintError' in message:
        return 'Valve constraint'
    return 'unclassified'


def outcome_id(run, iteration):
    return hashlib.sha256((str(run.resolve()) + ':' + str(iteration)).encode()).hexdigest()[:16]


def partial_records(run):
    rows = {}
    for path in sorted(run.rglob('summary.json')):
        if 'latest' in path.parts:
            continue
        try:
            document = json.loads(path.read_text())
        except (json.JSONDecodeError, FileNotFoundError):
            continue
        for record in document.get('list_of_iteration_records', []):
            number = record['iteration_number']
            data = record['iteration_data']['iteration_tc_execution_data']
            if data['iteration_result'] == 'FAIL':
                rows[number] = {'iteration': number, 'outcome': 'FAIL'}
    return list(rows.values())


def final_result(path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def collect():
    historical = json.loads((HISTORY / 'failure-investigation.json').read_text())
    known = {(str(HISTORY / row['stage']), row['iteration']): row for row in historical['failed_outcomes']}
    directories = [(HISTORY, 'original matrix and baseline'), (HISTORY / 'ubuntu-ble-recovery', 'recovery baseline'),
                   (FOLLOWUP / 'ubuntu-nordic-final', 'corrected Ubuntu/Nordic')]
    for name in ('rt12-read-integration', *[f'rt12-read-integration-v{number}' for number in range(2, 9)],
                 'rt21-callback-integration', 'rt21-callback-stage-integration-v2',
                 'rt21-callback-stage-integration-v2-editor-resume-20261012', 'rt21-callback-stage-integration-v3',
                 READ_CONTINUATION, READ_RETRY):
        directories.append((FOLLOWUP / name, name))
    failures = []
    incidents = []
    for root, phase in directories:
        for run in sorted((root / 'runs').glob('*')):
            path = run / 'result.json'
            final = final_result(path)
            records = final.get('records', []) if final else partial_records(run)
            for record in records:
                if record['outcome'] != 'FAIL':
                    continue
                prior = known.get((str(run), record['iteration']))
                signature = prior['signature'] if prior else new_signature(record)
                if not prior and phase == 'corrected Ubuntu/Nordic':
                    message = exception_message(record)
                    signature = ('Valve constraint' if 'Attribute verification failed' in message or final['case'] == 'TC_Send_Command_Read_Write_Attributes'
                                 else 'read comparison' if 'Concurrent read results mismatch' in message else 'unclassified')
                if phase in READ_PHASE_SIGNATURES:
                    signature = READ_PHASE_SIGNATURES[phase]
                if phase in ('rt21-callback-integration', 'rt21-callback-stage-integration-v2-editor-resume-20261012'):
                    signature = 'SecurePairing callback selection'
                verified = VERIFIED_FAILURES.get(outcome_id(run, record['iteration']))
                if verified:
                    signature = verified[0]
                proofs = [root / 'source-proof.json', root / 'hardware-summary.json', root / 'capture-audit.json']
                logs = sorted(path for path in (run / 'logs').rglob(f'{record["iteration"]}/controller_log_iteration_{record["iteration"]}_*.log') if 'latest' not in path.parts)
                captures = root / 'captures' / run.name
                evidence_lines = [{'path': str(HISTORY / item['log']), 'line': item['line']}
                                  for item in prior.get('evidence', [])] if prior else []
                if verified:
                    evidence_lines = [{'path': str(path), 'line': line} for path, line in verified[1]]
                failures.append({'id': outcome_id(run, record['iteration']), 'phase': phase, 'run': str(run),
                    'iteration': record['iteration'], 'signature': signature, 'category': KNOWLEDGE[signature][0],
                    'confidence': prior.get('confidence', 'likely; retained probes and logs') if prior else 'pending' if signature == 'unclassified' else 'likely; retained probes and logs',
                    'result': str(path), 'logs': [str(path) for path in logs], 'evidence_lines': evidence_lines,
                    'capture_directory': str(captures), 'source_and_closure': [str(path) for path in proofs if path.exists()],
                    'closed': bool(final and (captures / 'capture-proof.json').exists()),
                    'root': str(root), 'supervisor': str(root / (run.name + '.supervisor.log'))})
            if final and final['process_exit'] != 0 and final['executed'] < final['requested']:
                incidents.append({'run': str(run), 'phase': phase, 'exit': final['process_exit'],
                                  'unfinished': final['requested'] - final['executed'], 'root': str(root)})
    for run in sorted((FOLLOWUP / 'ble-wifi-runs').glob('wifi-primary-smokes-01-a*')):
        path = run / 'controller/summary.json'
        if not path.exists() or 'a12' in run.name:
            continue
        row = json.loads(path.read_text())
        if row['passed']:
            continue
        signature = 'BlueZ subscription' if 'a02' in run.name else 'GATT service discovery' if any(f'a{number:02d}' in run.name for number in (3, 5, 6, 7, 8)) else 'operational discovery/IPv6 timeout'
        captures = FOLLOWUP / 'captures' / run.name
        failures.append({'id': outcome_id(run, 1), 'phase': 'early offline BLE-Wi-Fi', 'run': str(run), 'iteration': 1,
            'signature': signature, 'category': 1, 'confidence': 'setup favored; exact Bluetooth/IPv6 mechanism not fully proved',
            'result': str(path), 'logs': [str(path) for path in sorted(run.rglob('*.log'))], 'evidence_lines': [],
            'capture_directory': str(captures), 'source_and_closure': [str(FOLLOWUP / 'ble-wifi-final-validation.json')],
            'closed': (captures / 'capture-proof.json').exists(), 'root': str(FOLLOWUP),
            'supervisor': str(FOLLOWUP / (run.name + '.console.log'))})
    assert len({row['id'] for row in failures}) == len(failures)
    assert sum(row['phase'] in ('original matrix and baseline', 'recovery baseline') for row in failures) == 113
    return failures, incidents


def eligible_files(row):
    run = Path(row['run'])
    capture = Path(row['capture_directory'])
    paths = [*run.rglob('*'), *capture.rglob('*'), Path(row['supervisor']),
             *[Path(path) for path in row['source_and_closure']]]
    root = Path(row['root'])
    for name in ('dut-uart.log', 'uart-relay.log', 'pi-forwarding.log'):
        paths.extend((root / 'relay-segments').rglob(name))
    unique = set()
    for path in paths:
        if not path.is_file() or path.is_symlink() or 'latest' in path.parts:
            continue
        if any(word in path.name.lower() for word in ('storage', 'credential', 'ssh-key', 'known-hosts')):
            continue
        resolved = path.resolve()
        if resolved in unique:
            continue
        unique.add(resolved)
        yield resolved


def additional_evidence(incidents):
    for incident in incidents:
        root = Path(incident['root'])
        run = Path(incident['run'])
        capture = root / 'captures' / run.name
        if (capture / 'capture-proof.json').exists():
            yield from eligible_files({'run': str(run), 'capture_directory': str(capture), 'root': str(root),
                'supervisor': str(root / (run.name + '.supervisor.log')), 'source_and_closure': []})
    closed_directories = [HISTORY / 'setup-failures', FOLLOWUP / 'network-inspection-01',
        FOLLOWUP / 'network-inspection-02', FOLLOWUP / 'ci-pr547',
        FOLLOWUP / 'ble-wifi-runs/wifi-primary-smokes-01', FOLLOWUP / 'ble-wifi-runs/wifi-primary-smokes-01-a11',
        FOLLOWUP / 'captures/wifi-primary-smokes-01', FOLLOWUP / 'captures/wifi-primary-smokes-01-a11',
        FOLLOWUP / 'rt21-callback-stage-integration-v2/captures']
    for directory in closed_directories:
        for path in directory.rglob('*'):
            if path.is_file() and not path.is_symlink() and not any(word in path.name.lower() for word in ('storage', 'credential', 'ssh-key')):
                yield path
    names = ('failure-investigation.json', 'failure-probes.json', 'failure-probes.log', 'transport-prerequisite.json',
        'check_transport_prerequisite.py', 'ubuntu-kernel-utc.log', 'pi-controller-kernel-utc.log',
        'first-smoke-setup-supervisor.log', 'capture-audit.json', 'closed-evidence-sha256.json',
        'final-summary-20261011-202835.tar.gz', 'final-summary-proof.json', 'baseline.tar.gz', 'pr539.tar.gz')
    for name in names:
        path = HISTORY / name
        if path.is_file():
            yield path
    for pattern in ('pi1-bluez-*-recovery.json', 'pi2-bluez-setup-repair.json', 'ubuntu-ble-*.json',
                    'wifi-primary-smokes-01*.console.log', 'wifi-primary-smokes-01*.reconnect.log'):
        yield from FOLLOWUP.glob(pattern)
    for name in ('ble-wifi-final-validation.json', 'ble-wifi-preparation.json', 'original-dut-linger.json',
                 'final-source/source-proof.json', 'rt21-callback-stage-integration-v2/editor-interruption.json',
                 'allowlisted-final-summary-20261012-151127.tar.gz', 'allowlisted-separate-completed-20261012-201316.tar.gz'):
        path = FOLLOWUP / name
        if path.is_file():
            yield path
    yield from FOLLOWUP.glob('allowlisted-separate-completed-*.tar.gz')


def render(catalog, manifest):
    rows = []
    for original in catalog['failures']:
        row = dict(original)
        if row['id'] in VERIFIED_FAILURES:
            row['signature'] = VERIFIED_FAILURES[row['id']][0]
            row['category'] = KNOWLEDGE[row['signature']][0]
            if VERIFIED_FAILURES[row['id']][1]:
                row['evidence_lines'] = [{'path': str(path), 'line': number}
                                         for path, number in VERIFIED_FAILURES[row['id']][1]]
        rows.append(row)
    fixed = sum(row['signature'] in RESOLUTIONS for row in rows)
    batch_state = ('Current batch is closed; continue investigating remaining failures in this order.'
                   if catalog.get('batch_closed') else
                   'Current batch continues unchanged; investigate remaining failures after its closeout, in this order.')
    lines = ['# PR539 Failure Evidence and Investigation Queue', '', 'Updated UTC: ' + catalog['updated_utc'], '',
        'Local working dossier. Not committed. Raw evidence contains keys/payloads and stays outside this repository. Existing originals, failed attempts, incomplete slots and historical archives are never deleted or rewritten by this updater.', '',
        f'{len(rows)} individually identified failed hardware outcomes. Process/setup incidents and CPU-proven PR defects are separate, not extra FAIL iterations.', '',
        'Investigation order: PR539, current methodology, pre-existing harness, pre-existing SDK, then uncertain. ' + batch_state + ' Classification is a hypothesis unless explicitly proved.', '',
                '## Current Resolution', '',
                'Resolution reconciled 2026-10-17 against published PR539/547/548/549/550 fixes and exact historical path extraction. **FIXED** means the identified defect is repaired in the PR, not merged upstream and not that an original FAIL became PASS. **OPEN** means no demonstrated fix for that exact mechanism. Fixture workarounds alone do not establish a PR fix.', '',
                f'Of the {len(rows)} historical failed outcomes below, **{fixed} map to FIXED mechanisms; {len(rows) - fixed} remain OPEN**. Native crashes and infrastructure/review issues are separate, not extra failed iterations. Catalog IDs and original evidence remain intact; verified v9 and corrected-rerun IDs display their exact fabric-index or metadata/scene attribution.', '',
                'Latest fixes and subsequent evidence: [review resolution](PR_REVIEW_20261013.md#current-resolution) and [full-matrix resolution](FULL_MATRIX_20261014.md#current-resolution). These reports also cover findings and campaigns newer than this historical catalog.', '',
                '## Remaining Work', '',
                '| OPEN Failure Family | Historical Outcomes | Next Action |', '| --- | ---: | --- |',
                *[f'| {KNOWLEDGE[signature][1]} | {sum(row["signature"] == signature for row in rows)} | {KNOWLEDGE[signature][3]} |'
                    for signature in sorted({row['signature'] for row in rows} - RESOLUTIONS.keys())], '',
                '- **OPEN:** exact native SIGSEGV root cause; PR549 repairs the proven callback lifetime defect, but no deciding native backtrace attributes every crash.',
                '- **FIXED:** independent controller-map aliasing is repaired in PR548 `e8fcf30` with per-controller deep copies; two regressions fail before and pass after, with all 107 RT_1_2 tests passing. Published to the feasel0 fork and GitHub head verified. Native timeout causality is still open. See [targeted execution](../37075/RT12_TARGETED_ATTRIBUTION_20261017.md).',
                '- **OPEN:** CI project-label workflow/token remediation and historical fixture closeout gaps.',
                '- **OPEN:** newer full-load read/subscription/cleanup timeouts and remaining coverage gaps. Patched Pi btmon has a live discovery-capture proof, not retroactive repair of the historical HCI losses or full commissioning coverage.', '',
        '## Evidence Locations and Preservation', '',
        f'- Historical originals: `{HISTORY}`', f'- Follow-up originals: `{FOLLOWUP}`',
        '- Pi1 retained counterpart: `/home/feasel/matter-pr539-ble-readiness-fix-20261011`',
        f'- Independent private content-addressed copies: `{ARCHIVE / "objects"}`',
        '- [Preservation manifest](preserved-files.json) maps every copied original to SHA-256, byte count and archived copy. [Structured catalog](catalog.json) provides exact unique IDs and classifications.',
        '- Only closed run evidence is copied. Active captures and growing logs are linked but deferred until closure. Credential/controller-storage files remain in their private original locations and are deliberately excluded from copies.',
        '- Copy integrity is checked against originals. A changed preserved original or missing copy is an error, not silently accepted. Capture readability is not authenticated Matter decryption.',
        f'- Preserved closed files: {len(manifest)}. Preservation notes: ' + ('; '.join(catalog['warnings']) if catalog['warnings'] else 'none.'), '',
        'Historical sealed archives: `final-summary-20261011-202835.tar.gz` (SHA-256 `58134c99e22f3dbcd4952f51f89f02e2a2d874a73367767dbc27f18a8b748c5e`) under the historical root; `allowlisted-final-summary-20261012-151127.tar.gz` (`eaa6420e42975f10443e29f572f1414cb4ecf2d37cb0aeef7d8b261e5a3b7188`) and `allowlisted-separate-completed-20261012-201316.tar.gz` (`31fa8c522fcf14c9b28d6d7eb9af7de22ee0f4d4023a50fb99dfa02cc1506d68`) under the follow-up root. Earlier seals do not cover newer or active attempts.', '',
        'Hardware: Ubuntu or Pi1 native Python controller; Pi2 Wi-Fi/on-network or genuinely unprovisioned BLE-Wi-Fi DUT; Nordic DK 001050208117 uses BLE-Thread through Ubuntu OTBR and RCP 8388F563A730D925. No new firmware or dataset change. Darwin/Android test names are not physical ecosystem controllers.', '']
    for index, category in enumerate(CATEGORIES):
        members = [row for row in rows if row['category'] == index]
        lines.extend([f'## {index + 1}. {category}', '', f'Failed hardware outcomes in this category: {len(members)}.', ''])
        if index == 0:
            lines.extend(['### FIXED: PR539-CPU-01: IP prerequisite before BLE', '',
                'Resolution: **FIXED** in PR539 `e9f5f6b`, retained in `b99759a`.', '',
                'Confirmed by extracted production readiness method and six-scenario CPU probe: pending Pi reset required an IP advertisement before BLE-Wi-Fi provisioning could occur. Repaired hook bypasses IP only for BLE and leaves the later IP prerequisite pending. No hardware FAIL is conclusively attributed to this defect.',
                f'Evidence: `{HISTORY / "failure-probes.json"}`, `{HISTORY / "transport-prerequisite.json"}`, `{HISTORY / "check_transport_prerequisite.py"}`, `{FOLLOWUP / "final-source/source-proof.json"}`, `{FOLLOWUP / "ble-wifi-final-validation.json"}`. Final-source primary/manual smokes and twenty cycles passed.', '',
                '### FIXED: PR539-CPU-02: Secondary commissioning-window discriminator', '',
                'Resolution: **FIXED** in PR539 `e9f5f6b`, retained in `b99759a`.', '',
                'Repaired secondary path forwards on-network transport and the actual opened-window discriminator rather than relying on the primary configuration. Focused controls and physical two-fabric boundary cycles verify this behavior; do not count CPU controls as hardware failures.',
                f'Evidence: `{FOLLOWUP / "final-source/qa/src/matter_qa/unit_tests/test_raspi_readiness.py"}`, `{FOLLOWUP / "final-source/source-proof.json"}`, `{FOLLOWUP / "ble-wifi-final-validation.json"}`. Matching PR539 four-file change was published in e9f5f6b7e8b1cfb1280f35f6b1c2d03237f0be2e at the user\'s request. Fresh review findings are recorded in [PR review](PR_REVIEW_20261013.md); publication does not establish merge clearance.'])
        if index == 3:
            lines.extend(['No failure is currently classified as a sufficiently established pre-existing SDK defect. The SDK callback notification contract explains a harness assumption; it is not itself a demonstrated SDK bug. Bluetooth/native interactions and concurrent read limits remain uncertain below.'])
        signatures = sorted({row['signature'] for row in members})
        for signature in signatures:
            knowledge = KNOWLEDGE[signature]
            resolution = RESOLUTIONS.get(signature)
            status = 'FIXED' if resolution else 'OPEN'
            lines.extend(['', f'### {status}: ' + knowledge[1], '',
                          f'Resolution: **{status}**. ' + (resolution or 'No published fix establishes resolution of this exact mechanism.'), '',
                          'Historical diagnosis (not current work): ' + knowledge[2], ''])
            if not resolution:
                lines.extend(['Next deciding check: ' + knowledge[3], ''])
            for row in sorted((row for row in members if row['signature'] == signature), key=lambda row: (row['phase'], row['run'], row['iteration'])):
                lines.extend([f'#### Failure {row["id"]}: {row["phase"]}, iteration {row["iteration"]}', '',
                    f'- Resolution: **{status}**. ' + (resolution or 'Investigation remains open; retain the original failure.'),
                    f'- Run: `{row["run"]}`', f'- Structured result: `{row["result"]}`',
                    '- Controller/DUT iteration logs: ' + (', '.join('`' + path + '`' for path in row['logs']) or '`' + row['run'] + '/logs/` (canonical per-iteration log not yet resolved).'),
                    f'- Supervisor/console: `{row["supervisor"]}`', f'- BLE HCI and IP capture directory: `{row["capture_directory"]}`',
                    '- Source/closure proof: ' + (', '.join('`' + path + '`' for path in row['source_and_closure']) or 'pending.'),
                    '- Deciding log references: ' + (', '.join('`' + item['path'] + ':' + str(item['line']) + '`' for item in row['evidence_lines']) or 'See raw logs; no fabricated line reference.'),
                    f'- Confidence: {row["confidence"]}. Evidence status: ' + ('closed; eligible for preservation.' if row['closed'] else 'active/unclosed; original evidence retained, snapshot deferred.'), ''])
        if index == 1:
            lines.extend(['### Setup and Infrastructure Incidents (Not Additional FAIL Outcomes)', '',
                f'- Initial ENOTTY launch failure: `{HISTORY / "setup-failures"}` and `first-smoke-setup-supervisor.log` under historical root; no native iteration outcome.',
                f'- Offline a01 precondition failed before valid DUT launch: `{FOLLOWUP / "ble-wifi-runs/wifi-primary-smokes-01"}` and corresponding console/reconnect logs; no valid test iteration.',
                f'- a08 single-ATT fail-open configuration: `{FOLLOWUP / "pi1-bluez-single-att-recovery.json"}` and a08 controller/DUT evidence above; does not add another failure to its existing FAIL.',
                f'- RA/address-generation and recovery: `{FOLLOWUP / "network-inspection-01"}`, `{FOLLOWUP / "network-inspection-02"}`, per-attempt DUT network-state files, `pi2-bluez-setup-repair.json`, `pi1-bluez-*-recovery.json`; original settings restored.',
                f'- a11 protocol PASS but fixture signaling/closeout failed: `{FOLLOWUP / "ble-wifi-runs/wifi-primary-smokes-01-a11"}`. Not a fully closed PASS gate.',
                f'- Editor interruption: `{FOLLOWUP / "rt21-callback-stage-integration-v2/editor-interruption.json"}`, retained run logs and host `*-crash-stop.json` capture records. Zero completed outcomes, ten unfinished; exact signal unknown. Durable continuation retained separately.',
                f'- Completion-watcher Python ABI setup: `{FOLLOWUP / "publish_separate_hardware_status.py"}` uses Python3.10 D-Bus bindings; wrong default interpreter was an observer/setup error, not hardware failure.',
                f'- Missing optional pairing-cleanup module: retained preflight logs under `{FOLLOWUP}`; no foreign-revision test substituted.', ''])
        if index == 2:
            lines.extend(['### Pre-Existing CI Workflow Incidents', '',
                f'Project-label workflow references missing project-map script and contained an exposed hardcoded PAT. Never use, print or copy that token; revoke/rotate separately. Metadata/redacted CI evidence: `{FOLLOWUP / "ci-pr547"}` and retained PR547-550 status checks. All four follow-ups are now non-draft at the user\'s request. Initial Restyled formatting failures were repaired in those follow-up PRs, not SDK/hardware failures.'])
        if index == 4:
            lines.extend(['### Native Crashes: Callback Lifetime Favored, Exact Cause Unproved', '',
                'Resolution: **OPEN** for exact crash attribution. The proven callback-lifetime defect is **FIXED** in PR549 `dbab50b` and retained by PR550 `2b0feed`; absence of a deciding native backtrace prevents closing every historical SIGSEGV.', '',
                'Five campaign SIGSEGV incidents: three original PR539, one original baseline, one corrected Ubuntu/Nordic. Each followed one PASS and left nine unfinished slots. The actual SDK setters retain native pointers, not Python callback objects; CPU probes prove local ctypes objects can be collected. Baseline reproduces the crash. Later combined campaigns completed without SIGSEGV; this does not prove the root cause of all five incidents.',
                f'Evidence: `{HISTORY / "failure-probes.json"}`, `{HISTORY / "ubuntu-kernel-utc.log"}`, `{HISTORY / "pi-controller-kernel-utc.log"}`, `{FOLLOWUP / "rt21-callback-integration"}` and `rt21-callback-stage-integration-v2-editor-resume-20261012`. Pi kernel query supplied no backtrace. Separate cpptools OOM event is a host caveat, not universal attribution.', '',
                '| Run | Process Exit | Unfinished Slots |', '| --- | ---: | ---: |'])
            for incident in catalog['incidents']:
                if incident['exit'] == -11:
                    lines.append(f'| `{incident["run"]}` | -11 | {incident["unfinished"]} |')
            lines.extend(['', 'Other original early exits follow already-counted read/cleanup FAILs; four blocked campaigns account for forty historical slots. Forty setup-blocked slots were subsequently run; 42 other original gaps remain outside the current affected-only queue. Do not replace incomplete accounting with fabricated FAILs.', ''])
    lines.extend(['## Automatic Additions and Next Work', '',
        f'Observer unit: `{UNIT}`. Linux inotify watches only current result/summary/capture-proof metadata, plus the batch ledger. It never resets, pairs, flashes, opens UART, changes SDK/firmware/configuration or publishes PRs. New failures default to the uncertain category unless deciding evidence matches a known mechanism. Stable IDs prevent duplicate additions; old catalog entries are never dropped.',
        'Closed artifacts are copied privately and hash-checked. Active logs/captures are indexed first and copied after closure. Observer persists independently of VS Code and exits when its durable hardware batch closes; no polling or sleeps. Failure investigation follows the requested category order, with no automatic PR publication.',
        'Manual refresh: `python3 investigation/pr539-failure-evidence/update_dossier.py --update`. Verification controls: `python3 investigation/pr539-failure-evidence/update_dossier.py --self-test`. Writeups and tooling are versioned on the fork-only investigation branch. Generated indexes, raw logs, private controller state and bulk preserved copies remain excluded from commits.', ''])
    temporary = HERE / 'FAILURES.md.tmp'
    temporary.write_text('\n'.join(lines))
    os.replace(temporary, HERE / 'FAILURES.md')


def read_campaign_context():
    for integration, filename in ((READ_RETRY, 'read-v10-service-owner.json'),
                                  (READ_CONTINUATION, 'read-v9-service-owner.json')):
        owner = FOLLOWUP / filename
        if owner.exists():
            return owner, FOLLOWUP / integration
    return None


def update_unlocked():
    failures, incidents = collect()
    catalog_path = HERE / 'catalog.json'
    prior = json.loads(catalog_path.read_text()) if catalog_path.exists() else {'failures': []}
    retained = {row['id']: row for row in prior['failures']}
    for row in failures:
        retained[row['id']] = {**retained.get(row['id'], {}), **row}
    manifest_path = HERE / 'preserved-files.json'
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    warnings = []
    for row in retained.values():
        if not row['closed']:
            continue
        for path in eligible_files(row):
            try:
                preserve(path, manifest, ARCHIVE)
            except RuntimeError as error:
                warnings.append(str(error))
    for path in additional_evidence(incidents):
        try:
            preserve(path, manifest, ARCHIVE)
        except RuntimeError as error:
            warnings.append(str(error))
    ledger = final_result(FOLLOWUP / 'separate-stage-v3-read-v8-hardware-queue.json')
    batch_closed = bool(ledger and len(ledger) == 2 and all(row.get('captures_closed') and row.get('uart_free') for row in ledger))
    context = read_campaign_context()
    if context is not None:
        summary = final_result(context[1] / 'hardware-summary.json')
        batch_closed = bool(summary and summary.get('owned_relays_closed') and summary.get('dataset_unchanged'))
    catalog = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'failures': list(retained.values()),
               'batch_closed': batch_closed,
               'incidents': incidents, 'warnings': sorted(set(warnings))}
    atomic_json(manifest_path, manifest)
    atomic_json(catalog_path, catalog)
    render(catalog, manifest)
    print(json.dumps({'dossier': str(HERE / 'FAILURES.md'), 'failed_outcomes': len(retained),
                      'preserved_files': len(manifest), 'warnings': catalog['warnings']}, sort_keys=True), flush=True)
    if warnings:
        raise RuntimeError('Preservation needs attention; see dossier warnings')


def update():
    with (HERE / '.update.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        update_unlocked()


def decode_events(payload):
    offset = 0
    while offset < len(payload):
        number, event, cookie, length = struct.unpack_from('iIII', payload, offset)
        name = os.fsdecode(payload[offset + 16:offset + 16 + length].split(b'\0', 1)[0])
        offset += 16 + length
        yield number, event, name


def watch():
    import dbus
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib

    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    if descriptor < 0:
        raise OSError(ctypes.get_errno(), 'inotify_init1')
    watches = {}
    mask = 0x00000008 | 0x00000080 | 0x00000100

    def register(directory):
        if directory.is_dir() and directory not in watches.values():
            number = libc.inotify_add_watch(descriptor, os.fsencode(directory), mask)
            if number < 0:
                raise OSError(ctypes.get_errno(), str(directory))
            watches[number] = directory

    context = read_campaign_context()
    if context is not None:
        owner_path, root = context
        active = [root]
    else:
        owner_path = FOLLOWUP / 'stage-v3-read-v8-service-owner.json'
        active = [FOLLOWUP / name for name in ('rt21-callback-stage-integration-v3', 'rt12-read-integration-v8')]
    register(FOLLOWUP)
    for root in active:
        register(root)
        for name in ('runs', 'captures'):
            register(root / name)
            for directory in (root / name).rglob('*'):
                if directory.is_dir() and not directory.is_symlink():
                    register(directory)
    owner = json.loads(owner_path.read_text())
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus(private=True)
    manager = dbus.Interface(bus.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1'),
                             'org.freedesktop.systemd1.Manager')
    unit_path = manager.GetUnit(owner['unit'])
    loop = GLib.MainLoop()
    callback_errors = []

    def unit_changed(interface, changed, invalidated):
        if str(interface) == 'org.freedesktop.systemd1.Unit' and str(changed.get('ActiveState', '')) in ('inactive', 'failed'):
            loop.quit()

    def evidence_changed(source, condition):
        try:
            payload = os.read(descriptor, 1024 * 1024)
            relevant = False
            for number, event, name in decode_events(payload):
                if event & 0x00004000:
                    relevant = True
                    continue
                directory = watches.get(number)
                if directory is None:
                    continue
                path = directory / name
                if event & 0x40000000 and event & (0x00000080 | 0x00000100):
                    register(path)
                    for child in path.rglob('*'):
                        if child.is_dir() and not child.is_symlink():
                            register(child)
                    relevant = True
                relevant |= name in ('summary.json', 'result.json', 'hardware-summary.json', 'capture-proof.json',
                                     'separate-stage-v3-read-v8-hardware-queue.json') and bool(event & (0x00000008 | 0x00000080))
            if relevant:
                update()
        except Exception as error:
            callback_errors.append(error)
            loop.quit()
        return True

    subscription = bus.add_signal_receiver(unit_changed, signal_name='PropertiesChanged',
        dbus_interface='org.freedesktop.DBus.Properties', path=unit_path)
    manager.Subscribe()
    io_watch = GLib.io_add_watch(descriptor, GLib.IO_IN, evidence_changed)
    print('DOSSIER_WATCH_READY: inotify and exact-unit D-Bus subscriptions active; fixture_access=false', flush=True)
    try:
        update()
        notify = os.environ.get('NOTIFY_SOCKET')
        if notify:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as connection:
                connection.connect('\0' + notify[1:] if notify.startswith('@') else notify)
                connection.sendall(b'READY=1\nSTATUS=Failure dossier updated; watching metadata only')
        properties = dbus.Interface(bus.get_object('org.freedesktop.systemd1', unit_path), 'org.freedesktop.DBus.Properties')
        if str(properties.Get('org.freedesktop.systemd1.Unit', 'ActiveState')) not in ('inactive', 'failed'):
            loop.run()
        if callback_errors:
            raise callback_errors[0]
        update()
    finally:
        GLib.source_remove(io_watch)
        subscription.remove()
        manager.Unsubscribe()
        bus.close()
        os.close(descriptor)
    print('DOSSIER_BATCH_CLOSED', flush=True)


class DossierTests(unittest.TestCase):
    def test_new_snapshot_does_not_inherit_a_past_read_signature(self):
        self.assertNotIn(READ_CONTINUATION, READ_PHASE_SIGNATURES)
        self.assertNotIn(READ_RETRY, READ_PHASE_SIGNATURES)
        self.assertEqual(READ_PHASE_SIGNATURES['rt12-read-integration-v7'], 'fabric-filtered Fabrics')

    def test_latest_read_campaign_owner_is_selected(self):
        with patch.object(Path, 'exists', return_value=True):
            self.assertEqual(read_campaign_context(),
                             (FOLLOWUP / 'read-v10-service-owner.json', FOLLOWUP / READ_RETRY))
        with patch.object(Path, 'exists', side_effect=[False, True]):
            self.assertEqual(read_campaign_context(),
                             (FOLLOWUP / 'read-v9-service-owner.json', FOLLOWUP / READ_CONTINUATION))
        with patch.object(Path, 'exists', return_value=False):
            self.assertIsNone(read_campaign_context())

    def test_noc_attribution_is_bound_to_verified_outcome(self):
        run = FOLLOWUP / 'rt12-read-integration-v8/runs/pr539-nordic-ubuntu-TC_RT_1_2-1'
        self.assertEqual(VERIFIED_FAILURES[outcome_id(run, 1)][0], 'fabric-filtered NOCs')
        self.assertNotIn(outcome_id(run, 2), VERIFIED_FAILURES)
        self.assertNotIn(outcome_id(run.with_name('pr539-nordic-ubuntu-TC_RT_1_2-10'), 1), VERIFIED_FAILURES)
        self.assertEqual(KNOWLEDGE['fabric-filtered NOCs'][0], 2)

    def test_fabric_index_resolution_is_bound_to_verified_v9_outcomes(self):
        run = FOLLOWUP / READ_CONTINUATION / 'runs/pr539-nordic-ubuntu-TC_RT_1_2-10'
        for iteration in range(1, 11):
            self.assertEqual(VERIFIED_FAILURES[outcome_id(run, iteration)][0], 'CurrentFabricIndex')
        self.assertNotIn(outcome_id(run, 11), VERIFIED_FAILURES)
        self.assertNotIn(outcome_id(FOLLOWUP / READ_RETRY / run.name, 1), VERIFIED_FAILURES)
        self.assertNotIn('unclassified', RESOLUTIONS)
        self.assertNotIn('read comparison', RESOLUTIONS)
        self.assertNotIn('multi-admin-cleanup-timeout', RESOLUTIONS)

    def test_corrected_rerun_resolution_is_bound_to_five_exact_outcomes(self):
        root = FOLLOWUP / 'ubuntu-nordic-final/runs'
        for iteration in (1, 2, 3, 8, 9):
            run = root / ('pr539-nordic-ubuntu-TC_RT_1_2-' + ('1' if iteration == 1 else '10'))
            signature, references = VERIFIED_FAILURES[outcome_id(run, iteration)]
            self.assertEqual(signature, 'verified metadata/fabric scenes')
            self.assertEqual(len(references), 3)
            self.assertTrue(all(number > 0 for path, number in references))
        self.assertNotIn(outcome_id(root / 'pr539-nordic-ubuntu-TC_RT_1_2-10', 4), VERIFIED_FAILURES)
        self.assertNotIn(outcome_id(root / 'unrelated-TC_RT_1_2-10', 2), VERIFIED_FAILURES)
        self.assertNotIn('read comparison', RESOLUTIONS)

    def test_closed_batch_writeup(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            catalog = {'failures': [], 'incidents': [], 'updated_utc': 'test', 'warnings': [], 'batch_closed': True}
            with patch.dict(render.__globals__, HERE=destination):
                render(catalog, {})
            document = (destination / 'FAILURES.md').read_text()
            self.assertIn('Current batch is closed', document)
            self.assertNotIn('Current batch continues unchanged', document)
            self.assertIn('e9f5f6b7e8b1cfb1280f35f6b1c2d03237f0be2e', document)

    def test_requested_order(self):
        self.assertEqual(len(CATEGORIES), 5)
        self.assertEqual(KNOWLEDGE['multi-admin-cleanup-timeout'][0], 4)
        self.assertEqual(KNOWLEDGE['SecurePairing callback selection'][0], 2)

    def test_resolution_preserves_failures_and_leaves_unknowns_open(self):
        for signature, commit in (('fabric-filtered NOCs', 'e0b6f61'),
                                  ('bulk-write-verification', '6e93374'),
                                  ('SecurePairing callback selection', '2b0feed'),
                                  ('multi-admin-cleanup-timeout', None), ('unclassified', None)):
            with self.subTest(signature=signature), tempfile.TemporaryDirectory() as directory:
                destination = Path(directory)
                row = {'id': 'retained-failure', 'signature': signature, 'category': KNOWLEDGE[signature][0],
                       'phase': 'historical', 'iteration': 1, 'run': '/private/run',
                       'result': '/private/run/result.json', 'logs': [], 'supervisor': '/private/console.log',
                       'capture_directory': '/private/capture', 'source_and_closure': [],
                       'evidence_lines': [], 'confidence': 'test', 'closed': True}
                catalog = {'failures': [row], 'incidents': [], 'updated_utc': 'test',
                           'warnings': [], 'batch_closed': True}
                with patch.dict(render.__globals__, HERE=destination):
                    render(catalog, {})
                document = (destination / 'FAILURES.md').read_text()
                self.assertIn('## Remaining Work', document)
                self.assertIn('#### Failure retained-failure:', document)
                self.assertEqual(catalog['failures'], [row])
                if commit:
                    self.assertIn('Resolution: **FIXED**', document)
                    self.assertIn(commit, document)
                    self.assertNotIn('Next deciding check:', document)
                else:
                    self.assertIn('Resolution: **OPEN**', document)
                    self.assertIn('Next deciding check:', document)

    def test_new_failure_is_not_assumed_harness(self):
        self.assertEqual(new_signature({'exception': {'exception_msg': 'Concurrent read results mismatch'}}), 'unclassified')
        self.assertEqual(new_signature({'exception': {'exception_msg': 'SDK secret payload'}}), 'unclassified')
        self.assertEqual(new_signature({'exception': {'exception_msg': 'SecurePairing target not seen'}}), 'SecurePairing callback selection')

    def test_unique_identity_includes_full_run(self):
        self.assertNotEqual(outcome_id(Path('/original/run'), 1), outcome_id(Path('/recovery/run'), 1))
        self.assertNotEqual(outcome_id(Path('/original/run'), 1), outcome_id(Path('/original/run'), 2))

    def test_preservation_and_changed_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'controller.log'
            source.write_bytes(b'private-log-data')
            manifest = {}
            preserve(source, manifest, root / 'archive')
            saved = manifest[str(source.resolve())]
            self.assertEqual(Path(saved['copy']).read_bytes(), source.read_bytes())
            self.assertEqual(saved['sha256'], digest(source))
            preserve(source, manifest, root / 'archive')
            self.assertEqual(len(manifest), 1)
            source.write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError, 'Preserved original changed'):
                preserve(source, manifest, root / 'archive')

    def test_partial_summary_deduplication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = {'list_of_iteration_records': [{'iteration_number': 2, 'iteration_data': {
                'iteration_tc_execution_data': {'iteration_result': 'FAIL'}}}]}
            for name in ('first', 'second'):
                (root / name).mkdir()
                (root / name / 'summary.json').write_text(json.dumps(document))
            self.assertEqual(len(partial_records(root)), 1)

    def test_inotify_result_and_overflow(self):
        name = b'result.json\0'
        payload = struct.pack('iIII', 12, 8, 0, len(name)) + name + struct.pack('iIII', -1, 0x4000, 0, 0)
        self.assertEqual(list(decode_events(payload)), [(12, 8, 'result.json'), (-1, 0x4000, '')])

    def test_result_in_progress_is_deferred(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'result.json'
            self.assertIsNone(final_result(path))
            path.write_text('{')
            self.assertIsNone(final_result(path))
            path.write_text('{"executed": 1}')
            self.assertEqual(final_result(path), {'executed': 1})

    def test_writeup_git_visibility(self):
        workspace = Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], cwd=HERE, text=True).strip())
        prefix = HERE.relative_to(workspace).as_posix()
        visible = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '--', prefix], cwd=workspace, text=True).splitlines()
        self.assertIn(prefix + '/FAILURES.md', visible)
        self.assertIn(prefix + '/PR_REVIEW_20261013.md', visible)
        self.assertNotIn(prefix + '/catalog.json', visible)
        self.assertNotIn(prefix + '/preserved-files.json', visible)
        self.assertFalse(ARCHIVE.is_relative_to(workspace))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--update', action='store_true')
    parser.add_argument('--watch', action='store_true')
    parser.add_argument('--launch-watch', action='store_true')
    options = parser.parse_args()
    if options.self_test:
        unittest.main(argv=['update_dossier.py'], exit=True)
    elif options.launch_watch:
        state = subprocess.run(['systemctl', '--user', 'is-active', UNIT], capture_output=True, text=True)
        if state.stdout.strip() != 'active':
            subprocess.run(['systemd-run', '--user', '--unit=' + UNIT, '--property=UMask=0077',
                            '--property=Type=notify', '--property=NotifyAccess=main', '--property=TimeoutStartSec=300',
                            '--property=StandardInput=null', '--property=Restart=no',
                            '--property=StandardOutput=append:' + str(ARCHIVE / 'observer.log'),
                            '--property=StandardError=append:' + str(ARCHIVE / 'observer.log'),
                            '/usr/bin/python3.10', str(HERE / 'update_dossier.py'), '--watch'], check=True)
        print(subprocess.check_output(['systemctl', '--user', 'show', UNIT, '--property=ActiveState',
                                      '--property=SubState', '--property=MainPID'], text=True), flush=True)
    elif options.watch:
        watch()
    elif options.update:
        update()
    else:
        parser.error('Choose --update, --watch, --launch-watch or --self-test')


if __name__ == '__main__':
    main()