import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time
import unittest
import urllib.request


PRIVATE = Path('/home/feasel/qa-mar6/37075-increment-20261017')
PREVIOUS = Path('/home/feasel/qa-mar6/rt12-followup-20261017')
LABELS = {
    'reset_completed': 'Reset Completed',
    'reset_command': 'matter device factoryreset',
    'reboot_command': 'kernel reboot',
    'boot': 'Booting',
    'commissionable': 'commissionable',
    'advertising': 'advertis',
    'discovery': 'discovery',
    'pase': 'PASE',
    'pbkdf_request': 'PBKDFParamRequest',
    'pbkdf_response': 'PBKDFParamResponse',
    'pake1': 'PASE_Pake1',
    'pake2': 'PASE_Pake2',
    'pake3': 'PASE_Pake3',
    'pairing_complete': 'Pairing complete',
    'commissioning_complete': 'Commissioning complete',
    'ble_connection': 'BLE connection',
    'ble_endpoint': 'BLE EndPoint',
    'ble_disconnect': 'disconnect',
    'ble_close': 'closing',
    'ble_subscribe': 'subscrib',
    'connection_established': 'connection established',
    'transport_closed': 'transport closed',
    'timeout': 'timed out',
    'timeout_label': 'timeout',
    'incorrect_state': 'Incorrect state',
    'internal_error': 'Internal error',
    'pairing_start': 'Commission with DUT and De-commission',
    'cleanup': 'cleaning_up',
    'case_busy': 'Already in the middle of CASE handshake',
    'case_start': 'CASE Server received Sigma1',
}
HEADER = re.compile(r'(>>>|<<<).*?E:(\d+)([ir]).*?S:(\d+).*?M:(\d+).*?Type ([0-9A-Fa-f]{4}):([0-9A-Fa-f]{2})')


def event(line):
    labels = [name for name, needle in LABELS.items() if needle.lower() in line.lower()]
    codes = re.findall(r'CHIP Error (0x[0-9A-Fa-f]{8})(?![0-9A-Fa-f])', line)
    header = HEADER.search(line)
    if not labels and not codes and not header:
        return None
    stamp = re.search(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[,.]\d+', line)
    epoch = re.search(r'\[(\d{10}\.\d+)\]', line)
    uptime = re.search(r'\[(\d{2,}:\d{2}:\d{2}\.\d+)\]', line)
    result = {'labels': labels, 'codes': codes,
        'timestamp': stamp[0] if stamp else None, 'epoch': float(epoch[1]) if epoch else None,
        'uptime': uptime[1] if uptime else None,
        'source': re.findall(r'([A-Za-z0-9_]+\.cpp):(\d+)', line)}
    if header:
        result['message'] = {'direction': header[1], 'exchange': int(header[2]), 'role': header[3],
            'session': int(header[4]), 'counter': int(header[5]),
            'protocol': int(header[6], 16), 'opcode': int(header[7], 16)}
        peer = re.search(r'((?:UDP|TCP):\[[0-9A-Fa-f:%]+\]:\d+|(?:UDP|TCP):[0-9.]+:\d+|BLE)', line)
        if peer:
            result['message']['peer_address'] = peer[1]
    return result


def read_events(path):
    rows = []
    with path.open(errors='replace') as stream:
        for number, line in enumerate(stream, 1):
            row = event(line)
            if row:
                rows.append({'line': number, **row})
    return rows


def save(name, document):
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    path = PRIVATE / name
    path.write_text(json.dumps(document, indent=2) + '\n')


def pase():
    selected = []
    for directory in ('rt21-first-failure-75', 'rt21-first-failure-75-successor-76'):
        manifest = json.loads((PREVIOUS / directory / 'manifest.json').read_text())
        for source, record in manifest['objects'].items():
            if not re.search(r'/(74|75|76)/(controller_log|Dut_log)', source):
                continue
            path = Path(record['copy'])
            with path.open('rb') as stream:
                assert hashlib.file_digest(stream, 'sha256').hexdigest() == record['sha256']
            rows = read_events(path)
            selected.append({'source': source, 'sha256': record['sha256'], 'events': rows})
    assert len(selected) == 6
    document = {'checked_utc': datetime.now(timezone.utc).isoformat(), 'logs': selected,
        'values_and_payloads_excluded': True}
    save('pase-74-76-events.json', document)
    for log in selected:
        rows = log['events']
        print(json.dumps({'source': log['source'], 'events': len(rows),
            'label_counts': dict(Counter(label for row in rows for label in row['labels']))}))
        shown = rows if '/75/' in log['source'] else rows[-30:] if '/74/' in log['source'] else rows[:35]
        for row in shown:
            print(json.dumps(row))


def sources():
    repository = '/home/feasel/matter-oct14/connectedhomeip-pr527-fixture'
    revision = '24a1bc052a7dfd3db809e43bb0da7c93b20bfad6'
    selections = {
        'src/crypto/CHIPCryptoPALOpenSSL.cpp': (1165, 1181),
        'src/controller/SetUpCodePairer.cpp': (100, 250, 270, 315, 390, 420, 560, 640, 790, 1000),
        'src/controller/python/ChipDeviceController-ScriptDevicePairingDelegate.cpp': (80, 120),
        'src/app/ReadHandler.cpp': (230, 280, 630, 675),
        'src/app/reporting/Engine.cpp': (875, 955, 1130, 1170),
        'src/app/OperationalSessionSetup.cpp': (75, 175, 450, 535),
        'src/app/CASESessionManager.cpp': (50, 220),
        'src/app/ReadClient.cpp': (1352, 1425, 1485, 1500),
    }
    for name, ranges in selections.items():
        result = subprocess.run(['git', '-C', repository, 'show', revision + ':' + name], capture_output=True, text=True)
        if result.returncode:
            print(json.dumps({'file': name, 'available_at_pinned_revision': False}))
            continue
        lines = result.stdout.splitlines()
        print(json.dumps({'file': name, 'revision': revision, 'sha256': hashlib.sha256(result.stdout.encode()).hexdigest()}))
        for lower, upper in zip(ranges[::2], ranges[1::2]):
            for number in range(lower, min(upper, len(lines)) + 1):
                print(f'{number}: {lines[number - 1]}')


def coordination_sources():
    repository = '/home/feasel/matter-oct14/connectedhomeip-pr527-fixture'
    revision = '24a1bc052a7dfd3db809e43bb0da7c93b20bfad6'
    markers = {
        'src/app/reporting/Engine.cpp': ('void Engine::Run()', 'void Engine::OnReportConfirm()', 'mNumReportsInFlight--'),
        'src/app/ReadHandler.cpp': ('ReadHandler::OnStatusResponse', 'void ReadHandler::MoveToState'),
        'src/app/CASESessionManager.cpp': ('FindExistingSessionSetup(peerId', 'session->Connect('),
        'src/app/CASESessionManager.h': ('uint8_t attemptCount = 1',),
        'src/app/OperationalSessionSetup.cpp': ('EnqueueConnectionCallbacks(', 'case State::Connecting:',
            'CHIP_ERROR_TIMEOUT == error || CHIP_ERROR_BUSY == error', 'NotifyConnectionCallbacks(',
            '--mRemainingAttempts;', '--attemptCount;'),
        'src/app/ReadClient.cpp': ('ReadClient::HandleDeviceConnectionFailure', 'mMinimalResubscribeDelay =',
            'ReadClient::EstablishSessionToPeer()'),
    }
    records = []
    for name, needles in markers.items():
        content = subprocess.check_output(['git', '-C', repository, 'show', revision + ':' + name])
        lines = content.decode().splitlines()
        found = {needle: [number for number, line in enumerate(lines, 1) if needle in line] for needle in needles}
        assert all(found.values()), name
        records.append({'file': name, 'revision': revision, 'sha256': hashlib.sha256(content).hexdigest(), 'markers': found})
    result = {'pinned_source_receipts': records, 'binary_compile_flags_not_inferred': True}
    save('coordination-pinned-sources.json', result)
    print(json.dumps(result, indent=2))


def dut_reporting_binary():
    specification = importlib.util.spec_from_file_location('rt12_binary_access', PREVIOUS / 'work.py')
    driver = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(driver)
    code = r'''from pathlib import Path
import hashlib,json,subprocess
assert Path('/etc/machine-id').read_text().strip()=='fa898f2a8e5c487489c516aaa233f86a'
expected='cbc6f50f2641ec5d93fdf074e2890ce8d5363fe3dce641e325bdfc1ad0ff947b'
binary=Path.home()/'matter-pr539-dut-20261007/bin/chip-pr539-dut'
assert hashlib.sha256(binary.read_bytes()).hexdigest()==expected, 'The retained DUT binary differs from the sealed reproduction'
symbol='_ZN4chip3app9reporting6Engine3RunEv'
output=subprocess.check_output(['objdump','-d','--disassemble='+symbol,str(binary)],text=True,timeout=30)
assert '<'+symbol+'>:' in output, 'Retained binary has no separately inspectable reporting Engine::Run symbol'
print(json.dumps({'binary':str(binary),'sha256':expected,'symbol':symbol,'disassembly':output}))
'''
    result = json.loads(driver.ssh('raspberrypi-2.local', code))
    save('dut-reporting-binary.json', result)
    print(json.dumps(result, indent=2))


def controller_retry_binary():
    specification = importlib.util.spec_from_file_location('rt12_retry_access', PREVIOUS / 'work.py')
    driver = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(driver)
    code = r'''from pathlib import Path
import hashlib,json,subprocess
assert Path('/etc/machine-id').read_text().strip()=='ef72df43fba94793ab724dc3013cec17'
binary=Path.home()/'matter-sdk74676-hardware-20261013/controller/matter/_ChipDeviceCtrl.so'
expected='a04c667b4adba6df6041674acf8787e54e0935b80bb0e3e46c98933af984dd11'
assert hashlib.sha256(binary.read_bytes()).hexdigest()==expected
symbols=subprocess.check_output(['nm',str(binary)],text=True,timeout=30)
selected=[line.split()[-1] for line in symbols.splitlines() if 'OperationalSessionSetup' in line and 'OnSessionEstablishmentError' in line]
assert len(selected)==1, 'Expected one concrete operational-session error handler'
output=subprocess.check_output(['objdump','-d','--disassemble='+selected[0],str(binary)],text=True,timeout=30)
assert '<'+selected[0]+'>:' in output
callers=[line.split()[-1] for line in symbols.splitlines() if 'ReadClient' in line and 'EstablishSessionToPeer' in line]
assert len(callers)==1
caller=subprocess.check_output(['objdump','-d','--disassemble='+callers[0],str(binary)],text=True,timeout=30)
needles=('TryNextResult','ScheduleSessionSetupReattempt','NotifyRetryHandlers','DequeueConnectionCallbacks')
print(json.dumps({'binary':str(binary),'sha256':expected,'symbol':selected[0],
    'call_markers':{needle:[line.strip() for line in output.splitlines() if needle in line] for needle in needles},
    'subscription_caller':{'symbol':callers[0],'disassembly':caller,
        'argument_and_call_instructions':[line.strip() for line in caller.splitlines()
            if 'mov\tw4,' in line or 'FindOrEstablishSession' in line]},
    'disassembly':output,'presence_does_not_establish_remaining_attempt_count':True}))
'''
    result = json.loads(driver.ssh('192.168.1.221', code))
    save('controller-retry-binary.json', result)
    print(json.dumps({key: value for key, value in result.items() if key != 'disassembly'}, indent=2))


def metadata():
    rows = []
    for number, directory in ((527, 'matter-qa-527'), (545, 'matter-qa-nordic-verification'),
            (548, 'matter-qa-read-consistency'), (549, 'matter-qa-callback-lifetime'), (550, 'matter-qa-stage-selection')):
        document = json.loads(subprocess.check_output(['gh', 'api', f'repos/CHIP-Specifications/matter-qa/pulls/{number}']))
        worktree = Path('/home/feasel/qa-mar6') / directory
        head = subprocess.check_output(['git', '-C', str(worktree), 'rev-parse', 'HEAD'], text=True).strip()
        row = {'number': number, 'head': document['head']['sha'], 'branch': document['head']['ref'],
            'fork': document['head']['repo']['full_name'], 'state': document['state'], 'draft': document['draft'],
            'local_head': head, 'local_head_matches': head == document['head']['sha'],
            'local_status': subprocess.check_output(['git', '-C', str(worktree), 'status', '--porcelain'], text=True).splitlines()}
        rows.append(row)
    save('current-pr-heads.json', {'utc': datetime.now(timezone.utc).isoformat(), 'pull_requests': rows})
    print(json.dumps(rows, indent=2))


def remote_probe():
    spec = importlib.util.spec_from_file_location('previous_investigation', PREVIOUS / 'work.py')
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    code = '''from pathlib import Path
import json,re,hashlib
assert Path('/etc/machine-id').read_text().strip()=='ef72df43fba94793ab724dc3013cec17'
root=Path('/home/feasel/matter-rt12-read-probe-20261017')
rows=[]
files=[]
for path in root.glob('runs/**/Dut_log*'):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for number,encoded in enumerate(stream,1):
            digest.update(encoded)
            line=encoded.decode(errors='replace')
            header=re.search(r'(>>>|<<<).*?E:(54314|54315)([ir]).*?S:(\\d+).*?M:(\\d+).*?Type ([0-9A-Fa-f]{4}):([0-9A-Fa-f]{2})',line)
            if header:
                stamp=re.search(r'\\[(\\d{10}\\.\\d+)\\]',line)
                rows.append({'file':str(path),'line':number,'epoch':float(stamp[1]) if stamp else None,'direction':header[1],
                    'exchange':int(header[2]),'session':int(header[4]),'counter':int(header[5]),'protocol':int(header[6],16),'opcode':int(header[7],16)})
    files.append({'file':str(path),'sha256':digest.hexdigest(),'bytes':path.stat().st_size})
print(json.dumps({'matched_pi_dut_events':rows,'files':files}))
'''
    compile(code, '<remote-matched-events>', 'exec')
    response = driver.ssh('192.168.1.221', code)
    document = json.loads(response)
    assert len(document['files']) == 1 and len(document['matched_pi_dut_events']) == 12
    save('pi-dut-cross-fixture-events.json', document)
    print(json.dumps(document, indent=2))


def qa_units():
    python = '/home/feasel/matter-oct14/connectedhomeip-pr527-fixture/out/python_env_host_313/bin/python'
    sdk = '/home/feasel/matter-oct14/connectedhomeip'
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    results = []
    for number, directory, module in ((548, 'matter-qa-read-consistency', 'test_rt12_read_consistency'),
            (527, 'matter-qa-527', 'test_pairing_cleanup')):
        worktree = Path('/home/feasel/qa-mar6') / directory
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
            PYTHONPATH='/home/feasel/qa-mar6/pr539-five-matrix-20261014/controller:' + str(worktree / 'src'),
            LD_LIBRARY_PATH=sdk + '/out/host-deps/libevent/usr/lib/x86_64-linux-gnu')
        destination = PRIVATE / (module + '.private.log')
        with destination.open('w') as stream:
            result = subprocess.run([python, '-B', '-m', 'unittest', 'matter_qa.unit_tests.' + module],
                cwd=worktree, env=environment, stdout=stream, stderr=subprocess.STDOUT)
        summary = re.findall(r'Ran \d+ tests? in [^\n]+|^OK$|^FAILED[^\n]*', destination.read_text(), re.M)
        row = {'pr': number, 'head': subprocess.check_output(['git', '-C', str(worktree), 'rev-parse', 'HEAD'], text=True).strip(),
            'suite': module, 'exit': result.returncode, 'summary': summary}
        results.append(row)
        print(json.dumps(row), flush=True)
        assert result.returncode == 0
    save('fresh-qa-unit-results.json', results)


def attribute_metadata():
    python = '/home/feasel/matter-oct14/connectedhomeip-pr527-fixture/out/python_env_host_313/bin/python'
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
        PYTHONPATH='/home/feasel/qa-mar6/pr539-five-matrix-20261014/controller',
        LD_LIBRARY_PATH='/home/feasel/matter-oct14/connectedhomeip/out/host-deps/libevent/usr/lib/x86_64-linux-gnu')
    code = '''import json
from matter import clusters
cluster=next(value for value in vars(clusters).values() if isinstance(value,type) and getattr(value,'id',None)==0xFFF1FC05)
rows=[]
for name,attribute in vars(cluster.Attributes).items():
    if isinstance(attribute,type) and getattr(attribute,'attribute_id',None) in (49,50,12289,16426):
        rows.append({'cluster':cluster.__name__,'name':name,'id':attribute.attribute_id,'type':str(getattr(attribute,'attribute_type',None))})
print(json.dumps(rows,indent=2))
'''
    result = subprocess.check_output([python, '-B', '-c', code], env=environment, text=True)
    save('decode-attribute-metadata.json', json.loads(result))
    print(result)


def discovery_filter():
    selected = []
    manifest = json.loads((PREVIOUS / 'rt21-first-failure-75/manifest.json').read_text())
    for name, record in manifest['objects'].items():
        if '/75/controller_log' not in name:
            continue
        path = Path(record['copy'])
        with path.open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == record['sha256']
        for number, line in enumerate(path.open(errors='replace'), 1):
            for label, pattern in {
                'short_discriminator': r'\bshort discriminator\s*(?:=|:)?\s*(0x[0-9A-Fa-f]+|\d+)',
                'long_discriminator': r'\blong discriminator\s*(?:=|:)?\s*(0x[0-9A-Fa-f]+|\d+)',
                'discovered_discriminator': r'discovered device with discriminator\s*(?:=|:)?\s*(\d+)',
                'filter': r'filter type (\d+).*?code (\d+)',
            }.items():
                match = re.search(pattern, line, re.I)
                if match:
                    selected.append({'line': number, 'label': label, 'numbers': list(match.groups())})
    root = Path('/home/feasel/qa-mar6/rt21-endurance-20261016/runs/combined-nordic-ubuntu-TC_RT_2_1-100')
    python = '/home/feasel/matter-oct14/connectedhomeip-pr527-fixture/out/python_env_host_313/bin/python'
    code = '''from pathlib import Path
import json,yaml
from unittest.mock import patch
from matter.native import GetLibraryHandle,HandleFlags
from matter.setup_payload import SetupPayload
config=yaml.safe_load(Path(''' + repr(str(root / 'config.yaml')) + ''').read_text())
rows=[]
def visit(value,path=()):
    if isinstance(value,dict):
        for key,item in value.items(): visit(item,path+(str(key),))
    elif isinstance(value,(str,int)) and 'manual' in '.'.join(path).lower() and len(str(value)) in (11,21) and str(value).isdigit():
        with patch('matter.setup_payload.setup_payload.GetLibraryHandle',return_value=GetLibraryHandle(HandleFlags(0))):
            payload=SetupPayload().ParseManualPairingCode(str(value))
        rows.append({'key':'.'.join(path),'short_discriminator':payload.short_discriminator,'long_discriminator':payload.long_discriminator})
visit(config)
invocation=json.loads(Path(''' + repr(str(root / 'invocation-private.json')) + ''').read_text())
def command_arguments(value):
    if isinstance(value,dict):
        for item in value.values(): command_arguments(item)
    elif isinstance(value,list):
        if '--discriminator' in value:
            discriminator=int(value[value.index('--discriminator')+1])
            rows.append({'key':'actual_invocation.--discriminator','long_discriminator':discriminator,
                'generated_manual_short_discriminator':discriminator>>8})
        else:
            for item in value: command_arguments(item)
command_arguments(invocation)
print('SAFE_RESULT:'+json.dumps(rows))
'''
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
        PYTHONPATH='/home/feasel/qa-mar6/pr539-five-matrix-20261014/controller',
        LD_LIBRARY_PATH='/home/feasel/matter-oct14/connectedhomeip/out/host-deps/libevent/usr/lib/x86_64-linux-gnu')
    output = subprocess.check_output([python, '-B', '-c', code], env=environment, text=True)
    safe = [line.removeprefix('SAFE_RESULT:') for line in output.splitlines() if line.startswith('SAFE_RESULT:')]
    assert len(safe) == 1
    result = {'sealed_log_discriminators': selected, 'parsed_config_discriminators': json.loads(safe[0])}
    save('nordic-discovery-filter.json', result)
    print(json.dumps(result, indent=2))


def serial_timing():
    manifest = json.loads((PREVIOUS / 'controller-object-manifest.json').read_text())
    selected = [name for name in manifest if name.startswith('serial-reads/')
        and ('/controller_log_iteration_' in name or '/Dut_log_iteration_' in name)]
    assert len(selected) == 2
    patterns = {
        'mrp_ack': r'Rxd Ack; Removing MessageCounter:(\d+) from Retrans Table on exchange (\d+)([ir])',
        'retransmission': r'<<(\d+) \[E:(\d+)([ir]) S:(\d+) M:(\d+)',
        'report_timeout': r'Time out! failed to receive (?:report data|status response) from Exchange: (\d+)([ir])',
        'chunked': r'MoreChunkedMessages\s*=\s*(true|false)',
        'im_status': r'\bStatus\s*=\s*(0x[0-9A-Fa-f]+)',
        'case_protocol_error': r'Received error \(protocol code (\d+)\) during pairing process:.*?CHIP Error (0x[0-9A-Fa-f]+)',
        'case_initiator': r'Initiating session on local FabricIndex (\d+) from 0x([0-9A-Fa-f]{16}) -> 0x([0-9A-Fa-f]{16})',
        'resubscription_peer': r'Will try to resubscribe to ([0-9A-Fa-f]+):([0-9A-Fa-f]{16}) at retry index (\d+) after (\d+)ms',
        'session_state': r"SecureSession\[[^\]]*, LSID:(\d+)\]: State change '([A-Za-z]+)' --> '([A-Za-z]+)'",
        'resubscription_force_case': r'OnResubscribeTimerCallback: ForceCASE = (\d+)',
    }
    fixed = ('Already in the middle of CASE handshake', 'CASE Server received Sigma1',
        'CASESession timed out', 'Resubscribe', 'resubscribe', 'Session establishment failed',
        'CASESession moving', 'CASESession: State', 'CASESessionManager', 'CASEClient',
        'CASE session established', 'SecureSession state change', 'ReadClient moving')
    document = {'logs': [], 'raw_values_excluded': True}
    with tarfile.open(PREVIOUS / 'controller-sealed-collection.tar.gz') as archive:
        for name in selected:
            digest = hashlib.sha256()
            rows = []
            nearest = None
            last_epoch = None
            for number, encoded in enumerate(archive.extractfile('objects/' + manifest[name]['sha256']), 1):
                digest.update(encoded)
                line = encoded.decode(errors='replace')
                epoch = re.search(r'\[(\d{10}\.\d+)\]', line)
                if epoch:
                    last_epoch = float(epoch[1])
                stamp = re.search(r'2026-10-17 09:(\d{2}):(\d{2})[,.](\d+)', line)
                if '/controller_log_' in name:
                    inside = stamp and 8 * 60 + 40 <= int(stamp[1]) * 60 + int(stamp[2]) <= 9 * 60 + 45
                else:
                    inside = last_epoch is not None and 1792242520 <= last_epoch <= 1792242585
                header = HEADER.search(line)
                if header:
                    nearest = {'exchange': int(header[2]), 'session': int(header[4]), 'counter': int(header[5])}
                if not inside:
                    continue
                fields = {label: list(match.groups()) for label, pattern in patterns.items()
                    if (match := re.search(pattern, line))}
                labels = [needle for needle in fixed if needle in line]
                row = event(line)
                if header or fields or labels:
                    rows.append({'line': number, 'epoch': last_epoch,
                        'timestamp': stamp[0] if stamp else None, 'fields': fields, 'labels': labels,
                        'nearest_preceding_header': nearest, 'message': row.get('message') if row else None})
            assert digest.hexdigest() == manifest[name]['sha256']
            document['logs'].append({'source': name, 'sha256': digest.hexdigest(), 'events': rows})
    save('serial-timing-events.json', document)
    for log in document['logs']:
        print(json.dumps({'source': log['source'], 'events': len(log['events']),
            'fields': dict(Counter(label for row in log['events'] for label in row['fields'])),
            'labels': dict(Counter(label for row in log['events'] for label in row['labels']))}))
        for row in log['events']:
            exchange = (row['message'] or row['nearest_preceding_header'] or {}).get('exchange')
            if row['fields'] and not set(row['fields']).intersection(('mrp_ack', 'retransmission', 'chunked', 'im_status')) or row['labels']:
                print(json.dumps(row))


def reporting_state(line):
    patterns = {
        'reports_in_flight': r'<RE> OnReportConfirm: NumReports = (\d+)',
        'handler_state': r'IM RH moving to \[([A-Za-z]+)\]',
        'build_generation': r'Building Reports for ReadHandler with LastReportGeneration = (\d+)',
    }
    result = {name: match[1] for name, pattern in patterns.items() if (match := re.search(pattern, line))}
    sent = re.search(r'<RE> ReportsInFlight = (\d+) with readHandler (\d+), RE has (more|no more) messages', line)
    if sent:
        result['report_sent'] = {'in_flight': int(sent[1]), 'cursor': int(sent[2]), 'more_chunks': sent[3] == 'more'}
    return result


def reporting_progress(rows, after_line, before_line):
    selected = [row for row in rows if after_line < row['line'] < before_line]
    reports = [row for row in selected if (message := row.get('message'))
        and (message['direction'], message['protocol'], message['opcode']) == ('<<<', 1, 5)]
    confirmations = [row for row in selected if 'reports_in_flight' in row['fields']]
    sent = [row for row in selected if 'report_sent' in row['fields']]
    return {'after_line_exclusive': after_line, 'before_line_exclusive': before_line,
        'report_send_headers': [{'line': row['line'], 'epoch': row['epoch'], 'message': row['message']} for row in reports],
        'distinct_report_exchanges': len({(row['message']['exchange'], row['message']['session']) for row in reports}),
        'confirmations': [{'line': row['line'], 'epoch': row['epoch'], 'post_release_in_flight': int(row['fields']['reports_in_flight'])}
            for row in confirmations],
        'cursor_observations': [{'line': row['line'], 'epoch': row['epoch'], **row['fields']['report_sent']} for row in sent],
        'cursor_is_not_handler_identity_or_allocation_count': True,
        'generic_states_not_assigned_to_exchanges': True}


def registration_marker(line):
    labels = {
        'operational_registration_attempt': 'Advertise operational node',
        'publication_marker': 'mDNS service published:',
        'advertiser_started': 'mDNS started advertising',
        'minimal_backend_started': 'CHIP minimal mDNS started advertising',
        'operational_records_configured': "CHIP minimal mDNS configured as 'Operational device'",
        'record_send_failure': 'Failed to advertise records:',
        'operational_registration_failure': 'Failed to advertise operational node',
        'wifi_connected': 'WiFi station is now connected',
        'ipv6_established': 'IPv6 connectivity established',
        'failsafe_expired': 'Fail-safe timer expired',
    }
    return [name for name, marker in labels.items() if marker.lower() in line.lower()]


def dnssd_registration():
    root = Path('/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs')
    records = []
    for attempt in ('a04', 'a09', 'a10'):
        path = root / ('wifi-primary-smokes-01-' + attempt) / 'dut/dut.log'
        digest = hashlib.sha256()
        rows = []
        with path.open('rb') as stream:
            for number, encoded in enumerate(stream, 1):
                digest.update(encoded)
                line = encoded.decode(errors='replace')
                labels = registration_marker(line)
                if labels:
                    stamp = re.search(r'\[(\d{10}\.\d+)\]', line)
                    rows.append({'line': number, 'epoch': float(stamp[1]) if stamp else None, 'labels': labels,
                        'service_types': re.findall(r'_matter[cd]?\._(?:tcp|udp)', line)})
        records.append({'attempt': attempt, 'path': str(path), 'sha256': digest.hexdigest(), 'events': rows})
    save('dnssd-registration-boundary.json', {'logs': records, 'attempt_is_not_completion': True,
        'publication_marker_is_not_wire_delivery': True})
    print(json.dumps(records, indent=2))


def subscription_lifecycle(line):
    established = re.search(r'Subscription established in (\d+)ms with SubscriptionID = 0x([0-9a-fA-F]+) '
        r'MinInterval = (\d+)s MaxInterval = (\d+)s Peer = ([0-9a-fA-F]+):([0-9a-fA-F]+)', line)
    if established:
        return {'kind': 'client_established', 'subscription': int(established[2], 16),
            'fabric': int(established[5], 16), 'peer_node': int(established[6], 16),
            'min_interval': int(established[3]), 'max_interval': int(established[4])}
    torn_down = re.search(r'Subscription id 0x([0-9a-fA-F]+) from node .* torn down', line)
    if torn_down:
        return {'kind': 'server_torn_down', 'subscription': int(torn_down[1], 16)}
    timeout = re.search(r'Subscription Liveness timeout with SubscriptionID = 0x([0-9a-fA-F]+)', line)
    if timeout:
        return {'kind': 'client_timeout', 'subscription': int(timeout[1], 16)}
    return None


def reporting_census():
    manifest = json.loads((PREVIOUS / 'controller-object-manifest.json').read_text())
    names = [name for name in manifest if name.startswith('serial-reads/')
        and ('/controller_log_iteration_' in name or '/Dut_log_iteration_' in name)]
    assert len(names) == 2
    logs = []
    with tarfile.open(PREVIOUS / 'controller-sealed-collection.tar.gz') as archive:
        for name in names:
            digest = hashlib.sha256()
            rows = []
            requests = []
            target_session = 16494 if '/controller_log_' in name else 22676
            epoch = None
            for number, encoded in enumerate(archive.extractfile('objects/' + manifest[name]['sha256']), 1):
                digest.update(encoded)
                line = encoded.decode(errors='replace')
                stamp = re.search(r'\[(\d{10}\.\d+)\]', line)
                if stamp:
                    epoch = float(stamp[1])
                header = HEADER.search(line)
                if header and (int(header[2]), int(header[4]), int(header[5]), int(header[6], 16), int(header[7], 16)) == (
                        12712, target_session, 223246027, 1, 2):
                    requests.append(number)
                row = subscription_lifecycle(line)
                if row:
                    rows.append({'line': number, 'epoch': epoch, **row})
            assert digest.hexdigest() == manifest[name]['sha256']
            assert requests
            logs.append({'source': name, 'sha256': digest.hexdigest(), 'th2_read_request_line': requests[0],
                'matched_request_counter': 223246027, 'matched_request_header_lines': requests, 'events': rows})
    controller = next(log for log in logs if '/controller_log_' in log['source'])
    dut = next(log for log in logs if '/Dut_log_' in log['source'])
    established = [row for row in controller['events'] if row['kind'] == 'client_established'
        and row['line'] < controller['th2_read_request_line']]
    ids = {row['subscription'] for row in established}
    closed_before_request = [row for row in dut['events'] if row['kind'] == 'server_torn_down'
        and row['subscription'] in ids and row['line'] < dut['th2_read_request_line']]
    closed_during_gap = [row for row in dut['events'] if row['kind'] == 'server_torn_down'
        and row['subscription'] in ids and row['epoch'] is not None and 1792242562.989 <= row['epoch'] <= 1792242569.767]
    result = {'logs': logs, 'client_established_before_th2': established,
        'unique_client_established_ids_before_th2': len(ids), 'matching_server_closures_before_th2': closed_before_request,
        'matching_server_closures_during_gap': closed_during_gap,
        'absence_of_teardown_logs_is_not_an_allocation_or_closure_proof': True,
        'server_active_handler_count_observed': None}
    save('reporting-census.json', result)
    print(json.dumps({key: value for key, value in result.items() if key != 'logs'}, indent=2))


def reporting_gap():
    manifest = json.loads((PREVIOUS / 'controller-object-manifest.json').read_text())
    selected = [name for name in manifest if name.startswith('serial-reads/') and '/Dut_log_iteration_' in name]
    assert len(selected) == 1
    name = selected[0]
    digest = hashlib.sha256()
    rows = []
    epoch = None
    with tarfile.open(PREVIOUS / 'controller-sealed-collection.tar.gz') as archive:
        for number, encoded in enumerate(archive.extractfile('objects/' + manifest[name]['sha256']), 1):
            digest.update(encoded)
            line = encoded.decode(errors='replace')
            stamp = re.search(r'\[(\d{10}\.\d+)\]', line)
            if stamp:
                epoch = float(stamp[1])
            if epoch is None or not 1792242562.6 <= epoch <= 1792242570:
                continue
            fields = reporting_state(line)
            header = HEADER.search(line)
            if fields or header:
                rows.append({'line': number, 'epoch': epoch, 'fields': fields,
                    'message': event(line).get('message') if header else None})
    assert digest.hexdigest() == manifest[name]['sha256']
    assert any(row['message'] and row['message']['counter'] == 47688567 for row in rows)
    result = {'source': name, 'sha256': digest.hexdigest(), 'events': rows,
        'after_th2_status_before_late_report': reporting_progress(rows, 489793, 492109),
        'handler_states_are_not_individually_identified': True}
    save('reporting-gap.json', result)
    states = [row for row in rows if row['fields']]
    print(json.dumps({'sha256': digest.hexdigest(), 'events': len(rows), 'state_events': len(states),
        'state_distribution': dict(Counter(str(row['fields']) for row in states)),
        'first_states': states[:12], 'last_states': states[-12:],
        'message_types': dict(Counter(f"{row['message']['direction']}:{row['message']['protocol']}:{row['message']['opcode']}"
            for row in rows if row['message'])),
        'th2_messages': [row for row in rows if row['message'] and row['message']['exchange'] == 12712],
        'after_th2_status_before_late_report': result['after_th2_status_before_late_report'],
        'handler_states_are_not_individually_identified': True}, indent=2))


def serial_summary():
    document = json.loads((PRIVATE / 'serial-timing-events.json').read_text())
    for log in document['logs']:
        controller = '/controller_log_' in log['source']
        print(json.dumps({'source': log['source'], 'event_count': len(log['events'])}))
        for row in log['events']:
            message = row['message'] or {}
            moment = row['timestamp'] or ''
            relevant = (controller and moment >= '2026-10-17 09:09:22') or (not controller and (row['epoch'] or 0) >= 1792242562
                and (message.get('exchange') == 12712 or row['labels'] or row['fields'].get('report_timeout')))
            if relevant and (message.get('exchange') == 12712 or row['labels'] or row['fields'].get('report_timeout')
                    or row['fields'].get('case_protocol_error') or message.get('protocol') == 0 and message.get('opcode') in (48,49,50,51,64)):
                print(json.dumps(row))


def serial_findings():
    logs = json.loads((PRIVATE / 'serial-timing-events.json').read_text())['logs']
    controller = next(log['events'] for log in logs if '/controller_log_' in log['source'])
    dut = next(log['events'] for log in logs if '/Dut_log_' in log['source'])
    reports = []
    for counter in (47688554, 47688560, 47688567):
        reports.append({'counter': counter,
            'dut_send': [{'line': row['line'], 'epoch': row['epoch']} for row in dut
                if row['message'] and row['message']['exchange'] == 12712 and row['message']['counter'] == counter
                and row['message']['direction'] == '<<<'],
            'controller_receive': [{'line': row['line'], 'timestamp': row['timestamp']} for row in controller
                if row['message'] and row['message']['exchange'] == 12712 and row['message']['counter'] == counter
                and row['message']['direction'] == '>>>']})
    retransmissions = [{'side': side, **row} for side, rows in (('controller', controller), ('dut', dut)) for row in rows
        if row['fields'].get('retransmission', ['0', '0'])[1] == '12712']
    final_ack = [{'side': side, **row} for side, rows in (('controller', controller), ('dut', dut)) for row in rows
        if row['fields'].get('mrp_ack', ['0'])[0] in ('47688560', '47688567', '223246083')]
    attempts = []
    for index, row in enumerate(controller):
        if 'case_initiator' not in row['fields']:
            continue
        following = next(event for event in controller[index + 1:] if event['message'] and
            event['message']['direction'] == '<<<' and event['message']['protocol'] == 0 and event['message']['opcode'] == 48)
        attempts.append({'initiator': row['fields']['case_initiator'], 'line': row['line'],
            'timestamp': row['timestamp'], 'sigma1': following['message'], 'sigma1_line': following['line']})
    activity = Counter(row['timestamp'][:19] for row in controller if row['timestamp'] and row['message']
        and '2026-10-17 09:09:22' <= row['timestamp'] <= '2026-10-17 09:09:34')
    result = {'reports': reports, 'explicit_retransmissions': retransmissions, 'final_acknowledgments': final_ack,
        'case_attempts': attempts, 'all_controller_message_records_per_second': dict(sorted(activity.items())),
        'records_are_not_packet_or_clock_calibration_proof': True}
    assert len(attempts) == 6 and len(reports[-1]['controller_receive']) == 5
    save('serial-detailed-findings.json', result)
    print(json.dumps(result, indent=2))


def remote_window_status():
    spec = importlib.util.spec_from_file_location('previous_investigation', PREVIOUS / 'work.py')
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    code = r'''from pathlib import Path
import json,re,hashlib,collections
assert Path('/etc/machine-id').read_text().strip()=='ef72df43fba94793ab724dc3013cec17'
rows=[]
for rootname in ('matter-rt12-read-probe-20261017','matter-rt12-read-probe-v2-20261017'):
    root=Path.home()/rootname
    for path in root.glob('runs/**/Dut_log*'):
        discriminator=[]
        for number,line in enumerate(path.open(errors='replace'),1):
            match=re.search(r'\bDiscriminator\s*(?:=|:)\s*(\d+)',line,re.I)
            stamp=re.search(r'\[(\d{10}\.\d+)\]',line)
            if match:
                discriminator.append({'line':number,'epoch':float(stamp[1]) if stamp else None,'discriminator':int(match[1])})
        rows.append({'root':rootname,'file':str(path),'discriminators':discriminator})
print(json.dumps({'logs':rows}))
'''
    response = driver.ssh('192.168.1.221', code)
    result = json.loads(response)
    save('probe-window-discriminators.json', result)
    print(json.dumps(result, indent=2))


def attribute_statuses(lines):
    current = None
    depth = 0
    opened = False
    for number, line in enumerate(lines, 1):
        if 'AttributeStatusIB =' in line:
            current = {'line': number}
            depth = 0
            opened = False
        if current is None:
            continue
        depth += line.count('{') - line.count('}')
        opened = opened or '{' in line
        match = re.search(r'\b(Endpoint|Cluster|Attribute|Status|ClusterStatus|cluster-status)\s*=\s*(0x[0-9A-Fa-f_]+|\d+)\b', line, re.I)
        if match:
            key = {'endpoint': 'Endpoint', 'cluster': 'Cluster', 'attribute': 'Attribute',
                'status': 'Status', 'clusterstatus': 'ClusterStatus', 'cluster-status': 'ClusterStatus'}[match[1].lower()]
            current[key] = int(match[2].replace('_', ''), 16 if match[2].startswith('0x') else 10)
        if opened and depth == 0:
            if current.get('Cluster') == 0xFFF1FC05 and current.get('Attribute') in (49, 50, 12289, 16426):
                yield current
            current = None


def decode_statuses():
    spec = importlib.util.spec_from_file_location('previous_investigation', PREVIOUS / 'work.py')
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    code = r'''from pathlib import Path
import json,re,hashlib,collections
assert Path('/etc/machine-id').read_text().strip()=='ef72df43fba94793ab724dc3013cec17'
'''
    code += inspect.getsource(attribute_statuses)
    code += r'''
paths=list((Path.home()/'matter-rt12-read-probe-v2-20261017').glob('runs/**/controller_log*'))
assert len(paths)==1
path=paths[0]
digest=hashlib.sha256()
def lines():
    with path.open('rb') as stream:
        for line in stream:
            digest.update(line)
            yield line.decode(errors='replace')
rows=list(attribute_statuses(lines()))
counts=collections.Counter((row.get('Endpoint'),row.get('Cluster'),row.get('Attribute'),row.get('Status'),row.get('ClusterStatus')) for row in rows)
print(json.dumps({'file':str(path),'sha256':digest.hexdigest(),'status_counts':[{'endpoint':key[0],'cluster':key[1],'attribute':key[2],
    'status':key[3],'cluster_status':key[4],'count':count} for key,count in counts.items()],'first_records':rows[:12]}))
'''
    result = json.loads(driver.ssh('192.168.1.221', code))
    assert len(result['status_counts']) >= 4 and all(row['status'] is not None for row in result['status_counts'])
    save('corrected-probe-decode-statuses.json', result)
    print(json.dumps(result, indent=2))


def history_audit():
    repository = Path(__file__).resolve().parents[2]
    paths = ['37075/failure-evidence/second-500-iteration-37-20260922.tar.gz',
        '37075/failure-evidence/third-500-jlink-usb-disruptions-20260922.tar.gz']
    metadata = json.loads(subprocess.check_output(['gh', 'api', 'repos/feasel0/connectedhomeip']))
    records = []
    patterns = {'github_token': rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b',
        'aws_access_id': rb'\bAKIA[0-9A-Z]{16}\b',
        'gitlab_token': rb'\bglpat-[A-Za-z0-9_-]{20,}\b',
        'private_key_header': rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'}
    parent = subprocess.check_output(['git', '-C', str(repository), 'rev-parse', '2533ea36^'], text=True).strip()
    for name in paths:
        entry = {'path': name, 'commit': parent}
        blob = subprocess.check_output(['git', '-C', str(repository), 'cat-file', '-s', parent + ':' + name], text=True).strip()
        entry['blob_bytes'] = int(blob)
        request = urllib.request.Request('https://raw.githubusercontent.com/feasel0/connectedhomeip/' + parent + '/' + name, method='HEAD')
        with urllib.request.urlopen(request, timeout=30) as response:
            entry['unauthenticated_head_status'] = response.status
        archive = repository / 'investigation' / name
        scanned = 0
        findings = []
        members = 0
        with tarfile.open(archive) as source:
            for member in source:
                if not member.isfile():
                    continue
                if members >= 200 or scanned >= 20 * 1024**2:
                    break
                members += 1
                content = source.extractfile(member).read(min(member.size, 2 * 1024**2, 20 * 1024**2 - scanned))
                scanned += len(content)
                for category, pattern in patterns.items():
                    for match in re.finditer(pattern, content):
                        findings.append({'member': member.name, 'line': content.count(b'\n', 0, match.start()) + 1, 'category': category})
        entry.update(scanned_members=members, scanned_bytes=scanned, candidate_credentials=findings,
            scan_is_bounded_not_a_clean_history_certificate=True)
        records.append(entry)
    recent = []
    for revision in ('2533ea36f33cfe32936080801670d378f75eb415', parent):
        names = subprocess.check_output(['git', '-C', str(repository), 'ls-tree', '-r', '--name-only', '-z', revision,
            '--', 'investigation', '37075', 'pr539-failure-evidence']).split(b'\0')
        scanned = 0
        blobs = 0
        findings = []
        for encoded in names:
            if not encoded:
                continue
            name = os.fsdecode(encoded)
            size = int(subprocess.check_output(['git', '-C', str(repository), 'cat-file', '-s', revision + ':' + name]))
            if size > 5 * 1024**2 or name.endswith(('.gz', '.zip', '.pcap', '.pcapng')):
                continue
            if blobs >= 200 or scanned + size > 20 * 1024**2:
                break
            content = subprocess.check_output(['git', '-C', str(repository), 'show', revision + ':' + name])
            blobs += 1
            scanned += len(content)
            for category, pattern in patterns.items():
                for match in re.finditer(pattern, content):
                    findings.append({'path': name, 'line': content.count(b'\n', 0, match.start()) + 1, 'category': category})
        recent.append({'commit': revision, 'scanned_blobs': blobs, 'scanned_bytes': scanned, 'candidate_credentials': findings})
    result = {'utc': datetime.now(timezone.utc).isoformat(), 'fork_private': metadata['private'], 'archives': records,
        'recent_investigation_trees': recent, 'history_or_credentials_modified': False}
    save('public-history-audit.json', result)
    print(json.dumps(result, indent=2))


def publication_check():
    repository = Path(__file__).resolve().parents[2]
    def git(*arguments):
        return subprocess.check_output(['git', '-C', str(repository), *arguments], text=True).strip()
    assert git('branch', '--show-current') == 'investigation/2026-10-17'
    assert git('remote', 'get-url', '--push', 'origin') == 'https://github.com/feasel0/connectedhomeip.git'
    lock = repository / '.git/index.lock'
    receipt = {'removed': False}
    if lock.exists():
        state = lock.stat()
        age = time.time() - state.st_mtime
        assert state.st_size == 0 and age > 1800, 'Do not remove a recent or nonempty index lock'
        owner = subprocess.run(['fuser', str(lock)], capture_output=True, text=True)
        assert owner.returncode == 1 and not owner.stdout.strip(), 'Index lock has an owner'
        processes = subprocess.check_output(['ps', '-eo', 'comm'], text=True).splitlines()
        assert not any(name == 'git' or name.startswith('git-') for name in processes), 'Git is active'
        current = lock.stat()
        assert (current.st_ino, current.st_mtime_ns, current.st_size) == (state.st_ino, state.st_mtime_ns, 0)
        lock.unlink()
        receipt = {'removed': True, 'age_seconds': round(age), 'bytes': 0, 'owner_pids': [], 'git_processes': []}
    names = ('investigation/README.md', 'investigation/37075/RT12_TARGETED_ATTRIBUTION_20261017.md',
        'investigation/37075/RT21_ENDURANCE_RT12_INVESTIGATION_20261016.md', 'investigation/37075/All PRs for 37075.md',
        'investigation/reports/2026-10-17_18-26-24.md')
    for name in names:
        path = repository / name
        for target in re.findall(r'\]\(([^)]+)\)', path.read_text()):
            if '://' not in target:
                assert (path.parent / target.split('#', 1)[0]).exists(), (name, target)
    subprocess.run(['git', '-C', str(repository), 'diff', '--check', '--', 'investigation'], check=True)
    save('publication-preflight.json', {'utc': datetime.now(timezone.utc).isoformat(), 'index_lock': receipt,
        'changed_document_links_valid': True, 'diff_check': 'PASS', 'fork_and_branch_verified': True})
    print(json.dumps({'index_lock': receipt, 'links': 'PASS', 'diff_check': 'PASS', 'fork_and_branch': 'PASS'}))


class ExtractionTest(unittest.TestCase):
    def test_reporting_state_excludes_values(self):
        self.assertEqual(reporting_state('<RE> OnReportConfirm: NumReports = 0'), {'reports_in_flight': '0'})
        self.assertEqual(reporting_state('IM RH moving to [CanStartReporting]'), {'handler_state': 'CanStartReporting'})
        self.assertEqual(reporting_state('Attribute value = DO_NOT_EXPORT'), {})

    def test_reporting_cursor_is_numeric_not_identity(self):
        self.assertEqual(reporting_state('<RE> ReportsInFlight = 4 with readHandler 23, RE has more messages'),
            {'report_sent': {'in_flight': 4, 'cursor': 23, 'more_chunks': True}})
        self.assertEqual(reporting_state('<RE> ReportsInFlight = 1 with readHandler 2, RE has no more messages'),
            {'report_sent': {'in_flight': 1, 'cursor': 2, 'more_chunks': False}})

    def test_reporting_progress_strict_bounds_and_no_identity_inference(self):
        message = {'direction': '<<<', 'protocol': 1, 'opcode': 5, 'exchange': 8, 'session': 2}
        rows = [
            {'line': 10, 'epoch': 1, 'fields': {}, 'message': message},
            {'line': 11, 'epoch': 2, 'fields': {'reports_in_flight': '3'}, 'message': None},
            {'line': 12, 'epoch': 3, 'fields': {'handler_state': 'CanStartReporting'}, 'message': None},
            {'line': 13, 'epoch': 4, 'fields': {}, 'message': message},
            {'line': 14, 'epoch': 5, 'fields': {'report_sent': {'cursor': 23, 'in_flight': 4, 'more_chunks': True}}, 'message': None},
            {'line': 15, 'epoch': 6, 'fields': {}, 'message': {**message, 'direction': '>>>'}},
            {'line': 16, 'epoch': 7, 'fields': {}, 'message': message},
        ]
        result = reporting_progress(rows, 10, 16)
        self.assertEqual([row['line'] for row in result['report_send_headers']], [13])
        self.assertEqual(result['distinct_report_exchanges'], 1)
        self.assertEqual(result['confirmations'][0]['post_release_in_flight'], 3)
        self.assertEqual(result['cursor_observations'][0]['cursor'], 23)
        self.assertNotIn('handler_state', json.dumps(result))
        self.assertTrue(result['generic_states_not_assigned_to_exchanges'])

    def test_reporting_progress_empty(self):
        result = reporting_progress([], 1, 2)
        self.assertEqual(result['confirmations'], [])
        self.assertEqual(result['distinct_report_exchanges'], 0)

    def test_subscription_lifecycle_has_direct_identity_only(self):
        row = subscription_lifecycle('Subscription established in 500ms with SubscriptionID = 0x1234abcd '
            'MinInterval = 0s MaxInterval = 60s Peer = 02:0000000000000001')
        self.assertEqual(row, {'kind': 'client_established', 'subscription': 0x1234abcd,
            'fabric': 2, 'peer_node': 1, 'min_interval': 0, 'max_interval': 60})
        self.assertEqual(subscription_lifecycle('Subscription id 0x1234abcd from node 2:1 torn down'),
            {'kind': 'server_torn_down', 'subscription': 0x1234abcd})
        self.assertEqual(subscription_lifecycle('Subscription Liveness timeout with SubscriptionID = 0x1234abcd, Peer = 2:1'),
            {'kind': 'client_timeout', 'subscription': 0x1234abcd})
        self.assertIsNone(subscription_lifecycle('SubscriptionId = 0x1234abcd, Attribute = DO_NOT_EXPORT'))

    def test_registration_attempt_is_not_publication_success(self):
        self.assertEqual(registration_marker('Advertise operational node SECRET'), ['operational_registration_attempt'])
        self.assertEqual(registration_marker('mDNS service published: SECRET'), ['publication_marker'])
        self.assertEqual(registration_marker('Session key = SECRET'), [])
        self.assertNotIn('SECRET', json.dumps(registration_marker('Advertise operational node SECRET')))
        self.assertEqual(registration_marker('CHIP minimal mDNS started advertising.'),
            ['advertiser_started', 'minimal_backend_started'])
        self.assertEqual(registration_marker('Failed to advertise records: SECRET'), ['record_send_failure'])

    def test_attribute_status_scope_and_no_values(self):
        sample = ['AttributeStatusIB =\n', '{\n', 'Path =\n', '{\n', 'Endpoint = 0x1,\n',
            'Cluster = 0xFFF1FC05,\n', 'Attribute = 0x31,\n', '}\n', 'ErrorStatus =\n', '{\n',
            'Status = 0x8D,\n', 'Secret = DO_NOT_EXPORT\n', '}\n', '}\n']
        rows = list(attribute_statuses(sample))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['Status'], 141)
        self.assertNotIn('DO_NOT_EXPORT', json.dumps(rows))
        self.assertEqual(list(attribute_statuses([line.replace('0xFFF1FC05', '0x6') for line in sample])), [])

    def test_actual_manufacturer_extensible_id_format(self):
        sample = ['AttributeStatusIB =', '{', 'Endpoint = 0x1,', 'Cluster = 0xfff1fc05,',
            'Attribute = 0x0000_0031,', 'status = 0x8d (INVALID_DATA_TYPE),', 'cluster-status = 0x11,', '}']
        row = list(attribute_statuses(sample))[0]
        self.assertEqual((row['Attribute'], row['Status'], row['ClusterStatus']), (49, 141, 17))

    def test_header(self):
        row = event('2026-10-17 09:09:22,925 >>> E:12712i S:16494 M:47688560 Type 0001:05 ReportData [UDP:[fd00::1]:5540]')
        self.assertEqual(row['message']['exchange'], 12712)
        self.assertEqual(row['message']['opcode'], 5)
        self.assertEqual(row['message']['peer_address'], 'UDP:[fd00::1]:5540')

    def test_source_error(self):
        row = event('BleEndPoint.cpp:662: CHIP Error 0x000000AC: Internal error')
        self.assertEqual(row['codes'], ['0x000000AC'])
        self.assertEqual(row['source'], [('BleEndPoint.cpp', '662')])

    def test_no_arbitrary_values(self):
        self.assertIsNone(event('Session key = DO_NOT_EXPORT'))
        self.assertNotIn('DO_NOT_EXPORT', json.dumps(event('PASE key = DO_NOT_EXPORT')))

    def test_hex_payload_is_not_error(self):
        self.assertIsNone(event('payload 0x12345678'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('self-test', 'pase', 'sources', 'metadata', 'remote_probe', 'qa_units', 'attribute_metadata', 'discovery_filter', 'serial_timing', 'serial_summary', 'serial_findings', 'history_audit', 'remote_window_status', 'decode_statuses', 'publication_check', 'reporting_gap', 'reporting_census', 'coordination_sources', 'dut_reporting_binary', 'controller_retry_binary', 'dnssd_registration'))
    action = parser.parse_args().action
    if action == 'self-test':
        unittest.main(argv=[__file__])
    else:
        globals()[action]()
