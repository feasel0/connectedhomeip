import argparse
import contextlib
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time
import traceback
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path('/home/feasel/qa-mar6/pi-nordic-endurance-20261018')
ORIGINAL = Path('/home/feasel/qa-mar6/rt21-endurance-20261016')
ACCESS = '/home/feasel/.copilot/skills/raspi-discovery-ssh/scripts/raspi_access.py'
ENV = dict(os.environ, PATH='/home/feasel/.local/libexec/raspi-access/package/usr/bin:' + os.environ['PATH'])
PI = '192.168.1.221'
DUT_PI = 'raspberrypi-2.local'
REMOTE = '/home/feasel/matter-pi-nordic-endurance-20261018'
PI_PYTHON = '/home/feasel/matter-pr527-fixed-native-20261009/controller-env/bin/python'


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def save(name, value):
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = ROOT / name
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def remote(host, code, interpreter='python3'):
    return json.loads(subprocess.check_output(['python3', ACCESS, 'ssh', '--host', host, '--',
        interpreter, '-c', code], env=ENV, text=True, timeout=120))


def dataset_hex(output):
    values = [line.strip() for line in output.splitlines() if re.fullmatch('[0-9a-fA-F]+', line.strip())]
    if len(values) != 1:
        raise ValueError('Expected one complete active dataset')
    payload = bytes.fromhex(values[0])
    if hashlib.sha256(payload).hexdigest() != 'ed2e96c79a37c1f8af308d0867c3adaa3ebf186b5b6d65dc3777617debc04d39':
        raise ValueError('Live Thread dataset differs from the verified fixture')
    return values[0]


def competing_processes(proc, allowed_root=None):
    owners = []
    for directory in proc.glob('[0-9]*'):
        try:
            arguments = [os.fsdecode(value) for value in (directory / 'cmdline').read_bytes().split(b'\0') if value]
            scripts = [value for value in arguments if Path(value).name.startswith('TC_') and value.endswith('.py')]
            app = (directory / 'comm').read_text().strip().startswith('chip-')
            if app or any(allowed_root is None or not Path(value).is_relative_to(allowed_root) for value in scripts):
                owners.append(int(directory.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return owners


def check_discovery_domain(active=False):
    if competing_processes(Path('/proc')):
        raise RuntimeError('A local Matter app or QA controller competes with this campaign')
    source = inspect.getsource(competing_processes)
    for host, identity, allowed in ((PI, 'ef72df43fba94793ab724dc3013cec17', REMOTE + '/combined' if active else None),
            (DUT_PI, 'fa898f2a8e5c487489c516aaa233f86a', None)):
        remote(host, 'from pathlib import Path\nimport json,os\n' + source +
            f'\nassert Path("/etc/machine-id").read_text().strip()=={identity!r}\n'
            f'assert not competing_processes(Path("/proc"),{allowed!r}), "Competing commissioning owner"\n'
            'print(json.dumps({"known_host_competitors":0}))\n')


def preflight():
    guard = load('pi_nordic_discovery_guard', Path(__file__).with_name('discovery_isolation.py'))
    guard.require_closed_campaign(ORIGINAL)
    guard.require_fixture_idle(ORIGINAL)
    check_discovery_domain()
    common = r'''import hashlib,json,os,subprocess
from pathlib import Path
def digest(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()
def run(*args): return subprocess.check_output(args,text=True,timeout=30).strip()
identity=Path('/etc/machine-id').read_text().strip()
active=[]
for path in Path('/proc').glob('[0-9]*/cmdline'):
    try:
        arguments=path.read_bytes().split(b'\0')
        if any(Path(os.fsdecode(value)).name.startswith('TC_') and value.endswith(b'.py') for value in arguments):
            active.append(int(path.parent.name))
    except (FileNotFoundError,PermissionError,ProcessLookupError): pass
assert not active, 'Another QA controller owns this host'
'''
    controller = remote(PI, common + r'''
assert identity=='ef72df43fba94793ab724dc3013cec17'
base=Path('/home/feasel/matter-sdk74676-hardware-20261013/controller/matter')
native=digest(base/'_ChipDeviceCtrl.so')
scanner=digest(base/'ble/scan_devices.py')
assert native=='a04c667b4adba6df6041674acf8787e54e0935b80bb0e3e46c98933af984dd11'
assert scanner=='f1d5e16d63876d0eacac25538e66ee3c89ca149943ce6426a274edadb3453aa8'
btmon=Path('/usr/local/bin/btmon')
assert btmon.stat().st_uid==0 and not btmon.stat().st_mode & 0o022
assert digest(btmon)=='8993b38f627eed04eac06dab481d879d5c52efab875169808060e26fcb8feb63'
address=run('busctl','get-property','org.bluez','/org/bluez/hci0','org.bluez.Adapter1','Address')
assert address=='s "2C:CF:67:EC:15:68"'
assert run('busctl','get-property','org.bluez','/org/bluez/hci0','org.bluez.Adapter1','Powered')=='b true'
verification=json.loads(run('sudo','-n','/usr/local/sbin/lab-resource-helper','verify','controller-hci'))
units=run('systemctl','list-units','--plain','--no-legend','--state=active,activating,deactivating','lab-resource-capture@controller-hci--*.service')
assert not units, 'Another Pi capture owns HCI'
print(json.dumps({'machine_id':identity,'architecture':run('uname','-m'),'native_sha256':native,
    'scanner_sha256':scanner,'btmon_sha256':digest(btmon),'hci_index':0,'adapter_address':'2C:CF:67:EC:15:68',
    'capture_policy_verified':True,'free_bytes':__import__('shutil').disk_usage(Path.home()).free,
    'utc':run('date','-u','+%Y-%m-%dT%H:%M:%SZ')}))
''')
    dut = remote(DUT_PI, common + r'''
assert identity=='fa898f2a8e5c487489c516aaa233f86a'
apps=[]
for path in Path('/proc').glob('[0-9]*/comm'):
    try:
        if path.read_text().strip().startswith('chip-'): apps.append(int(path.parent.name))
    except (FileNotFoundError,PermissionError,ProcessLookupError): pass
assert not apps, 'Wi-Fi DUT app could advertise a competing commissioning window'
print(json.dumps({'machine_id':identity,'matter_apps_running':False,'qa_controllers_running':False}))
''')
    dataset = dataset_hex(subprocess.check_output(['docker', 'exec', 'otbr-37075',
        'ot-ctl', 'dataset', 'active', '-x'], text=True, timeout=30))
    role = subprocess.check_output(['docker', 'exec', 'otbr-37075', 'ot-ctl', 'state'], text=True, timeout=30).strip()
    if role.splitlines()[0] not in ('leader', 'router'):
        raise RuntimeError('Thread border router is not attached')
    save('thread-dataset.private.json', {'hex': dataset})
    image = Path('/home/feasel/matter-oct14/connectedhomeip/out/pr527-nordic-reboot/merged.hex')
    firmware = json.loads(Path('/home/feasel/qa-mar6/pr527-followup-preparation-20261008/five-gates-progress.json').read_text())['firmware']
    image_hash = hashlib.sha256(image.read_bytes()).hexdigest()
    if image_hash != firmware['merged_hex_sha256']:
        raise RuntimeError('Held Nordic firmware artifact differs from the verified provenance')
    document = {'checked_utc': datetime.now(timezone.utc).isoformat(), 'controller': controller,
        'wifi_dut': dut, 'thread_dataset_sha256': hashlib.sha256(bytes.fromhex(dataset)).hexdigest(),
        'otbr_role': role.splitlines()[0], 'original_campaign_closed': True, 'local_fixture_idle': True,
        'firmware_artifact_sha256': image_hash, 'firmware_not_reflashed': True,
        'discovery_scope': 'No competing QA or chip-* apps on the three verified owned hosts; not a global network guarantee'}
    save('preflight.json', document)
    print(json.dumps(document, indent=2))


def transfer(action, local, target):
    subprocess.run(['python3', ACCESS, action, '--host', PI, '--local', str(local),
        '--remote', str(target)], env=ENV, check=True, timeout=600)


def prepare():
    preflight()
    if (ROOT / 'manifest.json').exists():
        if (ROOT / 'source-snapshot.tar.gz').exists() and not (ROOT / 'deployment.json').exists():
            deploy_snapshot()
            return
        raise FileExistsError('Do not overwrite a prepared campaign')
    manifest = json.loads((ORIGINAL / 'manifest.json').read_text())
    for name, expected in manifest['source_sha256'].items():
        if hashlib.sha256((ORIGINAL / 'combined' / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError('Original source snapshot changed: ' + name)
    manifest.update(scanner_sha256='f1d5e16d63876d0eacac25538e66ee3c89ca149943ce6426a274edadb3453aa8',
        controller_host='pi', prepared_utc=datetime.now(timezone.utc).isoformat(),
        controller_native_sha256='a04c667b4adba6df6041674acf8787e54e0935b80bb0e3e46c98933af984dd11')
    save('manifest.json', manifest)
    archive = ROOT / 'source-snapshot.tar.gz'
    with tarfile.open(archive, 'x:gz', dereference=True) as bundle:
        bundle.add(ORIGINAL / 'combined', arcname='combined', filter=lambda item: None if '__pycache__' in item.name else item)
        bundle.add(ORIGINAL / 'reference', arcname='reference')
        bundle.add(Path('/home/feasel/qa-mar6/pr539-five-matrix-20261014/campaign.py'), arcname='campaign.py')
        bundle.add(Path(__file__), arcname='pi_nordic_campaign.py')
        bundle.add(ROOT / 'manifest.json', arcname='manifest.json')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    remote(PI, f'''from pathlib import Path
import json
assert Path('/etc/machine-id').read_text().strip()=='ef72df43fba94793ab724dc3013cec17'
Path({REMOTE!r}).mkdir(mode=0o700,exist_ok=False)
print(json.dumps({{'fresh_directory':True}}))''')
    transfer('push', archive, REMOTE + '/source-snapshot.tar.gz')
    transfer('push', ROOT / 'thread-dataset.private.json', REMOTE + '/thread-dataset.private.json')
    deploy_snapshot()


def deploy_snapshot():
    digest = hashlib.sha256((ROOT / 'source-snapshot.tar.gz').read_bytes()).hexdigest()
    report = remote(PI, f'''from pathlib import Path
import hashlib,json,tarfile
root=Path({REMOTE!r})
archive=root/'source-snapshot.tar.gz'
assert hashlib.sha256(archive.read_bytes()).hexdigest()=={digest!r}
assert not (root/'combined').exists(), 'Do not overwrite a deployed source tree'
with tarfile.open(archive) as bundle: bundle.extractall(root,filter='data')
(root/'controller').symlink_to('/home/feasel/matter-sdk74676-hardware-20261013/controller',target_is_directory=True)
manifest=json.loads((root/'manifest.json').read_text())
for name,expected in manifest['source_sha256'].items():
    assert hashlib.sha256((root/'combined'/name).read_bytes()).hexdigest()==expected,name
print(json.dumps({{'source_archive_sha256':{digest!r},'source_files_verified':len(manifest['source_sha256'])}}))''',
    interpreter=PI_PYTHON)
    save('deployment.json', report)
    print(json.dumps(report))


def worker(count):
    campaign = load('pi_nordic_worker', ROOT / 'campaign.py')
    manifest = json.loads((ROOT / 'manifest.json').read_text())
    campaign.QA_HEAD = manifest['baseline']
    campaign.SDK_HEAD = manifest['runtime_held_constant']['sdk_head']
    campaign.REMOTE = str(ROOT)
    os.environ['PRIVATE_THREAD_DATASET'] = json.loads((ROOT / 'thread-dataset.private.json').read_text())['hex']
    sys.path.insert(0, str(ROOT / 'reference'))
    campaign.runtime('pi')
    return campaign.selected(SimpleNamespace(host='pi', platform='nordic', case='TC_RT_2_1', count=count))


def require_smoke_pass(result, capture):
    if tuple(result[key] for key in ('requested', 'executed', 'passed', 'failed', 'incomplete', 'process_exit')) != (1, 1, 1, 0, 0, 0):
        raise RuntimeError('Full endurance requires a completed passing native smoke')
    if not capture.get('complete') or capture.get('cleanup_errors') or capture.get('pi_acl', 0) <= 0 or capture.get('ipv6', 0) <= 0:
        raise RuntimeError('Full endurance requires verified Pi HCI and IPv6 smoke capture')


def require_final_ledger(result, count):
    records = result['records']
    passed = sum(row['outcome'] == 'PASS' for row in records)
    failed = sum(row['outcome'] == 'FAIL' for row in records)
    if ([row['iteration'] for row in records] != list(range(1, count + 1))
            or passed + failed != count or result['process_exit'] != 0
            or tuple(result[key] for key in ('requested', 'executed', 'passed', 'failed', 'incomplete')) !=
            (count, count, passed, failed, 0)):
        raise RuntimeError('Native final ledger is incomplete or inconsistent')


def archive_capture(directory, broker_runs=Path('/var/lib/lab-resource-helper/runs')):
    proof = json.loads((directory / 'capture-proof.json').read_text())
    if not proof['complete'] or proof['cleanup_errors']:
        raise RuntimeError('Never offload an unclosed capture')
    archive = directory.with_suffix('.tar.gz')
    with tarfile.open(archive, 'x:gz') as bundle:
        bundle.add(directory, arcname=directory.name)
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    remote_directory = REMOTE + '/capture-archive'
    remote(PI, f'''from pathlib import Path
import json,shutil
root=Path({remote_directory!r})
root.mkdir(mode=0o700,exist_ok=True)
assert shutil.disk_usage(root).free>8*1024**3+{archive.stat().st_size}
assert not (root/{archive.name!r}).exists()
print(json.dumps({{'archive_destination_ready':True}}))''')
    transfer('push', archive, remote_directory + '/' + archive.name)
    receipt = remote(PI, f'''from pathlib import Path
import hashlib,json
path=Path({remote_directory + '/' + archive.name!r})
with path.open('rb') as stream: actual=hashlib.file_digest(stream,'sha256').hexdigest()
assert actual=={digest!r}
print(json.dumps({{'sha256':actual,'bytes':path.stat().st_size,'private_archive':str(path)}}))''')
    if receipt['sha256'] != digest:
        raise RuntimeError('Remote capture hash verification failed; retain local originals')
    for packet in (directory / 'ubuntu/packets').glob('*.pcapng'):
        source = broker_runs / ('thread-lab--' + proof['token']) / 'packets' / packet.name
        with source.open('rb') as original, packet.open('rb') as copied:
            if hashlib.file_digest(original, 'sha256').hexdigest() != hashlib.file_digest(copied, 'sha256').hexdigest():
                raise RuntimeError('Closed broker capture differs from the archived copy')
        source.unlink()
    for name in ('ubuntu', 'pi'):
        shutil.rmtree(directory / name)
    archive.unlink()
    (directory / 'archive-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


@contextlib.contextmanager
def segmented_captures(coordinator):
    stop = threading.Event()
    ready = threading.Event()
    errors = []

    def capture():
        number = 0
        while not stop.is_set():
            number += 1
            phase = 'capture_context'
            try:
                with coordinator.captured(f'endurance-{number:04}', None):
                    ready.set()
                    stop.wait(180)
                phase = 'archive'
                archive_capture(ROOT / 'captures' / f'endurance-{number:04}')
            except BaseException as error:
                errors.append(type(error).__name__)
                try:
                    save('capture-thread-failure.private.json', {
                        'utc': datetime.now(timezone.utc).isoformat(), 'segment': f'endurance-{number:04}',
                        'phase': phase, 'exception_type': type(error).__name__, 'message': str(error),
                        'traceback': traceback.format_exc()})
                    (ROOT / 'capture-thread-failure.private.json').chmod(0o600)
                except OSError as write_error:
                    print('Capture diagnostic write failed: ' + type(write_error).__name__, file=sys.stderr, flush=True)
                ready.set()
                return

    thread = threading.Thread(target=capture, name='pi-nordic-capture-segments')
    thread.start()
    try:
        if not ready.wait(180) or errors:
            raise RuntimeError('Endurance capture startup failed')
        yield errors
    finally:
        stop.set()
        thread.join(timeout=300)
        if thread.is_alive() or errors:
            raise RuntimeError('Endurance capture closure failed')


def archive_check():
    require_smoke_pass(json.loads((ROOT / 'smoke.json').read_text()),
        json.loads((ROOT / 'captures/smoke/capture-proof.json').read_text()))
    preflight()
    sys.path.insert(0, '/home/feasel/qa-mar6/pr527-followup-preparation-20261008')
    readiness = load('pi_nordic_archive_check', Path('/home/feasel/qa-mar6/pr527-followup-preparation-20261008/run_readiness_batch.py'))
    coordinator = readiness.Coordinator.__new__(readiness.Coordinator)
    coordinator.output = ROOT
    coordinator.run_id = 'pi-nordic-archive-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    coordinator.capture_number = 0
    with coordinator.captured('archive-check', None):
        check_discovery_domain()
    archive_capture(ROOT / 'captures/archive-check')
    save('archive-check.json', {'verified_utc': datetime.now(timezone.utc).isoformat(),
        'closed_capture_transferred_and_hashed': True, 'local_duplicate_cleanup_verified': True,
        'commissioning_performed': False, 'native_iteration_count': 0})
    print('PASS: captured archive path, remote hash and exact local duplicate cleanup; no commissioning')


def smoke(count=1):
    preflight()
    if count == 100:
        require_smoke_pass(json.loads((ROOT / 'smoke.json').read_text()),
            json.loads((ROOT / 'captures/smoke/capture-proof.json').read_text()))
        if not json.loads((ROOT / 'archive-check.json').read_text())['local_duplicate_cleanup_verified']:
            raise RuntimeError('Endurance archive path is not verified')
    if not (ROOT / 'deployment.json').exists():
        raise RuntimeError('Pinned source deployment is required')
    sys.path.insert(0, '/home/feasel/qa-mar6/pr527-followup-preparation-20261008')
    readiness = load('pi_nordic_readiness', Path('/home/feasel/qa-mar6/pr527-followup-preparation-20261008/run_readiness_batch.py'))
    coordinator = readiness.Coordinator.__new__(readiness.Coordinator)
    coordinator.output = ROOT
    coordinator.run_id = 'pi-nordic-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    coordinator.capture_number = 0
    coordinator.children = []
    coordinator.streams = []
    label = 'smoke' if count == 1 else 'endurance'
    owner = None
    with (ROOT.parent / 'nordic-fixture.lock').open('r+') as fixture, (ROOT.parent / 'commissioning-discovery.lock').open('a+') as discovery:
        fcntl.flock(fixture, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(discovery, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            if count == 100:
                saved = ROOT / 'closed-smoke-relays'
                saved.mkdir(mode=0o700, exist_ok=False)
                for name in ('uart-relay.log', 'pi-forwarding.log', 'dut-uart.log'):
                    (ROOT / name).rename(saved / name)
            coordinator.start_relays()
            save('status.json', {'phase': 'SMOKE_RUNNING' if count == 1 else 'ENDURANCE_RUNNING', 'requested': count,
                'started_utc': datetime.now(timezone.utc).isoformat(),
                'coordinator_pid': os.getpid(),
                'coordinator_start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19],
                'exclusive_fixture_and_discovery_locks': True})
            capture_context = coordinator.captured('smoke', 'pi') if count == 1 else segmented_captures(coordinator)
            with capture_context as captures:
                code = f'''from pathlib import Path
import json,os,subprocess
assert Path('/etc/machine-id').read_text().strip()=='ef72df43fba94793ab724dc3013cec17'
root=Path({REMOTE!r})
environment=dict(os.environ,PYTHONPATH=str(root/'controller')+':'+str(root/'combined/src'))
stream=(root/{label + '-supervisor.log'!r}).open('x')
process=subprocess.Popen([{PI_PYTHON!r},'-B',str(root/'pi_nordic_campaign.py'),'worker','--run-root',str(root),'--count',{str(count)!r}],
    env=environment,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
owner={{'pid':process.pid,'start_ticks':Path(f'/proc/{{process.pid}}/stat').read_text().rsplit(')',1)[1].split()[19]}}
(root/{label + '-owner.json'!r}).write_text(json.dumps(owner)+'\\n')
print(json.dumps(owner))'''
                compile(code, '<launch-smoke>', 'exec')
                owner = remote(PI, code)
                save('remote-' + label + '-owner.json', owner)
                deadline = time.monotonic() + 1800 * count + 120
                last_progress = time.monotonic()
                last_domain_check = time.monotonic()
                completed = 0
                while True:
                    result = remote(PI, f'''from pathlib import Path
import json
root=Path({REMOTE!r})
path=root/'runs/combined-nordic-pi-TC_RT_2_1-{count}/result.json'
if path.exists():
    document=json.loads(path.read_text())
    print(json.dumps({{'finished':True,'result':document}}))
else:
    sys=__import__('sys')
    sys.path.insert(0,str(root/'reference'))
    from run_selected_case import read_records
    records=read_records(path.parent)
    status=Path('/proc/{owner['pid']}/stat')
    fields=status.read_text().rsplit(')',1)[1].split() if status.exists() else []
    print(json.dumps({{'finished':False,'executed':len(records),'free_bytes':__import__('shutil').disk_usage(root).free,
        'passed':sum(row['outcome']=='PASS' for row in records),
        'failed':sum(row['outcome']=='FAIL' for row in records),
        'alive':bool(fields and fields[19]=={owner['start_ticks']!r} and fields[0] not in ('Z','X'))}}))''', interpreter=PI_PYTHON)
                    if result['finished']:
                        save(label + '.json', result['result'])
                        break
                    if not result['alive']:
                        raise RuntimeError('Pi worker exited without a final native ledger; retain supervisor log')
                    if result['executed'] > completed:
                        completed = result['executed']
                        last_progress = time.monotonic()
                    save('native-progress.json', {'checked_utc': datetime.now(timezone.utc).isoformat(),
                        'requested': count, 'worker': owner, **result})
                    if count == 100 and time.monotonic() - last_domain_check >= 120:
                        check_discovery_domain(active=True)
                        last_domain_check = time.monotonic()
                    if (time.monotonic() - last_progress > 1800 or shutil.disk_usage(ROOT).free < 8 * 1024**3
                            or result['free_bytes'] < 8 * 1024**3
                            or count == 100 and captures):
                        stop_remote(owner, count)
                        raise RuntimeError('Campaign progress, disk reserve or capture safety gate failed')
                    if time.monotonic() > deadline:
                        stop_remote(owner, count)
                        raise TimeoutError('Pi smoke exceeded its original native timeout plus shutdown margin')
                    if any(child.poll() is not None for child in coordinator.children):
                        stop_remote(owner, count)
                        raise RuntimeError('Owned fixture relay exited')
                    threading.Event().wait(10)
            final = result['result']
            require_final_ledger(final, count)
            if count == 1 and (final['executed'], final['passed'], final['failed'], final['incomplete'], final['process_exit']) != (1, 1, 0, 0, 0):
                raise RuntimeError('Pi Nordic smoke did not pass; full campaign remains blocked')
            save('status.json', {'phase': 'SMOKE_PASSED' if count == 1 else 'ENDURANCE_CLOSED',
                'executed': final['executed'], 'passed': final['passed'],
                'failed': final['failed'], 'full_endurance_started': count == 100,
                'ended_utc': datetime.now(timezone.utc).isoformat()})
            print(json.dumps({'phase': label, 'requested': count, 'executed': final['executed'],
                'passed': final['passed'], 'failed': final['failed'], 'process_exit': final['process_exit']}), flush=True)
        except BaseException as error:
            save('interruption.json', {'utc': datetime.now(timezone.utc).isoformat(),
                'type': type(error).__name__, 'message': str(error)})
            if owner is not None:
                try:
                    stop_remote(owner, count)
                except Exception as cleanup:
                    save('remote-stop-error.json', {'type': type(cleanup).__name__})
            raise
        finally:
            for child in reversed(coordinator.children):
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGINT)
                    try:
                        child.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
            for stream in coordinator.streams:
                stream.close()


def stop_remote(owner, count=1):
    remote(PI, f'''from pathlib import Path
import json,os,signal
root=Path({REMOTE!r})
owners=[{owner!r}]
native=root/'runs/combined-nordic-pi-TC_RT_2_1-{count}/owner.json'
if native.exists(): owners.append(json.loads(native.read_text()))
for item in owners:
    path=Path('/proc')/str(item['pid'])/'stat'
    if path.exists() and path.read_text().rsplit(')',1)[1].split()[19]==str(item['start_ticks']):
        os.killpg(item['pid'],signal.SIGINT)
print(json.dumps({{'exact_owned_processes_signalled':True}}))''')


def status():
    document = json.loads((ROOT / 'status.json').read_text()) if (ROOT / 'status.json').exists() else {}
    count = 100 if document.get('requested') == 100 or document.get('full_endurance_started') else 1
    label = 'endurance' if count == 100 else 'smoke'
    native = remote(PI, f'''from pathlib import Path
import json,re,sys
root=Path({REMOTE!r})
sys.path.insert(0,str(root/'reference'))
from run_selected_case import read_records
target=root/'runs/combined-nordic-pi-TC_RT_2_1-{count}'
records=read_records(target)
result=target/'result.json'
owner_path=root/{label + '-owner.json'!r}
owner=json.loads(owner_path.read_text()) if owner_path.exists() else None
fields=[]
if owner:
    path=Path('/proc')/str(owner['pid'])/'stat'
    fields=path.read_text().rsplit(')',1)[1].split() if path.exists() else []
log=root/{label + '-supervisor.log'!r}
text=log.read_text(errors='replace') if log.exists() else ''
print(json.dumps({{'worker_alive':bool(owner and fields and fields[19]==str(owner['start_ticks']) and fields[0] not in ('Z','X')),
    'executed':len(records),'passed':sum(row['outcome']=='PASS' for row in records),
    'failed':sum(row['outcome']=='FAIL' for row in records),'result_exists':result.exists(),
    'terminal_error_classes':re.findall(r'^(\w+(?:Error|Exception)):',text,re.M)}}))''', interpreter=PI_PYTHON)
    report = {'checked_utc': datetime.now(timezone.utc).isoformat(), 'coordinator': document, 'native': native}
    save('latest-status.json', report)
    print(json.dumps(report, indent=2))


class CampaignTest(unittest.TestCase):
    def test_capture_thread_preserves_original_error_without_changing_shutdown(self):
        for phase in ('capture_context', 'archive'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)

                @contextlib.contextmanager
                def captured(label, host):
                    yield {}
                    if phase == 'capture_context':
                        raise subprocess.TimeoutExpired(['tshark', '-r', '/private/capture'], 120)

                failure = OSError('archive transfer diagnostic') if phase == 'archive' else None
                coordinator = SimpleNamespace(captured=captured)
                with patch(__name__ + '.ROOT', root), patch(__name__ + '.archive_capture', side_effect=failure) as archive:
                    with self.assertRaisesRegex(RuntimeError, 'Endurance capture closure failed'):
                        with segmented_captures(coordinator):
                            pass
                record = json.loads((root / 'capture-thread-failure.private.json').read_text())
                self.assertEqual((root / 'capture-thread-failure.private.json').stat().st_mode & 0o777, 0o600)
                self.assertEqual(record['phase'], phase)
                self.assertEqual(record['segment'], 'endurance-0001')
                self.assertEqual(record['exception_type'], 'TimeoutExpired' if phase == 'capture_context' else 'OSError')
                self.assertIn(record['exception_type'], record['traceback'])
                self.assertIn('120' if phase == 'capture_context' else 'archive transfer diagnostic', record['message'])
                if phase == 'capture_context':
                    archive.assert_not_called()
                else:
                    archive.assert_called_once_with(root / 'captures/endurance-0001')

    def test_closeout_preserves_interrupted_campaign_without_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initial = {'phase': 'ENDURANCE_RUNNING', 'requested': 100, 'coordinator_pid': -1, 'coordinator_start_ticks': '0'}
            (root / 'status.json').write_text(json.dumps(initial))
            (root / 'interruption.json').write_text('{}')
            (root / 'native-progress.json').write_text(json.dumps({'executed': 1, 'passed': 1, 'failed': 0}))
            with patch(__name__ + '.ROOT', root), patch(__name__ + '.remote') as access, patch(__name__ + '.transfer') as copy:
                closeout()
            access.assert_not_called()
            copy.assert_not_called()
            self.assertEqual(json.loads((root / 'external-closeout.json').read_text())['status'], 'INTERRUPTED_OR_UNVERIFIED')

    def test_closeout_reconciles_final_ledger_before_retention(self):
        for failed in (0, 1):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                initial = {'phase': 'ENDURANCE_RUNNING', 'requested': 100, 'coordinator_pid': -1, 'coordinator_start_ticks': '0'}
                (root / 'status.json').write_text(json.dumps(initial))
                result = {'requested': 100, 'executed': 100, 'passed': 100 - failed, 'failed': failed,
                    'incomplete': 0, 'process_exit': 0, 'records': [{'iteration': number,
                        'outcome': 'FAIL' if failed and number == 75 else 'PASS', 'summary': '/private/logs/summary.json'}
                        for number in range(1, 101)]}
                (root / 'endurance.json').write_text(json.dumps(result))
                capture = root / 'captures/endurance-0001'
                capture.mkdir(parents=True)
                (capture / 'capture-proof.json').write_text(json.dumps({'complete': True, 'cleanup_errors': []}))
                (capture / 'archive-receipt.json').write_text(json.dumps({'sha256': 'verified',
                    'private_archive': REMOTE + '/capture-archive/endurance-0001.tar.gz'}))
                original_read = Path.read_text
                reads = 0

                def read(path, *args, **kwargs):
                    nonlocal reads
                    if path == root / 'status.json':
                        reads += 1
                        return json.dumps(initial if reads == 1 else {'phase': 'ENDURANCE_CLOSED'})
                    return original_read(path, *args, **kwargs)

                def access(host, code, **kwargs):
                    compile(code, '<closeout-retention>', 'exec')
                    self.assertIn('protected_paths=protected', code)
                    return {'deleted_files': 0}

                with patch(__name__ + '.ROOT', root), patch.object(Path, 'read_text', read), \
                        patch(__name__ + '.remote', side_effect=access), patch(__name__ + '.transfer'):
                    closeout()
                final = json.loads((root / 'external-closeout.json').read_text())
                self.assertEqual((final['executed'], final['passed'], final['failed']), (100, 100 - failed, failed))
                self.assertEqual(final['records'], result['records'])

    def test_archive_hash_mismatch_preserves_local_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / 'segment'
            capture.mkdir()
            (capture / 'capture-proof.json').write_text(json.dumps({'complete': True, 'cleanup_errors': []}))
            (capture / 'evidence').write_bytes(b'private-capture')
            with patch(__name__ + '.remote', side_effect=[{}, {'sha256': 'wrong'}]), patch(__name__ + '.transfer'):
                with self.assertRaisesRegex(RuntimeError, 'retain local originals'):
                    archive_capture(capture)
            self.assertTrue((capture / 'evidence').exists())
            self.assertTrue(capture.with_suffix('.tar.gz').exists())

    def test_archive_removes_only_verified_closed_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / 'segment'
            packets = capture / 'ubuntu/packets'
            packets.mkdir(parents=True)
            (capture / 'pi').mkdir()
            (capture / 'capture-proof.json').write_text(json.dumps({'complete': True, 'cleanup_errors': [], 'token': 'owned'}))
            (packets / 'one.pcapng').write_bytes(b'captured-bytes')
            broker = root / 'broker/thread-lab--owned/packets'
            broker.mkdir(parents=True)
            (broker / 'one.pcapng').write_bytes(b'captured-bytes')
            (broker / 'other.pcapng').write_bytes(b'not-selected')

            def answer(host, code):
                return {'sha256': hashlib.sha256(capture.with_suffix('.tar.gz').read_bytes()).hexdigest()}

            with patch(__name__ + '.remote', side_effect=answer), patch(__name__ + '.transfer'):
                archive_capture(capture, root / 'broker')
            self.assertTrue((capture / 'capture-proof.json').exists())
            self.assertTrue((capture / 'archive-receipt.json').exists())
            self.assertFalse((broker / 'one.pcapng').exists())
            self.assertTrue((broker / 'other.pcapng').exists())
            self.assertFalse((capture / 'ubuntu').exists())

    def test_unclosed_capture_cannot_be_archived_or_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory)
            (capture / 'capture-proof.json').write_text(json.dumps({'complete': False, 'cleanup_errors': []}))
            with self.assertRaisesRegex(RuntimeError, 'unclosed capture'):
                archive_capture(capture)
            self.assertEqual(len(list(capture.iterdir())), 1)

    def test_discovery_owner_allowance_is_source_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            process = proc / '123'
            process.mkdir()
            (process / 'comm').write_text('python3\n')
            (process / 'cmdline').write_bytes(b'python3\0/owned/combined/TC_RT_2_1.py\0')
            self.assertEqual(competing_processes(proc), [123])
            self.assertEqual(competing_processes(proc, '/owned/combined'), [])
            self.assertEqual(competing_processes(proc, '/other'), [123])
            (process / 'comm').write_text('chip-all-cluste\n')
            self.assertEqual(competing_processes(proc, '/owned/combined'), [123])

    def test_complete_ledger_keeps_failures_and_rejects_hidden_or_missing_records(self):
        result = {'requested': 2, 'executed': 2, 'passed': 1, 'failed': 1, 'incomplete': 0, 'process_exit': 0,
            'records': [{'iteration': 1, 'outcome': 'PASS'}, {'iteration': 2, 'outcome': 'FAIL'}]}
        require_final_ledger(result, 2)
        result['passed'], result['failed'] = 2, 0
        with self.assertRaisesRegex(RuntimeError, 'inconsistent'):
            require_final_ledger(result, 2)
        result['passed'], result['failed'] = 1, 1
        result['records'].pop()
        with self.assertRaisesRegex(RuntimeError, 'inconsistent'):
            require_final_ledger(result, 2)

    def test_full_campaign_gate_preserves_failed_smoke(self):
        result = {'requested': 1, 'executed': 1, 'passed': 0, 'failed': 1, 'incomplete': 0, 'process_exit': 0}
        with self.assertRaisesRegex(RuntimeError, 'passing native smoke'):
            require_smoke_pass(result, {'complete': True, 'pi_acl': 10, 'ipv6': 10})

    def test_full_campaign_gate_requires_real_capture(self):
        result = {'requested': 1, 'executed': 1, 'passed': 1, 'failed': 0, 'incomplete': 0, 'process_exit': 0}
        for capture in ({'complete': True, 'pi_acl': 0, 'ipv6': 10},
                {'complete': False, 'pi_acl': 10, 'ipv6': 10},
                {'complete': True, 'pi_acl': 10, 'ipv6': 10, 'cleanup_errors': ['failure']}):
            with self.assertRaisesRegex(RuntimeError, 'verified Pi HCI'):
                require_smoke_pass(result, capture)
        require_smoke_pass(result, {'complete': True, 'pi_acl': 10, 'ipv6': 10})

    def test_dataset_must_be_unique_and_match_fixture(self):
        for output in ('Done\n', 'ab\r\ncd\r\nDone\n', 'ab\r\nDone\n'):
            with self.assertRaises(ValueError):
                dataset_hex(output)


def closeout():
    initial = json.loads((ROOT / 'status.json').read_text())
    if initial.get('phase') != 'ENDURANCE_RUNNING' or initial.get('requested') != 100:
        raise RuntimeError('Closeout must attach to the original running endurance coordinator')
    owner = {'pid': initial['coordinator_pid'], 'start_ticks': initial['coordinator_start_ticks']}
    deadline = time.monotonic() + 187000
    while True:
        path = Path('/proc') / str(owner['pid']) / 'stat'
        fields = path.read_text().rsplit(')', 1)[1].split() if path.exists() else []
        alive = bool(fields and fields[19] == owner['start_ticks'] and fields[0] not in ('Z', 'X'))
        if not alive:
            break
        if time.monotonic() > deadline:
            raise TimeoutError('Original coordinator exceeded closeout deadline; preserve all evidence')
        threading.Event().wait(30)
    state = json.loads((ROOT / 'status.json').read_text())
    if state.get('phase') != 'ENDURANCE_CLOSED' or (ROOT / 'interruption.json').exists():
        save('external-closeout.json', {'closed_utc': datetime.now(timezone.utc).isoformat(),
            'status': 'INTERRUPTED_OR_UNVERIFIED', 'original_coordinator': owner,
            'evidence_preserved': True, 'native_progress': json.loads((ROOT / 'native-progress.json').read_text())})
        return
    result = json.loads((ROOT / 'endurance.json').read_text())
    require_final_ledger(result, 100)
    receipts = [json.loads(path.read_text()) for path in sorted((ROOT / 'captures').glob('endurance-*/archive-receipt.json'))]
    segments = list((ROOT / 'captures').glob('endurance-*'))
    if not segments or len(receipts) != len(segments) or any(not json.loads((path / 'capture-proof.json').read_text())['complete'] for path in segments):
        raise RuntimeError('Final capture closure is incomplete; preserve all evidence')
    save('retention-captures.private.json', receipts)
    transfer('push', ROOT / 'retention-captures.private.json', REMOTE + '/retention-captures.private.json')
    result_digest = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    transfer('push', Path(__file__).parents[1] / 'pr539-failure-evidence/prune_successful_runs.py', REMOTE + '/retention_tool.py')
    report = remote(PI, f'''from pathlib import Path
import hashlib,importlib.util,json
root=Path({REMOTE!r})
run=root/'runs/combined-nordic-pi-TC_RT_2_1-100'
for path in (root/'endurance-owner.json',run/'owner.json'):
    owner=json.loads(path.read_text())
    stat=Path('/proc')/str(owner['pid'])/'stat'
    fields=stat.read_text().rsplit(')',1)[1].split() if stat.exists() else []
    assert not fields or fields[19]!=str(owner['start_ticks']) or fields[0] in ('Z','X'), 'Native owner remains active'
spec=importlib.util.spec_from_file_location('retention',root/'retention_tool.py')
tool=importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
result=json.loads((run/'result.json').read_text())
assert hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':')).encode()).hexdigest()=={result_digest!r}
plan=tool.plan([run])
protected=set()
for index,row in enumerate(result['records']):
    if row['outcome']=='FAIL':
        for neighbor in result['records'][max(0,index-1):index+2]:
            directory=Path(neighbor['summary']).parent/str(neighbor['iteration'])
            protected.update(str(path) for path in tool.walk_files(directory))
plan['files']=[row for row in plan['files'] if row['path'] not in protected]
plan['allocated_bytes']=sum(row['allocated'] for row in plan['files'])
receipt=tool.apply_plan(plan,protected_paths=protected)
receipt['failure_neighbor_files_retained']=len(protected)
receipt['successful_capture_archives_removed']=0
if result['failed']==0:
    for item in json.loads((root/'retention-captures.private.json').read_text()):
        path=Path(item['private_archive'])
        assert path.parent==root/'capture-archive' and path.name.startswith('endurance-')
        with path.open('rb') as stream: actual=hashlib.file_digest(stream,'sha256').hexdigest()
        assert actual==item['sha256']
        path.unlink()
        receipt['successful_capture_archives_removed']+=1
(root/'endurance-retention.json').write_text(json.dumps(receipt,indent=2)+'\\n')
print(json.dumps(receipt))''', interpreter=PI_PYTHON)
    save('external-closeout.json', {'closed_utc': datetime.now(timezone.utc).isoformat(),
        'status': 'CLOSED', 'original_coordinator': owner, 'requested': 100,
        'executed': result['executed'], 'passed': result['passed'], 'failed': result['failed'],
        'incomplete': 0, 'process_exit': result['process_exit'], 'records': result['records'],
        'closed_segments': len(segments), 'retention': report,
        'root_owned_pi_hci_cleanup': 'Protected broker files require an administrator-reviewed prune operation'})


def terminate(signum, frame):
    raise SystemExit(128 + signum)


if __name__ == '__main__':
    os.umask(0o077)
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('self-test', 'preflight', 'prepare', 'worker', 'smoke', 'status', 'endurance', 'archive-check', 'closeout'))
    parser.add_argument('--run-root', type=Path)
    parser.add_argument('--count', type=int, choices=(1, 100), default=1)
    arguments = parser.parse_args()
    if arguments.run_root:
        ROOT = arguments.run_root
    if arguments.action == 'self-test':
        unittest.main(argv=[__file__])
    elif arguments.action == 'prepare':
        prepare()
    elif arguments.action == 'worker':
        raise SystemExit(worker(arguments.count))
    elif arguments.action == 'smoke':
        smoke()
    elif arguments.action == 'endurance':
        smoke(100)
    elif arguments.action == 'archive-check':
        archive_check()
    elif arguments.action == 'closeout':
        closeout()
    elif arguments.action == 'status':
        status()
    else:
        preflight()
