import argparse
import asyncio
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
import signal
import shlex
import subprocess
import time
import sys
from pathlib import Path
from types import SimpleNamespace

from campaign_state import atomic, digest


class NativeResourceError(RuntimeError):
    pass


def verify_profile_sources(profile):
    for filename, expected in profile['source_hashes'].items():
        if digest(Path(filename)) != expected:
            raise ValueError('Native source, binary or configuration identity changed')
    if profile.get('asset_manifest'):
        path = Path(profile['asset_manifest'])
        if str(path) not in profile['source_hashes']:
            raise ValueError('Native asset manifest is not source-bound')
        for filename, expected in json.loads(path.read_text()).items():
            if not Path(filename).is_absolute() or digest(Path(filename)) != expected:
                raise ValueError('Native versioned XML asset identity changed')


def close_smoke_capture(profile, root):
    if not (root / 'capture-request.json').exists() or (root / 'capture-closed.json').exists():
        return
    document = hook(profile, 'capture_stop', root, [])
    capture = document['capture']
    if (capture['profile'] != profile['capture_profile'] or capture['run_id'] != profile['capture_id']
            or capture['state'] != 'stopped' or capture.get('error') is not None
            or not capture.get('child_exit_codes') or any(code != 0 for code in capture['child_exit_codes'])):
        raise ValueError('Smoke capture did not close cleanly with its reserved identity')
    atomic(root / 'capture-closed.json', document)


def close_smoke_fixture(profile, root):
    try:
        if not (root / 'fixture-closed.json').exists():
            document = hook(profile, 'fixture_stop', root, ['no_live_dut'])
            atomic(root / 'fixture-closed.json', document)
    finally:
        close_smoke_capture(profile, root)


def stop_smoke_dut(root, binary, expected):
    if ((root / 'tmp').is_symlink() or not os.path.samefile('/tmp', root / 'tmp')
            or Path('/proc/self/uid_map').read_text().split()[-1:] != ['1']):
        raise ValueError('DUT closure requires its exact private single-user namespace')
    binary = binary.resolve(strict=True)
    if digest(binary) != expected:
        raise ValueError('DUT closure executable identity changed')
    process = subprocess.run(['pidof', binary.name], capture_output=True, text=True, timeout=5,
                             stdin=subprocess.DEVNULL)
    if process.returncode not in {0, 1}:
        raise ValueError('Cannot establish namespace-local DUT process ownership')
    identities = []
    with ExitStack() as descriptors:
        for value in process.stdout.split():
            process_id = int(value)
            try:
                descriptor = os.pidfd_open(process_id)
            except ProcessLookupError:
                continue
            descriptors.callback(os.close, descriptor)
            if Path('/proc/' + str(process_id) + '/exe').resolve(strict=True) != binary:
                raise ValueError('DUT process executable does not match reserved artifact')
            identities.append((process_id, descriptor))
        for _, descriptor in identities:
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGTERM)
            except ProcessLookupError:
                pass
        import select
        for _, descriptor in identities:
            if not select.select([descriptor], [], [], 5)[0]:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                if not select.select([descriptor], [], [], 5)[0]:
                    raise ValueError('Exact namespace-local DUT did not exit')
    return {'no_live_dut': True, 'pids': [process_id for process_id, _ in identities], 'dut_sha256': expected}


def smoke_trust_store(profile):
    directory = Path(profile['paa_trust_store'])
    certificates = {str(path) for path in directory.glob('*.der') if path.is_file() and not path.is_symlink()}
    if not directory.is_absolute() or not certificates or not certificates <= profile['source_hashes'].keys():
        raise ValueError('Smoke requires the pinned source-bound PAA certificates without bypassing attestation')
    return str(directory)


def fixture_smoke(profile, root):
    if not root.is_dir() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise ValueError('Smoke root must be private and owned')
    if (any((root / name).is_symlink() for name in ['tmp', 'home'])
            or not os.path.samefile('/tmp', root / 'tmp') or os.environ.get('HOME') != str(root / 'home')):
        raise ValueError('Actual private native path namespace required before imports')
    for filename, expected in profile['source_hashes'].items():
        if digest(Path(filename)) != expected:
            raise ValueError('Smoke loaded source or binary identity changed')
    trust_store = smoke_trust_store(profile)
    lock = Path(profile['rf_lock']).open('r')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    import matter.native
    import matter.clusters as Clusters
    from matter.CertificateAuthority import CertificateAuthorityManager
    from matter.ChipDeviceCtrl import DiscoveryFilterType
    from matter.ChipStack import ChipStack
    from matter.storage import PersistentStorageJSON
    from matter_qa.library.platform.raspberrypi.raspi import Raspi

    endpoint = profile['fixture']
    rpi = SimpleNamespace(rpi_hostname=endpoint['address'] + ':' + str(endpoint['port']),
                          rpi_username=endpoint['user'], rpi_password='', rpi_sudo_password='',
                          app_config=SimpleNamespace(**{'matter_app': profile['dut_binary'],
                                                        'discriminator': profile['discriminator'],
                                                        'interface-id': 'wlan0'}),
                          factory_reset=SimpleNamespace(clear_wpa_supplicant_state=False, clear_bluetoothd_state=False),
                          logging=SimpleNamespace(capture_bluez=False, capture_hcidump=False, capture_tcpdump=False,
                                                  capture_dbus=False, capture_wpasupplicant=False))
    configuration = SimpleNamespace(dut_config=SimpleNamespace(rpi=rpi), iter_log_path=str(root), current_iteration=0)
    adapter = Raspi(configuration, None)
    result = {'scope': 'Bounded real fixture smoke; not a campaign iteration', 'started': time.time(),
              'result': 'INCOMPLETE', 'stage': 'ssh-start', 'campaign_iterations': 0,
              'sdk': profile['sdk'], 'qa': profile['qa'], 'source_hashes': profile['source_hashes']}
    stack = None
    authorities = None
    try:
        atomic(root / 'capture-request.json', {'profile': profile['capture_profile'], 'run_id': profile['capture_id']})
        capture = hook(profile, 'capture_start', root, [])['capture']
        if (capture['state'] != 'running' or capture['profile'] != profile['capture_profile']
            or capture['run_id'] != profile['capture_id']):
            raise ValueError('Smoke capture did not establish the reserved identity')
        adapter.start_test()
        remote_hash = adapter.matter_app_ssh_session.run('sha256sum ' + shlex.quote(profile['dut_binary']), hide=True).stdout.split()[0]
        if remote_hash != profile['dut_sha256']:
            raise ValueError('Deployed DUT binary identity changed')
        adapter.start_logging(file_name=str(root / 'dut.private.log'))
        result['stage'] = 'upstream-factory-reset'
        adapter.factory_reset_dut()
        running = adapter.matter_app_ssh_session.run('pidof ' + shlex.quote(Path(profile['dut_binary']).name),
                                                   hide=True, warn=True)
        if not running.ok or not running.stdout.strip() or adapter.stop_log_event.is_set():
            raise ValueError('Upstream adapter did not leave a live scoped DUT/log channel')
        result['dut_namespace_pids'] = running.stdout.split()
        result['stage'] = 'native-initialization'
        matter.native.Init()
        stack = ChipStack(persistentStorage=PersistentStorageJSON(str(root / 'controller.private.json')))
        authorities = CertificateAuthorityManager(chipStack=stack)
        controller = authorities.NewCertificateAuthority().NewFabricAdmin(vendorId=0xFFF1, fabricId=1).NewController(
            nodeId=112233, paaTrustStorePath=trust_store)

        async def commission_read_remove():
            result['stage'] = 'on-network-commissioning'
            node = await controller.CommissionOnNetwork(nodeId=445566, setupPinCode=20202021,
                                                       filterType=DiscoveryFilterType.LONG_DISCRIMINATOR,
                                                       filter=profile['discriminator'], discoveryTimeoutMsec=30000)
            if node != 445566:
                raise ValueError('Unexpected commissioned native node identity')
            result['stage'] = 'case-read'
            values = await controller.ReadAttribute(445566, [(0, Clusters.BasicInformation.Attributes.VendorID),
                                                             (0, Clusters.OperationalCredentials.Attributes.CommissionedFabrics)])
            vendor = values[0][Clusters.BasicInformation][Clusters.BasicInformation.Attributes.VendorID]
            fabrics = values[0][Clusters.OperationalCredentials][Clusters.OperationalCredentials.Attributes.CommissionedFabrics]
            if vendor != 0xFFF1 or fabrics != 1:
                raise ValueError('Fresh CASE attribute values disagree with clean fixture')
            result.update(vendor_id=vendor, commissioned_fabrics=fabrics, case_read=True)
            result['stage'] = 'fabric-removal'
            await controller.UnpairDevice(445566)
            result['fabric_removed'] = True

        asyncio.run(asyncio.wait_for(commission_read_remove(), timeout=150))
        result.update(result='PASS', stage='completed')
    except Exception as error:
        result.update(result='FAIL', error_kind=type(error).__name__)
        raise
    finally:
        cleanup = []
        try:
            adapter._kill_app()
            adapter.stop_log_event.set()
            if adapter.log_thread:
                adapter.log_thread.join(timeout=10)
                if adapter.log_thread.is_alive():
                    cleanup.append('upstream-log-thread-live')
            adapter.matter_app_ssh_session.close()
        except Exception as error:
            cleanup.append('adapter-' + type(error).__name__)
        try:
            if authorities:
                authorities.Shutdown()
            if stack:
                stack.Shutdown()
        except Exception as error:
            cleanup.append('stack-' + type(error).__name__)
        try:
            close_smoke_fixture(profile, root)
        except Exception as error:
            cleanup.append('fixture-' + type(error).__name__)
        result.update(ended=time.time(), cleanup_errors=cleanup)
        if cleanup:
            result['result'] = 'INCOMPLETE'
        atomic(root / 'smoke-result.private.json', result)
        lock.close()
    return 0 if result['result'] == 'PASS' else 1


def native_outcomes(document, requested):
    summary = document['test_summary_record']
    rows = document['list_of_iteration_records']
    if summary['total_number_of_iterations'] != requested:
        raise ValueError('Native requested iteration count disagrees with frozen block')
    ordinals = [row['iteration_number'] for row in rows]
    if len(ordinals) != len(set(ordinals)) or any(type(number) is not int or not 1 <= number <= requested for number in ordinals):
        raise ValueError('Duplicate or out-of-range native iteration identity')
    outcomes = []
    for row in rows:
        execution = (row.get('iteration_data') or {}).get('iteration_tc_execution_data') or {}
        result = execution.get('iteration_result')
        if not execution.get('iteration_end_time') or result not in {'PASS', 'FAIL'}:
            continue
        if not execution.get('iteration_begin_time'):
            raise ValueError('Native completed outcome lacks its start timestamp')
        outcomes.append({'ordinal': row['iteration_number'], 'outcome': result,
                         'started': execution['iteration_begin_time'], 'ended': execution['iteration_end_time'],
                         'signature': execution.get('exception')})
    passed = sum(row['outcome'] == 'PASS' for row in outcomes)
    failed = sum(row['outcome'] == 'FAIL' for row in outcomes)
    if (summary['number_of_iterations_completed'], summary['number_of_iterations_passed'],
            summary['number_of_iterations_failed']) != (len(outcomes), passed, failed):
        raise ValueError('Native summary totals disagree with actual completed iteration records')
    return outcomes


def command(profile, name, root):
    arguments = profile[name]
    if not isinstance(arguments, list) or not arguments or not all(isinstance(value, str) for value in arguments):
        raise ValueError('Native profile commands must be frozen argv arrays')
    return [value.replace('{attempt_root}', str(root)) for value in arguments]


def snapshot_iterations(profile, root, final=False):
    matches = list(root.glob(profile['summary_glob']))
    if not matches and not final:
        return []
    if len(matches) != 1 or not matches[0].resolve().is_relative_to(root.resolve()):
        raise ValueError('Expected exactly one attempt-owned native structured summary')
    raw = matches[0].read_bytes()
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        if final:
            raise
        return []
    outcomes = native_outcomes(document, int(profile['requested_iterations']))
    request_hash = digest(root / 'request.json')
    identity_hash = digest(root / 'identity.json')
    for outcome in outcomes:
        path = root / 'iteration-receipts' / (str(outcome['ordinal']).zfill(5) + '.json')
        receipt = dict(outcome, request_sha256=request_hash, identity_sha256=identity_hash,
                       summary_sha256=hashlib.sha256(raw).hexdigest())
        if path.exists():
            previous = json.loads(path.read_text())
            if any(previous[key] != value for key, value in receipt.items() if key != 'summary_sha256'):
                raise ValueError('Completed native iteration changed after durable publication')
        else:
            atomic(path, receipt)
        if outcome['outcome'] == 'FAIL' and not (root / 'first-failure.json').exists():
            atomic(root / 'first-failure.json', dict(receipt, preserve_entire_attempt=True,
                   capture_policy='Stop before reserved ring overwrite; retain every segment from this attempt'))
    return outcomes


def hook(profile, name, root, required):
    result = subprocess.run(command(profile, name, root), capture_output=True, text=True,
                            timeout=30, stdin=subprocess.DEVNULL)
    atomic(root / (name + '.stdout.private'), result.stdout)
    atomic(root / (name + '.stderr.private'), result.stderr)
    if result.returncode:
        if 'NativeResourceError:' in result.stderr:
            raise NativeResourceError('Fixture resource hook failed: ' + name)
        raise ValueError('Fixture hook failed: ' + name)
    document = json.loads(result.stdout)
    atomic(root / (name + '.json'), document)
    if not all(document.get(key) is True for key in required):
        raise ValueError('Fixture hook prerequisite not positively established: ' + name)
    return document


def fixture_json(profile, arguments):
    result = subprocess.run([*profile['fixture_ssh'], shlex.join(arguments)], capture_output=True,
                            text=True, timeout=25, stdin=subprocess.DEVNULL)
    if result.returncode:
        raise NativeResourceError('Exact private fixture command failed')
    return json.loads(result.stdout)


def wifi_hook(profile, root, action):
    verify_profile_sources(profile)
    if action in {'before', 'after', 'recovery'}:
        context = profile['fixture']['root'] + '/context'
        query = ('import hashlib,json,os;from pathlib import Path;'
                 'binary=Path(' + repr(profile['dut_binary']) + ');'
                 'print(json.dumps({"machine":Path("/etc/machine-id").read_text().strip(),'
                 '"boot":Path("/proc/sys/kernel/random/boot_id").read_text().strip(),'
                 '"private_tmp":os.path.samefile("/tmp",' + repr(context + '/tmp') + '),'
                 '"binary":hashlib.file_digest(binary.open("rb"),"sha256").hexdigest()}))')
        state = fixture_json(profile, ['python3', '-B', '-c', query])
        if (state['machine'] != profile['dut_machine_id'] or state['boot'] != profile['dut_boot_id']
                or state['private_tmp'] is not True or state['binary'] != profile['dut_sha256']):
            raise NativeResourceError('Wi-Fi fixture identity, namespace or artifact changed')
        if action == 'before':
            from campaign_state import connection
            request = json.loads((root / 'request.json').read_text())
            if 'rf_grant' in profile:
                grant = profile['rf_grant']
                if (grant != request['rf_owner'] or grant['machine_id'] != Path('/etc/machine-id').read_text().strip()
                        or grant['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip()):
                    raise ValueError('Remote RF grant or boot identity changed')
            else:
                authority = connection(Path(profile['rf_authority']), readonly=True)
                try:
                    reserved = authority.execute("SELECT * FROM ownership WHERE resource='rf:lab'").fetchone()
                    if (not reserved or reserved['released'] is not None or reserved['attempt_id'] != request['attempt_id']
                            or reserved['identity'] != json.dumps(request['rf_owner'], sort_keys=True)):
                        raise ValueError('No live global RF reservation for native attempt')
                finally:
                    authority.close()
            ssh = root / 'home/.ssh'
            ssh.mkdir(mode=0o700, parents=True, exist_ok=False)
            for filename in ['config', 'known_hosts', 'client-key']:
                source = Path(profile['ssh_directory']) / filename
                atomic(ssh / filename, source.read_text())
                (ssh / filename).chmod(0o600)
            return {'ownership_verified': True, 'rf_isolated': True, 'source_verified': True,
                    'mutable_paths_isolated': True, 'reset_ready': True, 'fixture': state}
        closed = fixture_json(profile, profile['fixture_close_argv'])
        if closed.get('no_live_dut') is not True:
            raise ValueError('DUT shutdown not positively established')
        return {'owned': True, 'bounded': True, 'reset_ready': True, 'ownership_verified': True,
                'no_orphaned_workers': True, 'fixture': state, 'dut_closed': closed}
    broker_action = {'capture_start': 'capture-start', 'capture_health': 'capture-status',
                     'capture_stop': 'capture-stop'}[action]
    result = fixture_json(profile, ['sudo', '-n', '/usr/local/sbin/lab-resource-helper', broker_action,
                                    'dut-mdns', profile['capture_id']])
    capture = result['capture']
    active = action != 'capture_stop'
    if (capture['profile'] != 'dut-mdns' or capture['run_id'] != profile['capture_id']
            or capture['state'] != ('running' if active else 'stopped') or capture.get('error') is not None):
        raise ValueError('Reserved capture ownership or lifecycle failure')
    if not active and (not capture.get('child_exit_codes') or any(code != 0 for code in capture['child_exit_codes'])):
        raise ValueError('Capture child did not close cleanly')
    directory = '/var/lib/lab-resource-helper/runs/dut-mdns--' + profile['capture_id']
    query = ('import hashlib,json,re,shutil;from pathlib import Path;root=Path(' + repr(directory) + ');'
             'files=sorted((root/"packets").glob("*.pcapng"),key=lambda path:path.stat().st_mtime_ns);'
             'closed=files' + ('[:-1]' if active else '') + ';'
             'log=(root/"dumpcap.log").read_text();'
             'print(json.dumps({"free_bytes":shutil.disk_usage(root).free,"file_count":len(files),'
             '"bytes":sum(path.stat().st_size for path in files),'
             '"closed_segments":{str(path):hashlib.file_digest(path.open("rb"),"sha256").hexdigest() for path in closed},'
             '"drop_counts":[int(value) for value in re.findall(r"Packets received/dropped on interface .*?: \\d+/(\\d+)",log)],'
             '"packet_counts":[int(value) for value in re.findall(r"Packets captured: (\\d+)",log)]}))')
    evidence = fixture_json(profile, ['python3', '-B', '-c', query])
    previous_path = root / 'capture-segments.json'
    previous = json.loads(previous_path.read_text()) if previous_path.exists() else {}
    current = evidence['closed_segments']
    if (evidence['free_bytes'] < 8 * 1024 ** 3 or evidence['file_count'] >= 15
            or any(current.get(filename) != expected for filename, expected in previous.items())):
        raise ValueError('Capture reserve, pre-overwrite or closed-segment integrity failure')
    atomic(previous_path, current)
    complete = (not active and bool(current) and evidence['bytes'] > 0 and bool(evidence['drop_counts'])
                and all(value == 0 for value in evidence['drop_counts']))
    atomic(root / 'capture-evidence.json', dict(evidence, capture=capture, integrity_complete=complete))
    if not active and not complete:
        raise ValueError('Closed capture has packet loss or unavailable drop accounting')
    return dict(result, owned=True, active=active, closed=not active, capacity_verified=True,
                closed_segments_hashed=True, integrity_complete=complete, evidence=evidence)


def execute(profile, root, stop, qualification=False, stretch=False):
    minimum = 1 if qualification or stretch else 10
    if profile.get('baseline') != 'pristine-upstream' or int(profile['requested_iterations']) < minimum:
        raise ValueError('Native profile is not an approved whole minimum block')
    if not profile.get('source_hashes'):
        raise ValueError('Native profile lacks immutable loaded-source/binary hashes')
    verify_profile_sources(profile)
    lock_path = Path(profile['rf_lock'])
    lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        atomic(root / 'rf-ownership.json', {'pid': os.getpid(), 'lock': str(lock_path), 'acquired': time.time()})
        return execute_locked(profile, root, stop, qualification)


def execute_locked(profile, root, stop, qualification):
    before_keys = ['ownership_verified', 'rf_isolated', 'source_verified', 'mutable_paths_isolated', 'reset_ready']
    hook(profile, 'before', root, before_keys)
    capture_started = False
    capture_closed = False
    process = None
    exit_code = None
    interruption = False
    try:
        capture_started = True
        atomic(root / 'capture-request.json', {'profile': 'dut-mdns', 'run_id': profile['capture_id']})
        hook(profile, 'capture_start', root, ['owned', 'active', 'capacity_verified'])
        environment = dict(os.environ, **profile.get('environment', {}))
        environment.pop('LD_PRELOAD', None)
        environment['PYTHONDONTWRITEBYTECODE'] = '1'
        with (root / 'native.private.log').open('xb') as output:
            process = subprocess.Popen(command(profile, 'argv', root), env=environment,
                                       stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            atomic(root / 'native-identity.json', {'pid': process.pid,
                   'start_ticks': Path('/proc/' + str(process.pid) + '/stat').read_text().rsplit(')', 1)[1].split()[19],
                   'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                   'machine_id': Path('/etc/machine-id').read_text().strip(), 'started': time.time()})
            deadline = time.monotonic() + float(profile['native_timeout_seconds'])
            next_health = 0
            while process.poll() is None:
                if stop.is_set() or time.monotonic() >= deadline:
                    interruption = True
                    process.send_signal(signal.SIGINT)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        atomic(root / 'forced-stop.json', {'wall': time.time(), 'pid': process.pid,
                                                         'reason': 'Owned native process ignored graceful interrupt'})
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                    break
                if time.monotonic() >= next_health:
                    snapshot_iterations(profile, root)
                    hook(profile, 'capture_health', root, ['owned', 'active', 'capacity_verified', 'closed_segments_hashed'])
                    next_health = time.monotonic() + 5
                stop.wait(0.2)
            exit_code = process.returncode
            atomic(root / 'native-exit.json', {'exit_code': exit_code, 'interrupted': interruption, 'wall': time.time()})
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        if capture_started:
            snapshot_iterations(profile, root)
            hook(profile, 'capture_stop', root, ['owned', 'closed', 'integrity_complete'])
            capture_closed = True
    matches = list(root.glob(profile['summary_glob']))
    if len(matches) != 1 or not matches[0].resolve().is_relative_to(root.resolve()):
        raise ValueError('Expected exactly one attempt-owned native structured summary')
    outcomes = snapshot_iterations(profile, root, final=True)
    native_failed = any(row['outcome'] == 'FAIL' for row in outcomes)
    if native_failed or interruption or exit_code != 0:
        hook(profile, 'recovery', root, ['owned', 'bounded', 'reset_ready'])
    hook(profile, 'after', root, ['ownership_verified', 'reset_ready', 'no_orphaned_workers'])
    complete = len(outcomes) == int(profile['requested_iterations']) and not interruption and capture_closed
    clean_exit = exit_code == 0 or (native_failed and exit_code == 1)
    outcome = ('FAIL' if native_failed else 'PASS') if complete and clean_exit else 'INCOMPLETE'
    artifacts = {str(path.relative_to(root)): digest(path) for path in root.rglob('*')
                 if path.is_file() and not path.is_symlink() and path.name not in {'receipt.json', 'detail.log'}}
    atomic(root / 'detail.log', {'native_summary': str(matches[0].relative_to(root)), 'artifacts': artifacts})
    result = {'outcome': outcome, 'iterations': outcomes, 'native_exit_code': exit_code,
            'requested_iterations': int(profile['requested_iterations']), 'complete_block': complete,
            'unexecuted': int(profile['requested_iterations']) - len(outcomes), 'artifacts': artifacts,
            'detail_hash': digest(root / 'detail.log'), 'qualification_only': qualification}
    if outcome == 'INCOMPLETE' and profile.get('incomplete_resources'):
        result.update(failure_domain='resource', quarantined_resources=profile['incomplete_resources'])
    return result


def cleanup_native(profile, root):
    errors = []
    operations = [('capture_stop', ['owned', 'closed', 'integrity_complete'])] if (root / 'capture-request.json').exists() else []
    operations.append(('after', ['ownership_verified', 'reset_ready', 'no_orphaned_workers']))
    for name, required in operations:
        try:
            hook(profile, name, root, required)
        except Exception as error:
            errors.append(name + ':' + type(error).__name__)
    return errors


def execute_guarded(profile, root, stop, qualification=False, stretch=False):
    if profile.get('remote_access'):
        return execute_remote(profile, root, stop, qualification, stretch=stretch)
    try:
        result = execute(profile, root, stop, qualification=qualification, stretch=stretch)
        result['cleanup_complete'] = True
        return result
    except Exception as error:
        cleanup_errors = cleanup_native(profile, root)
        result = {'outcome': 'INCOMPLETE', 'iterations': [], 'error_kind': type(error).__name__,
                  'failure_domain': ('resource' if isinstance(error, NativeResourceError) and not cleanup_errors
                                     else 'shared' if cleanup_errors else 'integrity'),
                  'cleanup_complete': not cleanup_errors, 'cleanup_errors': cleanup_errors,
                  'quarantined_resources': profile.get('failure_resources', []), 'qualification_only': qualification}
        atomic(root / 'detail.log', result)
        result['detail_hash'] = digest(root / 'detail.log')
        return result


def remote_json(profile, code):
    compile(code, '<native-remote-control>', 'exec')
    environment = dict(os.environ, **profile.get('transport_environment', {}))
    result = subprocess.run([*profile['remote_access'], 'python3', '-B', '-c', code], capture_output=True,
                            text=True, timeout=35, stdin=subprocess.DEVNULL, env=environment)
    if result.returncode:
        raise NativeResourceError('Owned remote native transport failed')
    return json.loads(result.stdout)


def prune_closed_native(root):
    from campaign_remote_worker import live, status
    job = root.parent / 'job'
    state = status(job)
    child = json.loads((job / 'child-identity.json').read_text())
    result = json.loads((root / 'native-receipt.json').read_text())
    if (state['live'] or live(child) or not (job / 'cleanup-closed.json').exists()
            or result['outcome'] != 'PASS' or result.get('cleanup_complete') is not True
            or not result.get('iterations') or any(row['outcome'] != 'PASS' for row in result['iterations'])):
        raise ValueError('Remote success retention requires positive worker, child, finalizer and outcome closure')
    if (root / 'retain-evidence.json').exists():
        return {'retained_shared_evidence': True}
    marker = root / 'retention.json'
    if marker.exists():
        plan = json.loads(marker.read_text())
    else:
        deletions = []
        for filename, expected in result['artifacts'].items():
            path = root / filename
            if (path.suffix not in {'.log', '.html', '.pcap', '.pcapng', '.pyc'}
                    and path.name not in {'controller.private.json', 'trace.private.json'}
                    and not path.is_relative_to(root / 'tmp') and not path.is_relative_to(root / 'home')):
                continue
            if (not path.resolve().is_relative_to(root.resolve()) or path.is_symlink()
                    or path.stat().st_uid != os.getuid() or path.stat().st_nlink != 1 or digest(path) != expected):
                raise ValueError('Remote success raw artifact identity or exclusive ownership changed')
            deletions.append({'file': filename, 'sha256': expected, 'bytes': path.stat().st_size})
        plan = {'receipt_sha256': digest(root / 'native-receipt.json'), 'deletions': deletions,
                'bytes': sum(item['bytes'] for item in deletions)}
        atomic(marker, plan)
    if digest(root / 'native-receipt.json') != plan['receipt_sha256']:
        raise ValueError('Remote committed native receipt changed before retention')
    for item in plan['deletions']:
        path = root / item['file']
        if not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
            raise ValueError('Remote retention path escaped its attempt')
        if path.exists():
            if digest(path) != item['sha256'] or path.stat().st_nlink != 1 or path.stat().st_uid != os.getuid():
                raise ValueError('Remote success raw artifact changed during retention')
            path.unlink()
    receipt = {'bytes': plan['bytes'], 'all_absent': all(not (root / item['file']).exists() for item in plan['deletions']),
               'plan_sha256': digest(marker)}
    atomic(root / 'retention-complete.json', receipt)
    return receipt


def retain_native_success(profile, root):
    if profile.get('remote_access'):
        request = json.loads((root / 'request.json').read_text())
        remote_root = str(Path(profile['remote_root']) / request['attempt_id'])
        code = ('import json,sys;from pathlib import Path;sys.path.insert(0,' + repr(profile['remote_program']) + ');'
                'from campaign_native import prune_closed_native;print(json.dumps(prune_closed_native(Path('
                + repr(remote_root + '/work') + '))))')
        atomic(root / 'remote-retention.json', remote_json(profile, code))
        capture_code = ('import json;from pathlib import Path;print((Path(' + repr(remote_root + '/work')
                        + ')/"capture-evidence.json").read_text())')
        evidence = remote_json(profile, capture_code)
    else:
        evidence = json.loads((root / 'capture-evidence.json').read_text())
    if evidence.get('integrity_complete') is not True or evidence['capture']['state'] != 'stopped':
        raise ValueError('Success capture retention requires complete closed evidence')
    if not profile.get('capture_access'):
        raise ValueError('No verified normal-user capture retention transport')
    transport = dict(profile, remote_access=profile['capture_access'])
    segments = evidence['closed_segments']
    code = ('import hashlib,json,os;from pathlib import Path;'
            'assert Path("/etc/machine-id").read_text().strip()==' + repr(profile['dut_machine_id']) + ';'
            'files=json.loads(' + repr(json.dumps(segments)) + ');deleted=[];'
            '\nfor filename,expected in files.items():\n'
            ' path=Path(filename);assert path.parent.parent.name==' + repr('dut-mdns--' + profile['capture_id']) + ';'
            'capture=json.loads((path.parent.parent/"capture.json").read_text());assert capture["state"]=="stopped" and not capture.get("error");'
            '\n if path.exists():\n'
            '  assert not path.is_symlink() and path.stat().st_uid==os.getuid() and path.stat().st_nlink==1;'
            'assert hashlib.file_digest(path.open("rb"),"sha256").hexdigest()==expected;'
            'deleted.append({"path":filename,"sha256":expected,"bytes":path.stat().st_size});path.unlink()\n'
            'print(json.dumps({"deleted":deleted,"all_absent":all(not Path(filename).exists() for filename in files)}))')
    retention = remote_json(transport, code)
    if retention.get('all_absent') is not True:
        raise ValueError('Successful capture deletion not positively verified')
    atomic(root / 'capture-retention.json', retention)


def execute_remote(profile, root, stop, qualification, stretch=False):
    for filename, expected in profile['source_hashes'].items():
        if digest(Path(filename)) != expected:
            raise ValueError('Remote transport or source-bound template changed')
    request = json.loads((root / 'request.json').read_text())
    remote_root = str(Path(profile['remote_root']) / request['attempt_id'])
    template = json.loads(Path(profile['remote_template']).read_text())
    template['rf_grant'] = request['rf_owner']
    template['qualification_only'] = qualification
    template['stretch_block'] = stretch
    for name in ['argv', 'before', 'capture_start', 'capture_health', 'capture_stop', 'recovery', 'after']:
        template[name] = [value.replace('{remote_profile}', remote_root + '/profile.json') for value in template[name]]
    setup = ('import json,sys;from pathlib import Path;sys.path.insert(0,' + repr(profile['remote_program']) + ');'
             'from campaign_state import atomic,digest;from campaign_remote_worker import queue;'
             'root=Path(' + repr(remote_root) + ');root.mkdir(mode=0o700);'
             '(root/"work").mkdir(mode=0o700);profile=json.loads(' + repr(json.dumps(template)) + ');'
             'atomic(root/"profile.json",profile);atomic(root/"work/request.json",json.loads(' + repr(json.dumps(request)) + '));'
             'job={"kind":"fixture","timeout_seconds":' + repr(float(profile['native_timeout_seconds']) + 120) + ','
             '"argv":["/usr/bin/python3","-B",' + repr(profile['remote_program'] + '/campaign_native.py') + ','
             '"block-run","--root",str(root/"work"),"--profile",str(root/"profile.json")],'
             '"cleanup_argv":["/usr/bin/python3","-B",' + repr(profile['remote_program'] + '/campaign_native.py') + ','
             '"native-cleanup","--root",str(root/"work"),"--profile",str(root/"profile.json")],'
             '"source_hashes":dict(profile["source_hashes"],**{str(root/"profile.json"):digest(root/"profile.json")})};'
             'print(json.dumps(queue(root/"job",' + repr(profile['controller_machine_id']) + ','
             + repr(request['attempt_id']) + ',job)))')
    queued = remote_json(profile, setup)
    atomic(root / 'remote-queue.json', queued)
    deadline = time.monotonic() + float(profile['native_timeout_seconds']) + 300
    stopped = False
    while True:
        stopping = stop.is_set() or time.monotonic() >= deadline
        query = ('import json,sys;from pathlib import Path;sys.path.insert(0,' + repr(profile['remote_program']) + ');'
                 'from campaign_state import atomic;from campaign_remote_worker import status,live,job_watch;'
                 'root=Path(' + repr(remote_root) + ');'
                 + ('atomic(root/"job/stop-request.json",{"reason":"owned coordinator stop"});job_watch(root/"job");' if stopping else '') +
                 'state=status(root/"job");child=root/"job/child-identity.json";'
                 'state["child_live"]=live(json.loads(child.read_text())) if child.exists() else False;'
                 'state["cleanup_closed"]=(root/"job/cleanup-closed.json").exists();'
                 'summaries=list((root/"work").glob("**/summary.json"));summary=None;'
                 '\nif len(summaries)==1:\n'
                 ' try: summary=json.loads(summaries[0].read_text())\n'
                 ' except json.JSONDecodeError: pass\n'
                 'receipt=root/"work/native-receipt.json"\n'
                 'print(json.dumps({"job":state,"summary":summary,"native_receipt":json.loads(receipt.read_text()) if receipt.exists() else None}))')
        document = remote_json(profile, query)
        atomic(root / 'remote-status.json', document)
        if document['summary'] is not None:
            atomic(root / 'remote-summary/summary.json', document['summary'])
            snapshot_iterations(profile, root)
        state = document['job']
        if (state['state'] in {'PASS', 'FAIL', 'INCOMPLETE'} and not state['live'] and not state['child_live']):
            stopped = True
            break
        if time.monotonic() > deadline + 180:
            raise NativeResourceError('Remote native closure unproven; RF reservation retained')
        stop.wait(3)
    result = document['native_receipt']
    if not stopped or not state['cleanup_closed'] or result is None or result.get('cleanup_complete') is not True:
        raise NativeResourceError('Remote native worker or fixture cleanup unproven; RF reservation retained')
    if document['summary'] is not None:
        result['iterations'] = snapshot_iterations(profile, root, final=True)
    atomic(root / 'remote-native-receipt.json', result)
    result['artifacts'] = {'remote-native-receipt.json': digest(root / 'remote-native-receipt.json')}
    result['remote_worker_stopped'] = True
    atomic(root / 'detail.log', {'remote_root': remote_root, 'job': state,
                                'native_receipt_sha256': digest(root / 'remote-native-receipt.json')})
    result['detail_hash'] = digest(root / 'detail.log')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Existing native runner: bounded real fixture qualification')
    parser.add_argument('action', choices=['fixture-smoke', 'capture-close', 'fixture-close', 'dut-close', 'wifi-hook', 'qa-run',
                                         'block-run', 'native-cleanup'])
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--profile', type=Path)
    parser.add_argument('--dut-binary', type=Path)
    parser.add_argument('--dut-sha256')
    parser.add_argument('--hook')
    options = parser.parse_args()
    if options.action == 'dut-close':
        print(json.dumps(stop_smoke_dut(options.root, options.dut_binary, options.dut_sha256)))
        raise SystemExit(0)
    profile = json.loads(options.profile.read_text())
    if options.action == 'block-run':
        identity = {'pid': os.getpid(), 'start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19],
                    'machine_id': Path('/etc/machine-id').read_text().strip(),
                    'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                    'cgroup': Path('/proc/self/cgroup').read_text()}
        if 'cron.service' not in identity['cgroup']:
            raise ValueError('Native remote block requires independent cron ownership')
        atomic(options.root / 'identity.json', identity)
        stopped = __import__('threading').Event()
        signal.signal(signal.SIGTERM, lambda *_: stopped.set())
        signal.signal(signal.SIGINT, lambda *_: stopped.set())
        request = json.loads((options.root / 'request.json').read_text())
        stretch = profile.get('stretch_block') is True
        if stretch and request['cell'].get('block_phase') != 'stretch':
            raise ValueError('Remote stretch request lacks the minimum-qualified coordinator grant')
        result = execute_guarded(profile, options.root, stopped,
            qualification=profile.get('qualification_only') is True, stretch=stretch)
        atomic(options.root / 'native-receipt.json', result)
        raise SystemExit(0 if result.get('cleanup_complete') is True else 1)
    elif options.action == 'native-cleanup':
        audit = options.root / 'finalizer'
        audit.mkdir(mode=0o700, exist_ok=True)
        for filename in ['capture-request.json', 'capture-segments.json']:
            source = options.root / filename
            if source.exists():
                atomic(audit / filename, json.loads(source.read_text()))
        errors = cleanup_native(profile, audit)
        print(json.dumps({'cleanup_errors': errors, 'closed': not errors}))
        raise SystemExit(1 if errors else 0)
    elif options.action == 'wifi-hook':
        print(json.dumps(wifi_hook(profile, options.root, options.hook)))
    elif options.action == 'qa-run':
        from campaign_isolation import isolated_command
        environment = dict(os.environ, **profile.get('environment', {}))
        environment.pop('LD_PRELOAD', None)
        arguments = isolated_command(options.root, [], command(profile, 'qa_argv', options.root))
        os.execvpe(arguments[0], arguments, environment)
    elif options.action == 'capture-close':
        close_smoke_capture(profile, options.root)
    elif options.action == 'fixture-close':
        close_smoke_fixture(profile, options.root)
    else:
        raise SystemExit(fixture_smoke(profile, options.root))
