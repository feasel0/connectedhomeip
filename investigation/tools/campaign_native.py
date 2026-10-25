import argparse
import asyncio
from contextlib import ExitStack
import fcntl
import json
import os
import signal
import shlex
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

from campaign_state import atomic, digest


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


def hook(profile, name, root, required):
    result = subprocess.run(command(profile, name, root), capture_output=True, text=True,
                            timeout=30, stdin=subprocess.DEVNULL)
    atomic(root / (name + '.stdout.private'), result.stdout)
    atomic(root / (name + '.stderr.private'), result.stderr)
    if result.returncode:
        raise ValueError('Fixture hook failed: ' + name)
    document = json.loads(result.stdout)
    atomic(root / (name + '.json'), document)
    if not all(document.get(key) is True for key in required):
        raise ValueError('Fixture hook prerequisite not positively established: ' + name)
    return document


def execute(profile, root, stop):
    if profile.get('baseline') != 'pristine-upstream' or int(profile['requested_iterations']) < 10:
        raise ValueError('Native profile is not an approved whole minimum block')
    if not profile.get('source_hashes'):
        raise ValueError('Native profile lacks immutable loaded-source/binary hashes')
    for filename, expected in profile['source_hashes'].items():
        if digest(Path(filename)) != expected:
            raise ValueError('Native source/binary/configuration changed')
    lock_path = Path(profile['rf_lock'])
    lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = lock_path.open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    atomic(root / 'rf-ownership.json', {'pid': os.getpid(), 'lock': str(lock_path), 'acquired': time.time()})
    before_keys = ['ownership_verified', 'rf_isolated', 'source_verified', 'mutable_paths_isolated', 'reset_ready']
    hook(profile, 'before', root, before_keys)
    capture_started = False
    capture_closed = False
    process = None
    exit_code = None
    interruption = False
    try:
        capture_started = True
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
                    hook(profile, 'capture_health', root, ['owned', 'active', 'capacity_verified', 'closed_segments_hashed'])
                    next_health = time.monotonic() + 5
                stop.wait(0.2)
            exit_code = process.returncode
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        if capture_started:
            hook(profile, 'capture_stop', root, ['owned', 'closed', 'integrity_complete'])
            capture_closed = True
    matches = list(root.glob(profile['summary_glob']))
    if len(matches) != 1 or not matches[0].resolve().is_relative_to(root.resolve()):
        raise ValueError('Expected exactly one attempt-owned native structured summary')
    outcomes = native_outcomes(json.loads(matches[0].read_text()), int(profile['requested_iterations']))
    native_failed = any(row['outcome'] == 'FAIL' for row in outcomes)
    if native_failed or interruption or exit_code != 0:
        hook(profile, 'recovery', root, ['owned', 'bounded', 'reset_ready'])
    hook(profile, 'after', root, ['ownership_verified', 'reset_ready', 'no_orphaned_workers'])
    complete = len(outcomes) == int(profile['requested_iterations']) and not interruption and capture_closed
    outcome = 'FAIL' if native_failed else ('PASS' if complete and exit_code == 0 else 'INCOMPLETE')
    artifacts = {str(path.relative_to(root)): digest(path) for path in root.rglob('*')
                 if path.is_file() and not path.is_symlink() and path.name not in {'receipt.json', 'detail.log'}}
    atomic(root / 'detail.log', {'native_summary': str(matches[0].relative_to(root)), 'artifacts': artifacts})
    lock.close()
    return {'outcome': outcome, 'iterations': outcomes, 'native_exit_code': exit_code,
            'requested_iterations': int(profile['requested_iterations']), 'complete_block': complete,
            'unexecuted': int(profile['requested_iterations']) - len(outcomes), 'artifacts': artifacts,
            'detail_hash': digest(root / 'detail.log'), 'qualification_only': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Existing native runner: bounded real fixture qualification')
    parser.add_argument('action', choices=['fixture-smoke', 'capture-close', 'fixture-close', 'dut-close'])
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--profile', type=Path)
    parser.add_argument('--dut-binary', type=Path)
    parser.add_argument('--dut-sha256')
    options = parser.parse_args()
    if options.action == 'dut-close':
        print(json.dumps(stop_smoke_dut(options.root, options.dut_binary, options.dut_sha256)))
        raise SystemExit(0)
    profile = json.loads(options.profile.read_text())
    if options.action == 'capture-close':
        close_smoke_capture(profile, options.root)
    elif options.action == 'fixture-close':
        close_smoke_fixture(profile, options.root)
    else:
        raise SystemExit(fixture_smoke(profile, options.root))
