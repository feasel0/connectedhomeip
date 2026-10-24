import fcntl
import json
import os
import signal
import subprocess
import time
from pathlib import Path

from campaign_state import atomic, digest


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
