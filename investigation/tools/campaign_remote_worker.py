import argparse
import fcntl
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from campaign_state import atomic, digest, health_violation, host_health


STOP = threading.Event()


def machine(expected):
    if Path('/etc/machine-id').read_text().strip() != expected:
        raise ValueError('Remote machine identity changed')


def live(identity):
    if identity['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        return False
    try:
        fields = Path('/proc/' + str(identity['pid']) + '/stat').read_text().rsplit(')', 1)[1].split()
        return fields[0] != 'Z' and fields[19] == identity['start_ticks']
    except FileNotFoundError:
        return False


def status(root):
    request = json.loads((root / 'request.json').read_text())
    machine(request['machine_id'])
    if root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise ValueError('Remote state directory ownership/privacy changed')
    document = {'attempt_id': request['attempt_id'], 'request_hash': digest(root / 'request.json'),
                'mode': request['mode'], 'state': 'RESERVED', 'live': False}
    if (root / 'identity.json').exists():
        owned = json.loads((root / 'identity.json').read_text())
        if owned['request_hash'] != document['request_hash'] or owned['attempt_id'] != request['attempt_id']:
            raise ValueError('Remote worker identity does not match request')
        document.update(identity=owned, live=live(owned), state='RUNNING' if live(owned) else 'INCOMPLETE')
    if (root / 'receipt.json').exists():
        receipt = json.loads((root / 'receipt.json').read_text())
        if receipt['identity'] != document.get('identity') or receipt['request_hash'] != document['request_hash']:
            raise ValueError('Remote receipt does not match worker ownership')
        document.update(state=receipt['state'], receipt=receipt, receipt_hash=digest(root / 'receipt.json'))
    return document


def cron_entry(root, attempt_id, install):
    lock_path = Path.home() / '.cache/matter-weekend-cron.lock'
    lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
        if result.returncode and not (result.returncode == 1 and 'no crontab for' in result.stderr):
            raise ValueError('Cannot safely read existing user crontab')
        before = result.stdout
        marker = '# matter-weekend-job-' + attempt_id
        lines = [line for line in before.splitlines() if not line.endswith(marker)]
        if install:
            request = json.loads((root / 'request.json').read_text())
            for action in ['scheduled', 'job-watch']:
                command = shlex.join([sys.executable, '-B', str(Path(__file__).resolve()), action,
                                      '--root', str(root), '--machine', request['machine_id']])
                if '%' in command or '\n' in command:
                    raise ValueError('Unsupported cron command characters')
                lines.append('* * * * * ' + command + ' >>' + shlex.quote(str(root / 'cron.log')) + ' 2>&1 ' + marker)
        after = '\n'.join(lines) + ('\n' if lines else '')
        if after != before:
            atomic(root / ('cron-before-' + str(time.time_ns()) + '.private.txt'), before)
            subprocess.run(['crontab', '-'], input=after, text=True, capture_output=True, timeout=10, check=True)


def queue(root, expected_machine, attempt_id, profile):
    machine(expected_machine)
    if not re.fullmatch('[a-z0-9-]{1,64}', attempt_id):
        raise ValueError('Invalid independently supervised job identity')
    if profile['kind'] not in {'build', 'fixture'} or not 1 <= float(profile['timeout_seconds']) <= 172800:
        raise ValueError('Unsupported or unbounded normal-user job')
    if not profile.get('source_hashes') or not isinstance(profile.get('argv'), list) or not profile['argv']:
        raise ValueError('Frozen job command and source identities required')
    if 'cleanup_argv' in profile and (not isinstance(profile['cleanup_argv'], list) or not profile['cleanup_argv']
            or not all(isinstance(value, str) and value for value in profile['cleanup_argv'])):
        raise ValueError('Job cleanup must be an explicit frozen argument array')
    for filename, expected in profile['source_hashes'].items():
        if digest(Path(filename)) != expected:
            raise ValueError('Queued job program identity changed')
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    atomic(root / 'request.json', {'machine_id': expected_machine, 'attempt_id': attempt_id,
           'mode': 'os-job', 'profile': profile, 'source_hash': digest(Path(__file__).resolve()),
           'latest_start': time.time() + 300})
    cron_entry(root, attempt_id, True)
    return status(root)


def job_cleanup(root):
    request = json.loads((root / 'request.json').read_text())
    profile = request['profile']
    if not profile.get('cleanup_argv') or (root / 'cleanup-closed.json').exists():
        return True
    with (root / 'cleanup.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        if (root / 'cleanup-closed.json').exists():
            return True
        attempts = list(root.glob('cleanup-attempt-*.json'))
        if len(attempts) >= 3:
            atomic(root / 'cleanup-exhausted.json', {'wall': time.time(), 'attempts': len(attempts)})
            return False
        for filename, expected in profile['source_hashes'].items():
            if digest(Path(filename)) != expected:
                raise ValueError('Independent cleanup source identity changed')
        with (root / 'cleanup.private.log').open('ab') as output:
            process = subprocess.Popen(profile['cleanup_argv'], stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                process.wait(timeout=75)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
        result = {'wall': time.time(), 'exit_code': process.returncode,
                  'request_hash': digest(root / 'request.json'), 'attempt': len(attempts) + 1}
        atomic(root / ('cleanup-attempt-' + str(result['attempt']) + '.json'), result)
        if process.returncode == 0:
            atomic(root / 'cleanup-closed.json', result)
            return True
        return False


def job_watch(root):
    current = status(root)
    request = json.loads((root / 'request.json').read_text())
    identity_path = root / 'child-identity.json'
    if not identity_path.exists():
        return current
    child = json.loads(identity_path.read_text())
    child_live = live(child)
    if not current['live'] and not child_live:
        if job_cleanup(root) or (root / 'cleanup-exhausted.json').exists():
            cron_entry(root, request['attempt_id'], False)
        return current
    heartbeat = root / 'heartbeat.json'
    expired = time.time() >= child['deadline']
    stale = heartbeat.exists() and time.time() - heartbeat.stat().st_mtime > 90
    watchdog = root / 'watchdog-stop.json'
    enforcement = watchdog.exists()
    if expired or stale or (root / 'stop-request.json').exists() or not current['live'] or enforcement:
        if not enforcement:
            atomic(watchdog, {'wall': time.time(), 'expired': expired, 'stale': stale,
                             'supervisor_live': current['live'], 'child': child})
        hard_stop = time.time() - json.loads(watchdog.read_text())['wall'] >= 15
        if child_live:
            if os.getpgid(child['pid']) != child['pid']:
                raise ValueError('Independent job process-group ownership changed')
            os.killpg(child['pid'], signal.SIGKILL if hard_stop else signal.SIGTERM)
        if current['live']:
            os.kill(current['identity']['pid'], signal.SIGKILL if hard_stop else signal.SIGTERM)
        return current
    return current


def scheduled(root):
    request = json.loads((root / 'request.json').read_text())
    if request['mode'] != 'os-job' or request['source_hash'] != digest(Path(__file__).resolve()):
        raise ValueError('Scheduled job mode or frozen worker identity changed')
    lock = (root / 'worker.lock').open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close()
        return status(root)
    current = status(root)
    if current['state'] != 'RESERVED':
        lock.close()
        return job_watch(root)
    if time.time() > request['latest_start']:
        raise ValueError('Queued job start reservation expired')
    profile = request['profile']
    for filename, expected in profile['source_hashes'].items():
        if digest(Path(filename)) != expected:
            raise ValueError('Scheduled job source changed before execution')
    owned = {'pid': os.getpid(), 'start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19],
             'uid': os.getuid(), 'machine_id': request['machine_id'], 'attempt_id': request['attempt_id'],
             'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
             'source_hash': request['source_hash'], 'request_hash': digest(root / 'request.json'),
             'started': time.time(), 'cgroup': Path('/proc/self/cgroup').read_text(),
             'session_id': os.getsid(0), 'kind': profile['kind']}
    if 'cron.service' not in owned['cgroup']:
        raise ValueError('Queued normal-user worker is not owned by the independent cron service')
    atomic(root / 'identity.json', owned)
    process = None
    interrupted = False
    initial_health = host_health(root)
    atomic(root / 'initial-health.json', initial_health)
    try:
        with (root / 'detail.log').open('xb') as output:
            process = subprocess.Popen(profile['argv'], stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True,
                                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
            child = dict(owned, pid=process.pid, started=time.time(), deadline=time.time() + float(profile['timeout_seconds']),
                         start_ticks=Path('/proc/' + str(process.pid) + '/stat').read_text().rsplit(')', 1)[1].split()[19])
            atomic(root / 'child-identity.json', child)
            while process.poll() is None:
                sample = host_health(root)
                atomic(root / 'heartbeat.json', dict(sample, child=process.pid))
                unsafe = health_violation(sample, initial_health)
                if unsafe:
                    atomic(root / 'resource-stop.json', {'initial': initial_health, 'current': sample})
                if unsafe or STOP.is_set() or (root / 'stop-request.json').exists() or time.time() >= child['deadline']:
                    interrupted = True
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                    break
                STOP.wait(1)
            final_health = host_health(root)
            resource_violation = health_violation(final_health, initial_health)
            if resource_violation:
                interrupted = True
                atomic(root / 'resource-stop.json', {'initial': initial_health, 'current': final_health,
                                   'reason': resource_violation})
        cleanup_complete = job_cleanup(root)
        atomic(root / 'receipt.json', {'state': 'INCOMPLETE' if interrupted or not cleanup_complete else ('PASS' if process.returncode == 0 else 'FAIL'),
               'identity': owned, 'request_hash': digest(root / 'request.json'), 'ended': time.time(),
               'detail_hash': digest(root / 'detail.log'), 'qualification_only': False,
               'exit_code': process.returncode, 'kind': profile['kind'], 'cleanup_complete': cleanup_complete})
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        lock.close()
        if not profile.get('cleanup_argv') or (root / 'cleanup-closed.json').exists():
            cron_entry(root, request['attempt_id'], False)
    return status(root)


def prepare(root, expected_machine, attempt_id, seconds):
    machine(expected_machine)
    if not re.fullmatch('[a-z0-9-]{1,64}', attempt_id) or not 1 <= seconds <= 60:
        raise ValueError('Only bounded, uniquely named synthetic workers are permitted')
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    atomic(root / 'request.json', {'machine_id': expected_machine, 'attempt_id': attempt_id,
           'seconds': seconds, 'mode': 'synthetic', 'source_hash': digest(Path(__file__).resolve())})


def launch(root):
    current = status(root)
    if current['state'] != 'RESERVED':
        return current
    lock = (root / 'worker.lock').open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return status(root)
    current = status(root)
    if current['state'] != 'RESERVED':
        return current
    if os.fork():
        lock.close()
        end = time.monotonic() + 3
        while time.monotonic() < end and not (root / 'identity.json').exists():
            STOP.wait(0.05)
        return status(root)
    os.setsid()
    descriptor = os.open(root / 'worker.log', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    null = os.open(os.devnull, os.O_RDONLY)
    os.dup2(null, 0)
    os.dup2(descriptor, 1)
    os.dup2(descriptor, 2)
    os.close(descriptor)
    os.close(null)
    if os.fork():
        os._exit(0)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    try:
        request = json.loads((root / 'request.json').read_text())
        if request['mode'] != 'synthetic' or digest(Path(__file__).resolve()) != request['source_hash']:
            raise ValueError('Unqualified mode or changed remote program')
        owned = {'pid': os.getpid(), 'start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19],
                 'uid': os.getuid(), 'machine_id': request['machine_id'], 'attempt_id': request['attempt_id'],
                 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                 'source_hash': request['source_hash'], 'request_hash': digest(root / 'request.json'),
                 'session_id': os.getsid(0), 'started': time.time(), 'capture_ownership': 'NONE_SYNTHETIC_ONLY'}
        atomic(root / 'identity.json', owned)
        atomic(root / 'detail.log', 'Bounded remote synthetic worker; no Matter imports or hardware.\n')
        interrupted = STOP.wait(request['seconds'])
        atomic(root / 'receipt.json', {'state': 'INCOMPLETE' if interrupted else 'PASS', 'identity': owned,
               'request_hash': digest(root / 'request.json'), 'ended': time.time(),
               'detail_hash': digest(root / 'detail.log'), 'qualification_only': True})
    finally:
        lock.close()
        os._exit(0)


def prune(root):
    current = status(root)
    if current['state'] != 'PASS' or current['live'] or not current['receipt'].get('qualification_only'):
        raise ValueError('Only closed verified synthetic success detail may be pruned')
    detail = root / 'detail.log'
    deleted = []
    for path in [detail, root / 'worker.log']:
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_uid != os.getuid():
            raise ValueError('Success detail is not exclusively owned')
        expected = digest(path)
        if path == detail and expected != current['receipt']['detail_hash']:
            raise ValueError('Remote success detail no longer matches receipt')
        deleted.append({'file': path.name, 'bytes': path.stat().st_size, 'sha256': expected})
    atomic(root / 'retention.json', {'receipt_hash': current['receipt_hash'], 'deletions': deleted, 'wall': time.time()})
    for row in deleted:
        (root / row['file']).unlink()
    return status(root)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description='Bounded synthetic remote ownership qualification; no native adapter')
    parser.add_argument('action', choices=['prepare', 'launch', 'status', 'stop', 'prune', 'queue', 'scheduled', 'job-watch'])
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--machine', required=True)
    parser.add_argument('--attempt')
    parser.add_argument('--seconds', type=float, default=12)
    parser.add_argument('--profile', type=Path)
    arguments = parser.parse_args()
    machine(arguments.machine)
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    if arguments.action == 'prepare':
        prepare(arguments.root, arguments.machine, arguments.attempt, arguments.seconds)
        result = status(arguments.root)
    elif arguments.action == 'launch':
        result = launch(arguments.root)
    elif arguments.action == 'queue':
        result = queue(arguments.root, arguments.machine, arguments.attempt, json.loads(arguments.profile.read_text()))
    elif arguments.action == 'scheduled':
        result = scheduled(arguments.root)
    elif arguments.action == 'job-watch':
        result = job_watch(arguments.root)
    elif arguments.action == 'stop':
        result = status(arguments.root)
        if result['live']:
            if result['mode'] == 'os-job':
                atomic(arguments.root / 'stop-request.json', {'wall': time.time()})
                job_watch(arguments.root)
            else:
                os.kill(result['identity']['pid'], signal.SIGTERM)
    elif arguments.action == 'prune':
        result = prune(arguments.root)
    else:
        result = status(arguments.root)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
