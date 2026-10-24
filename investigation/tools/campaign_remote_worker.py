import argparse
import fcntl
import json
import os
import re
import signal
import sys
import threading
import time
from pathlib import Path

from campaign_state import atomic, digest


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
                'mode': 'synthetic', 'state': 'RESERVED', 'live': False}
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
    parser.add_argument('action', choices=['prepare', 'launch', 'status', 'stop', 'prune'])
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--machine', required=True)
    parser.add_argument('--attempt')
    parser.add_argument('--seconds', type=float, default=12)
    arguments = parser.parse_args()
    machine(arguments.machine)
    if arguments.action == 'prepare':
        prepare(arguments.root, arguments.machine, arguments.attempt, arguments.seconds)
        result = status(arguments.root)
    elif arguments.action == 'launch':
        result = launch(arguments.root)
    elif arguments.action == 'stop':
        result = status(arguments.root)
        if result['live']:
            os.kill(result['identity']['pid'], signal.SIGTERM)
    elif arguments.action == 'prune':
        result = prune(arguments.root)
    else:
        result = status(arguments.root)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
