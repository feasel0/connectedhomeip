import argparse
import fcntl
import hashlib
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import campaign_state as ledger
import campaign_native


STOP = threading.Event()
SELF = Path(__file__).resolve()
FINAL = {'COMPLETE', 'CLOSED', 'BLOCKED'}
REQUIRED_GATES = {'consolidation', 'upstream_builds', 'runtime_imports', 'native_path_isolation',
                  'rf_ownership', 'fixture_smoke', 'capture_lifecycle', 'capacity_forecast', 'supervision'}


def control(*arguments, check=True):
    result = subprocess.run(['systemctl', '--user', '--no-pager', *arguments],
                            capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
    if check and result.returncode:
        raise RuntimeError('systemctl operation failed: ' + arguments[0])
    return result


def unit_status(unit):
    result = control('show', unit, '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID',
                     '-p', 'InvocationID', '-p', 'Result', '-p', 'ExecMainStatus', '-p', 'ControlGroup', check=False)
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def names(root):
    suffix = hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:16]
    return ('matter-weekend-coordinator-' + suffix + '.service', 'matter-weekend-watchdog-' + suffix + '.service')


def transition(database, entity, kind, detail):
    database.execute('INSERT INTO transitions(wall,entity,kind,detail) VALUES(?,?,?,?)',
                     (time.time(), entity, kind, json.dumps(detail, sort_keys=True)))
    database.execute('UPDATE campaign SET last_progress=?', (time.time(),))


def configuration(root):
    database = ledger.connection(root, readonly=True)
    campaign = dict(database.execute('SELECT * FROM campaign').fetchone())
    database.close()
    manifest = root / 'manifest.json'
    if ledger.digest(manifest) != campaign['manifest_hash']:
        raise ValueError('Immutable execution manifest changed')
    document = json.loads(manifest.read_text())
    for filename, expected in document['program_hashes'].items():
        if ledger.digest(root / 'program' / filename) != expected:
            raise ValueError('Frozen program changed')
    if document['mode'] == 'hardware':
        gates = document.get('gates', {})
        if set(gates) != REQUIRED_GATES or not all(gate.get('passed') is True for gate in gates.values()):
            raise ValueError('Mandatory hardware admission gates are not satisfied')
        for gate in gates.values():
            if ledger.digest(Path(gate['receipt'])) != gate['sha256']:
                raise ValueError('Admission gate receipt changed')
        if set(document.get('proofs', {})) != set('ABCDEFGHIJKL') or not all(
                value == 'PASS' for value in document['proofs'].values()):
            raise ValueError('Standalone-supervision proofs are incomplete')
        if not document.get('native_profile'):
            raise ValueError('No verified native workload profile')
        validate_hardware_limits(document)
    elif document['mode'] != 'synthetic':
        raise ValueError('Unknown execution mode')
    return document


def validate_hardware_limits(document):
    if (document['duration_seconds'] != 172800 or document['checkpoint_seconds'] != 86400
            or float(document.get('cleanup_margin_seconds', 0)) < 300):
        raise ValueError('Hardware campaign requires original 48h/24h limits and bounded cleanup reserve')
    profiles = document['native_profile']
    if set(profiles) != {cell['id'] for cell in document['cells']}:
        raise ValueError('Every admitted cell requires exactly one native profile')
    for cell in document['cells']:
        profile = profiles[cell['id']]
        timeout = float(profile['native_timeout_seconds'])
        if (profile['baseline'] != 'pristine-upstream' or profile['requested_iterations'] != 10
                or not 1 <= timeout <= 172200 or float(cell.get('estimated_seconds', 0)) <= 0
                or float(cell.get('timeout_seconds', 0)) < timeout + 300):
            raise ValueError('Minimum-block profile or native worker time/cleanup budget is unqualified')


def prepare(root, plan, settings):
    mode = settings.get('mode')
    if mode not in {'synthetic', 'hardware'}:
        raise ValueError('Explicit synthetic or hardware execution mode required')
    duration = float(settings.get('duration_seconds', 172800))
    if not 1 <= duration <= 172800 or (mode == 'hardware' and duration != 172800):
        raise ValueError('Invalid campaign wall-clock budget')
    if mode == 'hardware' and any('behavior' in cell for cell in settings['cells']):
        raise ValueError('Synthetic outcomes cannot enter a hardware manifest')
    ledger.initialize(root, plan, mode)
    program = root / 'program'
    program.mkdir(mode=0o700)
    for filename in ['campaign_state.py', 'campaign_service.py', 'campaign_native.py']:
        shutil.copy2(SELF.with_name(filename), program / filename)
    document = dict(settings, program_hashes={path.name: ledger.digest(path) for path in program.iterdir()},
                    duration_seconds=duration, checkpoint_seconds=settings.get('checkpoint_seconds', 86400),
                    machine_id=Path('/etc/machine-id').read_text().strip(),
                    summary_path=str(settings.get('summary_path', root / 'LIVE_SUMMARY.md')))
    database = ledger.connection(root)
    known = {row['id'] for row in database.execute('SELECT id FROM cells')}
    selected = [cell['id'] for cell in document['cells']]
    if not selected or len(selected) != len(set(selected)) or not set(selected) <= known:
        raise ValueError('Selected cells must be unique approved matrix identities')
    ledger.atomic(root / 'manifest.json', document)
    with database:
        database.execute("UPDATE campaign SET manifest_hash=?,state='PREPARED',disposition=?",
                         (ledger.digest(root / 'manifest.json'), mode + ': waiting for explicit service start'))
        for cell in selected:
            database.execute("UPDATE cells SET state='ADMITTED',gate_reason=? WHERE id=?", (mode, cell))
    database.close()
    ledger.render(root, Path(document['summary_path']))
    return document


def install(root):
    manifest = configuration(root)
    linger = subprocess.run(['loginctl', 'show-user', str(os.getuid()), '-p', 'Linger', '--value'],
                            capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if linger != 'yes':
        raise ValueError('User manager logout survival is not enabled; refusing service installation')
    directory = Path.home() / '.config/systemd/user'
    directory.mkdir(parents=True, exist_ok=True)
    for unit, action in zip(names(root), ['run', 'watch']):
        text = ('[Unit]\nDescription=Matter weekend ' + manifest['mode'] + ' ' + action + '\n'
                'StartLimitIntervalSec=60\nStartLimitBurst=3\n'
                '[Service]\nType=exec\n'
                f'ExecStart={sys.executable} -B {root}/program/campaign_service.py {action} --root {root}\n'
                'Restart=on-failure\nRestartPreventExitStatus=78\nRestartSec=2\n'
                'TimeoutStopSec=25\nKillMode=control-group\nUMask=0077\nNoNewPrivileges=yes\n'
                f'StandardOutput=append:{root}/{action}.log\nStandardError=append:{root}/{action}.log\n'
                '[Install]\nWantedBy=default.target\n')
        path = directory / unit
        if path.exists() and path.read_text() != text:
            raise ValueError('Existing service has different contents')
        ledger.atomic(path, text)
    control('daemon-reload')
    ledger.atomic(root / 'units.json', {'coordinator': names(root)[0], 'watchdog': names(root)[1],
                                      'uid': os.getuid(), 'linger': linger, 'enabled': False})


def health(root):
    available = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            available['ram_bytes'] = int(line.split()[1]) * 1024
    available.update(free_bytes=shutil.disk_usage(root).free, wall=time.time(),
                     boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    return available


def finish(database, attempt, state, reason):
    with database:
        changed = database.execute("UPDATE attempts SET state=?,ended=?,evidence=? WHERE id=? AND state='RUNNING'",
                                   (state, time.time(), reason, attempt['id'])).rowcount
        if changed:
            transition(database, attempt['id'], 'ATTEMPT_TERMINAL', {'state': state, 'reason': reason})


def identity():
    return {'pid': os.getpid(), 'start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19],
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'machine_id': Path('/etc/machine-id').read_text().strip(), 'uid': os.getuid(),
            'invocation_id': os.environ.get('INVOCATION_ID'), 'source_hash': ledger.digest(SELF)}


def worker(root, attempt_id):
    manifest = configuration(root)
    directory = root / 'attempts' / attempt_id
    request = json.loads((directory / 'request.json').read_text())
    if request['manifest_hash'] != ledger.digest(root / 'manifest.json'):
        raise ValueError('Worker request is not bound to frozen manifest')
    owned = identity()
    if not owned['invocation_id']:
        raise ValueError('Local worker requires independent systemd ownership')
    ledger.atomic(directory / 'identity.json', owned)
    if manifest['mode'] == 'hardware':
        profile = manifest['native_profile'][request['cell']['id']]
        result = campaign_native.execute(profile, directory, STOP)
        ledger.atomic(directory / 'receipt.json', dict(result, attempt_id=attempt_id, cell_id=request['cell']['id'],
                      identity=owned, manifest_hash=request['manifest_hash']))
        return
    behavior = request['cell'].get('behavior')
    if behavior not in {'PASS', 'FAIL', 'HANG', 'CAPTURE_FAILURE', 'OWNERSHIP_FAILURE'}:
        raise ValueError('Unknown synthetic behavior')
    ledger.atomic(directory / 'detail.log', 'Synthetic qualification worker: ' + behavior + '\n')
    if behavior == 'HANG':
        STOP.wait(600)
        return
    if STOP.wait(float(request['cell'].get('seconds', 0.2))):
        return
    outcome = behavior if behavior in {'PASS', 'FAIL'} else 'BLOCKED'
    ledger.atomic(directory / 'receipt.json', {'attempt_id': attempt_id, 'cell_id': request['cell']['id'],
                  'identity': owned, 'outcome': outcome, 'detail_hash': ledger.digest(directory / 'detail.log'),
                  'manifest_hash': request['manifest_hash'], 'qualification_only': True})


def launch(root, database, cell):
    attempt_id = uuid.uuid4().hex
    unit = 'matter-weekend-worker-' + attempt_id + '.service'
    directory = root / 'attempts' / attempt_id
    directory.mkdir(mode=0o700, parents=True)
    ledger.atomic(directory / 'request.json', {'cell': cell, 'manifest_hash': ledger.digest(root / 'manifest.json')})
    with database:
        database.execute('INSERT INTO attempts(id,cell_id,state,unit,created) VALUES(?,?,?,?,?)',
                         (attempt_id, cell['id'], 'RUNNING', unit, time.time()))
        transition(database, attempt_id, 'WORKER_RESERVED', {'unit': unit})
    subprocess.run(['systemd-run', '--user', '--quiet', '--unit', unit, '--property=Type=exec',
                    '--property=RemainAfterExit=yes', '--property=KillMode=control-group',
                    '--property=TimeoutStopSec=60', '--property=UMask=0077',
                    '--property=NoNewPrivileges=' + ('yes' if 'behavior' in cell else 'no'),
                    '--property=RuntimeMaxSec=' + str(float(cell.get('timeout_seconds', 10)) + 10),
                    '--property=StandardOutput=append:' + str(directory / 'worker.log'),
                    '--property=StandardError=append:' + str(directory / 'worker.log'),
                    sys.executable, '-B', str(SELF), 'worker', '--root', str(root), '--attempt', attempt_id],
                   capture_output=True, check=True, timeout=20, stdin=subprocess.DEVNULL)


def reconcile(root, database):
    for attempt in database.execute("SELECT * FROM attempts WHERE state='RUNNING'").fetchall():
        directory = root / 'attempts' / attempt['id']
        state = unit_status(attempt['unit'])
        if state.get('ActiveState') in {'active', 'activating', 'deactivating'} and state.get('SubState') != 'exited':
            identity_path = directory / 'identity.json'
            if identity_path.exists():
                owned = json.loads(identity_path.read_text())
                if owned['invocation_id'] != state.get('InvocationID') or str(owned['pid']) != state.get('MainPID'):
                    finish(database, attempt, 'BLOCKED', 'Live service ownership mismatch')
            continue
        receipt_path = directory / 'receipt.json'
        if not receipt_path.exists():
            finish(database, attempt, 'INCOMPLETE', 'Worker ended without durable receipt; ID will not be replayed')
            continue
        receipt = json.loads(receipt_path.read_text())
        owned = json.loads((directory / 'identity.json').read_text())
        if (receipt['identity'] != owned or receipt['attempt_id'] != attempt['id'] or receipt['cell_id'] != attempt['cell_id']
                or owned['invocation_id'] != state.get('InvocationID')
                or receipt['manifest_hash'] != ledger.digest(root / 'manifest.json')
                or receipt['detail_hash'] != ledger.digest(directory / 'detail.log')
                or receipt['outcome'] not in {'PASS', 'FAIL', 'BLOCKED', 'INCOMPLETE'}):
            finish(database, attempt, 'BLOCKED', 'Receipt ownership or integrity mismatch')
            continue
        if state.get('Result') != 'success' or state.get('ExecMainStatus') != '0':
            finish(database, attempt, 'INCOMPLETE', 'Receipt not accompanied by clean service exit')
            continue
        for filename, expected in receipt.get('artifacts', {}).items():
            artifact = directory / filename
            if not artifact.resolve().is_relative_to(directory.resolve()) or ledger.digest(artifact) != expected:
                raise ValueError('Native evidence integrity mismatch')
        if receipt['outcome'] in {'PASS', 'FAIL', 'INCOMPLETE'}:
            with database:
                outcomes = receipt.get('iterations', [{'ordinal': 1, 'outcome': receipt['outcome']}])
                for outcome in outcomes:
                    if outcome['outcome'] in {'PASS', 'FAIL'}:
                        ledger.record_outcome(database, attempt['id'], outcome['ordinal'], outcome['outcome'],
                                              ledger.digest(receipt_path), signature=outcome.get('signature'))
                database.execute("UPDATE attempts SET identity=?,integrity='COMPLETE' WHERE id=?",
                                 (json.dumps(owned, sort_keys=True), attempt['id']))
        finish(database, attempt, receipt['outcome'], 'Verified native receipt' if receipt.get('iterations') else 'Verified synthetic outcome')


def close(root, database, manifest, disposition, reason):
    for attempt in database.execute("SELECT * FROM attempts WHERE state='RUNNING'").fetchall():
        directory = root / 'attempts' / attempt['id']
        ledger.atomic(directory / 'closeout.json', {'unit': unit_status(attempt['unit']), 'reason': reason, 'wall': time.time()})
        state = unit_status(attempt['unit'])
        owned_path = directory / 'identity.json'
        if state.get('MainPID') not in {'', '0', None}:
            if not owned_path.exists() or json.loads(owned_path.read_text())['invocation_id'] != state.get('InvocationID'):
                disposition, reason = 'BLOCKED', 'Cannot prove live worker ownership; worker not signaled'
            else:
                control('stop', attempt['unit'])
        try:
            reconcile(root, database)
        except (ValueError, OSError, KeyError, sqlite3.Error) as error:
            ledger.atomic(directory / 'closeout-reconciliation-error.json', {'kind': type(error).__name__})
        finish(database, attempt, 'INCOMPLETE', reason)
    with database:
        database.execute('UPDATE campaign SET state=?,disposition=?', (disposition, reason))
        transition(database, 'campaign', 'CLOSEOUT', {'disposition': disposition, 'reason': reason})
    ledger.render(root, Path(manifest['summary_path']))
    ledger.atomic(root / 'final-status.json', ledger.status(root))


def fail_closed(root, error):
    database = ledger.connection(root)
    manifest = {'summary_path': str(root / 'LIVE_SUMMARY.md')}
    try:
        close(root, database, manifest, 'BLOCKED', 'Operational failure: ' + type(error).__name__)
    except Exception as cleanup_error:
        ledger.atomic(root / 'cleanup-error.json', {'kind': type(cleanup_error).__name__, 'wall': time.time()})
        with database:
            database.execute("UPDATE campaign SET state='BLOCKED',disposition=?",
                             ('Owned-worker closure unresolved: ' + type(cleanup_error).__name__,))
            transition(database, 'campaign', 'CLEANUP_UNRESOLVED', {'kind': type(cleanup_error).__name__})
    finally:
        database.close()


def run(root):
    manifest = configuration(root)
    lock = (root / 'coordinator.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    database = ledger.connection(root)
    campaign = database.execute('SELECT * FROM campaign').fetchone()
    if campaign['state'] in FINAL:
        ledger.render(root, Path(manifest['summary_path']))
        return
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if campaign['boot_id'] and campaign['boot_id'] != boot:
        close(root, database, manifest, 'BLOCKED', 'Host reboot: full fixture and remote ownership revalidation required')
        return
    if campaign['started'] is None:
        now = time.time()
        with database:
            database.execute("UPDATE campaign SET started=?,deadline=?,boot_id=?,state='RUNNING' WHERE started IS NULL",
                             (now, now + manifest['duration_seconds'], boot))
            transition(database, 'campaign', 'ACTUAL_START', {'started': now, 'deadline': now + manifest['duration_seconds']})
    with database:
        transition(database, 'campaign', 'COORDINATOR_START', identity())
    while True:
        configuration(root)
        reconcile(root, database)
        campaign = database.execute('SELECT * FROM campaign').fetchone()
        sample = health(root)
        ledger.atomic(root / 'heartbeat.json', sample)
        with database:
            database.execute('INSERT INTO health(wall,host,document) VALUES(?,?,?)',
                             (sample['wall'], manifest['machine_id'], json.dumps(sample)))
        if campaign['state'] in FINAL:
            ledger.render(root, Path(manifest['summary_path']))
            return
        if not campaign['checkpoint_done'] and time.time() >= campaign['started'] + manifest['checkpoint_seconds']:
            with database:
                database.execute('UPDATE campaign SET checkpoint_done=1')
                transition(database, 'campaign', '24H_CHECKPOINT', {'synthetic': manifest['mode'] == 'synthetic'})
            ledger.atomic(root / 'checkpoint-24h.json', ledger.status(root))
        unsafe = database.execute("SELECT 1 FROM attempts WHERE state IN ('INCOMPLETE','BLOCKED')").fetchone()
        if unsafe or sample['free_bytes'] < 8 * 1024 ** 3 or sample['ram_bytes'] < 256 * 1024 ** 2:
            close(root, database, manifest, 'BLOCKED', 'Unsafe/ambiguous attempt or resource reserve violation')
            return
        margin = float(manifest.get('cleanup_margin_seconds', 0))
        if STOP.is_set() or (root / 'stop-request.json').exists() or time.time() >= campaign['deadline'] - margin:
            close(root, database, manifest, 'CLOSED', 'Graceful stop request or immutable absolute deadline')
            return
        if not database.execute("SELECT 1 FROM attempts WHERE state='RUNNING'").fetchone():
            completed = {row['cell_id'] for row in database.execute('SELECT cell_id FROM attempts')}
            selected = next((cell for cell in manifest['cells'] if cell['id'] not in completed), None)
            if selected is None:
                close(root, database, manifest, 'COMPLETE', 'Selected qualification workload complete')
                return
            estimate = float(selected.get('estimated_seconds', selected.get('seconds', 1)))
            if time.time() + estimate + margin >= campaign['deadline']:
                close(root, database, manifest, 'CLOSED', 'Insufficient remaining time for next whole block and cleanup')
                return
            launch(root, database, selected)
        ledger.render(root, Path(manifest['summary_path']))
        STOP.wait(0.25)


def watch(root):
    manifest = configuration(root)
    database = ledger.connection(root)
    while not STOP.is_set():
        campaign = database.execute('SELECT * FROM campaign').fetchone()
        if campaign['state'] in FINAL:
            if database.execute("SELECT 1 FROM attempts WHERE state='RUNNING'").fetchone():
                close(root, database, manifest, 'BLOCKED', 'Terminal campaign still has unresolved live attempts')
            return
        heartbeat = root / 'heartbeat.json'
        stale = heartbeat.exists() and time.time() - heartbeat.stat().st_mtime > 15
        expired = campaign['deadline'] is not None and time.time() > campaign['deadline'] + 10
        for attempt in database.execute("SELECT * FROM attempts WHERE state='RUNNING'").fetchall():
            cell = next(cell for cell in manifest['cells'] if cell['id'] == attempt['cell_id'])
            if time.time() - attempt['created'] > float(cell.get('timeout_seconds', 10)):
                ledger.atomic(root / 'attempts' / attempt['id'] / 'watchdog.json',
                              {'wall': time.time(), 'unit': unit_status(attempt['unit']), 'reason': 'Worker deadline exceeded'})
                close(root, database, manifest, 'BLOCKED', 'Independent watchdog detected worker hang')
                return
        if stale or expired:
            ledger.atomic(root / 'watchdog-enforcement.json', {'wall': time.time(), 'stale': stale, 'expired': expired})
            close(root, database, manifest, 'BLOCKED', 'Independent watchdog progress/deadline enforcement')
            control('stop', names(root)[0], check=False)
            return
        STOP.wait(0.25)


def prune(root):
    database = ledger.connection(root)
    for attempt in database.execute("SELECT * FROM attempts WHERE state='PASS' AND integrity='COMPLETE'").fetchall():
        row = database.execute('SELECT * FROM iterations WHERE attempt_id=?', (attempt['id'],)).fetchone()
        directory = root / 'attempts' / attempt['id']
        receipt = directory / 'receipt.json'
        detail = directory / 'detail.log'
        if not row or row['receipt_hash'] != ledger.digest(receipt):
            raise ValueError('No matching durable committed success receipt')
        result = json.loads(receipt.read_text())
        if detail.exists() and ledger.digest(detail) != result['detail_hash']:
            raise ValueError('Success detail integrity changed')
        with database:
            transition(database, attempt['id'], 'SUCCESS_DETAIL_PRUNE', {'receipt_hash': row['receipt_hash']})
        detail.unlink(missing_ok=True)
    database.close()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['prepare', 'install', 'start', 'run', 'watch', 'worker', 'status', 'stop', 'prune'])
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--settings', type=Path)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--attempt')
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    try:
        if arguments.action == 'prepare':
            prepare(root, arguments.plan, json.loads(arguments.settings.read_text()))
        elif arguments.action == 'install':
            install(root)
        elif arguments.action == 'start':
            configuration(root)
            install(root)
            control('start', names(root)[1], names(root)[0])
        elif arguments.action == 'status':
            print(json.dumps({'ledger': ledger.status(root), 'services': {unit: unit_status(unit) for unit in names(root)}}, indent=2))
        elif arguments.action == 'stop':
            ledger.atomic(root / 'stop-request.json', {'wall': time.time()})
        elif arguments.action == 'prune':
            prune(root)
        else:
            {'run': run, 'watch': watch, 'worker': lambda path: worker(path, arguments.attempt)}[arguments.action](root)
    except Exception as error:
        if arguments.action in {'start', 'run', 'watch'} and (root / 'campaign.sqlite').exists():
            fail_closed(root, error)
        elif arguments.action == 'worker':
            ledger.atomic(root / 'attempts' / arguments.attempt / 'worker-error.json',
                          {'kind': type(error).__name__, 'wall': time.time()})
        print('BLOCKED: ' + type(error).__name__, file=sys.stderr)
        return 78
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
