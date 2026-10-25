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
    elif document['mode'] == 'qualification':
        if (not 1 <= document['duration_seconds'] <= 7200
                or set(document.get('native_profile', {})) != {cell['id'] for cell in document['cells']}):
            raise ValueError('Qualification requires bounded separate native profiles')
        for profile in document['native_profile'].values():
            if (profile['baseline'] != 'pristine-upstream' or not 1 <= profile['requested_iterations'] <= 10
                    or not 1 <= float(profile['native_timeout_seconds']) <= 6600):
                raise ValueError('Unqualified native qualification bounds')
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
        stretch = profile.get('stretch_profile')
        if stretch is not None:
            target = int(cell['target_iterations'])
            if (target not in {15, 20, 30} or stretch['requested_iterations'] != target - 10
                    or stretch['baseline'] != 'pristine-upstream'
                    or float(cell.get('stretch_estimated_seconds', 0)) <= 0
                    or any(stretch.get(key) != profile.get(key) for key in ['rf_authority', 'remote_access',
                        'controller_machine_id', 'controller_boot_id', 'remote_worker'])
                    or not 1 <= float(stretch['native_timeout_seconds']) <= 172200
                    or float(cell['timeout_seconds']) < float(stretch['native_timeout_seconds']) + 300):
                raise ValueError('Stretch must be a bounded whole remainder after the mandatory minimum')


def prepare(root, plan, settings):
    mode = settings.get('mode')
    if mode not in {'synthetic', 'hardware', 'qualification'}:
        raise ValueError('Explicit synthetic, hardware or qualification execution mode required')
    duration = float(settings.get('duration_seconds', 172800))
    if not 1 <= duration <= 172800 or (mode == 'hardware' and duration != 172800):
        raise ValueError('Invalid campaign wall-clock budget')
    if mode != 'synthetic' and any('behavior' in cell for cell in settings['cells']):
        raise ValueError('Synthetic outcomes cannot enter a hardware manifest')
    if root.exists():
        database = ledger.connection(root)
        campaign = database.execute('SELECT * FROM campaign').fetchone()
        try:
            if (mode != 'hardware' or campaign['mode'] != 'PREPARATION' or campaign['started'] is not None
                    or campaign['plan_hash'] != ledger.digest(plan)
                    or database.execute('SELECT 1 FROM attempts').fetchone()
                    or database.execute('SELECT 1 FROM ownership WHERE released IS NULL').fetchone()):
                raise ValueError('Only the unlaunched, positively unowned approved production ledger may be admitted')
        finally:
            database.close()
    else:
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
    if mode == 'hardware':
        targets = dict(database.execute('SELECT id,target FROM cells'))
        if any(cell.get('target_iterations') != targets[cell['id']] for cell in document['cells']):
            raise ValueError('Hardware target must match the approved plan exactly')
    ledger.atomic(root / 'manifest.json', document)
    with database:
        database.execute("UPDATE campaign SET manifest_hash=?,mode=?,state='PREPARED',disposition=?",
                 (ledger.digest(root / 'manifest.json'), mode, mode + ': waiting for explicit service start'))
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
    return ledger.host_health(root)


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
    if manifest['mode'] in {'hardware', 'qualification'}:
        profile = manifest['native_profile'][request['cell']['id']]
        stretch = request['cell'].get('block_phase') == 'stretch'
        if stretch:
            database = ledger.connection(root, readonly=True)
            try:
                count = database.execute('SELECT COUNT(*) FROM iterations i JOIN attempts a ON a.id=i.attempt_id '
                                         'WHERE a.cell_id=?', (request['cell']['id'],)).fetchone()[0]
            finally:
                database.close()
            if manifest['mode'] != 'hardware' or count < 10:
                raise ValueError('Stretch cannot precede a committed ten-iteration minimum')
            profile = profile['stretch_profile']
        result = campaign_native.execute_guarded(profile, directory, STOP,
            qualification=manifest['mode'] == 'qualification', stretch=stretch)
        ledger.atomic(directory / 'receipt.json', dict(result, attempt_id=attempt_id, cell_id=request['cell']['id'],
                      identity=owned, manifest_hash=request['manifest_hash']))
        return
    behavior = request['cell'].get('behavior')
    if behavior not in {'PASS', 'FAIL', 'HANG', 'CAPTURE_FAILURE', 'OWNERSHIP_FAILURE', 'RESOURCE_FAILURE'}:
        raise ValueError('Unknown synthetic behavior')
    ledger.atomic(directory / 'detail.log', 'Synthetic qualification worker: ' + behavior + '\n')
    if behavior == 'HANG':
        STOP.wait(600)
        return
    if STOP.wait(float(request['cell'].get('seconds', 0.2))):
        return
    if behavior == 'RESOURCE_FAILURE':
        ledger.atomic(directory / 'receipt.json', {'attempt_id': attempt_id, 'cell_id': request['cell']['id'],
            'identity': owned, 'outcome': 'INCOMPLETE', 'detail_hash': ledger.digest(directory / 'detail.log'),
            'manifest_hash': request['manifest_hash'], 'qualification_only': True, 'cleanup_complete': True,
            'failure_domain': 'resource', 'quarantined_resources': request['cell']['resources']})
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
    manifest = configuration(root)
    request = {'cell': cell, 'attempt_id': attempt_id, 'manifest_hash': ledger.digest(root / 'manifest.json')}
    if manifest['mode'] != 'synthetic':
        profile = manifest['native_profile'][cell['id']]
        request['rf_owner'] = {'campaign_id': database.execute('SELECT id FROM campaign').fetchone()[0],
            'attempt_id': attempt_id, 'worker': profile.get('remote_worker', unit).replace('{attempt_id}', attempt_id),
            'machine_id': profile.get('controller_machine_id', manifest['machine_id']),
            'boot_id': profile.get('controller_boot_id', Path('/proc/sys/kernel/random/boot_id').read_text().strip())}
        authority = ledger.connection(Path(profile['rf_authority']))
        try:
            ledger.reserve_resources(authority, ['rf:lab'], request['rf_owner'])
        finally:
            authority.close()
    ledger.atomic(directory / 'request.json', request)
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


def ingest_iterations(directory, database, attempt):
    for path in sorted((directory / 'iteration-receipts').glob('*.json')):
        document = json.loads(path.read_text())
        if (document['request_sha256'] != ledger.digest(directory / 'request.json')
                or document['identity_sha256'] != ledger.digest(directory / 'identity.json')
                or not document.get('started') or not document.get('ended')):
            raise ValueError('Durable iteration receipt ownership or integrity changed')
        with database:
            ledger.record_outcome(database, attempt['id'], document['ordinal'], document['outcome'],
                                  ledger.digest(path), signature=document.get('signature'))


def isolate_failure(database, attempt, manifest, receipt):
    domain = receipt.get('failure_domain', 'shared')
    resources = receipt.get('quarantined_resources', [])
    isolated = domain == 'resource' and receipt.get('cleanup_complete') is True and bool(resources)
    if isolated:
        profile = manifest['native_profile'][attempt['cell_id']]
        if not set(resources) <= set(profile.get('failure_resources', [])):
            raise ValueError('Failure attempted to quarantine unqualified resources')
        for cell in manifest['cells']:
            if set(resources) & set(cell.get('resources', [])):
                database.execute("UPDATE cells SET state='QUARANTINED',gate_reason=? WHERE id=?",
                                 ('Isolated infrastructure failure: ' + attempt['id'], cell['id']))
    transition(database, attempt['id'], 'FAILURE_DOMAIN', {'isolated': isolated, 'domain': domain,
                                                        'resources': resources})


def unsafe_attempt(database):
    for attempt in database.execute("SELECT id FROM attempts WHERE state IN ('INCOMPLETE','BLOCKED')"):
        row = database.execute("SELECT detail FROM transitions WHERE entity=? AND kind='FAILURE_DOMAIN' "
                               'ORDER BY sequence DESC LIMIT 1', (attempt['id'],)).fetchone()
        if row is None or json.loads(row['detail']).get('isolated') is not True:
            return True
    return False


def next_block(database, manifest):
    eligible = {row['id'] for row in database.execute("SELECT id FROM cells WHERE state='ADMITTED'")}
    counts = dict(database.execute('SELECT a.cell_id,COUNT(i.id) FROM attempts a '
                                   'LEFT JOIN iterations i ON i.attempt_id=a.id GROUP BY a.cell_id').fetchall())
    attempted = {row['cell_id'] for row in database.execute('SELECT cell_id FROM attempts')}
    if manifest['mode'] != 'hardware':
        return next((cell for cell in manifest['cells'] if cell['id'] in eligible and cell['id'] not in attempted), None)
    for phase in ['minimum', 'stretch']:
        for cell in manifest['cells']:
            if cell['id'] not in eligible:
                continue
            completed = counts.get(cell['id'], 0)
            if phase == 'minimum' and completed < 10:
                return dict(cell, block_phase=phase)
            profile = manifest['native_profile'][cell['id']]
            if phase == 'stretch' and profile.get('stretch_profile') and 10 <= completed < cell['target_iterations']:
                return dict(cell, block_phase=phase, estimated_seconds=cell['stretch_estimated_seconds'])
    return None


def release_attempt_rf(root, database, attempt, receipt):
    manifest = configuration(root)
    if manifest['mode'] == 'synthetic':
        return
    profile = manifest['native_profile'][attempt['cell_id']]
    if (receipt.get('cleanup_complete') is not True
            or (profile.get('controller_machine_id', manifest['machine_id']) != manifest['machine_id']
                and receipt.get('remote_worker_stopped') is not True)):
        raise ValueError('RF release requires local and remote worker closure')
    request = json.loads((root / 'attempts' / attempt['id'] / 'request.json').read_text())
    owner = request['rf_owner']
    authority = ledger.connection(Path(profile['rf_authority']))
    try:
        ledger.release_resources(authority, ['rf:lab'], owner,
            {'owner': owner, 'worker_stopped': True, 'fixture_ready': True, 'capture_closed': True,
             'receipt_sha256': ledger.digest(root / 'attempts' / attempt['id'] / 'receipt.json')})
    finally:
        authority.close()


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
                else:
                    ingest_iterations(directory, database, attempt)
            continue
        if (directory / 'identity.json').exists():
            ingest_iterations(directory, database, attempt)
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
                        if not (directory / 'iteration-receipts' / (str(outcome['ordinal']).zfill(5) + '.json')).exists():
                            ledger.record_outcome(database, attempt['id'], outcome['ordinal'], outcome['outcome'],
                                                  ledger.digest(receipt_path), signature=outcome.get('signature'))
                database.execute("UPDATE attempts SET identity=?,integrity='COMPLETE' WHERE id=?",
                                 (json.dumps(owned, sort_keys=True), attempt['id']))
        if receipt['outcome'] in {'INCOMPLETE', 'BLOCKED'}:
            with database:
                isolate_failure(database, attempt, configuration(root), receipt)
        release_attempt_rf(root, database, attempt, receipt)
        reason = 'Verified synthetic outcome' if configuration(root)['mode'] == 'synthetic' else 'Verified native receipt'
        finish(database, attempt, receipt['outcome'], reason)


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
        if manifest.get('prune_successes') is True:
            prune(root)
        campaign = database.execute('SELECT * FROM campaign').fetchone()
        previous_health = database.execute('SELECT document FROM health ORDER BY wall DESC LIMIT 1').fetchone()
        sample = health(root)
        resource_violation = ledger.health_violation(sample, json.loads(previous_health['document']) if previous_health else None)
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
        unsafe = unsafe_attempt(database)
        if unsafe or resource_violation:
            close(root, database, manifest, 'BLOCKED', 'Unsafe/ambiguous attempt or resource violation: ' + str(resource_violation))
            return
        margin = float(manifest.get('cleanup_margin_seconds', 0))
        if STOP.is_set() or (root / 'stop-request.json').exists() or time.time() >= campaign['deadline'] - margin:
            close(root, database, manifest, 'CLOSED', 'Graceful stop request or immutable absolute deadline')
            return
        if not database.execute("SELECT 1 FROM attempts WHERE state='RUNNING'").fetchone():
            selected = next_block(database, manifest)
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


def finish_retention(directory, retention):
    if ledger.digest(directory / 'receipt.json') != retention['receipt_hash']:
        raise ValueError('Retained success receipt changed')
    for item in retention['deletions']:
        path = directory / item['file']
        if not path.resolve().is_relative_to(directory.resolve()) or path.is_symlink():
            raise ValueError('Success retention path escaped its owned attempt')
        if path.exists():
            if (ledger.digest(path) != item['sha256'] or path.stat().st_uid != os.getuid()
                    or path.stat().st_nlink != 1):
                raise ValueError('Success artifact changed during retention')
            path.unlink()
    ledger.atomic(directory / 'retention-complete.json', {'bytes': retention['bytes'],
        'all_absent': all(not (directory / item['file']).exists() for item in retention['deletions'])})


def prune(root):
    database = ledger.connection(root)
    for attempt in database.execute("SELECT * FROM attempts WHERE state='PASS' AND integrity='COMPLETE'").fetchall():
        directory = root / 'attempts' / attempt['id']
        if (directory / 'retention-complete.json').exists():
            continue
        if (directory / 'retention.json').exists():
            finish_retention(directory, json.loads((directory / 'retention.json').read_text()))
            continue
        if (directory / 'retain-evidence.json').exists():
            continue
        rows = database.execute('SELECT * FROM iterations WHERE attempt_id=?', (attempt['id'],)).fetchall()
        receipt = directory / 'receipt.json'
        detail = directory / 'detail.log'
        if not rows:
            raise ValueError('No matching durable committed success receipt')
        result = json.loads(receipt.read_text())
        if result.get('outcome') != 'PASS' or any(row['native_outcome'] != 'PASS' for row in rows):
            raise ValueError('Success pruning cannot include a failed or ambiguous native result')
        for row in rows:
            iteration = directory / 'iteration-receipts' / (str(row['ordinal']).zfill(5) + '.json')
            bound = iteration if iteration.exists() else receipt
            if row['receipt_hash'] != ledger.digest(bound):
                raise ValueError('No matching durable committed success receipt')
        state = unit_status(attempt['unit'])
        if state.get('MainPID') not in {'0', '', None} or state.get('SubState') not in {'exited', 'dead', 'failed'}:
            raise ValueError('Success worker closure not established')
        manifest = configuration(root)
        if manifest['mode'] != 'synthetic' and result.get('cleanup_complete') is not True:
            raise ValueError('Native success fixture and capture cleanup incomplete')
        if result.get('remote_worker_stopped') is False:
            raise ValueError('Remote native success worker still live')
        if manifest['mode'] != 'synthetic':
            profile = manifest['native_profile'][attempt['cell_id']]
            request = json.loads((directory / 'request.json').read_text())
            if request['cell'].get('block_phase') == 'stretch':
                profile = profile['stretch_profile']
            if profile.get('automatic_native_retention') is True:
                campaign_native.retain_native_success(profile, directory)
        deletions = []
        for filename, expected in result.get('artifacts', {}).items():
            path = directory / filename
            if not path.resolve().is_relative_to(directory.resolve()) or ledger.digest(path) != expected:
                raise ValueError('Success artifact integrity changed before retention')
            raw = (path.suffix in {'.log', '.html', '.pcap', '.pcapng', '.pyc'}
                   or path.name in {'controller.private.json', 'trace.private.json'}
                   or path.is_relative_to(directory / 'tmp') or path.is_relative_to(directory / 'home'))
            if raw:
                if path.is_symlink() or path.stat().st_uid != os.getuid() or path.stat().st_nlink != 1:
                    raise ValueError('Success artifact is not exclusively owned')
                deletions.append({'file': filename, 'bytes': path.stat().st_size, 'sha256': expected})
        if detail.exists() and ledger.digest(detail) != result['detail_hash']:
            raise ValueError('Success detail integrity changed')
        if detail.exists():
            deletions.append({'file': 'detail.log', 'bytes': detail.stat().st_size, 'sha256': ledger.digest(detail)})
        retention = {'receipt_hash': ledger.digest(receipt), 'deletions': deletions,
                     'bytes': sum(item['bytes'] for item in deletions), 'wall': time.time()}
        ledger.atomic(directory / 'retention.json', retention)
        with database:
            transition(database, attempt['id'], 'SUCCESS_DETAIL_PRUNE', retention)
        finish_retention(directory, retention)
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
