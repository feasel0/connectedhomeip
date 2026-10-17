import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
DIRECTORIES = ('37075', 'pr539-failure-evidence')
BRANCH = 'investigation/2026-10-17'
STATE = REPOSITORY / 'investigation/.relocation-state.json'
RAW_SUFFIXES = ('.log', '.pcap', '.pcapng', '.btsnoop', '.tar', '.tar.gz', '.tgz',
                '.tar.xz', '.zip', '.elf', '.bin', '.hex', '.so', '.sqlite',
                '.sqlite3', '.db', '.pem', '.key', '.private.json')


def git(*arguments, input_data=None):
    return subprocess.check_output(['git', *arguments], cwd=REPOSITORY, input=input_data)


def paths(data):
    return [os.fsdecode(part) for part in data.split(b'\0') if part]


def checksum(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def allowed(path):
    return not path.endswith(RAW_SUFFIXES)


def audit():
    lock = REPOSITORY / '.git/index.lock'
    owners = subprocess.run(['fuser', str(lock)], capture_output=True, text=True)
    processes = subprocess.check_output(['ps', '-eo', 'pid,etimes,comm'], text=True)
    print(json.dumps({'utc': time.strftime('%Y-%m-%d_%H-%M-%S', time.gmtime()),
        'branch': git('branch', '--show-current').decode().strip(),
        'index_lock': {'exists': lock.exists(), 'bytes': lock.stat().st_size if lock.exists() else None,
            'age_seconds': round(time.time() - lock.stat().st_mtime) if lock.exists() else None,
            'owner_pids': owners.stdout.split()},
        'git_processes': [line.split() for line in processes.splitlines()[1:] if line.split()[-1] == 'git'],
        'push_url': git('remote', 'get-url', '--push', 'origin').decode().strip()}, indent=2))


def initialize():
    assert git('branch', '--show-current').decode().strip() == BRANCH
    urls = git('remote', 'get-url', '--push', '--all', 'origin').decode().splitlines()
    assert urls == ['https://github.com/feasel0/connectedhomeip.git'], 'Unexpected push destination'
    lock = REPOSITORY / '.git/index.lock'
    if lock.exists():
        information = lock.stat()
        assert information.st_size == 0 and time.time() - information.st_mtime > 3600
        owners = subprocess.run(['fuser', str(lock)], capture_output=True, text=True)
        assert owners.returncode == 1 and not owners.stdout.strip()
        processes = subprocess.check_output(['ps', '-eo', 'comm'], text=True).splitlines()
        assert 'git' not in processes
        assert lock.stat().st_ino == information.st_ino
        lock.unlink()
    for key, value in (('remote', 'origin'), ('merge', 'refs/heads/' + BRANCH), ('pushRemote', 'origin')):
        git('config', 'branch.' + BRANCH + '.' + key, value)
    print(json.dumps({'branch': BRANCH, 'push_only': urls, 'stale_lock_cleared': not lock.exists()}))


def move():
    assert git('branch', '--show-current').decode().strip() == BRANCH
    assert not (REPOSITORY / '.git/index.lock').exists()
    assert not STATE.exists(), 'Relocation has already started'
    assert not git('diff', '--cached', '--name-only'), 'Do not mix an existing staged snapshot'
    visible = paths(git('ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', *DIRECTORIES))
    ignored = paths(git('ls-files', '--others', '--ignored', '--exclude-standard', '-z', '--', *DIRECTORIES))
    tracked = paths(git('ls-files', '-z', '--', *DIRECTORIES))
    original = {}
    for name in visible + ignored:
        path = REPOSITORY / name
        information = path.lstat()
        original[name] = {'device': information.st_dev, 'inode': information.st_ino,
            'bytes': information.st_size, 'visible': name in visible,
            'sha256': checksum(path) if name in visible and allowed(name) and path.is_file() else None}
    state = {'before_head': git('rev-parse', 'HEAD').decode().strip(), 'original': original,
        'tracked_old_paths': tracked, 'excluded_raw_archives': [name for name in visible if not allowed(name)]}
    STATE.write_text(json.dumps(state, indent=2) + '\n')
    for name in DIRECTORIES:
        source = REPOSITORY / name
        destination = REPOSITORY / 'investigation' / name
        assert source.is_dir() and not source.is_symlink() and not destination.exists()
        source.rename(destination)
        source.symlink_to(Path('investigation') / name, target_is_directory=True)
    git('update-index', '--force-remove', '-z', '--stdin', input_data=b''.join(
        os.fsencode(name) + b'\0' for name in tracked))
    print(json.dumps({'moved': list(DIRECTORIES), 'previously_visible': len(visible),
        'previously_ignored': len(ignored), 'raw_archives_not_to_publish': state['excluded_raw_archives'],
        'compatibility_symlinks': True}, indent=2))


def verify():
    state = json.loads(STATE.read_text())
    failures = []
    for name, original in state['original'].items():
        destination = REPOSITORY / 'investigation' / name
        information = destination.lstat()
        if (information.st_dev, information.st_ino) != (original['device'], original['inode']):
            failures.append({'path': name, 'error': 'inode changed'})
        if original['sha256'] and checksum(destination) != original['sha256']:
            failures.append({'path': name, 'error': 'visible content changed'})
    hidden = [str(Path('investigation') / name) for name, row in state['original'].items()
        if not row['visible'] or not allowed(name)]
    result = subprocess.run(['git', 'check-ignore', '--no-index', '-z', '--stdin'], cwd=REPOSITORY,
        input=b''.join(os.fsencode(name) + b'\0' for name in hidden), capture_output=True)
    assert result.returncode in (0, 1), result.stderr.decode()
    failures.extend({'path': name, 'error': 'previously private path became visible'}
        for name in sorted(set(hidden) - set(paths(result.stdout))))
    visible = paths(git('ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', 'investigation'))
    prohibited = [name for name in visible if not allowed(name)]
    assert not failures and not prohibited, {'relocation_failures': failures, 'prohibited': prohibited}
    print(json.dumps({'preserved_inodes': len(state['original']), 'hidden_paths_verified': len(hidden),
        'visible_count': len(visible), 'visible_bytes': sum((REPOSITORY / name).stat().st_size for name in visible),
        'compatibility_paths_resolve': all((REPOSITORY / name).resolve() == REPOSITORY / 'investigation' / name
            for name in DIRECTORIES), 'raw_payloads_visible': prohibited}, indent=2))


def staged():
    names = paths(git('diff', '--cached', '--name-only', '-z'))
    added = paths(git('diff', '--cached', '--name-only', '--diff-filter=ACMRT', '-z'))
    assert names, 'There is nothing staged'
    assert all(name.startswith('investigation/') or name.startswith(tuple(root + '/' for root in DIRECTORIES))
        for name in names), 'Unrelated changes are staged'
    assert all(name.startswith('investigation/') and allowed(name) for name in added)
    blobs = []
    for name in added:
        content = git('show', ':' + name)
        assert len(content) < 5 * 1024**2 and b'\0' not in content, name
        assert not re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', content), name
        blobs.append({'path': name, 'bytes': len(content)})
    print(json.dumps({'changed_paths': len(names), 'published_files': len(blobs),
        'published_bytes': sum(row['bytes'] for row in blobs), 'files': blobs}, indent=2))


class BoundaryTest(unittest.TestCase):
    def test_raw_payloads_rejected(self):
        for name in ('logs/native.log', 'capture.pcapng', 'failure.tar.gz', 'admin.private.json', 'key.pem'):
            self.assertFalse(allowed('investigation/' + name))

    def test_summaries_and_tools_allowed(self):
        for name in ('report.md', 'summary.json', 'manifest.json', 'runner.py', 'fixture.yaml', 'SHA256SUMS'):
            self.assertTrue(allowed('investigation/' + name))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('self-test', 'audit', 'initialize', 'move', 'verify', 'staged'))
    action = parser.parse_args().action
    if action == 'self-test':
        unittest.main(argv=[__file__])
    else:
        globals()[action]()