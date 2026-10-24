import argparse
import json
import os
import subprocess
import threading
import time
import uuid
from pathlib import Path

from campaign_state import atomic, digest


ACCESS = '/home/feasel/.copilot/skills/raspi-discovery-ssh/scripts/raspi_access.py'
SOURCE = Path(__file__).resolve().parent


def qualify(root, host, identity, machine):
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    run_id = 'synthetic-' + uuid.uuid4().hex[:16]
    remote = '/home/feasel/matter-weekend-synthetic-20261024/' + run_id
    environment = dict(os.environ, PATH='/home/feasel/.local/libexec/raspi-access/package/usr/bin:' + os.environ['PATH'])
    prefix = ['python3', ACCESS]
    host_arguments = ['--host', host] + (['--identity', identity] if identity else [])

    def ssh(*command):
        result = subprocess.run(prefix + ['ssh', *host_arguments, '--', *command], env=environment,
                                capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        if result.returncode:
            atomic(root / 'access-failure.json', {'returncode': result.returncode, 'stderr': result.stderr})
            raise RuntimeError('Verified remote qualification access failed; private diagnostic retained')
        return json.loads(result.stdout)

    code = ('import json; from pathlib import Path; '
            f'assert Path("/etc/machine-id").read_text().strip()=={machine!r}; '
            f'Path({remote!r}).mkdir(mode=0o700,parents=True,exist_ok=False); print(json.dumps({{"created":True}}))')
    ssh('python3', '-c', code)
    for filename in ['campaign_remote_worker.py', 'campaign_state.py']:
        subprocess.run(prefix + ['push', *host_arguments, '--local', str(SOURCE / filename),
                                  '--remote', remote + '/' + filename], env=environment,
                       check=True, timeout=45, stdin=subprocess.DEVNULL, capture_output=True)

    def action(name):
        return ssh('python3', '-B', remote + '/campaign_remote_worker.py', name,
                   '--root', remote + '/attempt', '--machine', machine,
                   '--attempt', run_id, '--seconds', '12')

    results = {'remote_root': remote, 'host': host, 'machine_id': machine,
               'program_hashes': {name: digest(SOURCE / name) for name in ['campaign_remote_worker.py', 'campaign_state.py']}}
    try:
        action('prepare')
        before = action('launch')
        if not before['live'] or before['identity']['source_hash'] != results['program_hashes']['campaign_remote_worker.py']:
            raise AssertionError('Remote synthetic worker failed to start with expected identity')
        repeated = action('launch')
        if before['identity'] != repeated['identity']:
            raise AssertionError('Reconnect duplicated or replaced remote worker')
        atomic(root / 'launch-and-reconnect.json', {'before': before, 'after': repeated})
        end = time.monotonic() + 35
        final = None
        while time.monotonic() < end:
            final = action('status')
            if final['state'] == 'PASS' and not final['live']:
                break
            threading.Event().wait(0.5)
        if final is None or final['state'] != 'PASS' or final['live']:
            raise AssertionError('Remote worker did not complete cleanly after all launching SSH sessions exited')
        last = action('launch')
        if last['identity'] != before['identity'] or last['state'] != 'PASS' or last['live']:
            raise AssertionError('Completed remote attempt was silently rerun')
        pruned = action('prune')
        if pruned['receipt_hash'] != last['receipt_hash'] or pruned['live']:
            raise AssertionError('Success pruning changed final receipt or restarted worker')
        results.update(B={'result': 'PASS', 'proof': 'Launching SSH exited; reconnect found identical live worker; receipt completed later'},
                       J={'result': 'PASS', 'proof': 'Repeated launch adopted same PID/start/boot/request; terminal attempt not rerun; no live worker'},
                       final=final, success_detail_pruned=True, remote_lingering_changed=False, privileged_units_installed=False,
                       scope='Bounded remote synthetic process only; not qualification of native Matter/capture adapters')
    finally:
        atomic(root / 'qualification-results.json', results)
        try:
            remaining = action('status')
            if remaining['live']:
                action('stop')
        except (RuntimeError, subprocess.SubprocessError):
            results['cleanup'] = 'UNVERIFIED: remote access unavailable; bounded synthetic worker expires within 60 seconds'
        atomic(root / 'qualification-results.json', results)
    return results


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--identity')
    parser.add_argument('--machine', required=True)
    arguments = parser.parse_args()
    print(json.dumps(qualify(arguments.root, arguments.host, arguments.identity, arguments.machine), indent=2))
