"""One reversible native Pi BLE/Wi-Fi comparison using retained fixture code."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import time


ACCESS = '/home/feasel/.copilot/skills/raspi-discovery-ssh/scripts/raspi_access.py'
DUT = 'raspberrypi-2.local'
CONTROLLER = '192.168.1.221'
BUILD = '/home/feasel/matter-ecred-integration-20261020/linked-01'
FIXTURE = '/home/feasel/matter-pr539-ble-readiness-fix-20261011'
APP = '/home/feasel/matter-pr539-ble-wifi-20261011'
PYTHON = '/home/feasel/matter-pr527-fixed-native-20261009/controller-env/bin/python'
SDK = '/home/feasel/matter-hardware-539-20261007/sdk'
PACKAGED_SRCVERSION = '44E430CCAFA3D32BFBC5C69'
MODULES = [('net/bluetooth/bluetooth.ko', 'bluetooth'), ('drivers/bluetooth/btbcm.ko', 'btbcm'),
           ('drivers/bluetooth/hci_uart.ko', 'hci_uart'), ('net/bluetooth/rfcomm/rfcomm.ko', 'rfcomm'),
           ('net/bluetooth/bnep/bnep.ko', 'bnep'), ('net/bluetooth/hidp/hidp.ko', 'hidp')]

CHANNEL_SAMPLER = r'''
import json,pathlib,subprocess,time
path=pathlib.Path(__import__('sys').argv[1])
with path.open('x') as output:
    deadline=time.monotonic()+600
    while time.monotonic()<deadline and not path.with_suffix('.stop').exists():
        reply=subprocess.run(['sudo','-n','cat','/sys/kernel/debug/bluetooth/l2cap'],capture_output=True,text=True,timeout=3)
        memory={line.split(':')[0]:int(line.split()[1])*1024 for line in pathlib.Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemAvailable:','SwapFree:'))}
        output.write(json.dumps({'monotonic':time.monotonic(),'epoch':time.time(),'channels':reply.stdout,'memory':memory})+'\n')
        output.flush()
        __import__('threading').Event().wait(0.05)
'''


def remote(host, *command, check=True, timeout=60):
    """Use existing private-pipe credentials and strict host-key verification."""
    result = subprocess.run(['python3', '-B', ACCESS, 'ssh', '--host', host, '--', *command],
        capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'Remote {command[0]} failed on {host}: {result.stderr[-500:]}')
    return result


def python(host, code, **kwargs):
    """Compile remote snippets before dispatch and keep output private by default."""
    compile(code, '<ecred-remote>', 'exec')
    return remote(host, 'python3', '-B', '-c', code, **kwargs)


def switch(variant):
    """Change only the idle DUT's runtime modules, never packaged module files."""
    remote(DUT, 'sudo', '-n', 'systemctl', 'stop', 'bluetooth.service')
    remote(DUT, 'sudo', '-n', 'systemctl', 'stop', 'ecred-bluez.service', check=False)
    current = python(DUT, "from pathlib import Path; path=Path('/sys/module/bluetooth/srcversion'); print(path.read_text().strip() if path.exists() else '')").stdout.strip()
    if variant != 'packaged' or (current and current != PACKAGED_SRCVERSION):
        for name in ('hidp', 'rfcomm', 'bnep', 'hci_uart', 'btbcm', 'bluetooth'):
            remote(DUT, 'sudo', '-n', '/usr/sbin/modprobe', '-r', name)
    if variant == 'packaged':
        for name in ('bluetooth', 'btbcm', 'hci_uart', 'rfcomm', 'bnep'):
            remote(DUT, 'sudo', '-n', '/usr/sbin/modprobe', name)
        remote(DUT, 'sudo', '-n', 'systemctl', 'start', 'bluetooth.service')
    else:
        remote(DUT, 'sudo', '-n', '/usr/sbin/modprobe', 'ecdh_generic')
        for filename, name in MODULES:
            remote(DUT, 'sudo', '-n', '/usr/sbin/insmod', f'{BUILD}/{variant}/{filename}')
        remote(DUT, 'sudo', '-n', 'systemd-run', '--collect', '--unit=ecred-bluez',
            '--property=RuntimeMaxSec=25min', '/usr/libexec/bluetooth/bluetoothd', '-E', '-P', 'battery')
    python(DUT, "import subprocess,time; deadline=time.monotonic()+25\nwhile time.monotonic()<deadline:\n result=subprocess.run(['bluetoothctl','list'],capture_output=True,text=True,timeout=5)\n if '2C:CF:67:EC:14:9F' in result.stdout: break\n __import__('threading').Event().wait(0.2)\nelse: raise TimeoutError('DUT adapter did not return after module switch')\nsubprocess.run(['bluetoothctl','power','on'],check=True,capture_output=True,timeout=10)")
    proof = python(DUT, "import json,pathlib; print(json.dumps({name:(pathlib.Path('/sys/module')/name/'srcversion').read_text().strip() for name in ['bluetooth','btbcm','hci_uart','rfcomm','bnep']}))")
    return json.loads(proof.stdout)


def main():
    """Run one original/proposed attempt and restore baseline even on failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    os.environ['PATH'] = '/home/feasel/.local/libexec/raspi-access/package/usr/bin:' + os.environ['PATH']
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    record = {'started_epoch': time.time(), 'attempts': [], 'restored': False}
    credential = args.output / 'wifi-credentials.private.json'
    controller_root = '/home/feasel/' + args.output.name
    runtime_credential = controller_root + '/wifi-credentials.private.json'
    changed = False
    audio_paused = False
    try:
        for host, identity in ((DUT, 'fa898f2a8e5c487489c516aaa233f86a'),
                       (CONTROLLER, 'ef72df43fba94793ab724dc3013cec17')):
            python(host, f"from pathlib import Path; import shutil; assert Path('/etc/machine-id').read_text().strip()=={identity!r}; assert shutil.disk_usage('/home/feasel').free>=8589934592")
        python(CONTROLLER, f"from pathlib import Path; Path({controller_root!r}).mkdir(mode=0o700)")
        data = python(DUT, "import json,subprocess; base=['sudo','-n','nmcli']; profile=['connection','show','uuid','7eb3a397-5691-4138-9811-c57829da34db']; print(json.dumps({'ssid':subprocess.check_output(base+['-g','802-11-wireless.ssid']+profile,text=True).strip(),'psk':subprocess.check_output(base+['--show-secrets','-g','802-11-wireless-security.psk']+profile,text=True).strip()}))")
        private = json.loads(data.stdout)
        if not private['ssid'] or not private['psk']:
            raise RuntimeError('Existing DUT Wi-Fi profile lacks credentials')
        credential.write_text(json.dumps(private))
        subprocess.run(['python3', '-B', ACCESS, 'push', '--host', CONTROLLER,
            '--local', str(credential), '--remote', runtime_credential], check=True, capture_output=True)
        credential.unlink()
        remote(DUT, 'sudo', '-n', 'loginctl', 'enable-linger', 'feasel')
        remote(DUT, 'sudo', '-n', 'systemd-run', '--on-active=30min', '--unit=ecred-emergency-baseline',
            '/usr/sbin/reboot')
        changed = True
        if remote(DUT, 'systemctl', '--user', 'is-active', 'wireplumber.service', check=False).returncode == 0:
            remote(DUT, 'systemctl', '--user', 'stop', 'wireplumber.service')
            audio_paused = True
        remote(CONTROLLER, 'sudo', '-n', 'systemctl', 'stop', 'bluetooth.service')
        remote(CONTROLLER, 'sudo', '-n', 'systemd-run', '--collect', '--unit=ecred-bluez',
            '--property=RuntimeMaxSec=25min', '/usr/libexec/bluetooth/bluetoothd', '-E', '-P', 'battery')
        for variant in ('original', 'proposed'):
            token = 'ecred-' + variant + '-20261020'
            attempt = {'variant': variant, 'run': token, 'started_epoch': time.time(), 'module_srcversions': switch(variant)}
            record['attempts'].append(attempt)
            capture = remote(CONTROLLER, 'sudo', '-n', '/usr/local/sbin/lab-resource-helper',
                'capture-start', 'controller-hci', token)
            (args.output / (variant + '-capture-start.private.json')).write_text(capture.stdout)
            run_directory = controller_root + '/' + variant
            sampler_path = '/home/feasel/matter-ecred-integration-20261020/' + variant + '-channels.private.jsonl'
            compile(CHANNEL_SAMPLER, '<channel-sampler>', 'exec')
            remote(DUT, 'systemd-run', '--user', '--collect', '--unit=' + token + '-channels',
                '/usr/bin/python3', '-B', '-c', CHANNEL_SAMPLER, sampler_path)
            try:
                remote(DUT, 'systemd-run', '--user', '--collect', '--on-active=3s',
                    '--timer-property=AccuracySec=1s', '--unit=' + token,
                    '/usr/bin/python3', APP + '/offline_wifi_dut.py', '--run', token)
                with (args.output / (variant + '-native.private.log')).open('w') as log:
                    result = subprocess.run(['python3', '-B', ACCESS, 'ssh', '--host', CONTROLLER, '--',
                        'env', 'PYTHONPATH=' + FIXTURE + '/final-source/qa/src', PYTHON, FIXTURE + '/probe_ble_wifi.py',
                        '--sdk-root', SDK, '--run-dir', run_directory, '--credentials', runtime_credential,
                        '--mode', 'primary'], stdout=log, stderr=subprocess.STDOUT, timeout=480)
                attempt['native_exit'] = result.returncode
                summary = python(CONTROLLER, f"from pathlib import Path; print(Path({run_directory + '/summary.json'!r}).read_text())")
                attempt['native_summary'] = json.loads(summary.stdout)
            finally:
                closure = remote(CONTROLLER, 'sudo', '-n', '/usr/local/sbin/lab-resource-helper',
                    'capture-stop', 'controller-hci', token)
                (args.output / (variant + '-capture-stop.private.json')).write_text(closure.stdout)
                deadline = time.monotonic() + 660
                while time.monotonic() < deadline:
                    try:
                        recovery = python(DUT, f"from pathlib import Path; root=Path({APP + '/runs/' + token!r}); (root/'controller-finished').touch(); path=root/'offline-summary.json'; print(path.read_text() if path.exists() else '{{}}')", check=False, timeout=25)
                        summary = json.loads(recovery.stdout) if recovery.returncode == 0 else {}
                        if summary.get('recovery_passed'):
                            attempt['recovery_summary'] = summary
                            break
                    except (subprocess.TimeoutExpired, ValueError):
                        pass
                    __import__('threading').Event().wait(2)
                else:
                    raise TimeoutError('Existing DUT recovery watchdog did not restore the network')
                python(DUT, f"from pathlib import Path; Path({sampler_path!r}).with_suffix('.stop').touch()")
                subprocess.run(['python3', '-B', ACCESS, 'pull', '--host', DUT, '--remote', sampler_path,
                    '--local', str(args.output / (variant + '-channels.private.jsonl'))], check=True, capture_output=True)
            attempt['ended_epoch'] = time.time()
            print(json.dumps({'variant': variant, 'native_exit': attempt.get('native_exit'),
                'native_passed': attempt.get('native_summary', {}).get('passed')}, sort_keys=True), flush=True)
        record['restored_module_srcversions'] = switch('packaged')
        record['restored'] = record['restored_module_srcversions']['bluetooth'] == PACKAGED_SRCVERSION
    except Exception as error:
        record['setup_or_runtime_error'] = {'type': type(error).__name__, 'detail': str(error)}
        raise
    finally:
        if changed and not record['restored']:
            try:
                record['restored_module_srcversions'] = switch('packaged')
                record['restored'] = record['restored_module_srcversions']['bluetooth'] == PACKAGED_SRCVERSION
            except Exception as error:
                record['rollback_error'] = type(error).__name__
        if changed:
            remote(CONTROLLER, 'sudo', '-n', 'systemctl', 'stop', 'ecred-bluez.service', check=False)
            remote(CONTROLLER, 'sudo', '-n', 'systemctl', 'start', 'bluetooth.service', check=False)
        if audio_paused:
            remote(DUT, 'systemctl', '--user', 'start', 'wireplumber.service', check=False)
        python(CONTROLLER, f"from pathlib import Path; Path({runtime_credential!r}).unlink(missing_ok=True)", check=False)
        credential.unlink(missing_ok=True)
        if record['restored']:
            remote(DUT, 'sudo', '-n', 'systemctl', 'stop', 'ecred-emergency-baseline.timer', check=False)
            remote(DUT, 'sudo', '-n', 'loginctl', 'disable-linger', 'feasel', check=False)
        record['ended_epoch'] = time.time()
        (args.output / 'comparison.private.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return 0 if record['restored'] and len(record['attempts']) == 2 else 1


if __name__ == '__main__':
    raise SystemExit(main())
