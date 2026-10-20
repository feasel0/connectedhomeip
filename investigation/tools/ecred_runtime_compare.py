"""One reversible native Pi BLE/Wi-Fi comparison using retained fixture code."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import signal


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
BOOT_ROOT = '/opt/ecred-validation-20261020'
BOOT_SELECTOR = '''#!/bin/sh
set -eu
root=/opt/ecred-validation-20261020
variant=$(cat "$root/armed")
case "$variant" in original|proposed) ;; *) exit 1;; esac
mv "$root/armed" "$root/consumed"
mkdir -p /run/modprobe.d
cp "$root/$variant/modprobe.conf" /run/modprobe.d/ecred-validation.conf
touch /run/ecred-validation-active
modprobe ecdh_generic
modprobe rfkill
modprobe libaes
for module in bluetooth btbcm hci_uart rfcomm bnep hidp; do
    modprobe "$module"
done
'''
BOOT_UNIT = '''[Unit]
Description=One-shot EATT validation module selection
DefaultDependencies=no
After=systemd-remount-fs.service
Before=systemd-udev-trigger.service systemd-modules-load.service bluetooth.service
ConditionPathExists=/opt/ecred-validation-20261020/armed
[Service]
Type=oneshot
ExecStart=/opt/ecred-validation-20261020/select
RemainAfterExit=yes
[Install]
WantedBy=sysinit.target
'''


def prepare_boot():
    """Install only a root-owned one-shot selector; preserve packaged boot files."""
    code = f'''import hashlib,json,pathlib,subprocess
root=pathlib.Path({BOOT_ROOT!r}); staging=pathlib.Path('/home/feasel/matter-ecred-integration-20261020/boot-files')
staging.mkdir(mode=0o700,exist_ok=False)
manifest=json.loads(pathlib.Path({BUILD + '/linked-result.json'!r}).read_text())
assert len(manifest['records'])==2
def install(source,destination,mode='0644'):
    subprocess.run(['sudo','-n','install','-D','-o','root','-g','root','-m',mode,str(source),str(destination)],check=True)
for entry in manifest['records']:
    variant=entry['variant']; directives=[]
    for relative,metadata in entry['modules'].items():
        source=pathlib.Path({BUILD!r})/variant/relative
        assert hashlib.sha256(source.read_bytes()).hexdigest()==metadata['sha256']
        destination=root/variant/source.name
        install(source,destination)
        name=subprocess.check_output(['/usr/sbin/modinfo','-F','name',str(source)],text=True).strip()
        directives.append('install '+name+' /usr/sbin/insmod '+str(destination))
    path=staging/(variant+'.conf'); path.write_text('\\n'.join(directives)+'\\n'); install(path,root/variant/'modprobe.conf')
files={{'select':{BOOT_SELECTOR!r},'ecred-validation.service':{BOOT_UNIT!r},'watchdog.conf':'[Manager]\\nRuntimeWatchdogSec=10s\\nRebootWatchdogSec=2min\\n','rollback.service':'[Unit]\\nConditionPathExists=/run/ecred-validation-active\\n[Service]\\nType=oneshot\\nExecStart=/usr/sbin/reboot\\n','rollback.timer':'[Unit]\\nConditionPathExists=/run/ecred-validation-active\\n[Timer]\\nOnBootSec=18min\\nUnit=ecred-validation-rollback.service\\n[Install]\\nWantedBy=timers.target\\n'}}
for name,content in files.items():
    path=staging/name; path.write_text(content)
    target=root/'select' if name=='select' else pathlib.Path('/etc/systemd/system.conf.d/90-ecred-validation.conf') if name=='watchdog.conf' else pathlib.Path('/etc/systemd/system')/('ecred-validation-'+name if name.startswith('rollback') else name)
    assert not target.exists(),str(target)
    install(path,target,'0755' if name=='select' else '0644')
subprocess.run(['sudo','-n','systemctl','daemon-reload'],check=True)
subprocess.run(['sudo','-n','systemd-analyze','verify','/etc/systemd/system/ecred-validation.service','/etc/systemd/system/ecred-validation-rollback.timer'],check=True,capture_output=True)
subprocess.run(['sudo','-n','systemctl','enable','ecred-validation.service','ecred-validation-rollback.timer'],check=True,capture_output=True)
print('PREPARED: one-shot selector, matching module files, packaged boot untouched')
'''
    return python(DUT, code, timeout=180)


def reconnect(previous_boot, timeout=360):
    """Wait for an identity-verified new boot, bounded by hardware recovery."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = python(DUT, "from pathlib import Path; assert Path('/etc/machine-id').read_text().strip()=='fa898f2a8e5c487489c516aaa233f86a'; print(Path('/proc/sys/kernel/random/boot_id').read_text().strip())", check=False, timeout=15)
            if result.returncode == 0 and result.stdout.strip() != previous_boot:
                return result.stdout.strip()
        except subprocess.TimeoutExpired:
            pass
        __import__('threading').Event().wait(2)
    raise TimeoutError('DUT did not return on a new verified boot within six minutes')

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


def preflight(host, identity):
    """Require the verified idle fixture before changing its Bluetooth stack."""
    return python(host, f'''import json,os,pathlib,shutil
assert pathlib.Path('/etc/machine-id').read_text().strip()=={identity!r}
assert shutil.disk_usage('/home/feasel').free>=8589934592
busy=[]
for proc in pathlib.Path('/proc').iterdir():
    if not proc.name.isdecimal() or int(proc.name)==os.getpid(): continue
    try:
        name=(proc/'comm').read_text().strip()
        arguments=(proc/'cmdline').read_bytes().decode(errors='replace').split('\\0')
        scripts={{pathlib.Path(argument).name for argument in arguments}}
        if name in ('btmon','dumpcap','chip-pr539-ble') or scripts.intersection({{'probe_ble_wifi.py','offline_wifi_dut.py'}}):
            busy.append({{'pid':int(proc.name),'name':name}})
    except OSError: pass
assert not busy,busy
print(json.dumps({{'identity':{identity!r},'idle':True}}))''')


def channel_trace(start, output=None):
    """Trace ready/delete CID state synchronously, not by assuming polling coverage."""
    if start:
        code = r'''import subprocess,pathlib
base='/sys/kernel/tracing'; instance=base+'/instances/ecred20261020'
subprocess.run(['sudo','-n','mkdir','-p',instance],check=True)
def write(path,value,append=False):
    result=subprocess.run(['sudo','-n','tee']+(['-a'] if append else [])+[path],input=value,text=True,capture_output=True)
    if result.returncode: raise RuntimeError(path+': '+result.stderr)
functions=subprocess.check_output(['sudo','-n','cat',base+'/available_filter_functions'],text=True).splitlines()
existing=subprocess.check_output(['sudo','-n','cat',base+'/kprobe_events'],text=True)
assert not existing.strip() or all('ecred' in line for line in existing.splitlines()),'Unrelated kprobe events exist'
definitions=[]
for event,prefix in [('ready','l2cap_chan_ready'),('delete','l2cap_chan_del')]:
    matches=[line.split()[0] for line in functions if line.split()[0].split('.')[0]==prefix and '[bluetooth]' in line]
    assert len(matches)==1,matches
    function=matches[0]
    definitions.append(f'p:ecred20261020/{event} {function} scid=+38(%x0):u16 dcid=+36(%x0):u16 psm=+32(%x0):u16 state=+16(%x0):u8')
write(base+'/kprobe_events','\n'.join(definitions)+'\n')
write(instance+'/buffer_size_kb','1024\n')
write(instance+'/events/ecred20261020/filter','psm == 39\n')
write(instance+'/events/ecred20261020/enable','1\n')
write(instance+'/tracing_on','1\n')
'''
        return python(DUT, code)
    code = r'''import subprocess,json,pathlib
instance='/sys/kernel/tracing/instances/ecred20261020'
subprocess.run(['sudo','-n','tee',instance+'/tracing_on'],input='0\n',text=True,capture_output=True,check=True)
trace=subprocess.check_output(['sudo','-n','cat',instance+'/trace'],text=True)
paths=subprocess.check_output(['sudo','-n','find',instance+'/per_cpu','-mindepth','2','-maxdepth','2','-name','stats','-type','f'],text=True).splitlines()
assert paths,'No per-CPU trace statistics collected'
stats={pathlib.Path(path).parent.name:subprocess.check_output(['sudo','-n','cat',path],text=True) for path in paths}
print(json.dumps({'trace':trace,'per_cpu_stats':stats}))
'''
    result = python(DUT, code)
    output.write_text(result.stdout)
    return result


def switch(variant):
    """Clear retained old objects by packaged reboot, then require zero core refs."""
    if variant not in ('original', 'proposed', 'packaged'):
        raise ValueError('Unknown module family')
    previous = python(DUT, "from pathlib import Path; print(Path('/proc/sys/kernel/random/boot_id').read_text().strip())").stdout.strip()
    remote(DUT, 'sudo', '-n', 'rm', '-f', BOOT_ROOT + '/armed')
    remote(DUT, 'sudo', '-n', 'systemctl', 'reboot', check=False)
    reconnect(previous)
    if variant != 'packaged':
        remote(DUT, 'systemctl', '--user', 'stop', 'wireplumber.service')
        remote(DUT, 'sudo', '-n', 'systemctl', 'stop', 'bluetooth.service')
        remote(DUT, 'sudo', '-n', 'systemctl', 'mask', '--runtime', 'bluetooth.service')
        remote(DUT, 'sudo', '-n', 'install', '-D', '-m', '0644', BOOT_ROOT + '/' + variant + '/modprobe.conf', '/run/modprobe.d/ecred-validation.conf')
        for name in ('hidp', 'rfcomm', 'bnep', 'hci_uart', 'btbcm'):
            remote(DUT, 'sudo', '-n', '/usr/sbin/modprobe', '-r', name)
        python(DUT, "from pathlib import Path; root=Path('/sys/module/bluetooth'); assert int((root/'refcnt').read_text())==0; assert not list((root/'holders').iterdir())")
        remote(DUT, 'sudo', '-n', '/usr/sbin/modprobe', '-r', 'bluetooth')
        for name in ('ecdh_generic', 'rfkill', 'libaes'):
            remote(DUT, 'sudo', '-n', '/usr/sbin/modprobe', name)
        for filename, name in MODULES:
            remote(DUT, 'sudo', '-n', '/usr/sbin/modprobe', name)
        remote(DUT, 'sudo', '-n', 'touch', '/run/ecred-validation-active')
        remote(DUT, 'sudo', '-n', 'systemctl', 'start', 'ecred-validation-rollback.timer')
        remote(DUT, 'sudo', '-n', 'systemd-run', '--collect', '--unit=ecred-bluez',
            '--property=RuntimeMaxSec=25min', '/usr/libexec/bluetooth/bluetoothd', '-E', '-P', 'battery')
    python(DUT, "import subprocess,time; deadline=time.monotonic()+25\nwhile time.monotonic()<deadline:\n result=subprocess.run(['bluetoothctl','list'],capture_output=True,text=True,timeout=5)\n if '2C:CF:67:EC:14:9F' in result.stdout: break\n __import__('threading').Event().wait(0.2)\nelse: raise TimeoutError('DUT adapter did not return after module switch')\nsubprocess.run(['bluetoothctl','power','on'],check=True,capture_output=True,timeout=10)")
    proof = python(DUT, "import json,pathlib; print(json.dumps({name:(pathlib.Path('/sys/module')/name/'srcversion').read_text().strip() for name in ['bluetooth','btbcm','hci_uart','rfcomm','bnep'] if (pathlib.Path('/sys/module')/name/'srcversion').exists()}))")
    identities = json.loads(proof.stdout)
    if variant == 'packaged':
        assert identities['bluetooth'] == PACKAGED_SRCVERSION
    else:
        for filename, name in MODULES:
            expected = remote(DUT, '/usr/sbin/modinfo', '-F', 'srcversion', BOOT_ROOT + '/' + variant + '/' + Path(filename).name).stdout.strip()
            loaded = python(DUT, f"from pathlib import Path; print(Path('/sys/module/{name}/srcversion').read_text().strip())").stdout.strip()
            if loaded != expected:
                raise RuntimeError('Loaded module identity mismatch: ' + name)
            identities[name] = loaded
        remote(DUT, 'sudo', '-n', 'systemctl', 'is-active', 'ecred-bluez.service')
    return identities


def main():
    """Run one original/proposed attempt and restore baseline even on failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--variant', choices=('both', 'original', 'proposed'), default='both')
    args = parser.parse_args()
    variants = ('original', 'proposed') if args.variant == 'both' else (args.variant,)
    def terminate(signum, frame):
        raise KeyboardInterrupt('Coordinator interrupted by signal ' + str(signum))
    signal.signal(signal.SIGTERM, terminate)
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
            preflight(host, identity)
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
        changed = True
        remote(CONTROLLER, 'sudo', '-n', 'systemctl', 'stop', 'bluetooth.service')
        remote(CONTROLLER, 'sudo', '-n', 'systemctl', 'mask', '--runtime', 'bluetooth.service')
        remote(CONTROLLER, 'sudo', '-n', 'systemd-run', '--collect', '--unit=ecred-bluez',
            '--property=RuntimeMaxSec=25min', '/usr/libexec/bluetooth/bluetoothd', '-E', '-P', 'battery')
        for variant in variants:
            token = 'ecred-' + variant + '-20261020'
            attempt = {'variant': variant, 'run': token, 'started_epoch': time.time()}
            record['attempts'].append(attempt)
            attempt['module_srcversions'] = switch(variant)
            remote(DUT, 'sudo', '-n', 'loginctl', 'enable-linger', 'feasel')
            (args.output / 'comparison.private.json').write_text(json.dumps(record, indent=2) + '\n')
            channel_trace(True)
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
                try:
                    closure = remote(CONTROLLER, 'sudo', '-n', '/usr/local/sbin/lab-resource-helper',
                        'capture-stop', 'controller-hci', token)
                    (args.output / (variant + '-capture-stop.private.json')).write_text(closure.stdout)
                except Exception as error:
                    attempt['capture_cleanup_error'] = str(error)
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
                channel_trace(False, args.output / (variant + '-kernel-trace.private.json'))
                objects = remote(CONTROLLER, 'busctl', '--system', '--json=short', 'call', 'org.bluez', '/',
                    'org.freedesktop.DBus.ObjectManager', 'GetManagedObjects', check=False)
                (args.output / (variant + '-bluez-objects.private.json')).write_text(objects.stdout)
            attempt['ended_epoch'] = time.time()
            print(json.dumps({'variant': variant, 'native_exit': attempt.get('native_exit'),
                'native_passed': attempt.get('native_summary', {}).get('passed')}, sort_keys=True), flush=True)
        record['restored_module_srcversions'] = switch('packaged')
        record['restored'] = record['restored_module_srcversions']['bluetooth'] == PACKAGED_SRCVERSION
    except BaseException as error:
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
            remote(CONTROLLER, 'sudo', '-n', 'systemctl', 'unmask', '--runtime', 'bluetooth.service', check=False)
            remote(CONTROLLER, 'sudo', '-n', 'systemctl', 'start', 'bluetooth.service', check=False)
        if audio_paused:
            remote(DUT, 'systemctl', '--user', 'start', 'wireplumber.service', check=False)
        try:
            python(CONTROLLER, f"from pathlib import Path; Path({runtime_credential!r}).unlink(missing_ok=True)", check=False)
        except Exception as error:
            record['credential_cleanup_error'] = str(error)
        credential.unlink(missing_ok=True)
        if record['restored']:
            remote(DUT, 'sudo', '-n', 'systemctl', 'stop', 'ecred-emergency-baseline.timer', check=False)
            remote(DUT, 'sudo', '-n', 'loginctl', 'disable-linger', 'feasel', check=False)
        record['ended_epoch'] = time.time()
        (args.output / 'comparison.private.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return 0 if record['restored'] and len(record['attempts']) == len(variants) else 1


if __name__ == '__main__':
    raise SystemExit(main())
