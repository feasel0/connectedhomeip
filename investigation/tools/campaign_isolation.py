import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import select
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import uuid

from campaign_state import atomic, digest


def isolated_command(root, mappings, arguments, map_root=False, namespace_reset=False):
    root = root.resolve()
    if not root.is_dir() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise ValueError('Native writable root must already be private and owned')
    executable = shutil.which('bwrap')
    if executable is None:
        raise ValueError('Rootless namespace tool unavailable')
    scratch = root / 'tmp'
    home = root / 'home'
    if scratch.is_symlink() or home.is_symlink():
        raise ValueError('Private native temporary storage and HOME must not be symlinks')
    scratch.mkdir(mode=0o700, exist_ok=True)
    home.mkdir(mode=0o700, exist_ok=True)
    command = [executable, '--unshare-user', '--unshare-pid', '--die-with-parent', '--new-session',
               '--ro-bind', '/', '/', '--dev', '/dev', '--proc', '/proc',
               '--bind', str(scratch), '/tmp', '--bind', str(root), str(root),
               '--setenv', 'HOME', str(home), '--setenv', 'TMPDIR', '/tmp', '--chdir', str(root)]
    if map_root:
        command[2:2] = ['--uid', '0', '--gid', '0']
    if map_root or namespace_reset:
        shim = root / 'namespace-sudo'
        atomic(shim, '#!' + sys.executable + '\nimport os,sys\nos.execv(' + repr(sys.executable) +
               ',[' + repr(sys.executable) + ',' + repr(str(Path(__file__).resolve())) +
             ',"namespace-sudo","--root",' + repr(str(root)) + ',"--",*sys.argv[1:]])\n')
        shim.chmod(0o700)
        command.extend(['--ro-bind', str(shim), '/usr/bin/sudo'])
    seen = set()
    for mapping in mappings:
        original = Path(mapping['original'])
        private = Path(mapping['private'])
        if not original.is_absolute() or original.is_symlink() or not original.is_file():
            raise ValueError('Every native compiled path must resolve to an existing, non-symlink sealed file')
        if digest(original) != mapping['original_sha256']:
            raise ValueError('Original sealed native state changed before namespace creation')
        if not private.is_file() or private.is_symlink() or not private.resolve().is_relative_to(root):
            raise ValueError('Native state replacement must be an attempt-private regular file')
        if str(original.resolve()) in seen:
            raise ValueError('Duplicate native path mapping')
        seen.add(str(original.resolve()))
        command.extend(['--bind', str(private.resolve()), str(original.resolve())])
    return command + ['--', *arguments]


def namespace_sudo(arguments, root=None):
    mapping = Path('/proc/self/uid_map').read_text().split()
    if (root is None or (root / 'tmp').is_symlink() or not os.path.samefile('/tmp', root / 'tmp')
            or len(mapping) != 3 or mapping[0] != str(os.geteuid()) or mapping[2] != '1'):
        raise ValueError('DUT storage command requires exact private tmp and single-user mapped namespace')
    arguments = list(arguments)
    while arguments:
        option = arguments[0]
        if option in {'-S', '-n', '--'}:
            arguments.pop(0)
            if option == '--':
                break
        elif option == '-p' and len(arguments) > 1:
            arguments = arguments[2:]
        else:
            break
    if len(arguments) < 3 or arguments[:2] != ['rm', '-rf']:
        raise ValueError('Only upstream DUT temporary-storage deletion is permitted')
    paths = arguments[2:]
    if not all(Path(path).parent == Path('/tmp') and Path(path).name.startswith('chip_') for path in paths):
        raise ValueError('DUT deletion path is outside private temporary storage')
    os.execv('/bin/rm', ['/bin/rm', '-rf', '--', *paths])


def fixture_prepare(root, address, seconds, capture_ids=()):
    if not 10 <= seconds <= 172800 or not Path('/usr/sbin/sshd').is_file():
        raise ValueError('Bounded lifetime and installed OpenSSH server required')
    if len(capture_ids) > 4 or any(not re.fullmatch('[a-z0-9_-]{1,64}', run_id) for run_id in capture_ids):
        raise ValueError('Capture reservations must be explicit bounded broker run identities')
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    (root / 'context').mkdir(mode=0o700)
    with socket.socket() as listener:
        listener.bind((address, 0))
        port = listener.getsockname()[1]
    for name in ['host-key', 'client-key']:
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(root / name)],
                       check=True, stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
    user = pwd.getpwuid(os.getuid()).pw_name
    forced = shlex.join([sys.executable, '-B', str(Path(__file__).resolve()), 'fixture-shell', '--root', str(root)])
    configuration = ('Port ' + str(port) + '\nListenAddress ' + address + '\nHostKey ' + str(root / 'host-key') +
                     '\nPidFile ' + str(root / 'sshd.pid') + '\nAuthorizedKeysFile ' + str(root / 'client-key.pub') +
                     '\nAllowUsers ' + user + '\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n'
                     'PubkeyAuthentication yes\nUsePAM no\nStrictModes yes\nPermitRootLogin no\n'
                     'X11Forwarding no\nAllowTcpForwarding no\nPermitTunnel no\nLogLevel VERBOSE\nForceCommand ' + forced + '\n')
    atomic(root / 'sshd_config', configuration)
    subprocess.run(['/usr/sbin/sshd', '-t', '-f', str(root / 'sshd_config')], check=True,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
    result = {'root': str(root), 'address': address, 'port': port, 'user': user, 'seconds': seconds,
              'program_sha256': digest(Path(__file__).resolve()), 'config_sha256': digest(root / 'sshd_config'),
              'host_public_key': (root / 'host-key.pub').read_text().split()[:2], 'capture_ids': list(capture_ids)}
    atomic(root / 'fixture.json', result)
    return result


def fixture_capture_command(profile, command):
    arguments = shlex.split(command)
    if arguments[:3] != ['sudo', '-n', '/usr/local/sbin/lab-resource-helper']:
        return None
    if (len(arguments) != 6 or arguments[3] not in {'capture-start', 'capture-status', 'capture-stop'}
            or arguments[4] != 'dut-mdns' or arguments[5] not in profile.get('capture_ids', [])):
        raise ValueError('Unreserved fixture capture broker command')
    return arguments


def namespace_exec(identity, arguments, environment):
    from campaign_remote_worker import live

    if not live(identity):
        raise ValueError('Reserved namespace owner is no longer live')
    descriptors = []
    try:
        target = os.open('/proc/' + str(identity['pid']) + '/ns/user', os.O_RDONLY)
        descriptors.append(target)
        pid_namespace = os.open('/proc/' + str(identity['pid']) + '/ns/pid', os.O_RDONLY)
        descriptors.append(pid_namespace)
        owner = fcntl.ioctl(pid_namespace, 0xb701)
        descriptors.append(owner)
        for descriptor in descriptors:
            os.set_inheritable(descriptor, True)
        command = ['/usr/bin/nsenter', '--target', str(identity['pid']), '--user=/proc/self/fd/' + str(owner),
                   '--preserve-credentials', '--mount', '--pid', '--']
        if os.fstat(owner).st_ino != os.fstat(target).st_ino:
            command += ['/usr/bin/nsenter', '--user=/proc/self/fd/' + str(target), '--preserve-credentials', '--']
        command += arguments
        os.execve(command[0], command, environment)
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def fixture_shell(root):
    from campaign_remote_worker import live

    profile = json.loads((root / 'fixture.json').read_text())
    identity = json.loads((root / 'namespace.json').read_text())
    if profile['program_sha256'] != digest(Path(__file__).resolve()) or not live(identity):
        raise ValueError('Fixture namespace is not the reserved live owner')
    command = os.environ.get('SSH_ORIGINAL_COMMAND')
    if not command:
        raise ValueError('Only explicit upstream fixture commands are accepted')
    capture = fixture_capture_command(profile, command)
    if capture is not None:
        os.execv('/usr/bin/sudo', capture)
    context = root / 'context'
    env = dict(os.environ, HOME=str(context / 'home'), TMPDIR='/tmp')
    namespace_exec(identity, ['/bin/sh', '-c', 'cd ' + shlex.quote(str(context)) + ' && ' + command], env)


def fixture_serve(root):
    from campaign_remote_worker import live

    profile = json.loads((root / 'fixture.json').read_text())
    if profile['program_sha256'] != digest(Path(__file__).resolve()) or profile['config_sha256'] != digest(root / 'sshd_config'):
        raise ValueError('Fixture program or SSH configuration changed')
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    read_descriptor, write_descriptor = os.pipe()
    anchor = [sys.executable, '-B', '-c', 'import threading; threading.Event().wait(' + str(profile['seconds']) + ')']
    arguments = isolated_command(root / 'context', [], anchor, namespace_reset=True)
    arguments[1:1] = ['--info-fd', str(write_descriptor)]
    namespace = None
    server = None
    child = None
    identity = None
    with (root / 'transport.private.log').open('xb') as log:
        try:
            namespace = subprocess.Popen(arguments, pass_fds=[write_descriptor], stdout=log, stderr=log)
            os.close(write_descriptor)
            if not select.select([read_descriptor], [], [], 10)[0]:
                raise ValueError('Fixture namespace did not publish identity')
            with os.fdopen(read_descriptor) as stream:
                child = json.load(stream)['child-pid']
            identity = {'pid': child, 'start_ticks': Path('/proc/' + str(child) + '/stat').read_text().rsplit(')', 1)[1].split()[19],
                        'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                        'uid': os.getuid(), 'program_sha256': profile['program_sha256']}
            atomic(root / 'namespace.json', identity)
            server = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', str(root / 'sshd_config')],
                                      stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
            deadline = time.monotonic() + profile['seconds']
            while time.monotonic() < deadline and not (root / 'stop.json').exists() and not stop.is_set():
                if namespace.poll() is not None or server.poll() is not None:
                    raise ValueError('Fixture namespace or SSH endpoint exited early')
                stop.wait(1)
        finally:
            if identity is not None and live(identity):
                os.kill(child, signal.SIGKILL)
            if namespace is not None:
                namespace.wait(timeout=10)
            if server is not None:
                if server.poll() is None:
                    os.killpg(server.pid, signal.SIGTERM)
                server.wait(timeout=10)
            atomic(root / 'closed.json', {'wall': time.time(), 'namespace_live': identity is not None and live(identity),
                                         'server_exit': server.returncode if server else None})
    return 0


def execute(profile, arguments):
    root = Path(profile['writable_root'])
    mappings = profile['sealed_paths']
    if not mappings:
        paths = profile.get('compiled_tmp_paths', [])
        if not paths or any(not Path(path).is_absolute() or Path(path).parent != Path('/tmp') for path in paths):
            raise ValueError('Exact compiled native mutable path inventory is required before import')
    command = isolated_command(root, mappings, arguments)
    result = subprocess.run(command, stdin=subprocess.DEVNULL)
    if any(digest(Path(mapping['original'])) != mapping['original_sha256'] for mapping in mappings):
        raise ValueError('Original native state changed despite namespace boundary')
    return result.returncode


def runtime_proof(base, python, event_library, build_directory=None, qa_archive=None):
    root = base / ('runtime-proof-' + uuid.uuid4().hex[:12])
    root.mkdir(mode=0o700)
    result = {'scope': 'Import/loader qualification only; no native stack, radio, protocol or fixture initialization',
              'started': time.time(), 'result': 'INCOMPLETE', 'root': str(root)}
    freeze = json.loads((base / 'source-freeze.private.json').read_text())
    archive_source = root / 'qa-package-source'
    archive_source.mkdir()
    if qa_archive is not None:
        receipt = json.loads((base / 'qa-export.private.json').read_text())
        if receipt['sha'] != freeze['sources']['qa']['sha'] or receipt['archive_sha256'] != digest(qa_archive):
            raise ValueError('Transferred QA archive does not match frozen revision/export')
        with tarfile.open(qa_archive) as archive:
            archive.extractall(archive_source, filter='data')
    else:
        process = subprocess.Popen(['git', '-C', str(base / 'qa-baseline'), 'archive', freeze['sources']['qa']['sha']],
                                   stdout=subprocess.PIPE)
        with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
            archive.extractall(archive_source, filter='data')
        process.stdout.close()
        if process.wait(timeout=30):
            raise ValueError('Exact frozen QA packaging export failed')
    build = (build_directory or base / 'controller-build') / 'obj'
    wheels = list((build / 'src/controller/python/matter-controller-wheels').glob('*.whl'))
    wheels += list((build / 'src/python_testing/matter_testing_infrastructure/matter-testing._build_wheel').glob('*.whl'))
    if len(wheels) != 4:
        raise ValueError('Expected exact fresh controller and testing wheels')
    result['wheel_hashes'] = {str(path): digest(path) for path in wheels}
    executable = root / 'venv/bin/python'
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONPATH='', LD_PRELOAD='',
                       LD_LIBRARY_PATH=str(event_library))
    seals = {str(path): digest(path) for path in map(Path, ['/tmp/chip_counters.ini', '/tmp/chip_config.ini',
                                                         '/tmp/chip_factory.ini', '/tmp/chip_kvs'])
             if path.is_file() and not path.is_symlink()}
    result['original_seals'] = seals
    try:
        with (root / 'installation.private.log').open('xb') as output:
            subprocess.run([str(python), '-m', 'venv', str(root / 'venv')], check=True, stdout=output,
                           stderr=subprocess.STDOUT, timeout=120)
            subprocess.run([str(executable), '-m', 'pip', 'install', *map(str, wheels), str(archive_source)],
                           env=environment, check=True, stdout=output, stderr=subprocess.STDOUT,
                           timeout=900, stdin=subprocess.DEVNULL)
            subprocess.run([str(executable), '-m', 'pip', 'check'], env=environment, check=True, stdout=output,
                           stderr=subprocess.STDOUT, timeout=30)
        code = ('import ctypes,hashlib,json,sys; from pathlib import Path; '
                'import matter.native,matter.ChipDeviceCtrl,matter_qa; '
                'from matter_qa.library.base_test_classes.matter_qa_base_test_class import MatterQABaseTestCaseClass; '
                'native=Path(matter.native.__file__).parent.parent/"_ChipDeviceCtrl.so"; '
                'loaded=ctypes.CDLL(str(native)); '
                'modules={name:module.__file__ for name,module in sys.modules.items() '
                'if name.startswith(("matter.","matter_qa")) and getattr(module,"__file__",None)}; '
                'print("CAMPAIGN_IMPORT_JSON="+json.dumps({"python":sys.version,"native":str(native),'
                '"native_sha256":hashlib.file_digest(native.open("rb"),"sha256").hexdigest(),'
                '"module_hashes":{name:{"path":path,"sha256":hashlib.file_digest(open(path,"rb"),"sha256").hexdigest()} '
                'for name,path in modules.items()}},sort_keys=True))')
        arguments = isolated_command(root, [], [str(executable), '-B', '-c', code])
        arguments[1:1] = ['--unshare-net', '--tmpfs', '/run']
        process = subprocess.run(arguments, env=environment, capture_output=True, text=True,
                                 timeout=90, stdin=subprocess.DEVNULL)
        atomic(root / 'imports.private.stdout', process.stdout)
        atomic(root / 'imports.private.stderr', process.stderr)
        process.check_returncode()
        records = [line.removeprefix('CAMPAIGN_IMPORT_JSON=') for line in process.stdout.splitlines()
                   if line.startswith('CAMPAIGN_IMPORT_JSON=')]
        if len(records) != 1:
            raise ValueError('Missing or duplicate import proof record')
        result['imports'] = json.loads(records[0])
        expected = build / 'src/controller/python/matter/_ChipDeviceCtrl.so'
        if result['imports']['native_sha256'] != digest(expected):
            raise ValueError('Installed native library differs from freshly compiled artifact')
        if any(digest(Path(path)) != expected for path, expected in seals.items()):
            raise ValueError('Original native state seal changed')
        result['result'] = 'PASS'
    except Exception as error:
        result.update(result='BLOCKED', error_kind=type(error).__name__)
    finally:
        result['ended'] = time.time()
        atomic(root / 'runtime-result.private.json', result)
    print(json.dumps({'root': str(root), 'result': result['result'], 'error_kind': result.get('error_kind')}), flush=True)
    return 0 if result['result'] == 'PASS' else 1


class IsolationTests(unittest.TestCase):
    def test_normal_uid_namespace_preserves_identity_and_scopes_upstream_reset(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            root = Path(directory)
            code = ('import os,subprocess;from pathlib import Path;assert os.geteuid()==' + str(os.getuid()) + ';'
                    'Path("/tmp/chip_normal_uid_probe").write_text("private");'
                    'subprocess.run(["/bin/sh","-c","sudo -n rm -rf /tmp/chip_*"],check=True);'
                    'assert not Path("/tmp/chip_normal_uid_probe").exists()')
            process = subprocess.run(isolated_command(root, [], [sys.executable, '-B', '-c', code], namespace_reset=True),
                                     capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
            self.assertEqual(process.returncode, 0, process.stderr.decode())

    def test_independent_entry_preserves_normal_uid_and_scoped_reset(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            root = Path(directory)
            read_descriptor, write_descriptor = os.pipe()
            command = isolated_command(root, [], [sys.executable, '-B', '-c',
                'import threading;threading.Event().wait(20)'], namespace_reset=True)
            command[1:1] = ['--info-fd', str(write_descriptor)]
            process = subprocess.Popen(command, pass_fds=[write_descriptor], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            os.close(write_descriptor)
            identity = None
            try:
                self.assertTrue(select.select([read_descriptor], [], [], 5)[0])
                with os.fdopen(read_descriptor) as stream:
                    child = json.load(stream)['child-pid']
                identity = {'pid': child, 'start_ticks': Path('/proc/' + str(child) + '/stat').read_text().rsplit(')', 1)[1].split()[19],
                            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
                inner = ('import os,subprocess;from pathlib import Path;assert os.geteuid()==' + str(os.getuid()) + ';'
                         'Path("/tmp/chip_entry_probe").write_text("private");'
                         'subprocess.run(["/bin/sh","-c","sudo -n rm -rf /tmp/chip_*"],check=True);'
                         'assert not Path("/tmp/chip_entry_probe").exists()')
                code = ('import os,sys;sys.path.insert(0,' + repr(str(Path(__file__).resolve().parent)) + ');'
                        'from campaign_isolation import namespace_exec;namespace_exec(' + repr(identity) + ',' +
                        repr([sys.executable, '-B', '-c', inner]) + ',dict(os.environ))')
                entered = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, timeout=10)
                self.assertEqual(entered.returncode, 0, entered.stderr.decode())
            finally:
                if identity is not None:
                    try:
                        os.kill(identity['pid'], signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.communicate(timeout=5)

    def test_fixture_capture_control_accepts_only_reserved_installed_broker_actions(self):
        profile = {'capture_ids': ['owned-w2']}
        prefix = 'sudo -n /usr/local/sbin/lab-resource-helper '
        self.assertEqual(fixture_capture_command(profile, prefix + 'capture-stop dut-mdns owned-w2')[-1], 'owned-w2')
        for command in ['capture-stop dut-mdns foreign', 'capture-stop thread-lab owned-w2',
                        'recover dut-mdns owned-w2', 'capture-stop dut-mdns owned-w2 extra']:
            with self.assertRaises(ValueError):
                fixture_capture_command(profile, prefix + command)
        self.assertIsNone(fixture_capture_command(profile, 'sudo -n rm -rf /tmp/chip_*'))

    def test_explicit_tmp_inventory_uses_directory_boundary_without_file_mounts(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            root = Path(directory)
            profile = {'writable_root': str(root), 'sealed_paths': [], 'compiled_tmp_paths': ['/tmp/chip_config.ini']}
            code = ('from pathlib import Path; original=Path("/tmp/chip_config.ini"); '
                    'replacement=Path("/tmp/chip_config.new"); replacement.write_text("private"); '
                    'replacement.replace(original)')
            original = Path('/tmp/chip_config.ini')
            before = digest(original) if original.exists() else None
            self.assertEqual(execute(profile, [sys.executable, '-B', '-c', code]), 0)
            self.assertEqual((root / 'tmp/chip_config.ini').read_text(), 'private')
            self.assertEqual(digest(original) if original.exists() else None, before)
            profile['compiled_tmp_paths'] = ['/var/tmp/chip_config.ini']
            with self.assertRaises(ValueError):
                execute(profile, ['/usr/bin/true'])

    def test_private_directory_symlink_is_refused_before_execution(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            root = Path(directory)
            (root / 'tmp').symlink_to('/tmp', target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'must not be symlinks'):
                isolated_command(root, [], ['/usr/bin/true'])

    @unittest.skipUnless(Path('/usr/sbin/sshd').is_file(), 'OpenSSH server unavailable on this host')
    def test_private_fixture_ssh_configuration(self):
        with tempfile.TemporaryDirectory(prefix='matter-ssh-config-', dir=Path.home()) as directory:
            root = Path(directory) / 'fixture'
            profile = fixture_prepare(root, '127.0.0.1', 10)
            self.assertNotEqual(profile['port'], 22)
            self.assertEqual((root / 'client-key').stat().st_mode & 0o777, 0o600)
            self.assertIn('PasswordAuthentication no', (root / 'sshd_config').read_text())

    def test_independent_commands_share_private_process_and_storage_namespace(self):
        with tempfile.TemporaryDirectory(prefix='matter-shared-namespace-', dir=Path.home()) as directory:
            root = Path(directory)
            code = 'import threading; from pathlib import Path; Path("/tmp/chip_anchor").write_text("owned"); threading.Event().wait(15)'
            command = isolated_command(root, [], [sys.executable, '-B', '-c', code], map_root=True)
            read_descriptor, write_descriptor = os.pipe()
            command[1:1] = ['--info-fd', str(write_descriptor)]
            process = subprocess.Popen(command, pass_fds=[write_descriptor], stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE, start_new_session=True)
            os.close(write_descriptor)
            identity = None
            try:
                self.assertTrue(select.select([read_descriptor], [], [], 5)[0])
                with os.fdopen(read_descriptor) as stream:
                    identity = json.load(stream)
                deadline = time.monotonic() + 3
                while not (root / 'tmp/chip_anchor').exists() and time.monotonic() < deadline:
                    select.select([], [], [], 0.01)
                self.assertTrue((root / 'tmp/chip_anchor').exists())
                nested = ['nsenter', '--target', str(identity['child-pid']), '--user', '--preserve-credentials',
                          '--mount', '--pid', '--']
                query = 'from pathlib import Path; assert Path("/tmp/chip_anchor").read_text()=="owned"; Path("/tmp/chip_other").write_text("shared")'
                entered = subprocess.run([*nested, sys.executable, '-B', '-c', query], capture_output=True, timeout=5)
                self.assertEqual(entered.returncode, 0, entered.stderr.decode())
                subprocess.run([*nested, '/bin/sh', '-c', 'sudo -n rm -rf /tmp/chip_*'],
                               check=True, capture_output=True, timeout=5)
                self.assertFalse((root / 'tmp/chip_anchor').exists())
                self.assertFalse((root / 'tmp/chip_other').exists())
            finally:
                if identity is not None:
                    try:
                        os.kill(identity['child-pid'], signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.communicate(timeout=5)

    def test_mapped_root_scopes_upstream_delete_and_process_lookup(self):
        with tempfile.TemporaryDirectory(prefix='matter-fixture-proof-', dir=Path.home()) as directory:
            base = Path(directory)
            seal = base / 'host-seal'
            seal.write_text('outside namespace writable root\n')
            root = base / 'private'
            root.mkdir(mode=0o700)
            code = ('import os,subprocess; from pathlib import Path; assert os.geteuid()==0; '
                    'assert not Path("/proc/' + str(os.getpid()) + '").exists(); '
                    'Path("/tmp/chip_campaign_probe").write_text("private DUT state"); '
                    'subprocess.run(["/bin/sh","-c","sudo -n rm -rf /tmp/chip_*"],check=True); '
                    'assert subprocess.run(["sudo","-n","/bin/true"],capture_output=True).returncode!=0; '
                    'assert not Path("/tmp/chip_campaign_probe").exists(); blocked=False\n'
                    'try: Path(' + repr(str(seal)) + ').write_text("must not write host")\n'
                    'except OSError: blocked=True\nassert blocked')
            subprocess.run(isolated_command(root, [], [sys.executable, '-B', '-c', code], map_root=True),
                           check=True, capture_output=True, timeout=15)
            self.assertEqual(seal.read_text(), 'outside namespace writable root\n')

    def test_namespace_storage_command_refuses_host_execution(self):
        with self.assertRaises(ValueError):
            namespace_sudo(['rm', '-rf', '/tmp/chip_campaign_probe'])

    def test_real_namespace_redirects_writes_and_protects_seal(self):
        with tempfile.TemporaryDirectory(prefix='matter-isolation-proof-', dir=Path.home()) as directory:
            base = Path(directory)
            original = base / 'sealed-counter.ini'
            original.write_text('original sealed bytes\n')
            untouched = base / 'unmapped-seal.ini'
            untouched.write_text('must remain read-only\n')
            root = base / 'private'
            root.mkdir(mode=0o700)
            replacement = root / 'counter.ini'
            replacement.write_text('new private counters\n')
            mapping = {'original': str(original), 'private': str(replacement), 'original_sha256': digest(original)}
            code = ('from pathlib import Path; Path(' + repr(str(original)) + ').write_text("private write"); '
                    'Path("/tmp/private-only").write_text("isolated"); '
                    'blocked=False\ntry: Path(' + repr(str(untouched)) + ').write_text("bad")\n'
                    'except OSError: blocked=True\nassert blocked')
            subprocess.run(isolated_command(root, [mapping], [sys.executable, '-B', '-c', code]),
                           check=True, capture_output=True, timeout=10)
            self.assertEqual(original.read_text(), 'original sealed bytes\n')
            self.assertEqual(replacement.read_text(), 'private write')
            self.assertEqual(untouched.read_text(), 'must remain read-only\n')
            self.assertTrue((root / 'tmp/private-only').exists())

    def test_changed_original_is_refused_before_child_starts(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            root = Path(directory)
            original = root / 'seal'
            original.write_text('old')
            replacement = root / 'replacement'
            replacement.write_text('private')
            mapping = {'original': str(original), 'private': str(replacement), 'original_sha256': '0' * 64}
            with self.assertRaises(ValueError):
                isolated_command(root, [mapping], ['/usr/bin/true'])


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    actions = parser.add_subparsers(dest='action', required=True)
    actions.add_parser('self-test')
    fixture = actions.add_parser('fixture-prepare')
    fixture.add_argument('--root', type=Path, required=True)
    fixture.add_argument('--address', required=True)
    fixture.add_argument('--seconds', type=int, required=True)
    fixture.add_argument('--capture-id', action='append', default=[])
    for name in ['fixture-serve', 'fixture-shell']:
        action = actions.add_parser(name)
        action.add_argument('--root', type=Path, required=True)
    scoped = actions.add_parser('namespace-sudo')
    scoped.add_argument('--root', type=Path, required=True)
    scoped.add_argument('command', nargs=argparse.REMAINDER)
    run = actions.add_parser('run')
    run.add_argument('--profile', type=Path, required=True)
    run.add_argument('command', nargs=argparse.REMAINDER)
    runtime = actions.add_parser('runtime')
    runtime.add_argument('--root', type=Path, required=True)
    runtime.add_argument('--python', type=Path, required=True)
    runtime.add_argument('--event-library', type=Path, required=True)
    runtime.add_argument('--build-directory', type=Path)
    runtime.add_argument('--qa-archive', type=Path)
    options = parser.parse_args()
    if options.action == 'self-test':
        unittest.main(argv=[__file__])
    elif options.action == 'namespace-sudo':
        arguments = options.command[1:] if options.command[:1] == ['--'] else options.command
        namespace_sudo(arguments, options.root)
    elif options.action == 'fixture-prepare':
        print(json.dumps(fixture_prepare(options.root, options.address, options.seconds, options.capture_id)))
    elif options.action == 'fixture-serve':
        raise SystemExit(fixture_serve(options.root))
    elif options.action == 'fixture-shell':
        fixture_shell(options.root)
    elif options.action == 'runtime':
        raise SystemExit(runtime_proof(options.root, options.python, options.event_library,
                                     options.build_directory, options.qa_archive))
    else:
        arguments = options.command[1:] if options.command[:1] == ['--'] else options.command
        raise SystemExit(execute(json.loads(options.profile.read_text()), arguments))
