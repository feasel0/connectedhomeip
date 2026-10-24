import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import uuid

from campaign_state import atomic, digest


def isolated_command(root, mappings, arguments):
    root = root.resolve()
    if not root.is_dir() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise ValueError('Native writable root must already be private and owned')
    executable = shutil.which('bwrap')
    if executable is None:
        raise ValueError('Rootless namespace tool unavailable')
    scratch = root / 'tmp'
    home = root / 'home'
    scratch.mkdir(mode=0o700, exist_ok=True)
    home.mkdir(mode=0o700, exist_ok=True)
    command = [executable, '--unshare-user', '--unshare-pid', '--die-with-parent', '--new-session',
               '--ro-bind', '/', '/', '--dev', '/dev', '--proc', '/proc',
               '--bind', str(scratch), '/tmp', '--bind', str(root), str(root),
               '--setenv', 'HOME', str(home), '--setenv', 'TMPDIR', '/tmp', '--chdir', str(root)]
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


def execute(profile, arguments):
    root = Path(profile['writable_root'])
    mappings = profile['sealed_paths']
    if not mappings:
        raise ValueError('Exact compiled native mutable path inventory is required before import')
    command = isolated_command(root, mappings, arguments)
    result = subprocess.run(command, stdin=subprocess.DEVNULL)
    if any(digest(Path(mapping['original'])) != mapping['original_sha256'] for mapping in mappings):
        raise ValueError('Original native state changed despite namespace boundary')
    return result.returncode


def runtime_proof(base, python, event_library):
    root = base / ('runtime-proof-' + uuid.uuid4().hex[:12])
    root.mkdir(mode=0o700)
    result = {'scope': 'Import/loader qualification only; no native stack, radio, protocol or fixture initialization',
              'started': time.time(), 'result': 'INCOMPLETE', 'root': str(root)}
    freeze = json.loads((base / 'source-freeze.private.json').read_text())
    archive_source = root / 'qa-package-source'
    archive_source.mkdir()
    process = subprocess.Popen(['git', '-C', str(base / 'qa-baseline'), 'archive', freeze['sources']['qa']['sha']],
                               stdout=subprocess.PIPE)
    with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
        archive.extractall(archive_source, filter='data')
    process.stdout.close()
    if process.wait(timeout=30):
        raise ValueError('Exact frozen QA packaging export failed')
    build = base / 'controller-build/obj'
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
    run = actions.add_parser('run')
    run.add_argument('--profile', type=Path, required=True)
    run.add_argument('command', nargs=argparse.REMAINDER)
    runtime = actions.add_parser('runtime')
    runtime.add_argument('--root', type=Path, required=True)
    runtime.add_argument('--python', type=Path, required=True)
    runtime.add_argument('--event-library', type=Path, required=True)
    options = parser.parse_args()
    if options.action == 'self-test':
        unittest.main(argv=[__file__])
    elif options.action == 'runtime':
        raise SystemExit(runtime_proof(options.root, options.python, options.event_library))
    else:
        arguments = options.command[1:] if options.command[:1] == ['--'] else options.command
        raise SystemExit(execute(json.loads(options.profile.read_text()), arguments))
