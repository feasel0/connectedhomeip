import argparse
import configparser
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tarfile
import time
import unittest
import uuid

from campaign_state import atomic, digest


def linux_modules(text):
    configuration = configparser.ConfigParser(interpolation=None)
    configuration.read_string(text)
    selected = []
    for section in configuration.sections():
        row = configuration[section]
        platforms = set(row.get('platforms', '').split(',')) - {''}
        excluded = set(row.get('excluded-platforms', '').split(','))
        if (not platforms or 'linux' in platforms) and 'linux' not in excluded:
            selected.append({'path': row['path'], 'url': row['url']})
    return selected


def nested(base, objects, relative):
    sdk = base / 'sdk-baseline'
    repository = objects / relative
    parent = json.loads((base / 'linux-dependencies.private.json').read_text())
    expected = next(row['sha'] for row in parent['modules'] if row['path'] == relative)
    output = subprocess.check_output(['git', '-C', str(repository), 'ls-tree', '-r', expected], text=True)
    records = []
    for line in output.splitlines():
        metadata, path = line.split('\t', 1)
        if not metadata.startswith('160000 '):
            continue
        revision = metadata.split()[2]
        source = repository / path
        target = sdk / relative / path
        if target.exists() and any(target.iterdir()):
            raise ValueError('Do not overwrite populated nested dependency')
        subprocess.run(['git', '-C', str(source), 'cat-file', '-e', revision + '^{commit}'], check=True)
        target.mkdir(parents=True, exist_ok=True)
        process = subprocess.Popen(['git', '-C', str(source), 'archive', '--format=tar', revision],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
            archive.extractall(target, filter='data')
        process.stdout.close()
        process.wait(timeout=30)
        if process.returncode:
            raise RuntimeError('Exact nested dependency export failed')
        records.append({'path': str(Path(relative) / path), 'sha': revision})
        print('EXPORTED_NESTED_PIN', records[-1]['path'], revision, flush=True)
    atomic(base / ('nested-' + Path(relative).parts[1] + '.private.json'), records)


def prepare(base, objects):
    sdk = base / 'sdk-baseline'
    git = lambda *arguments: subprocess.check_output(['git', '-C', str(sdk), *arguments], text=True)
    sha = git('rev-parse', 'HEAD').strip()
    source = json.loads((base / 'source-freeze.private.json').read_text())
    if sha != source['sources']['sdk']['sha'] or git('diff', '--name-only', 'HEAD').strip():
        raise ValueError('Baseline source identity or cleanliness changed')
    pins = {}
    for line in git('ls-tree', '-r', 'HEAD').splitlines():
        metadata, path = line.split('\t', 1)
        if metadata.startswith('160000 '):
            pins[path] = metadata.split()[2]
    modules = linux_modules((sdk / '.gitmodules').read_text())
    records = []
    for row in modules:
        if shutil.disk_usage(base).free < 9 * 1024 ** 3:
            raise ValueError('Stopping dependency export before storage reserve violation')
        relative = row['path']
        expected = pins[relative]
        repository = objects / relative
        available = subprocess.run(['git', '-C', str(repository), 'cat-file', '-e', expected + '^{commit}'],
                                   capture_output=True, timeout=20).returncode == 0
        record = dict(row, sha=expected, available=available)
        records.append(record)
        atomic(base / 'linux-dependencies.private.json', {'sdk': sha, 'modules': records})
        if not available:
            print('MISSING_PIN', relative, expected, flush=True)
            continue
        target = sdk / relative
        if any(target.iterdir()) if target.exists() else False:
            raise ValueError('Do not replace an already populated baseline dependency')
        target.mkdir(parents=True, exist_ok=True)
        process = subprocess.Popen(['git', '-C', str(repository), 'archive', '--format=tar', expected],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
            archive.extractall(target, filter='data')
        process.stdout.close()
        process.wait(timeout=30)
        if process.returncode:
            raise RuntimeError('Exact dependency archive failed: ' + relative)
        print('EXPORTED_PIN', relative, expected, flush=True)
    missing = [row for row in records if not row['available']]
    print(json.dumps({'sdk': sha, 'exported': len(records) - len(missing), 'missing': missing,
                      'free_bytes': shutil.disk_usage(base).free}, indent=2))
    return not missing


def compile_controller(base, environment):
    if shutil.disk_usage(base).free < 10 * 1024 ** 3:
        raise ValueError('Insufficient free space for bounded controller compilation')
    sdk = base / 'sdk-baseline'
    freeze = json.loads((base / 'source-freeze.private.json').read_text())
    revision = subprocess.check_output(['git', '-C', str(sdk), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != freeze['sources']['sdk']['sha']:
        raise ValueError('Frozen SDK source identity changed')
    tools = environment / '.environment'
    event = environment / 'out/host-deps/libevent/usr'
    env = dict(os.environ, PW_PROJECT_ROOT=str(sdk), PW_ENVIRONMENT_ROOT=str(tools),
               _PW_ACTUAL_ENVIRONMENT_ROOT=str(tools),
               PKG_CONFIG_PATH=str(event / 'lib/x86_64-linux-gnu/pkgconfig'),
               CPLUS_INCLUDE_PATH=str(event / 'include'), C_INCLUDE_PATH=str(event / 'include'),
               LIBRARY_PATH=str(event / 'lib/x86_64-linux-gnu'))
    env['PATH'] = ':'.join([str(tools / 'cipd/packages/pigweed/bin'), str(tools / 'cipd/packages/pigweed'),
                            str(tools / 'pigweed-venv/bin'), env['PATH']])
    identifier = uuid.uuid4().hex[:12]
    log = base / ('controller-build-' + identifier + '.private.log')
    result = {'id': identifier, 'sdk': revision, 'started': time.time(), 'log': str(log),
              'source_changes': False, 'native_security_test_mode': False, 'parallel_jobs': 6,
              'host_libevent_prefix': str(event)}
    with log.open('xb') as output:
        process = subprocess.Popen([str(tools / 'cipd/packages/pigweed/bin/ninja'),
                                    '-C', str(base / 'controller-build'), '-j6', 'python_wheels'],
                                   cwd=sdk, env=env, stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            result['exit'] = process.wait(timeout=3600)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            result.update(exit=process.returncode, incomplete=True)
    result.update(ended=time.time(), free_bytes=shutil.disk_usage(base).free,
                  wheels={str(path.relative_to(base)): digest(path) for path in (base / 'controller-build').rglob('*.whl')})
    atomic(base / ('controller-build-' + identifier + '-exit.json'), result)
    print(json.dumps(result, indent=2), flush=True)
    if result['exit']:
        print('\n'.join(log.read_text().splitlines()[-35:]), flush=True)
    return result['exit']


def export_native_source(base):
    sdk = base / 'sdk-baseline'
    freeze = json.loads((base / 'source-freeze.private.json').read_text())
    revision = subprocess.check_output(['git', '-C', str(sdk), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != freeze['sources']['sdk']['sha']:
        raise ValueError('Frozen source changed before native transfer')
    if subprocess.check_output(['git', '-C', str(sdk), 'diff', '--name-only', 'HEAD'], text=True).strip():
        raise ValueError('Native source export must be pristine upstream')
    output = base / ('native-source-' + uuid.uuid4().hex[:12] + '.private.tar.gz')
    files = {}
    with tarfile.open(output, 'x:gz', compresslevel=1) as archive:
        for path in sorted(sdk.rglob('*')):
            relative = path.relative_to(sdk)
            if any(part in {'.git', '__pycache__', '.environment', 'out'} for part in relative.parts):
                continue
            if path.is_file() and not path.is_symlink():
                files[str(relative)] = digest(path)
            archive.add(path, arcname=str(Path('sdk-baseline') / relative), recursive=False)
    result = {'sdk': revision, 'archive': str(output), 'sha256': digest(output), 'files': files,
              'dependency_receipt_sha256': digest(base / 'linux-dependencies.private.json'),
              'nested_dependency_receipts': {path.name: digest(path) for path in base.glob('nested-*.private.json')}}
    atomic(base / 'native-source.private.json', result)
    print(json.dumps({key: value for key, value in result.items() if key != 'files'}), flush=True)


def native_arguments(role):
    if role == 'dut':
        return 'chip_enable_ble=false chip_config_network_layer_ble=false chip_mdns="platform" treat_warnings_as_errors=false'
    if role != 'controller':
        raise ValueError('Unsupported native artifact role')
    return ('matter_log_json_payload_hex=true matter_log_json_payload_decode_full=true '
            'matter_enable_tracing_support=true chip_detail_logging=true '
            'chip_project_config_include_dirs=["//config/python"] '
            'chip_config_network_layer_ble=true chip_enable_ble=true '
            'chip_enable_nfc_based_commissioning=false chip_inet_config_enable_ipv4=true '
            'chip_crypto="boringssl" chip_build_controller_dynamic_server=true '
            'chip_support_webrtc_python_bindings=false chip_device_config_enable_joint_fabric=true '
            'chip_mdns="platform" treat_warnings_as_errors=false')


def compile_native(base, environment, role):
    if os.uname().machine != 'aarch64' or shutil.disk_usage(base).free < 10 * 1024 ** 3:
        raise ValueError('Native ARM64 host and sufficient storage required')
    manifest = json.loads((base / 'native-source.private.json').read_text())
    sdk = base / 'sdk-baseline'
    for relative, expected in manifest['files'].items():
        path = sdk / relative
        if not path.resolve().is_relative_to(sdk.resolve()) or digest(path) != expected:
            raise ValueError('Native source manifest mismatch: ' + relative)
    tools = environment / '.environment'
    env = dict(os.environ, PW_PROJECT_ROOT=str(sdk), PW_ENVIRONMENT_ROOT=str(tools),
               _PW_ACTUAL_ENVIRONMENT_ROOT=str(tools), PYTHONDONTWRITEBYTECODE='1',
               ZAP_INSTALL_PATH=str(tools / 'cipd/packages/zap'))
    env['PATH'] = ':'.join([str(tools / 'cipd/packages/pigweed/bin'), str(tools / 'cipd/packages/pigweed'),
                            str(tools / 'pigweed-venv/bin'), env['PATH']])
    output = base / ('arm64-' + role)
    identifier = role + '-' + uuid.uuid4().hex[:12]
    arguments = native_arguments(role)
    root = sdk if role == 'controller' else sdk / 'examples/all-clusters-app/linux'
    commands = [[str(tools / 'cipd/packages/pigweed/gn'), 'gen', '--check', '--fail-on-unused-args',
                 '--root=' + str(root), str(output), '--args=' + arguments],
                [str(tools / 'cipd/packages/pigweed/bin/ninja'), '-C', str(output), '-j2',
                 'python_wheels' if role == 'controller' else 'chip-all-clusters-app']]
    result = {'sdk': manifest['sdk'], 'role': role, 'started': time.time(), 'arguments': arguments,
              'source_changes': False, 'source_manifest_sha256': digest(base / 'native-source.private.json'),
              'commands': commands, 'exit': None, 'native_security_test_mode': False}
    with (base / (identifier + '.private.log')).open('xb') as log:
        for command in commands:
            process = subprocess.run(command, cwd=sdk, env=env, stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=subprocess.STDOUT, timeout=6900, check=False)
            result['exit'] = process.returncode
            if process.returncode:
                break
    artifacts = list(output.rglob('*.whl')) if role == 'controller' else [output / 'chip-all-clusters-app']
    result.update(ended=time.time(), artifacts={str(path): digest(path) for path in artifacts if path.is_file()},
                  free_bytes=shutil.disk_usage(base).free)
    atomic(base / (identifier + '-exit.private.json'), result)
    print(json.dumps(result), flush=True)
    return result['exit']


class BuildTests(unittest.TestCase):
    def test_native_roles_do_not_override_security_mode(self):
        self.assertIn('chip_enable_ble=false', native_arguments('dut'))
        self.assertIn('chip_config_network_layer_ble=false', native_arguments('dut'))
        self.assertIn('config/python', native_arguments('controller'))
        for role in ['dut', 'controller']:
            self.assertNotIn('SECURITY_TEST_MODE', native_arguments(role))
            self.assertNotIn('project_config_header', native_arguments(role))
        with self.assertRaises(ValueError):
            native_arguments('unknown')

    def test_platform_selection(self):
        text = ('[submodule "all"]\npath=common\nurl=https://example.invalid/common\n'
                '[submodule "linux"]\npath=linux\nurl=https://example.invalid/linux\nplatforms=linux,darwin\n'
                '[submodule "other"]\npath=other\nurl=https://example.invalid/other\nplatforms=esp32\n'
                '[submodule "excluded"]\npath=excluded\nurl=https://example.invalid/excluded\nexcluded-platforms=linux\n')
        self.assertEqual([row['path'] for row in linux_modules(text)], ['common', 'linux'])


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['self-test', 'prepare', 'nested', 'compile', 'native-export', 'native-build'])
    parser.add_argument('--root', type=Path)
    parser.add_argument('--objects', type=Path)
    parser.add_argument('--module')
    parser.add_argument('--environment', type=Path)
    parser.add_argument('--role', choices=['dut', 'controller'])
    options = parser.parse_args()
    if options.action == 'self-test':
        unittest.main(argv=[__file__])
    elif options.action == 'nested':
        nested(options.root, options.objects, options.module)
    elif options.action == 'compile':
        raise SystemExit(compile_controller(options.root, options.environment))
    elif options.action == 'native-export':
        export_native_source(options.root)
    elif options.action == 'native-build':
        raise SystemExit(compile_native(options.root, options.environment, options.role))
    else:
        prepare(options.root, options.objects)
