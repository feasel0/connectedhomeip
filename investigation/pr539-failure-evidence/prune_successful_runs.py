import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import tarfile
import unittest


SKIP_DIRECTORIES = {'.git', '.environment', 'out', 'build', 'validation-tools-venv',
                    'controller-env', 'qa', 'qa-live', 'pr539', 'baseline', 'third_party',
                    'node_modules', '__pycache__', 'objects'}
SUMMARY_NAMES = {'result.json', 'summary.json', 'test_summary.yaml', 'test_summary.json',
                 'hardware-summary.json', 'validation.json', 'capture-proof.json', 'progress.json'}


def read_document(path):
    try:
        document = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def complete_result(document):
    if not document or not (document.get('ended_utc') or document.get('ended_at')):
        return False
    requested = document.get('requested')
    executed = document.get('executed', document.get('native_outcomes'))
    records = document.get('records')
    if not isinstance(requested, int) or isinstance(requested, bool) or requested <= 0:
        return False
    if executed != requested or not isinstance(records, list) or len(records) != requested:
        return False
    if document.get('process_exit', 0) not in (0, 1):
        return False
    if document.get('unfinished', 0) or document.get('incomplete_slots', 0) or document.get('setup_failures'):
        return False
    return all(isinstance(record, dict) and record.get('outcome') in ('PASS', 'FAIL') for record in records)


def successful_result(document):
    return (complete_result(document) and document.get('process_exit', 0) == 0
            and document.get('passed') == document['requested'] and document.get('failed') == 0
            and all(record['outcome'] == 'PASS' for record in document['records']))


def walk_files(root):
    for directory, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if name not in SKIP_DIRECTORIES
                          and not (Path(directory) / name).is_symlink()]
        for name in filenames:
            path = Path(directory) / name
            if not path.is_symlink():
                yield path


def detailed_files(root):
    if not root.is_dir() or root.is_symlink():
        return
    for path in walk_files(root):
        if path.name not in SUMMARY_NAMES and not path.name.endswith('summary.json'):
            yield path


def custom_success(document):
    if not document or document.get('passed') is not True:
        return False
    if not (document.get('ended_utc') or document.get('finished_utc')):
        return False
    if document.get('error') or document.get('failure_type'):
        return False
    if 'cleanup_unpair_passed' in document and document['cleanup_unpair_passed'] is not True:
        return False
    if 'requested_iterations' in document:
        if len(document.get('iterations', [])) != document['requested_iterations']:
            return False
    return all(check.get('passed') is True for check in document.get('checks', []))


def native_summary(document):
    if not document or not document.get('test_summary_record', {}).get('test_case_ended_at'):
        return None
    summary = document['test_summary_record']
    records = document.get('list_of_iteration_records', [])
    requested = summary.get('total_number_of_iterations')
    if not isinstance(requested, int) or isinstance(requested, bool) or requested <= 0:
        return None
    if summary.get('number_of_iterations_completed') != requested or len(records) != requested:
        return None
    outcomes = {}
    for record in records:
        number = record.get('iteration_number')
        outcome = record.get('iteration_data', {}).get('iteration_tc_execution_data', {}).get('iteration_result')
        if not isinstance(number, int) or isinstance(number, bool) or number in outcomes or outcome not in ('PASS', 'FAIL'):
            return None
        outcomes[number] = outcome
    return outcomes


def run_is_active(run):
    for path in run.glob('*owner*.json'):
        owner = read_document(path) or {}
        process = owner.get('pid', owner.get('native_pid'))
        if not isinstance(process, int) or process <= 0:
            continue
        try:
            fields = Path(f'/proc/{process}/stat').read_text().split(') ', 1)[1].split()
        except FileNotFoundError:
            continue
        expected = owner.get('start_ticks', owner.get('starttick', owner.get('start_time_ticks')))
        if fields[0] != 'Z' and (expected is None or str(expected) == fields[19]):
            return True
    return False


def file_entry(path):
    status = path.stat()
    return {'path': str(path), 'size': status.st_size, 'allocated': status.st_blocks * 512,
            'mtime_ns': status.st_mtime_ns, 'device': status.st_dev, 'inode': status.st_ino}


def summary_digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def failure_paths(catalog):
    protected = set()

    def collect(value, key=''):
        if isinstance(value, dict):
            for field, item in value.items():
                collect(item, field)
        elif isinstance(value, list):
            for item in value:
                collect(item, key)
        elif isinstance(value, str) and value.startswith('/') and key not in ('root', 'run'):
            path = Path(value)
            protected.add(str(path.resolve()))
            if path.is_file():
                return
            elif path.is_dir():
                protected.update(str(item.resolve()) for item in walk_files(path))

    collect(catalog)
    return protected


def plan(roots, manifest_path=None, catalog_path=None):
    roots = [root.resolve() for root in roots]
    candidates = set()
    successful = {}
    retained = set()
    passed_iteration_directories = set()
    campaign_results = {}
    summary_guards = {}

    def select_run(run, passed, summary):
        if run.is_symlink() or run_is_active(run):
            retained.add(str(run))
            return
        successful[str(run)] = {'run': str(run), 'passed': passed, 'summary': str(summary)}
        summary_guards[str(summary)] = summary_digest(summary)
        candidates.update(detailed_files(run))
        if run.parent.name == 'runs':
            campaign = run.parent.parent
            candidates.update(detailed_files(campaign / 'captures' / run.name))
            sibling_roots = (campaign,)
        else:
            sibling_roots = (run.parent,)
        for sibling in sibling_roots:
            for suffix in ('.supervisor.log', '.console.log', '.reconnect.log'):
                path = sibling / (run.name + suffix)
                if path.is_file() and not path.is_symlink():
                    candidates.add(path)

    for root in roots:
        files = list(walk_files(root))
        for result in sorted(path for path in files if path.name == 'result.json'):
            document = read_document(result)
            run = result.parent
            if run.parent.name == 'runs':
                campaign_results.setdefault(run.parent.parent, []).append(successful_result(document))
            if successful_result(document):
                select_run(run, document['passed'], result)
            else:
                retained.add(str(run))
        for summary in sorted(path for path in files if path.name == 'summary.json'):
            document = read_document(summary)
            outcomes = native_summary(document)
            if outcomes is not None:
                run = next((parent.parent for parent in summary.parents if parent.name == 'logs'), None)
                if run is None or run_is_active(run):
                    continue
                result_path = next((parent / 'result.json' for parent in (run, *run.parents)
                                    if (parent / 'result.json').is_file()), None)
                result = read_document(result_path) if result_path is not None else None
                if result is not None and not complete_result(result):
                    continue
                if result_path is not None:
                    summary_guards[str(result_path)] = summary_digest(result_path)
                if all(outcome == 'PASS' for outcome in outcomes.values()):
                    select_run(run, len(outcomes), summary)
                else:
                    summary_guards[str(summary)] = summary_digest(summary)
                    for number, outcome in outcomes.items():
                        directory = summary.parent / str(number)
                        if outcome == 'PASS' and directory.is_dir() and not directory.is_symlink():
                            candidates.update(detailed_files(directory))
                            passed_iteration_directories.add(str(directory))
                continue
            if not custom_success(document):
                continue
            run = summary.parent
            if run.name == 'controller' or document.get('ble_commissioning_passed') is True:
                if run.name == 'controller':
                    run = run.parent
                offline = read_document(run / 'dut/offline-summary.json')
                if (not offline or offline.get('completed_by_controller') is not True
                        or offline.get('recovery_passed') is not True or offline.get('app_exit') != 0):
                    continue
                offline_path = run / 'dut/offline-summary.json'
                summary_guards[str(offline_path)] = summary_digest(offline_path)
                for capture_root in (run.parent.parent / 'captures',):
                    candidates.update(detailed_files(capture_root / run.name))
                for suffix in ('.console.log', '.reconnect.log'):
                    path = run.parent.parent / (run.name + suffix)
                    if path.is_file() and not path.is_symlink():
                        candidates.add(path)
            select_run(run, len(document.get('iterations', [])) or 1, summary)
    for campaign, outcomes in campaign_results.items():
        closure = read_document(campaign / 'hardware-summary.json') or {}
        if all(outcomes) and closure.get('owned_relays_closed') is True and closure.get('dataset_unchanged') is True:
            summary_guards[str(campaign / 'hardware-summary.json')] = summary_digest(campaign / 'hardware-summary.json')
            for path in campaign.glob('*.log'):
                if not path.is_symlink():
                    candidates.add(path)
            candidates.update(detailed_files(campaign / 'relay-segments'))
    if catalog_path is not None:
        catalog = read_document(catalog_path)
        if catalog is None:
            raise ValueError('Missing failure catalog')
        candidates.difference_update(Path(path) for path in failure_paths(catalog))
        summary_guards[str(catalog_path)] = summary_digest(catalog_path)
    entries = [file_entry(path) for path in sorted(candidates)]
    removed_sources = []
    objects = []
    if manifest_path is not None:
        manifest = read_document(manifest_path)
        if manifest is None:
            raise ValueError('Missing preservation manifest')
        summary_guards[str(manifest_path)] = summary_digest(manifest_path)
        selected = {entry['path'] for entry in entries}
        eligible_roots = [Path(path) for path in (*successful, *passed_iteration_directories)]
        protected = failure_paths(read_document(catalog_path)) if catalog_path is not None else set()
        for filename in manifest:
            path = Path(filename)
            if (filename not in protected and path.resolve() == path
                and path.name not in SUMMARY_NAMES and not path.name.endswith('summary.json')
                and any(path.is_relative_to(root) for root in eligible_roots)):
                selected.add(filename)
        removed_sources = sorted(key for key in manifest if key in selected)
        retained_copies = {value['copy'] for key, value in manifest.items() if key not in selected}
        removable = {value['copy'] for key, value in manifest.items()
                     if key in selected and value['copy'] not in retained_copies}
        objects = [file_entry(Path(path)) for path in sorted(removable)]
        for filename in removed_sources:
            item = manifest[filename]
            if item['copy'] in removable:
                with Path(item['copy']).open('rb') as stream:
                    if hashlib.file_digest(stream, 'sha256').hexdigest() != item['sha256']:
                        raise ValueError('Archived successful detail checksum mismatch: ' + item['copy'])
    return {'roots': [str(root) for root in roots], 'successful_runs': list(successful.values()),
            'retained_runs': sorted(retained - set(successful)),
            'summary_guards': summary_guards,
            'passed_iteration_directories': sorted(passed_iteration_directories), 'files': entries,
            'removed_manifest_sources': removed_sources, 'archive_objects': objects,
            'allocated_bytes': sum(entry['allocated'] for entry in entries + objects)}


def apply_plan(document, manifest_path=None, protected_paths=()):
    entries = document['files'] + document.get('archive_objects', [])
    selected = {entry['path'] for entry in entries}
    if selected.intersection(str(path) for path in protected_paths):
        raise ValueError('Plan overlaps protected failure evidence')
    roots = [Path(root) for root in document['roots']]
    for filename, expected in document.get('summary_guards', {}).items():
        if summary_digest(Path(filename)) != expected:
            raise ValueError('Summary changed after planning: ' + filename)
    manifest = read_document(manifest_path) if manifest_path is not None else None
    if document.get('removed_manifest_sources'):
        if manifest is None:
            raise ValueError('Preservation manifest is required')
        remaining = {key: value for key, value in manifest.items()
                     if key not in document['removed_manifest_sources']}
        retained_copies = {value['copy'] for value in remaining.values()}
        if any(entry['path'] in retained_copies for entry in document.get('archive_objects', [])):
            raise ValueError('Archive object still has retained references')
        roots.extend({Path(entry['path']).parent for entry in document.get('archive_objects', [])})
    else:
        remaining = manifest
    for entry in entries:
        path = Path(entry['path'])
        if path.is_symlink() or path.resolve() != path or not any(path.is_relative_to(root) for root in roots):
            raise ValueError('Path escaped an approved evidence root')
        actual = file_entry(path)
        if any(actual[key] != entry[key] for key in ('size', 'mtime_ns', 'device', 'inode')):
            raise ValueError('Artifact changed after planning: ' + str(path))
    for run in document['successful_runs']:
        if run_is_active(Path(run['run'])):
            raise ValueError('Run is active: ' + run['run'])
    for entry in entries:
        Path(entry['path']).unlink()
    if manifest_path is not None and remaining is not None:
        temporary = manifest_path.with_name(manifest_path.name + '.retention-tmp')
        temporary.write_text(json.dumps(remaining, indent=2, sort_keys=True) + '\n')
        os.replace(temporary, manifest_path)
    return {'completed_utc': datetime.now(timezone.utc).isoformat(),
            'successful_runs': len(document['successful_runs']),
            'passed_iteration_directories': len(document.get('passed_iteration_directories', [])),
            'deleted_files': len(document['files']), 'deleted_archive_objects': len(document.get('archive_objects', [])),
            'freed_allocated_bytes': document['allocated_bytes'], 'summaries_retained': True}


def prune_archive(path, replacements=None):
    replacements = replacements or {}
    before = file_entry(path)
    retained = {}
    removed = []
    successful_roots = set()
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            if member.isfile() and member.name.endswith('/summary.json'):
                document = json.load(archive.extractfile(member))
                if custom_success(document):
                    successful_roots.add(str(Path(member.name).parent))
        if not successful_roots and not replacements:
            return {'path': str(path), 'removed_members': 0, 'freed_allocated_bytes': 0}
        temporary = path.with_name(path.name + '.retention-tmp')
        if temporary.exists():
            raise ValueError('Archive rewrite temporary already exists')
        with tarfile.open(temporary, 'w:gz') as destination:
            for member in archive.getmembers():
                is_success_detail = any(member.name.startswith(root + '/')
                                        or member.name.startswith(root + '.') for root in successful_roots)
                if is_success_detail and Path(member.name).name not in SUMMARY_NAMES:
                    removed.append(member.name)
                    continue
                if member.name in ('SHA256SUMS', 'MANIFEST.sha256'):
                    continue
                if member.name in replacements:
                    content = Path(replacements[member.name]).read_bytes()
                    member.size = len(content)
                    destination.addfile(member, io.BytesIO(content))
                    retained[member.name] = hashlib.sha256(content).hexdigest()
                elif member.isfile():
                    content = archive.extractfile(member).read()
                    retained[member.name] = hashlib.sha256(content).hexdigest()
                    destination.addfile(member, io.BytesIO(content))
                else:
                    destination.addfile(member)
            hashes = ''.join(digest + '  ' + name + '\n' for name, digest in sorted(retained.items())).encode()
            manifest_member = tarfile.TarInfo('SHA256SUMS')
            manifest_member.size = len(hashes)
            manifest_member.mode = 0o600
            destination.addfile(manifest_member, io.BytesIO(hashes))
    with tarfile.open(temporary) as archive:
        for name, digest in retained.items():
            if hashlib.sha256(archive.extractfile(name).read()).hexdigest() != digest:
                raise ValueError('Retained archive member failed verification')
        names = set(archive.getnames())
        if names.intersection(removed):
            raise ValueError('Successful archive member was not removed')
    if file_entry(path) != before:
        raise ValueError('Archive changed during rewrite')
    temporary.chmod(0o600)
    os.replace(temporary, path)
    return {'path': str(path), 'removed_members': len(removed),
            'retained_files_verified': len(retained), 'retained_member_bytes_unchanged': True,
            'freed_allocated_bytes': before['allocated'] - file_entry(path)['allocated']}


class RetentionTests(unittest.TestCase):
    def test_exclusive_archive_copy_is_pruned_after_original_was_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'runs/passed'
            run.mkdir(parents=True)
            (run / 'result.json').write_text(json.dumps(self.result(['PASS'])))
            archived = root / 'objects/detail'
            archived.parent.mkdir()
            archived.write_text('successful detail')
            manifest = root / 'preserved-files.json'
            manifest.write_text(json.dumps({str(run / 'console.log'): {
                'copy': str(archived), 'sha256': summary_digest(archived)}}))
            document = plan([root], manifest)
            self.assertEqual([entry['path'] for entry in document['archive_objects']], [str(archived)])
            apply_plan(document, manifest)
            self.assertFalse(archived.exists())
            self.assertEqual(read_document(manifest), {})

    def test_archived_copy_shared_with_failure_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'runs/passed'
            run.mkdir(parents=True)
            (run / 'result.json').write_text(json.dumps(self.result(['PASS'])))
            archived = root / 'objects/detail'
            archived.parent.mkdir()
            archived.write_text('shared detail')
            item = {'copy': str(archived), 'sha256': summary_digest(archived)}
            failed = str(root / 'runs/failed/console.log')
            manifest = root / 'preserved-files.json'
            manifest.write_text(json.dumps({str(run / 'console.log'): item, failed: item}))
            document = plan([root], manifest)
            self.assertEqual(document['archive_objects'], [])
            apply_plan(document, manifest)
            self.assertTrue(archived.exists())
            self.assertEqual(set(read_document(manifest)), {failed})

    def test_missing_original_failure_reference_protects_archive_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'runs/passed'
            run.mkdir(parents=True)
            (run / 'result.json').write_text(json.dumps(self.result(['PASS'])))
            archived = root / 'objects/detail'
            archived.parent.mkdir()
            archived.write_text('protected detail')
            filename = str(run / 'console.log')
            manifest = root / 'preserved-files.json'
            manifest.write_text(json.dumps({filename: {'copy': str(archived), 'sha256': summary_digest(archived)}}))
            catalog = root / 'catalog.json'
            catalog.write_text(json.dumps({'failures': [{'logs': [filename]}]}))
            document = plan([root], manifest, catalog)
            self.assertEqual(document['archive_objects'], [])
            self.assertEqual(document['removed_manifest_sources'], [])

    def result(self, outcomes, exit_code=0):
        return {'requested': len(outcomes), 'executed': len(outcomes),
                'passed': outcomes.count('PASS'), 'failed': outcomes.count('FAIL'),
                'process_exit': exit_code, 'ended_utc': 'closed',
                'records': [{'iteration': number, 'outcome': outcome}
                            for number, outcome in enumerate(outcomes, 1)]}

    def test_only_complete_success_is_eligible(self):
        self.assertTrue(successful_result(self.result(['PASS', 'PASS'])))
        self.assertFalse(successful_result(self.result(['PASS', 'FAIL'], 1)))
        self.assertFalse(successful_result(self.result(['PASS'], -11)))
        interrupted = self.result(['PASS'])
        interrupted['requested'] = 10
        self.assertFalse(successful_result(interrupted))
        self.assertFalse(successful_result({'passed': True}))
        self.assertFalse(successful_result(None))

    def test_missing_end_or_records_is_not_success(self):
        document = self.result(['PASS'])
        document.pop('ended_utc')
        self.assertFalse(successful_result(document))
        document = self.result(['PASS'])
        document['records'] = []
        self.assertFalse(successful_result(document))

    def test_plan_retains_summaries_and_mixed_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, outcomes, exit_code in (('passed', ['PASS'], 0), ('mixed', ['PASS', 'FAIL'], 1)):
                run = root / 'runs' / name
                run.mkdir(parents=True)
                (run / 'result.json').write_text(json.dumps(self.result(outcomes, exit_code)))
                (run / 'summary.json').write_text('{}')
                (run / 'console.log').write_text('log')
            document = plan([root])
            self.assertEqual([entry['path'] for entry in document['files']],
                             [str(root / 'runs/passed/console.log')])
            self.assertTrue((root / 'runs/passed/console.log').exists())
            self.assertEqual(len(document['retained_runs']), 1)

    def test_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / 'outside'
            outside.mkdir()
            (outside / 'failure.log').write_text('retain')
            run = root / 'runs/passed'
            run.mkdir(parents=True)
            (run / 'result.json').write_text(json.dumps(self.result(['PASS'])))
            (run / 'linked').symlink_to(outside, target_is_directory=True)
            self.assertEqual(plan([root])['files'], [])

    def test_failed_closeout_is_not_a_success(self):
        document = {'passed': True, 'ended_utc': 'closed', 'cleanup_unpair_passed': False}
        self.assertFalse(custom_success(document))
        document['cleanup_unpair_passed'] = True
        self.assertTrue(custom_success(document))

    def test_apply_preserves_summary_and_rejects_changed_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'runs/passed'
            run.mkdir(parents=True)
            (run / 'result.json').write_text(json.dumps(self.result(['PASS'])))
            detail = run / 'console.log'
            detail.write_text('passed log')
            document = plan([root])
            detail.write_text('changed passed log')
            with self.assertRaisesRegex(ValueError, 'changed after planning'):
                apply_plan(document)
            self.assertTrue(detail.exists())
            receipt = apply_plan(plan([root]))
            self.assertEqual(receipt['deleted_files'], 1)
            self.assertTrue((run / 'result.json').exists())
            self.assertFalse(detail.exists())

    def test_shared_archive_copy_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'runs/passed'
            run.mkdir(parents=True)
            (run / 'result.json').write_text(json.dumps(self.result(['PASS'])))
            detail = run / 'console.log'
            detail.write_text('shared bytes')
            copy_path = root / 'objects/shared'
            copy_path.parent.mkdir()
            copy_path.write_text('shared bytes')
            manifest_path = root / 'manifest.json'
            manifest_path.write_text(json.dumps({str(detail): {'copy': str(copy_path)},
                                                 str(root / 'failed.log'): {'copy': str(copy_path)}}))
            document = plan([root], manifest_path)
            self.assertEqual(document['archive_objects'], [])
            apply_plan(document, manifest_path)
            self.assertTrue(copy_path.exists())
            self.assertEqual(set(read_document(manifest_path)), {str(root / 'failed.log')})

    def test_protected_failure_reference_aborts_before_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'runs/passed'
            run.mkdir(parents=True)
            (run / 'result.json').write_text(json.dumps(self.result(['PASS'])))
            detail = run / 'console.log'
            detail.write_text('retain')
            with self.assertRaisesRegex(ValueError, 'protected failure'):
                apply_plan(plan([root]), protected_paths=[detail])
            self.assertTrue(detail.exists())

    def test_changed_summary_aborts_before_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'runs/passed'
            run.mkdir(parents=True)
            result = run / 'result.json'
            result.write_text(json.dumps(self.result(['PASS'])))
            detail = run / 'console.log'
            detail.write_text('retain')
            document = plan([root])
            result.write_text(json.dumps(self.result(['FAIL'], 1)))
            with self.assertRaisesRegex(ValueError, 'Summary changed'):
                apply_plan(document)
            self.assertTrue(detail.exists())

    def test_mixed_archive_keeps_failure_and_success_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'evidence.tar.gz'
            content = {'passed/summary.json': json.dumps({'passed': True, 'ended_utc': 'closed'}).encode(),
                       'passed/console.log': b'pass details', 'failed/console.log': b'failure details',
                       'passed.console.log': b'pass console', 'failed/summary.json': b'{"passed": false}'}
            with tarfile.open(path, 'w:gz') as archive:
                for name, data in content.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            receipt = prune_archive(path)
            self.assertEqual(receipt['removed_members'], 2)
            with tarfile.open(path) as archive:
                self.assertNotIn('passed/console.log', archive.getnames())
                self.assertEqual(archive.extractfile('failed/console.log').read(), content['failed/console.log'])
                self.assertEqual(archive.extractfile('passed/summary.json').read(), content['passed/summary.json'])

    def test_native_summary_requires_exact_completion(self):
        document = {'test_summary_record': {'test_case_ended_at': 'closed',
                                           'total_number_of_iterations': 2, 'number_of_iterations_completed': 2},
                    'list_of_iteration_records': [
                        {'iteration_number': 1, 'iteration_data': {'iteration_tc_execution_data': {'iteration_result': 'PASS'}}},
                        {'iteration_number': 2, 'iteration_data': {'iteration_tc_execution_data': {'iteration_result': 'FAIL'}}}]}
        self.assertEqual(native_summary(document), {1: 'PASS', 2: 'FAIL'})
        document['test_summary_record']['total_number_of_iterations'] = 3
        self.assertIsNone(native_summary(document))

    def test_protocol_pass_without_worker_closeout_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'runs/wifi-primary-smoke'
            run.mkdir(parents=True)
            summary = {'passed': True, 'ended_utc': 'closed', 'ble_commissioning_passed': True}
            (run / 'summary.json').write_text(json.dumps(summary))
            detail = run / 'console.log'
            detail.write_text('protocol pass with unknown worker closeout')
            self.assertEqual(plan([root])['files'], [])
            self.assertTrue(detail.exists())

    def test_mixed_native_run_keeps_shared_console_and_failed_iteration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'runs/mixed'
            logs = run / 'logs/MatterTest/test/Case'
            for number in (1, 2):
                (logs / str(number)).mkdir(parents=True)
                (logs / str(number) / 'controller.log').write_text('iteration details')
            (run / 'console.log').write_text('shared failure context')
            (run / 'result.json').write_text(json.dumps(self.result(['PASS', 'FAIL'], 1)))
            document = {'test_summary_record': {'test_case_ended_at': 'closed',
                                               'total_number_of_iterations': 2, 'number_of_iterations_completed': 2},
                        'list_of_iteration_records': [
                            {'iteration_number': 1, 'iteration_data': {'iteration_tc_execution_data': {'iteration_result': 'PASS'}}},
                            {'iteration_number': 2, 'iteration_data': {'iteration_tc_execution_data': {'iteration_result': 'FAIL'}}}]}
            (logs / 'summary.json').write_text(json.dumps(document))
            receipt = apply_plan(plan([root]))
            self.assertEqual(receipt['deleted_files'], 1)
            self.assertTrue((run / 'console.log').exists())
            self.assertTrue((logs / '2/controller.log').exists())
            self.assertTrue((logs / 'summary.json').exists())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', action='append', type=Path, default=[])
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--catalog', type=Path)
    parser.add_argument('--apply', type=Path)
    parser.add_argument('--receipt', type=Path)
    arguments = parser.parse_args()
    if arguments.self_test:
        unittest.main(argv=['prune_successful_runs.py'], exit=True)
    if arguments.apply:
        if not arguments.receipt or arguments.receipt.exists():
            parser.error('Specify a new receipt path when applying a reviewed plan')
        document = read_document(arguments.apply)
        if document is None:
            parser.error('Missing cleanup plan')
        lock_path = (arguments.manifest.parent if arguments.manifest else arguments.apply.parent) / '.update.lock'
        with lock_path.open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            protected = failure_paths(read_document(arguments.catalog)) if arguments.catalog else ()
            receipt = apply_plan(document, arguments.manifest, protected)
            with arguments.receipt.open('x') as destination:
                json.dump(receipt, destination, indent=2)
                destination.write('\n')
        print(json.dumps(receipt, indent=2))
        return
    if not arguments.root:
        parser.error('Specify evidence roots; default operation is read-only planning')
    print(json.dumps(plan(arguments.root, arguments.manifest, arguments.catalog), indent=2))


if __name__ == '__main__':
    main()
