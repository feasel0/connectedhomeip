import argparse
import calendar
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import campaign_state as ledger
from consolidation_check import catalog_rows, check_catalog


ROOT = Path(__file__).resolve().parents[1]
PR_SEEDS = {'project-chip/connectedhomeip': [74938, 74889, 74888, 74886, 74858, 74676, 74432, 74431, 74430, 72902, 72824, 72823],
            'CHIP-Specifications/matter-qa': [527, 528, 529, 539, 544, 545, 547, 548, 549, 550]}


def command(*arguments):
    return subprocess.check_output(arguments, text=True, stderr=subprocess.PIPE, timeout=60)


def cutoff(now):
    year, month = divmod(now.year * 12 + now.month - 1 - 4, 12)
    month += 1
    return now.replace(year=year, month=month, day=min(now.day, calendar.monthrange(year, month)[1]))


def source_snapshot(base):
    snapshots = {}
    for name, ref in [('sdk', 'master'), ('qa', 'main')]:
        repository = base / (name + '-upstream.git')
        git = lambda *arguments: command('git', '-C', str(repository), *arguments)
        sha = git('rev-parse', 'refs/remotes/origin/' + ref).strip()
        remote = git('ls-remote', 'origin', 'refs/heads/' + ref).split()[0]
        if sha != remote:
            raise ValueError('Upstream moved during source freeze; refetch explicitly before admission')
        files = git('ls-tree', '-r', '--name-only', sha).splitlines()
        cases = [name for name in files if Path(name).name.startswith('TC_') and name.endswith('.py')]
        selected = cases + ([name for name in files if name.endswith('/raspi.py')] if name == 'qa' else [])
        hashes = {path: hashlib.sha256(subprocess.check_output(['git', '-C', str(repository), 'show', sha + ':' + path])).hexdigest()
                  for path in selected}
        snapshots[name] = {'sha': sha, 'ref': ref, 'url': git('remote', 'get-url', 'origin').strip(),
                           'repository': str(repository), 'case_paths': cases, 'source_hashes': hashes,
                           'executed_runtime': 'NOT_BUILT_OR_ADMITTED'}
    return snapshots


def pr_snapshot(now):
    records = []
    for repository, seeds in PR_SEEDS.items():
        query = 'repo:' + repository + ' is:pr is:open author:feasel0'
        search = json.loads(command('gh', 'api', 'search/issues', '-X', 'GET', '-f', 'q=' + query, '-f', 'per_page=100'))
        if search['total_count'] > len(search['items']) or search.get('incomplete_results'):
            raise ValueError('PR search completeness not established')
        numbers = sorted(set(seeds) | {item['number'] for item in search['items']})
        for number in numbers:
            response = json.loads(command('gh', 'api', 'repos/' + repository + '/pulls/' + str(number)))
            created = datetime.fromisoformat(response['created_at'].replace('Z', '+00:00'))
            disposition = ('ALREADY-UPSTREAM' if response.get('merged_at') else
                           'EXCLUDE-AGE' if created < cutoff(now) else
                           'EXCLUDE-UNRELATED' if number == 74858 else
                           'DIAGNOSTIC-ONLY' if number in {74431, 74432} else 'EXCLUDE-UNREADY')
            records.append({'repository': repository, 'number': number, 'created': response['created_at'],
                            'state': response['state'], 'merged': bool(response.get('merged_at')),
                            'draft': response['draft'], 'head': response['head']['sha'],
                            'base': response['base']['sha'], 'url': response['html_url'],
                            'title': response['title'], 'disposition': disposition,
                            'reason': 'No preapproved, frozen same-cell candidate procedure; technical qualification not inferred from draft/CI'})
    return records


def locators(text):
    return sorted({value.rstrip('.,;:') for value in re.findall(r'/home/feasel/[^\s`"<>|)\]]+', text)})


def historical_documents(base, snapshots, prs, now):
    original = ROOT / 'pr539-failure-evidence/FAILURES.md'
    check_catalog(original)
    text = original.read_text()
    rows = catalog_rows(text)
    catalog = ['# Historical Failure Catalog', '',
               '158 original FAIL outcomes; 80 mapped to addressed mechanisms; 78 OPEN. Original outcomes remain FAIL.',
               'FIXED describes a mapped correction, not an upstream merge, universal attribution or new PASS.',
               f'Generated UTC: {now.isoformat()}. Original dossier SHA256: `{ledger.digest(original)}`.',
               'All detailed observations and original source references remain in [the unchanged dossier](pr539-failure-evidence/FAILURES.md).', '']
    classification = mechanism = None
    for row in rows:
        if row['classification'] != classification:
            classification = row['classification']
            catalog.extend(['## ' + classification, ''])
        if row['mechanism'] != mechanism:
            mechanism = row['mechanism']
            catalog.extend(['### ' + mechanism, ''])
        catalog.extend(['#### Failure ' + row['id'] + ': ' + row['description'], '',
                        '- Resolution: **' + row['resolution'] + '**. Original native outcome: FAIL.',
                        f'- Original observations and evidence: [dossier source](pr539-failure-evidence/FAILURES.md#L{row["line"]}).', ''])
    destination = ROOT / 'FAILURE_CATALOG.md'
    if destination.exists():
        raise FileExistsError('Do not overwrite an independently maintained consolidation')
    ledger.atomic(destination, '\n'.join(catalog))
    check_catalog(original, destination)
    paths = []
    for value in locators(text):
        path = Path(value)
        record = {'path': value, 'availability': 'UNVERIFIED', 'sha256': None}
        try:
            if path.is_file():
                record.update(availability='AVAILABLE_LOCAL_FILE', bytes=path.stat().st_size)
                if path.stat().st_size <= 2 * 1024 ** 2 and path.suffix in {'.json', '.yaml', '.md'}:
                    record['sha256'] = ledger.digest(path)
            elif path.is_dir():
                record['availability'] = 'AVAILABLE_LOCAL_DIRECTORY'
        except OSError:
            pass
        paths.append(record)
    ledger.atomic(base / 'historical-locators.private.json', {'source_hash': ledger.digest(original), 'paths': paths})
    evidence = ['# Evidence Index', '', f'Availability snapshot: {now.isoformat()}; host: Ubuntu operator.',
                'Original raw artifacts were not moved, rewritten or pruned. Availability is not an integrity or gap-free-coverage claim.',
                'Remote-only paths remain UNVERIFIED. Current hashes do not replace original sealed hashes.',
                'Per-failure identities and pointers: [historical catalog](FAILURE_CATALOG.md) and [unchanged detailed dossier](pr539-failure-evidence/FAILURES.md).',
                'Private checked reference manifest: `' + str(base / 'historical-locators.private.json') + '`.', '',
                '| Original Locator | Availability | Current SHA256 / Limitation |', '| --- | --- | --- |']
    for record in paths:
        evidence.append('| `' + record['path'].replace('|', '\\|') + '` | ' + record['availability'] + ' | '
                        + (record['sha256'] or 'Not recursively/full-file hashed; consult original preservation manifest') + ' |')
    ledger.atomic(ROOT / 'EVIDENCE_INDEX.md', '\n'.join(evidence) + '\n')
    registry = ['# PR Inventory', '', f'Live upstream API snapshot: {now.isoformat()}. Four-calendar-month cutoff: {cutoff(now).date()}.',
                'Seed PRs and all current author-owned open PRs in both repositories were queried.',
                'Primary baseline is clean upstream. Zero open PRs are BASELINE-REQUIRED; automated A/B is disabled.',
                'EXCLUDE-UNREADY here is an admission blocker, not a claim that a separately reviewed PR is technically defective.',
                'No exact frozen same-cell candidate configuration/procedure is approved for this campaign; draft status is not technical readiness.', '',
                '| Repository / PR | Created | State | Draft | Exact HEAD | Disposition |', '| --- | --- | --- | --- | --- | --- |']
    for record in prs:
        registry.append(f'| [{record["repository"]} #{record["number"]}]({record["url"]}) | {record["created"]} | '
                        f'{record["state"]} | {record["draft"]} | `{record["head"]}` | {record["disposition"]} |')
    registry.extend(['', 'Dependencies, current-head regressions/platform evidence and unresolved review state require independent qualification before any candidate admission.',
                     'No PR administration, integration, undraft, review or merge was performed.'])
    ledger.atomic(ROOT / 'PR_INVENTORY.md', '\n'.join(registry) + '\n')
    status = ['# Investigation Status', '',
              'Historical 158 FAIL / 80 mapped / 78 OPEN is unchanged. The new campaign has zero hardware outcomes.',
              'Consolidation adds root navigation only; original dossiers, dated reports, private evidence and branch history are retained.', '',
              '## Established And Unresolved', '',
              '- Narrow QA readiness, metadata/fabric/map-alias, callback and stage defects have documented focused corrections; original exact mappings remain authoritative.',
              '- RT12 has controller-receipt/dispatch and DUT inter-report timing contributions; no universal production transport correction is proved.',
              '- Historical BLE/adapter/GATT, DNS-SD, CASE Busy and Thread/SRP symptoms retain their original evidence and attribution limitations.',
              '- Compiled native mutable paths require pre-import isolation; a fresh Python storage file is not sufficient.', '',
              '## Current Preparation', '',
              f'- QA upstream main: `{snapshots["qa"]["sha"]}`; SDK upstream master: `{snapshots["sdk"]["sha"]}`. Source refs only; these are not executed-runtime provenance.',
              '- The connected Nordic is RCP 8388F563A730D925; DK 001050208117 is absent, so Thread-DUT cells remain gated.',
              '- Ubuntu lingering is already enabled. Controller Pi lingering is disabled and was not changed.',
              '- Actual local systemd and remote synthetic lifecycle proofs are separate from hardware results.',
              '- Pristine upstream Raspi reset broadly deletes /tmp/chip_* and launches the app through an SSH channel. An isolated, source-preserving fixture boundary is required.',
              '- Current-source controller/DUT binaries, native mutable-path isolation, actual capture/fixture qualification and runtime estimates are not yet established.', '',
              '## Navigation', '',
              '- [Historical failure catalog](FAILURE_CATALOG.md)', '- [Evidence index](EVIDENCE_INDEX.md)',
              '- [Live PR registry](PR_INVENTORY.md)', '- [Approved campaign plan](WEEKEND_MATRIX_PLAN_2026-10-24.md)',
              '- [Unchanged detailed resolution dossier](pr539-failure-evidence/FAILURES.md)',
              '- [Dated investigation reports](reports/)', '',
              'Hardware admission remains blocked until every required global and selected fixture gate is positively qualified.']
    ledger.atomic(ROOT / 'INVESTIGATION_STATUS.md', '\n'.join(status) + '\n')
    return Counter(record['availability'] for record in paths)


def prepare(base, export_documents=False):
    now = datetime.now(timezone.utc)
    snapshots = source_snapshot(base)
    ledger.atomic(base / 'source-freeze.private.json', {'captured': now.isoformat(), 'sources': snapshots})
    prs = pr_snapshot(now)
    ledger.atomic(base / 'pr-freeze.private.json', {'captured': now.isoformat(), 'prs': prs})
    if export_documents:
        counts = historical_documents(base, snapshots, prs, now)
        print('Historical availability:', dict(counts), flush=True)
    root = base / 'hardware-campaign'
    campaign = ledger.initialize(root, ROOT / 'WEEKEND_MATRIX_PLAN_2026-10-24.md')
    database = ledger.connection(root)
    with database:
        for topology in ['T1', 'T2', 'T3', 'T4']:
            database.execute('UPDATE cells SET gate_reason=? WHERE topology=?',
                             ('Nordic DK not connected; only RCP present; current-source runtime and fixture gates unqualified', topology))
        for topology in ['D1', 'D2', 'D3']:
            database.execute('UPDATE cells SET gate_reason=? WHERE topology=?',
                             ('No independently qualified Matter-DUT dongle; existing dongle is active RCP, not interchangeable', topology))
        for topology in ['W1', 'W2']:
            database.execute('UPDATE cells SET gate_reason=? WHERE topology=?',
                             ('Current-upstream builds/native storage isolation and SSH-independent safe Raspi lifecycle not qualified', topology))
        for topology in ['B1', 'B2']:
            database.execute('UPDATE cells SET gate_reason=? WHERE topology=?',
                             ('BLE-enabled current-upstream Pi image, reset/advertising and independent capture lifecycle not qualified', topology))
        database.execute("UPDATE campaign SET state='BLOCKED',disposition=?",
                         ('Prelaunch: no cell satisfies current-source runtime, safe native path isolation and fixture/capture gates',))
    database.close()
    visible = ROOT / 'campaigns/2026-10-weekend/LIVE_SUMMARY.md'
    ledger.render(root, visible)
    ledger.atomic(base / 'prelaunch-result.json', {'campaign_id': campaign, 'root': str(root),
                  'sources': snapshots, 'native_hardware_executed': 0, 'state': 'BLOCKED',
                  'case_filename_alias': {'TC_LEVEL_CONTROL': 'TC_Level_Control.py'},
                  'extra_cases': {'TC_RT_2_2': 'GATED: second isolated network unavailable',
                                  'TC_BDX_OTA': 'GATED: qualified provider/requestor/update image unavailable',
                                  'TC_Bridge_Add_Remove': 'GATED: dynamic bridge fixture unavailable'},
                  'minimum_core_iterations': 480, 'stretch_target': 1110,
                  'capacity': 'UNQUALIFIED: no current-source representative native timings; no fit-in-48h claim'})
    print(json.dumps({'campaign': campaign, 'root': str(root), 'state': 'BLOCKED', 'hardware_executed': 0}, indent=2))


def assess(base, local_proof, remote_proof, runtime_proof, build_receipt):
    root = base / 'hardware-campaign'
    current = ledger.status(root)
    if current['campaign']['started'] is not None or current['attempts']:
        raise ValueError('Prelaunch assessment cannot rewrite an active or previously launched campaign')
    sources = json.loads((base / 'source-freeze.private.json').read_text())
    local = json.loads((local_proof / 'qualification-results.json').read_text())
    remote = json.loads((remote_proof / 'qualification-results.json').read_text())
    runtime = json.loads((runtime_proof / 'runtime-result.private.json').read_text())
    build = json.loads(build_receipt.read_text())
    frozen_program = local_proof / 'crash-and-progress/program'
    program = {path.name: ledger.digest(path) for path in Path(__file__).resolve().parent.glob('*campaign*.py')}
    for filename in ['campaign_state.py', 'campaign_service.py', 'campaign_native.py']:
        if ledger.digest(frozen_program / filename) != program[filename]:
            raise ValueError('Local lifecycle proofs do not cover the current execution program')
    for filename, expected in remote['program_hashes'].items():
        if program[filename] != expected:
            raise ValueError('Remote proofs do not cover the current program')
    wheel_integrity = bool(build.get('wheels')) and all(
        ledger.digest(base / filename) == expected for filename, expected in build['wheels'].items())
    if build['sdk'] != sources['sources']['sdk']['sha'] or build['exit'] != 0 or not wheel_integrity:
        raise ValueError('Successful current-source build and wheel integrity not established')
    if runtime['result'] != 'PASS':
        raise ValueError('Current-source import proof did not pass')
    proof_rows = {key: value for key, value in local.items() if key in set('ABCDEFGHIJKL')}
    proof_rows.update({key: remote[key] for key in ['B', 'J']})
    document = {'captured': datetime.now(timezone.utc).isoformat(), 'state': 'BLOCKED',
                'campaign_id': current['campaign']['id'], 'hardware_launched': False, 'executed': 0,
                'admitted_cells': 0, 'candidate_cells': 88, 'planned_minimum_core': 480, 'planned_target': 1110,
                'started': None, 'deadline': None, 'source_manifest': str(base / 'source-freeze.private.json'),
                'source_manifest_sha256': ledger.digest(base / 'source-freeze.private.json'),
                'plan_sha256': ledger.digest(ROOT / 'WEEKEND_MATRIX_PLAN_2026-10-24.md'),
                'ledger': str(root / 'campaign.sqlite'), 'program_hashes': program,
                'build_receipt': {'path': str(build_receipt), 'sha256': ledger.digest(build_receipt)},
                'runtime_receipt': {'path': str(runtime_proof / 'runtime-result.private.json'),
                                    'sha256': ledger.digest(runtime_proof / 'runtime-result.private.json')},
                'proofs': proof_rows, 'proof_scope': 'Synthetic lifecycle only; not native fixture/capture qualification',
                'literal_shared_ide_termination': 'NOT_EXECUTED; independent launcher SIGKILL and manager cgroup proved',
                'reboot_reconciliation': 'NOT_EXECUTED; host was not rebooted and units were not enabled',
                'hardware_manifest': 'NOT_CREATED: mandatory gates not satisfied',
                'hardware_service': 'NOT_INSTALLED_OR_STARTED',
                'blockers': ['Nordic DK absent; only RCP and unqualified DFU-mode peripheral observed',
                             'Fresh ARM64 controller and DUT builds/imports are not qualified',
                             'Upstream Raspi host-wide reset and SSH-channel app lifetime are not safely isolated',
                             'Native full-run remote supervision and reboot/ownership reconciliation not qualified',
                             'Actual capture rotation/closure/hash/drop/ownership and full failure-context retention not qualified',
                             'Global RF/fixture reset smoke and current-source timing/capacity forecast unavailable',
                             'Full native watchdog OOM/PSI/Thread guards and independent-resource quarantine not implemented',
                             'Hardware success-detail pruning is not qualified; synthetic pruning only'],
                'a_b': 'DISABLED; no candidate configuration approved',
                'policy': 'Preserve failed/interrupted/uncertain/shared evidence; prune verified exclusive success detail'}
    ledger.atomic(base / 'admission-assessment.private.json', document)
    database = ledger.connection(root)
    with database:
        database.execute("UPDATE campaign SET state='BLOCKED',disposition=?",
                         ('No admitted hardware cell: fresh Ubuntu import/build passed; native Pi/reset/capture and Nordic gates remain blocked',))
        for topology in ['W1', 'W2']:
            database.execute('UPDATE cells SET gate_reason=? WHERE topology=?',
                             ('Ubuntu build/import proof passed; ARM64 image, source-preserving remote reset/lifetime and capture gates remain unqualified', topology))
    database.close()
    ledger.render(root, ROOT / 'campaigns/2026-10-weekend/LIVE_SUMMARY.md')
    print(json.dumps({'assessment': str(base / 'admission-assessment.private.json'), 'state': 'BLOCKED',
                      'hardware_executed': 0, 'candidates': 88, 'admitted': 0}, indent=2))


class PreflightTests(unittest.TestCase):
    def test_assessment_cannot_rewrite_launched_campaign(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            ledger.initialize(base / 'hardware-campaign', ROOT / 'WEEKEND_MATRIX_PLAN_2026-10-24.md')
            database = ledger.connection(base / 'hardware-campaign')
            with database:
                database.execute('UPDATE campaign SET started=123')
            database.close()
            with self.assertRaises(ValueError):
                assess(base, None, None, None, None)

    def test_calendar_month_cutoff(self):
        self.assertEqual(cutoff(datetime(2026, 10, 24, tzinfo=timezone.utc)).date().isoformat(), '2026-06-24')
        self.assertEqual(cutoff(datetime(2026, 6, 30, tzinfo=timezone.utc)).date().isoformat(), '2026-02-28')

    def test_locator_delimiters(self):
        self.assertEqual(locators('`/home/feasel/run/a.json`, [/home/feasel/run/b.log]'),
                         ['/home/feasel/run/a.json', '/home/feasel/run/b.log'])


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['self-test', 'prepare', 'assess'])
    parser.add_argument('--root', type=Path)
    parser.add_argument('--export-documents', action='store_true')
    parser.add_argument('--local-proof', type=Path)
    parser.add_argument('--remote-proof', type=Path)
    parser.add_argument('--runtime-proof', type=Path)
    parser.add_argument('--build-receipt', type=Path)
    options = parser.parse_args()
    if options.action == 'self-test':
        unittest.main(argv=[__file__])
    elif options.action == 'assess':
        assess(options.root, options.local_proof, options.remote_proof, options.runtime_proof, options.build_receipt)
    else:
        prepare(options.root, options.export_documents)
