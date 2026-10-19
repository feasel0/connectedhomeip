"""Prepare diagnostic-only source files in a fresh private DUT overlay."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile


REVISION = '24a1bc052a7dfd3db809e43bb0da7c93b20bfad6'
SDK = Path('/home/feasel/matter-oct14/connectedhomeip-pr527-fixture')
TOOLS = Path(__file__).resolve().parent
DESTINATION = Path('/home/feasel/qa-mar6/th2-reporting-trace-20261019-mrp')
SOURCES = ('src/app/ReadHandler.cpp', 'src/app/reporting/Engine.cpp', 'src/messaging/ReliableMessageMgr.cpp')


def replace_once(source: str, before: str, after: str) -> str:
    """Refuse a changed source anchor rather than guessing an insertion point."""
    assert source.count(before) == 1, before
    return source.replace(before, after, 1)


def prepare() -> None:
    """Create only an isolated source overlay, never edit a live checkout."""
    assert not DESTINATION.exists(), 'Never replace an existing diagnostic overlay'
    outputs = {}
    hashes = {}
    for relative in SOURCES:
        source = subprocess.check_output(['git', '-C', str(SDK), 'show', REVISION + ':' + relative], text=True)
        hashes[relative] = hashlib.sha256(source.encode()).hexdigest()
        source = '#include <app/ReportingTrace.h>\n' + source
        if relative.endswith('ReadHandler.cpp'):
            anchor = '    mObserver = observer;\n}'
            assert source.count(anchor) == 2
            source = source.replace(anchor, '    mObserver = observer;\n'
                '    investigation::ReportingTrace::Get().Allocate(reinterpret_cast<uintptr_t>(this), IsType(InteractionType::Subscribe));\n'
                '    INVESTIGATION_RH(this, Allocate, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0, ShouldReportUnscheduled(), 0);\n}')
            source = replace_once(source, 'ReadHandler::~ReadHandler()\n{', 'ReadHandler::~ReadHandler()\n{\n'
                '    INVESTIGATION_RH(this, Release, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0, ShouldReportUnscheduled(), 0);\n'
                '    investigation::ReportingTrace::Get().Release(reinterpret_cast<uintptr_t>(this));')
            source = replace_once(source, '        mManagementCallback.GetInteractionModelEngine()->GetReportingEngine().OnReportConfirm();\n    }\n\n    mState =',
                '        INVESTIGATION_RH(this, Confirm, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0, false, 0);\n'
                '        mManagementCallback.GetInteractionModelEngine()->GetReportingEngine().OnReportConfirm();\n    }\n\n    mState =')
            source = replace_once(source, '    mState = aTargetState;\n', '    mState = aTargetState;\n'
                '    INVESTIGATION_RH(this, State, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0, ShouldReportUnscheduled(), 1);\n')
        elif relative.endswith('reporting/Engine.cpp'):
            source = replace_once(source, 'void Engine::Run()\n{', 'void Engine::Run()\n{\n'
                '    investigation::ReportingTrace::Get().pass++;\n'
                '    investigation::TraceEvent passEvent; passEvent.kind = investigation::TraceKind::Pass;\n'
                '    passEvent.cursor = mCurReadHandlerIdx; passEvent.inFlight = mNumReportsInFlight;\n'
                '    passEvent.allocated = static_cast<uint32_t>(mpImEngine->mReadHandlers.Allocated());\n'
                '    investigation::ReportingTrace::Get().Record(passEvent);')
            condition = '        if (readHandler->ShouldReportUnscheduled() || mpImEngine->GetReportScheduler()->IsReportableNow(readHandler))'
            source = replace_once(source, condition,
                '        const bool traceDirect = readHandler->ShouldReportUnscheduled();\n'
                '        const bool traceScheduled = !traceDirect && mpImEngine->GetReportScheduler()->IsReportableNow(readHandler);\n'
                '        INVESTIGATION_RH(readHandler, Visit, mCurReadHandlerIdx, mNumReportsInFlight,\n'
                '            static_cast<uint32_t>(mpImEngine->mReadHandlers.Allocated()), 0, traceDirect || traceScheduled,\n'
                '            traceDirect ? 1 : (traceScheduled ? 2 : 0));\n'
                '        if (traceDirect || traceScheduled)')
            source = replace_once(source, '            CHIP_ERROR err      = BuildAndSendSingleReportData(readHandler);',
                '            INVESTIGATION_RH(readHandler, BuildBegin, mCurReadHandlerIdx, mNumReportsInFlight,\n'
                '                static_cast<uint32_t>(mpImEngine->mReadHandlers.Allocated()), 0, true, 0);\n'
                '            CHIP_ERROR err      = BuildAndSendSingleReportData(readHandler);\n'
                '            investigation::TraceEvent buildEvent; buildEvent.kind = investigation::TraceKind::BuildEnd;\n'
                '            buildEvent.identity = reinterpret_cast<uintptr_t>(readHandler); buildEvent.result = err.AsInteger();\n'
                '            buildEvent.inFlight = mNumReportsInFlight; investigation::ReportingTrace::Get().Record(buildEvent);')
            source = replace_once(source, '    if (IsRunScheduled())\n    {\n        return CHIP_NO_ERROR;',
                '    if (IsRunScheduled())\n    {\n'
                '        investigation::TraceEvent coalesced; coalesced.kind = investigation::TraceKind::Coalesced;\n'
                '        coalesced.inFlight = mNumReportsInFlight; investigation::ReportingTrace::Get().Record(coalesced);\n'
                '        return CHIP_NO_ERROR;')
            source = replace_once(source, '    ReturnErrorOnFailure(systemLayer->ScheduleWork(Run, this));',
                '    const CHIP_ERROR traceResult = systemLayer->ScheduleWork(Run, this);\n'
                '    investigation::TraceEvent scheduled; scheduled.kind = investigation::TraceKind::Schedule;\n'
                '    scheduled.result = traceResult.AsInteger(); scheduled.inFlight = mNumReportsInFlight;\n'
                '    investigation::ReportingTrace::Get().Record(scheduled);\n'
                '    ReturnErrorOnFailure(traceResult);')
            source = replace_once(source, '    mNumReportsInFlight--;\n', '    mNumReportsInFlight--;\n'
                '    investigation::TraceEvent confirmed; confirmed.kind = investigation::TraceKind::Confirm;\n'
                '    confirmed.inFlight = mNumReportsInFlight; investigation::ReportingTrace::Get().Record(confirmed);\n')
        else:
            anchor = '            // Clear the entry from the retransmision table.\n'
            source = replace_once(source, anchor,
                '            investigation::TraceEvent ack; ack.kind = investigation::TraceKind::MrpAck;\n'
                '            ack.exchange = entry->ec->GetExchangeId(); ack.messageCounter = ackMessageCounter;\n'
                '            const auto ackHandle = entry->ec->GetSessionHandle();\n'
                '            if (ackHandle->IsSecureSession())\n'
                '            {\n'
                '                auto * secure = ackHandle->AsSecureSession();\n'
                '                ack.session = secure->GetLocalSessionId(); ack.fabric = secure->GetFabricIndex();\n'
                '                ack.node = secure->GetPeerNodeId();\n'
                '            }\n'
                '            investigation::ReportingTrace::Get().Record(ack);\n' + anchor)
        outputs[relative] = source
    DESTINATION.mkdir(mode=0o700, parents=True)
    for relative, source in outputs.items():
        destination = DESTINATION / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source)
    shutil.copyfile(TOOLS / 'ReportingTrace.h', DESTINATION / 'src/app/ReportingTrace.h')
    manifest = {'revision': REVISION, 'source_sha256': hashes,
        'overlay': str(DESTINATION), 'diagnostic_only': True, 'production_files_modified': False,
        'files': {relative: hashlib.sha256((DESTINATION / relative).read_bytes()).hexdigest()
            for relative in (*outputs, 'src/app/ReportingTrace.h')}}
    (DESTINATION / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


def self_test() -> None:
    """Check bounded capacity, generation reuse, loss accounting and binary export."""
    program = r'''
#include "ReportingTrace.h"
#include <cassert>
int main() {
    auto & trace = investigation::ReportingTrace::Get();
    trace.Allocate(123, true);
    trace.armRequested = 1;
    investigation::TraceEvent event; event.identity = 123;
    trace.Record(event);
    assert(trace.events[0].generation == 1 && trace.events[0].subscriptions == 1);
    trace.Release(123); trace.Allocate(123, false); trace.Record(event);
    assert(trace.events[1].generation == 2 && trace.events[1].subscriptions == 0);
    for (unsigned index = 0; index < trace.kCapacity + 5; index++) { trace.Record(event); }
    assert(trace.total == trace.kCapacity + 7 && trace.lost == 7);
    for (uintptr_t identity = 200; identity < 264; identity++) { trace.Allocate(identity, true); }
    assert(trace.lostIdentities == 1);
    assert(trace.Dump());
}
'''
    with tempfile.TemporaryDirectory(prefix='reporting-trace-test-') as directory:
        binary = str(Path(directory) / 'test')
        subprocess.run(['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-I', str(TOOLS), '-x', 'c++', '-', '-o', binary],
            input=program, text=True, check=True, capture_output=True)
        import os
        output = Path(directory) / 'trace.bin'
        subprocess.run([binary], env=dict(os.environ, MATTER_REPORT_TRACE=str(output)), check=True)
        assert output.stat().st_size == 64 + 80 * 4096
    print('PASS: fixed capacity, stable generations, subscription count, loss counters and binary export')


def compile_overlay() -> None:
    """Syntax-check real diagnostic translation units without emitting objects."""
    build = SDK / 'out/python_lib_host'
    manifest = json.loads((DESTINATION / 'manifest.json').read_text())
    for relative, digest in manifest['files'].items():
        assert hashlib.sha256((DESTINATION / relative).read_bytes()).hexdigest() == digest, relative
    headers = DESTINATION / 'pinned-headers'
    owned = ('src', 'config', 'zzz_generated', 'data_model')
    if not headers.exists():
        names = subprocess.check_output(['git', '-C', str(SDK), 'ls-tree', '-r', '--name-only', REVISION, *owned],
            text=True).splitlines()
        names = [name for name in names if Path(name).suffix in ('.h', '.hpp', '.inc', '.def')]
        archive = subprocess.check_output(['git', '-C', str(SDK), 'archive', REVISION, '--', *names])
        headers.mkdir(mode=0o700)
        with tarfile.open(fileobj=io.BytesIO(archive)) as source:
            source.extractall(headers, filter='data')
        (headers / '.revision').write_text(REVISION + '\n')
    assert (headers / '.revision').read_text().strip() == REVISION
    database = json.loads(subprocess.check_output(['ninja', '-C', str(build), '-t', 'compdb'], text=True))
    for relative in SOURCES:
        entry = next(row for row in database if row['file'].endswith(relative))
        arguments = shlex.split(entry['command'])
        filtered = []
        index = 0
        while index < len(arguments):
            token = arguments[index]
            if token in ('-o', '-MF', '-MT', '-MQ'):
                index += 2
                continue
            if token in ('-c', '-MD', '-MMD'):
                index += 1
                continue
            if token.startswith('-I'):
                include = (Path(entry['directory']) / token[2:]).resolve()
                if include.is_relative_to(SDK):
                    relative_include = include.relative_to(SDK)
                    if relative_include.parts[0] in owned:
                        token = '-I' + str(headers / relative_include)
            filtered.append(str(DESTINATION / relative) if token == entry['file'] else token)
            index += 1
        filtered.extend(['-fsyntax-only', '-I' + str(DESTINATION / 'src')])
        print('Checking ' + relative, flush=True)
        subprocess.run(filtered, cwd=entry['directory'], check=True)
    print('PASS: all three real SDK translation units syntax-checked with native build flags; no objects overwritten')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('self-test', 'prepare', 'compile'))
    action = parser.parse_args().action
    {'self-test': self_test, 'prepare': prepare, 'compile': compile_overlay}[action]()
