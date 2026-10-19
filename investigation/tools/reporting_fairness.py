"""Execute pinned reporting methods with deterministic, explicitly stubbed dependencies."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from trace_lifecycle import save


REVISION = '24a1bc052a7dfd3db809e43bb0da7c93b20bfad6'
REPOSITORY = Path('/home/feasel/matter-oct14/connectedhomeip-pr527-fixture')
HARNESS = r'''
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <deque>
#include <iostream>
#include <stdexcept>
#include <vector>
using CHIP_ERROR = int;
constexpr CHIP_ERROR CHIP_NO_ERROR = 0;
constexpr CHIP_ERROR CHIP_ERROR_INCORRECT_STATE = 1;
constexpr uint32_t CHIP_IM_MAX_REPORTS_IN_FLIGHT = 4;
#define VerifyOrDie(condition) assert(condition)
#define ChipLogDetail(...) ((void) 0)
#define TEMPORARY_RETURN_IGNORED (void)
#define ReturnErrorOnFailure(expression) do { auto error = (expression); if (error != 0) { return error; } } while (0)
enum class Loop { Continue, Break };
namespace System {
struct Layer {
    using Callback = void (*)(Layer *, void *);
    Callback callback = nullptr;
    void * context = nullptr;
    bool pending = false;
    bool failNext = false;
    unsigned requests = 0;
    CHIP_ERROR ScheduleWork(Callback next, void * state) {
        requests++;
        if (failNext) { failNext = false; return 2; }
        assert(!pending);
        callback = next; context = state; pending = true;
        return CHIP_NO_ERROR;
    }
    void Drain() {
        if (pending) { pending = false; callback(this, context); }
    }
};
}
struct SessionManager {
    System::Layer layer;
    System::Layer * SystemLayer() { return &layer; }
};
namespace Messaging {
struct ExchangeManager {
    SessionManager sessions;
    SessionManager * GetSessionManager() { return &sessions; }
};
}
struct Engine;
struct InteractionModelEngine;
struct ManagementCallback {
    InteractionModelEngine * engine = nullptr;
    InteractionModelEngine * GetInteractionModelEngine() { return engine; }
};
struct Observer {
    Engine * engine = nullptr;
    void OnBecameReportable(void *);
};
struct ReadHandler {
    enum class HandlerState { Idle, CanStartReporting, AwaitingReportResponse, AwaitingDestruction };
    enum class InteractionType { Read, Subscribe };
    HandlerState mState = HandlerState::CanStartReporting;
    InteractionType type = InteractionType::Subscribe;
    ManagementCallback mManagementCallback;
    Observer * mObserver = nullptr;
    unsigned ordinal = 0;
    bool CanStartReporting() const { return mState == HandlerState::CanStartReporting; }
    bool IsAwaitingReportResponse() const { return mState == HandlerState::AwaitingReportResponse; }
    bool IsType(InteractionType expected) const { return type == expected; }
    bool IsPriming() const { return false; }
    bool IsDirty() const { return true; }
    ELIGIBILITY_METHOD
    void MoveToState(HandlerState aTargetState);
};
struct HandlerPool {
    std::vector<ReadHandler *> handlers;
    size_t Allocated() const { return handlers.size(); }
    template <typename Callback> void ForEachActiveObject(Callback callback) {
        for (auto * handler : handlers) { if (callback(handler) == Loop::Break) { break; } }
    }
};
struct Scheduler {
    bool IsReportableNow(ReadHandler * handler) { return handler->CanStartReporting(); }
};
struct InteractionModelEngine {
    HandlerPool mReadHandlers;
    Scheduler scheduler;
    Messaging::ExchangeManager exchanges;
    Engine * reporting = nullptr;
    ReadHandler * ActiveHandlerAt(uint32_t index) { return mReadHandlers.handlers.at(index); }
    Scheduler * GetReportScheduler() { return &scheduler; }
    Messaging::ExchangeManager * GetExchangeManager() { return &exchanges; }
    Engine & GetReportingEngine() { return *reporting; }
};
struct Engine {
    InteractionModelEngine * mpImEngine;
    uint32_t mNumReportsInFlight = 0;
    uint32_t mCurReadHandlerIdx = 0;
    bool mRunScheduled = false;
    ReadHandler * mRunningReadHandler = nullptr;
    struct DirtySet { void ReleaseAll() {} } mGlobalDirtySet;
    std::deque<ReadHandler *> awaiting;
    std::vector<unsigned> grants;
    bool IsRunScheduled() const { return mRunScheduled; }
    void Run();
    static void Run(System::Layer * aSystemLayer, void * apAppState);
    CHIP_ERROR ScheduleRun();
    void OnReportConfirm();
    CHIP_ERROR BuildAndSendSingleReportData(ReadHandler * handler) {
        assert(handler->CanStartReporting());
        mNumReportsInFlight++;
        assert(mNumReportsInFlight <= CHIP_IM_MAX_REPORTS_IN_FLIGHT);
        awaiting.push_back(handler);
        grants.push_back(handler->ordinal);
        handler->MoveToState(ReadHandler::HandlerState::AwaitingReportResponse);
        return CHIP_NO_ERROR;
    }
};
void Observer::OnBecameReportable(void *) { (void) engine->ScheduleRun(); }
PINNED_METHODS
struct Fixture {
    InteractionModelEngine interaction;
    Engine engine{&interaction};
    Observer observer{&engine};
    std::vector<ReadHandler> handlers;
    explicit Fixture(unsigned count) : handlers(count) {
        interaction.reporting = &engine;
        for (unsigned index = 0; index < count; index++) {
            auto & handler = handlers[index];
            handler.ordinal = index;
            handler.mManagementCallback.engine = &interaction;
            handler.mObserver = &observer;
            interaction.mReadHandlers.handlers.push_back(&handler);
        }
        handlers.back().type = ReadHandler::InteractionType::Read;
    }
    System::Layer & Layer() { return interaction.exchanges.sessions.layer; }
    void ConfirmFirst() {
        assert(!engine.awaiting.empty());
        auto * handler = engine.awaiting.front();
        engine.awaiting.pop_front();
        handler->MoveToState(ReadHandler::HandlerState::CanStartReporting);
        assert(Layer().pending);
        Layer().Drain();
    }
};
int main() {
    try {
        unsigned placements = 0;
        for (unsigned count : {1u, 2u, 4u, 5u, 16u, 32u}) {
            for (unsigned start = 0; start < count; start++) {
                Fixture fixture(count);
                fixture.engine.mCurReadHandlerIdx = start;
                assert(fixture.engine.ScheduleRun() == CHIP_NO_ERROR);
                fixture.Layer().Drain();
                for (unsigned step = 0; step < count * 8; step++) { fixture.ConfirmFirst(); }
                std::vector<unsigned> totals(count, 0);
                for (unsigned ordinal : fixture.engine.grants) { totals[ordinal]++; }
                if (*std::min_element(totals.begin(), totals.end()) < 8) {
                    throw std::runtime_error("continuously eligible handler starved");
                }
                unsigned betweenReadGrants = 0;
                for (unsigned ordinal : fixture.engine.grants) {
                    if (ordinal == count - 1) { betweenReadGrants = 0; }
                    else { betweenReadGrants++; }
                    if (betweenReadGrants >= count) { throw std::runtime_error("round-robin bound exceeded"); }
                }
                placements++;
            }
        }
        Fixture full(16);
        full.engine.Run();
        auto requests = full.Layer().requests;
        auto * handler = full.engine.awaiting.front();
        full.engine.awaiting.pop_front();
        handler->MoveToState(ReadHandler::HandlerState::CanStartReporting);
        assert(full.engine.mNumReportsInFlight == 3);
        assert(full.Layer().requests == requests + 1);
        assert(full.Layer().pending);
        full.Layer().Drain();
        assert(full.engine.mNumReportsInFlight == 4);
        Fixture failure(1);
        failure.engine.Run();
        failure.Layer().failNext = true;
        failure.engine.awaiting.clear();
        failure.handlers[0].MoveToState(ReadHandler::HandlerState::CanStartReporting);
        assert(failure.handlers[0].ShouldReportUnscheduled());
        assert(!failure.Layer().pending && !failure.engine.mRunScheduled);
        assert(failure.engine.ScheduleRun() == CHIP_NO_ERROR);
        failure.Layer().Drain();
        assert(failure.engine.grants.size() == 2);
        std::cout << "{\"fair_placements\":" << placements
                  << ",\"credit_wakeup\":true,\"ignored_schedule_error_control\":true}" << std::endl;
        return 0;
    } catch (const std::exception & error) {
        std::cerr << error.what() << std::endl;
        return 1;
    }
}
'''


def method(source: str, signature: str, closing: str = '\n}') -> str:
    """Select one complete pinned method at its known top-level boundary."""
    assert source.count(signature) == 1, signature
    start = source.index(signature)
    end = source.index(closing, start) + len(closing)
    return source[start:end]


def run() -> None:
    """Compile and execute real pinned methods with positive and negative controls."""
    compiler = shutil.which('c++')
    assert compiler, 'A host C++ compiler is required'
    paths = ('src/app/reporting/Engine.cpp', 'src/app/ReadHandler.cpp', 'src/app/ReadHandler.h')
    sources = {path: subprocess.check_output(['git', '-C', str(REPOSITORY), 'show', REVISION + ':' + path], text=True)
        for path in paths}
    engine = sources[paths[0]]
    methods = '\n'.join(method(engine, signature) for signature in (
        'void Engine::Run(System::Layer *', 'CHIP_ERROR Engine::ScheduleRun()', 'void Engine::Run()',
        'void Engine::OnReportConfirm()'))
    methods += '\n' + method(sources[paths[1]], 'void ReadHandler::MoveToState(')
    eligibility = method(sources[paths[2]], 'bool ShouldReportUnscheduled() const', '\n    }')
    program = HARNESS.replace('ELIGIBILITY_METHOD', eligibility).replace('PINNED_METHODS', methods)
    variants = {'pinned': program, 'cursor_reset_negative_control': program.replace('void Engine::Run()\n{',
        'void Engine::Run()\n{\n    mCurReadHandlerIdx = 0;')}
    results = {}
    with tempfile.TemporaryDirectory(prefix='reporting-fairness-') as directory:
        for name, content in variants.items():
            binary = str(Path(directory) / name)
            subprocess.run([compiler, '-std=c++17', '-O0', '-x', 'c++', '-', '-o', binary],
                input=content, text=True, check=True, capture_output=True)
            result = subprocess.run([binary], text=True, capture_output=True, timeout=10)
            if name == 'pinned':
                assert result.returncode == 0, result.stderr
                results[name] = json.loads(result.stdout)
            else:
                assert result.returncode == 1 and 'continuously eligible handler starved' in result.stderr, result.stderr
                results[name] = {'expected_starvation_detected': True}
    receipt = {'revision': REVISION, 'source_sha256': {path: hashlib.sha256(content.encode()).hexdigest()
        for path, content in sources.items()}, 'results': results,
        'actual_methods': ['Engine::Run (both overloads)', 'Engine::ScheduleRun', 'Engine::OnReportConfirm',
            'ReadHandler::MoveToState', 'ReadHandler::ShouldReportUnscheduled'],
        'stubs': ['stable vector pool; no allocation/removal', 'all subscriptions immediately reportable',
            'always-successful builder; every report chunk expects a response', 'deterministic asynchronous work queue',
            'FIFO successful IM confirmations; no MRP, transport, clocks or real event loop'],
        'not_a_hardware_or_full_sdk_regression': True}
    save('reporting-fairness-probe.json', receipt)
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('self-test',))
    parser.parse_args()
    run()
