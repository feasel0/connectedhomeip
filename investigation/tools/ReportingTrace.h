#pragma once

#include <array>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace investigation {

enum class TraceKind : uint8_t
{
    Allocate, Release, State, Visit, BuildBegin, BuildEnd, Confirm, Schedule, Coalesced, Pass, MrpAck
};

struct TraceEvent
{
    uint64_t sequence = 0;
    uint64_t monotonicUs = 0;
    uint64_t identity = 0;
    uint64_t node = 0;
    uint32_t generation = 0;
    uint32_t pass = 0;
    uint32_t cursor = UINT32_MAX;
    uint32_t allocated = UINT32_MAX;
    uint32_t inFlight = UINT32_MAX;
    uint32_t subscriptions = 0;
    uint32_t lost = 0;
    int32_t result = 0;
    uint32_t messageCounter = 0;
    uint16_t fabric = 0;
    uint16_t exchange = UINT16_MAX;
    uint16_t session = UINT16_MAX;
    TraceKind kind = TraceKind::State;
    uint8_t interaction = 0;
    uint8_t state = 0;
    uint8_t eligible = 0;
    uint8_t reason = 0;
};
static_assert(sizeof(TraceEvent) == 80);

struct TraceSlot
{
    uintptr_t identity = 0;
    uint32_t generation = 0;
    bool subscription = false;
};

struct ReportingTrace
{
    static constexpr size_t kCapacity = 4096;
    std::array<TraceEvent, kCapacity> events{};
    std::array<TraceSlot, 64> slots{};
    uint64_t total = 0;
    uint32_t lost = 0;
    uint32_t lostIdentities = 0;
    uint32_t generation = 0;
    uint32_t pass = 0;
    uint32_t subscriptions = 0;
    bool armed = false;
    bool installed = false;
    volatile std::sig_atomic_t armRequested = 0;
    volatile std::sig_atomic_t dumpRequested = 0;

    static ReportingTrace & Get()
    {
        static ReportingTrace trace;
        return trace;
    }

    static void Signal(int signal)
    {
        auto & trace = Get();
        if (signal == SIGUSR2)
        {
            trace.armRequested = 1;
        }
        else if (signal == SIGUSR1)
        {
            trace.dumpRequested = 1;
        }
    }

    TraceSlot * Find(uintptr_t identity)
    {
        for (auto & slot : slots)
        {
            if (slot.identity == identity)
            {
                return &slot;
            }
        }
        return nullptr;
    }

    void Allocate(uintptr_t identity, bool subscription)
    {
        if (!installed && std::getenv("MATTER_REPORT_TRACE") != nullptr)
        {
            installed = true;
            std::signal(SIGUSR2, Signal);
            std::signal(SIGUSR1, Signal);
        }
        auto * slot = Find(0);
        if (slot == nullptr || identity == 0 || Find(identity) != nullptr)
        {
            lostIdentities++;
            return;
        }
        *slot = { identity, ++generation, subscription };
        subscriptions += subscription ? 1 : 0;
    }

    void Release(uintptr_t identity)
    {
        auto * slot = Find(identity);
        if (slot == nullptr)
        {
            lostIdentities++;
            return;
        }
        subscriptions -= slot->subscription ? 1 : 0;
        *slot = {};
    }

    void Record(TraceEvent event)
    {
        if (armRequested)
        {
            armRequested = 0;
            total = 0;
            lost = 0;
            armed = true;
        }
        if (armed)
        {
            auto * slot = event.identity != 0 ? Find(static_cast<uintptr_t>(event.identity)) : nullptr;
            event.generation = slot != nullptr ? slot->generation : 0;
            event.sequence = total;
            event.monotonicUs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
            event.pass = pass;
            event.subscriptions = subscriptions;
            if (total >= kCapacity)
            {
                lost++;
            }
            event.lost = lost;
            events[total++ % kCapacity] = event;
        }
        if (dumpRequested)
        {
            dumpRequested = 0;
            Dump();
        }
    }

    bool Dump()
    {
        const char * path = std::getenv("MATTER_REPORT_TRACE");
        if (path == nullptr)
        {
            return false;
        }
        auto * stream = std::fopen(path, "wb");
        if (stream == nullptr)
        {
            return false;
        }
        const uint64_t header[] = { UINT64_C(0x4d54525452414345), sizeof(TraceEvent), total, lost,
                                    lostIdentities, subscriptions, pass, kCapacity };
        bool success = std::fwrite(header, sizeof(header), 1, stream) == 1;
        const uint64_t begin = total > kCapacity ? total - kCapacity : 0;
        for (uint64_t index = begin; success && index < total; index++)
        {
            success = std::fwrite(&events[index % kCapacity], sizeof(TraceEvent), 1, stream) == 1;
        }
        return std::fclose(stream) == 0 && success;
    }
};

} // namespace investigation

#define INVESTIGATION_RH(handler, eventKind, cursorValue, flightValue, allocatedValue, resultValue, eligibility, reasonValue) \
    do \
    { \
        auto * traceHandler = (handler); \
        investigation::TraceEvent traceEvent; \
        traceEvent.kind = investigation::TraceKind::eventKind; \
        traceEvent.identity = reinterpret_cast<uintptr_t>(traceHandler); \
        traceEvent.interaction = static_cast<uint8_t>(traceHandler->mInteractionType); \
        traceEvent.state = static_cast<uint8_t>(traceHandler->mState); \
        auto * traceSession = traceHandler->GetSession(); \
        if (traceSession != nullptr) \
        { \
            traceEvent.fabric = traceHandler->GetAccessingFabricIndex(); \
            traceEvent.node = traceHandler->GetInitiatorNodeId(); \
            traceEvent.session = traceSession->GetLocalSessionId(); \
        } \
        if (traceHandler->mExchangeCtx) \
        { \
            traceEvent.exchange = traceHandler->mExchangeCtx->GetExchangeId(); \
        } \
        traceEvent.cursor = (cursorValue); \
        traceEvent.inFlight = (flightValue); \
        traceEvent.allocated = (allocatedValue); \
        traceEvent.result = (resultValue); \
        traceEvent.eligible = (eligibility); \
        traceEvent.reason = (reasonValue); \
        investigation::ReportingTrace::Get().Record(traceEvent); \
    } while (0)
