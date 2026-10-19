# Outstanding Mechanisms: 2026-10-19 UTC

This investigation excludes the ten existing PRs owned by another agent.
Original outcomes remain unchanged. The historical dossier still contains
158 failed outcomes, 80 repaired-mechanism attributions and 78 OPEN outcomes.
The later RT12 experiments and endurance campaigns are separate ledgers.

## TH-2: Eligibility and Fairness

Affected observation: the original `serial-reads` RT12 iteration 1 under
`/home/feasel/qa-mar6/rt12-followup-20261017`, plus separately counted read-shape
probes described in [the attribution record](RT12_TARGETED_ATTRIBUTION_20261017.md).
Do not assign the five already-attributed historical mismatch IDs to this cause.

The original read uses exchange 12712, controller session 16494 and DUT session
22676. Its ReadRequest counter is 223246027. The DUT processes status counter
223246083 at epoch 1792242562.989 and sends the next ReportData counter 47688567
at 1792242569.767: a 6.778-second server-log interval. Packet delivery latency
after that send remains a separate part of the controller timeout.

### New Evidence

The bounded extractor verifies the complete sealed DUT object SHA256
`ddc01b92b90544a0eec40222ff2ecb4cc646f98443a768df4a1de94d8a19e6b8`.
Strictly between source lines 489793 and 492109 it finds:

- 13 generic credit releases, each logging three reports after decrement.
- 12 outgoing ReportData headers on 12 other exchange/session pairs.
- 12 post-send observations with four occupied credits and cursor values 3-14.
- No allocation count, pointer identity or per-handler eligibility decision.

These observations establish continued shared reporting progress. Cursor values
are not handler identities; generic state/build markers are not assigned to
TH-2. In particular, the nearby cursor-15 send is not independent proof of
TH-2's slot or queue residence.

The full hash-verified controller log contains 20 distinct subscription IDs
established before the exact TH-2 request. Five are replacements. The DUT log
explicitly tears down the five old IDs before that request, leaving 15 candidate
subscriptions on fabrics 2-16, consistent with the intended workload. None of
these IDs has a matching server teardown in the gap. Absence of teardown logs
is not a direct pool census or proof that every candidate remained active.
An allocated idle subscription also need not be reportable.

### A-H Assessment

| Question | Current Answer |
| --- | --- |
| A: Eligible throughout? | Conditional source answer: a read in `CanStartReporting` is eligible without consulting subscription timing. Successful chunk status processing transitions there. Runtime residence throughout the interval is not individually logged. |
| B: What prevented eligibility? | No preventing handler state is demonstrated. Neither min/max subscription intervals nor dirty state gate a one-off read in the pinned predicate. Do not invent a state from generic markers. |
| C: If eligible, why not selected? | Four credits are repeatedly occupied while the shared cursor advances. Waiting behind other candidates is consistent with the evidence, not an identified per-handler scheduling trace. |
| D: How many competitors? | Fifteen candidate subscriptions plus one foreground read are supported by workload and lifecycle evidence. Actual allocated, eligible and awaiting counts were not directly sampled. Twelve distinct competing report exchanges occur strictly inside the gap. |
| E: Expected round-robin opportunities? | Global cursor progression 3-14 is observed; TH-2's own visits are unknown. An isolated execution of the actual pinned method passes 60 stable-pool cursor placements. |
| F: Missing completion wakeup? | Normal source has two triggers: full-credit release schedules work; transition to `CanStartReporting` schedules a one-off read. Global work continues. An injected ScheduleWork failure loses a wakeup because callers ignore the error, but no such runtime failure is established here. |
| G: Indefinitely delayed by subscriptions? | Not under the probe's stable-pool, successful-build, successful-scheduling and continuing-confirmation assumptions. It finds no starvation. This is not a proof for real transport, changing pools, errors or the event loop. |
| H: Defect or workload latency? | Still OPEN. Shared-credit workload latency is supported; defective fairness/liveness has not been reproduced. Do not classify a diagnostic improvement as an original test PASS. |

### Executable Check

`python3 -B investigation/tools/reporting_fairness.py self-test` extracts six
methods from SDK revision `24a1bc052a7dfd3db809e43bb0da7c93b20bfad6`:
both Engine::Run overloads, ScheduleRun, OnReportConfirm, MoveToState and
ShouldReportUnscheduled. Source hashes are retained in the private receipt.

Sixty initial cursor placements across pools of 1, 2, 4, 5, 16 and 32 pass
repeated-grant and read-grant bounds. A deliberately reset-to-zero cursor
mutation produces the expected starvation failure. Full-credit release schedules
one deferred pass. A separate injected scheduling-error control strands an
eligible read until a later successful schedule, demonstrating a possible
failure condition, not evidence of this historical cause.

Dependencies are explicitly stubbed: stable vector pool, no removal, always
reportable subscriptions, successful chunk builder, FIFO IM confirmations and a
deterministic work queue. No real MRP, clocks or transport run. This is an
offline method probe, not a full SDK regression or deployed-DUT test.

### Deciding Experiment and Ownership

Owner: this investigation. Status: OPEN, runtime experiment blocked by the
original Pi/Nordic endurance fixture ownership. No production fix.

The smallest next instrumentation must be confined to an isolated pinned DUT
snapshot, never the active campaign. Use a fixed-capacity binary event buffer
with monotonic time and an overflow counter, not per-attribute formatted logs.
Each record must carry a stable allocation generation plus handler identity,
read/subscribe type, fabric/node, exchange/session when attached, state,
eligibility result/reason, cursor, allocated count and in-flight count. Record
allocation/release, pass scheduled/coalesced/started, ScheduleWork result,
each cursor visit, build result, IM confirmation and MRP acknowledgment
separately. Buffer overflow invalidates complete queue-residence claims.
This instrumentation is specified, not yet implemented or run.

After the original Nordic run releases ownership, use a small matched original
parallel RT12 control and a diagnostic closing subscriptions only after the
original required subscription-report verification succeeds. Keep all 15 added
controllers, commissioning, writes/reads, timeouts, consistency and fresh-value
assertions unchanged. Keep the instrumented runtime identical between arms.

Before parallel operations, require matching server teardown IDs for every
established/replacement subscription plus a directly observed zero allocated
subscription count and no resumption/new allocation during a bounded quiet
barrier. Client `Shutdown()` alone is insufficient. Instrumented count plus
teardown is preferable to arbitrary delay; if closure cannot be proved, do not
run or interpret the diagnostic arm as subscription-free. Apply a matched
barrier to the control so elapsed time is not an uncontrolled second factor.
Record each native result, read latency, handler eligibility/visits/credits,
CASE and MRP activity. Never automatically launch another endurance campaign.

## TH-3: Secondary CASE Busy

Affected observation: the next foreground read in the original serialized
iteration, failing Busy before an IM ReadRequest. Subscription timeouts force
background CASE on fabrics 2-4; TH-2's fabric-2 exchange 12713 starts first.
Fabric-3 exchange 12714 meets an occupied responder and receives Busy; the
foreground TH-3 joins that peer's establishment result. Subsequent subscription
backoff is separate from its default one-attempt establishment.

Status: expected contention policy / secondary consequence of the timeout
episode, not an independently established defect. Owner: this investigation for
dependency tracking only. No retry change. Reopen as an independent mechanism
only if a separate incorrect state, retry contract violation or liveness failure
is reproduced under an appropriate focused regression.

## Other Retained Families

| Exact Evidence ID | Symptom / Evidence | Hypothesis and Confidence | Deciding Check / Status |
| --- | --- | --- | --- |
| January 2025 iteration 99 | CASE E44918: Sigma3 counter 140688176 at 15:00:19.433; repeated Sigma2 counter 73580410 at 15:00:21.320; final CASESession.cpp:633 timeout. | Failure before CASE completion, high confidence; why Sigma3 was not accepted remains unknown. | Correlate controller capture with responder receive/validation evidence; relevant DUT/OTBR evidence missing. OPEN, investigation owner. |
| January 2025 iteration 78 | CASE E43681 Sigma3 at 14:15:35.228 followed by secure-channel status at 14:15:35.929; native final CommandSender.cpp:343 timeout. Earlier catalog identifies subsequent encrypted CommissioningComplete. | Distinct post-CASE command-progress failure, high confidence in phase, not root cause. | Authenticate command/response capture and responder delivery; missing relevant DUT/OTBR evidence. OPEN, investigation owner. |
| PR528 enabled Ubuntu iteration 36 | Wildcard SubscribeRequest INVALID_ACTION after report/status retransmission and timeout; intended controller/OTBR/DUT network identities agree. | Late-state/status handling or delivery loss remain candidates; neither proved. | Correlate exact report/status exchange with handler close/reuse; historical packet capture absent. OPEN, investigation owner. |

The January check now binds its controller logs to SHA256
`21c2341f41f0f3675f00a2984bf16e79a2d7dba153da79dd61865dfec064ce3e`
(99) and `8e4fdfccd2c088781896fe26d10a025ad38e897b806e7ed3b240253192a37ea0`
(78). Times above are historical log-local, not newly calibrated UTC.
Repeated Sigma2 does not locate a network drop or prove responder malfunction.

The standalone Wi-Fi PASE IncorrectState, BLE-Wi-Fi operational failures,
unattributed SIGSEGV/prolonged PASE and original Thread/SRP/routing families
remain candidates for exact dossier-ID correlation, not newly enumerated bugs.
No original OPEN ID was closed or reassigned during this turn. Multiple similar
exceptions are not evidence of independent defects or a shared root cause.
