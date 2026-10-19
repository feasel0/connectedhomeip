# Outstanding Mechanisms: 2026-10-19 UTC

This investigation excludes the ten existing PRs owned by another agent.
Original outcomes remain unchanged. The historical dossier still contains
158 failed outcomes, 80 repaired-mechanism attributions and 78 OPEN outcomes.
The later RT12 experiments and endurance campaigns are separate ledgers.

## Segment 322: Forensics Closed, Exact Exception Unresolved

The original endurance remains interrupted: 55 PASS, one interruption-contaminated
native FAIL and 44 without native outcomes. No restart or outcome rewrite occurred.
The coordinator imports `captured()` from the original
`/home/feasel/qa-mar6/pr527-followup-preparation-20261008/run_readiness_batch.py`;
complete-file SHA256
`a08b120ab2b68f0000c9908a8d6743b6568e57e65f6df6cab5c161970daf43eb`,
mtime October 15, before campaign launch. Its source archive contains the earlier
worker bootstrap, not this dependency; do not overstate frozen-source provenance.

The helper stops/retrieves both captures, writes incomplete proof, checks ring
boundaries, counts three packet filters, then marks complete. Archiving follows
only a successful capture context.

| UTC on October 19 | Retained Observation |
| --- | --- |
| 11:01:07.426644 | Segment 321 complete proof written: IPv6 250, Pi ACL 1281. |
| 11:01:10.296687 | Segment 321 archive receipt written; remote archive remains present, 7,941,551 bytes. |
| 11:01:10.297981 | Segment 322 capture context begins. |
| 11:04:13.306401 | Pi broker ends cleanly; child exit 0. |
| 11:04:18.923878 | Ubuntu broker ends cleanly; child exit 0. |
| 11:04:20.551391 | Segment 322 incomplete proof written, cleanup_errors empty. |
| 11:06:28.429357 | Worker alive, 55 PASS, remote free disk 49,330,388,992 bytes. |
| 11:06:30.914906 | Outer interruption: Endurance capture closure failed. |
| about 11:06:31 | Coordinator exits status 1, not killed by OOM. |
| 11:06:49.322303 | Kernel kills cpptools PID 2917847; anon RSS 21,887,840 KiB, global OOM, no swap. |

Segment 322 retains both captures and one 2,440,392-byte infrastructure pcapng;
dumpcap reports 8559 captured packets. Both broker units are inactive/dead, with
error null and child exit zero. No local archive, receipt or remote segment-322
archive exists. The incomplete proof and source ordering locate the failure
before archiving. The original exception is absent from the three retained
coordinator/closeout logs and bounded accessible service/kernel journal windows.
The thread kept only its class in memory. Later recount success does not restore
that information. The roughly 130-second gap fits a 120-second count timeout,
but no TimeoutExpired or failing packet-counter return code is retained.

| Candidate | Finding |
| --- | --- |
| Acquisition failure | Actual traffic and clean capture-child exits; no demonstrated acquisition error or proof of gap-free coverage. |
| Broker closure/retrieval | Contradicted by clean native/broker states and empty cleanup errors. |
| Validation interruption | Strongly supported boundary; final counts/complete fields were never written. Exact exception unknown. |
| Archive/transfer failure | No segment-322 archive artifact; incomplete proof and ordering place failure before this stage. |
| Resource exhaustion | Global RAM exhaustion confirmed after coordinator exit, not an earlier OOM kill. Earlier pressure is plausible but unmeasured; historical local disk reserve unavailable. |
| Supervisor logic error | No demonstrated wrong stop decision or invalid validation predicate. |

Historical forensic status: INSUFFICIENT EVIDENCE for the underlying exception;
task closed after exhausting retained records. Private correlation/hashes:
`/home/feasel/qa-mar6/37075-increment-20261017/segment322-forensic.private.json`.
Do not repeat missing-record searches or launch a replacement campaign.

A demonstrated investigation-tool defect is corrected: future capture-thread
failures retain phase, segment, message and traceback in owner-only
`capture-thread-failure.private.json`. The regression fails before and passes
after for capture-context and archive errors, requiring unchanged terminal
shutdown error and archive ordering. All 11 coordinator-tool tests pass.
Validation, timeout and stop policy are unchanged. This cannot recover the old
exception, repair the interrupted run or reclassify iteration 56.

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
current local disk reserve, not a live original endurance process. MainPID is
zero and both fixture locks have no owner. Current local free disk is about
7.34 GB, below the unchanged 8-GiB reserve. No matched run or production fix.

The smallest next instrumentation must be confined to an isolated pinned DUT
snapshot, never the active campaign. Use a fixed-capacity binary event buffer
with monotonic time and an overflow counter, not per-attribute formatted logs.
Each record must carry a stable allocation generation plus handler identity,
read/subscribe type, fabric/node, exchange/session when attached, state,
eligibility result/reason, cursor, allocated count and in-flight count. Record
allocation/release, pass scheduled/coalesced/started, ScheduleWork result,
each cursor visit, build result, IM confirmation and MRP acknowledgment
separately. Buffer overflow invalidates complete queue-residence claims.
The bounded Linux diagnostic is now implemented in
`tools/ReportingTrace.h` and `tools/prepare_reporting_trace.py`. It generates
only private overlays from revision `24a1bc0`, with original and generated
source hashes. Its recorder test and syntax checks of all three actual SDK
translation units pass. No production checkout was edited. No instrumented
application was linked, deployed or run; no new runtime inference follows.

The fixed ring contains 4096 80-byte records and 64 allocation identities.
Generation reuse, subscription accounting, record overflow, identity overflow
and binary export have isolated checks. Linux signals request arming/export;
the actual export occurs at a subsequent stack-thread event, never in the
signal handler. Runtime artifacts must stay private. This Linux recorder is
not Nordic firmware and its approximately 320 KiB event ring must not be
ported unchanged to the DK. Overflow or unmatched identities invalidate a
complete residence claim. Scheduler eligibility is sampled at actual visits,
not continuously; a missing visit is not proof of continuously eligible state.
MRP acknowledgment is separately instrumented at a matching retransmission
entry, not inferred from an IM status or generic credit release. The private
overlay is `/home/feasel/qa-mar6/th2-reporting-trace-20261019-mrp`.

The harmless recorder-only `runtime-test` now passes: actual SIGUSR2/SIGUSR1
arming/export, placement allocation/release/address reuse with new generations,
ordered decoded events, sequence/time, ring loss and identity overflow. Private
0700 directory plus child umask 077 yields verified 0600 exports; temporary
outputs are removed. This host measured 49 ns/event armed with 64 identities,
2 ns disabled, and 579 microseconds/full-ring export, within provisional
10-us/event and 100-ms/export test budgets. These are not DUT performance limits.

The runtime objects are ProbeHandler, not SDK ReadHandler. Actual SDK lifecycle
hooks, linked-app transport callbacks, runtime completeness and workload overhead
remain unverified. This does not make the DUT diagnostic ready or prove absent
events mean non-execution. No additional instrumentation layer was added.

After fixture and resource gates pass, use a small matched original
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

## Historical Ubuntu BLE: 66 Outcomes Remain OPEN

The hash-checked extraction in `tools/historical_ble.py` reads the original
catalog-selected logs and structured private invocations, exporting only
fixed labels, numeric errors and protocol/source identities. All 66 invocations
selected `--ble-controller 0`. Configured index is not actual hardware identity.
The 55 PASE IncorrectState and 11 empty-discovery outcomes split as follows:

| Original Signature | Count | Direct Observation | Primary Cause |
| --- | ---: | --- | --- |
| PASE IncorrectState | 44 | Native scan timeout at BLEManagerImpl.cpp:937, then BlueZ InProgress during scan-stop cleanup, then IncorrectState at ScriptDevicePairingDelegate.cpp:101 | OPEN |
| Empty discovery | 11 | Scan-start marker and InProgress/stop-failure markers; no matching native BLEManager timeout marker | OPEN |
| Recovery PASE IncorrectState | 11 | Adapter unavailable at local initialization/scan, followed by IncorrectState | OPEN |

InProgress is not evidence that discovery start failed. In the 44 cases its
position is after the timeout; cleanup failure does not establish the primary
cause of discovery failure. A scan-start message is also not independent HCI
coverage. No explicit PASE packet header was found in any selected controller
log. This establishes an observed local pre-PASE failure stage, not proof that
no radio traffic occurred or that a peer protocol defect caused it.

At 2026-10-11 19:28:31 UTC the original recovery snapshot records controller
MAC `48:E7:DA:C3:30:40`. Its rfkill snapshot explicitly identifies unblocked
`hci0`. The kernel snapshot also contains hci0 observations. A bounded service
restart is recorded at 19:29:14 UTC, without source revision changes. A later
BlueZ snapshot identifies only hci1 at that same MAC, powered and idle. The
later working index-1 configuration does not establish historical index-0
absence, particularly for the earlier 55 discovery/stop-error cases. Historical
MAC-to-index binding at each failure and the exact renumbering interval remain
missing. Wrong-index attribution is SUSPECTED, not an eligible production fix.

The original Ubuntu capture profile contains infrastructure packets, not a
controller-host HCI capture. Its zero Ubuntu ACL count is therefore not proof
of zero BLE activity. Pi HCI capture is a different host and cannot fill this
gap. The retained Ubuntu native library has runtime SHA256
`01ccbe6c4b2f6c6c17a275b409ffe1ae61b652dbb687bc8cb89181ae4b23079a`;
the invocations do not individually record an SDK revision. Reading matching
source is not a sufficient historical source-to-binary attestation.

### Historical Evidence Exhaustion

Original PR539 scan/discovery runs start at 16:06-16:42 UTC October 11; baseline
timeout runs at 19:16-19:18; recovery runs at 19:29:16 and 19:30:39. The retained
kernel hci0 scan-command 0x2042 timeout (-110) at log-local 10:26:56 is earlier,
not an index/availability sample at each failure. The 17-byte Bluetooth journal
has no useful daemon history. No additional original Ubuntu controller-host HCI
capture exists in the bounded provenance/capture locations inspected.

| Group | Supported / Contradicted | Smallest Deciding Reproduction |
| --- | --- | --- |
| A: 44 | Native timeout before stop InProgress; primary stop-error attribution contradicted. No demonstrated PASE exchange. | Same-time MAC/index/D-Bus binding, known DUT advertising, controller-host HCI and native callbacks during one scan. |
| B: 11 | Empty discovery/stop error observed; group A's native timeout marker absent. | Public discovery result/filtering versus measured advertisements, with same-time adapter binding. |
| C: 11 | Local availability/initialization failure after service restart; identity does not prove current D-Bus availability. | Same-process kernel identity, exported BlueZ objects, configured index and initialization result. |

These searches are exhausted: retain exact IDs OPEN / INSUFFICIENT EVIDENCE.
Do not repeatedly investigate unavailable historical records. Present-day
reproduction could distinguish hypotheses but cannot automatically attribute
old IDs. None was launched without its deciding state; no stop/readiness/index
production correction is justified.

### Exact IDs

All IDs below keep `OPEN_PENDING_PROVENANCE`, their original FAIL, run and
iteration. Nothing is merged or removed from the 158-outcome ledger.
The following run names are relative to the original root
`/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/`, except the two
explicit recovery runs under that root's `../ubuntu-ble-recovery/runs/`.

| Run | Count | IDs |
| --- | ---: | --- |
| baseline-nordic-ubuntu-TC_RT_1_1-1 | 1 | 8588996a79109b9a |
| baseline-nordic-ubuntu-TC_RT_1_1-10 | 10 | 87a85a6c954e897f, c2f8c1111243cda1, e417af69fb50c241, c800c8e8091dd702, ef789d779df06d11, d14468a1250a20f5, c924db8bd0f889ae, 0d82548aa489bc83, 5dcbd66a71248487, e446c1bac17df3d4 |
| pr539-nordic-ubuntu-TC_Android_Pair-1 | 1 | 1799111f3b752bb8 |
| pr539-nordic-ubuntu-TC_Android_Pair-10 | 10 | d41797bef0aa5d35, a136d1ae323dd41b, c054288656972f51, f8ebead5a863f9fb, 84ac45432c00f9f8, 1bf3d64d7cd2424d, 507e04a3f5f7bd7b, 13f82a4be6307a7b, 945793c57c00e40c, 37dcad67bbb0aed5 |
| pr539-nordic-ubuntu-TC_Darwin_Pair-1 | 1 | b94ec3a4c7ebc911 |
| pr539-nordic-ubuntu-TC_Darwin_Pair-10 | 10 | 38f38e4418c6b9fd, 1e00dad854fe5e99, 321ddd2dd408604e, 1c4782f7d743f35f, b4a8160f7049fff3, 95936f2fb1f53dcb, a4bb4a2c2f6c7913, 7d935f9c394cabcc, 524bfb0aa0be7e58, b15ba55a9b5689d2 |
| pr539-nordic-ubuntu-TC_RT_1_1-1 | 1 | 87c9fe2f03552d6c |
| pr539-nordic-ubuntu-TC_RT_1_1-10 | 10 | 553a496ea727ada2, ba40ddbafe007c10, ff47adb8c12a4292, 6911e61d9c0c73d7, 67d24e011354369b, ca13dc9249566e8e, f0ed0adf98ec4968, a3f457c89b3e8e1a, a658e4a057dbdacf, 5c9a28603b3d853d |
| pr539-nordic-ubuntu-TC_RT_2_1-1 | 1 | 6a8a99bb8fbc2d27 |
| pr539-nordic-ubuntu-TC_RT_2_1-10 | 10 | 3f9414bbaf9f6dda, 2680d9fc607bdbcc, 6213ab44eb21a0e8, 84f043c79428ca2c, 316885f26ffaa7d2, f28debac1866b54e, 7aff8c5ed1354930, 67bdcb409983777c, d7f195bdbad1c7c5, fa6ab04b3a425912 |
| recovery/baseline-nordic-ubuntu-TC_RT_1_1-1 | 1 | 5d8926a308e70e27 |
| recovery/baseline-nordic-ubuntu-TC_RT_1_1-10 | 10 | a53e51acd9734b89, 6cf5a8a82dc0f02c, 522cccb922be4296, 2b717d6c1fc81512, 3705dffcfaf0985e, b930efee0cced71a, 2cde073e7ff361d6, 40500505afc76042, 9fc9e346b2c6c2bb, 93ebcddf6291e6c9 |

Private derived hashes and event line identities are in
`/home/feasel/qa-mar6/37075-increment-20261017/historical-ble-accounting.json`.
Four regression tests cover redaction, configured-vs-actual identity,
protocol-vs-source-name detection and ordered same-log timeout classification,
including JSON reload. Deciding evidence is timestamped controller-host
adapter/index ownership and HCI/advertising coverage, not a new preventive SDK
change. No new campaign was launched to fill these historical gaps.

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

### Five GATT Failures Narrowed

All five retained HCI captures show successful connection to the exact native
selected peer `2C:CF:67:EC:14:9F`, handle 0x0040, then a peer-to-controller
Read By Group Type response (ATT 0x11), fixed CID 0x0004, returning primary
service 0xfff6. This is a response, not an advertisement or request. Direction
comes from dissector source/destination columns; H4 direction and Bluetooth
src/dst fields are empty and were not treated as proof.

| Original ID | Attempt | Connection Frame | Service Frame | Service End Handle |
| --- | --- | ---: | ---: | --- |
| 326b6e82a2407b74 | a03 | 42 | 62 | 0x0042 |
| 9b2a44b24023d8e5 | a05 | 35 | 53 | 0x004e |
| f47c1cab6351cf41 | a06 | 40 | 60 | 0x0054 |
| 27790c2fe89dcbd1 | a07 | 33 | 52 | 0x005a |
| 415e90edd5f1e1b4 | a08 | 35 | 54 | 0x0060 |

No radio activity, wrong selected peer and no Matter primary service do not
explain these five failures. Native CHIP-service selection nevertheless fails.
This does not establish characteristic discovery, ServicesResolved completion,
D-Bus proxy export or native service-list correctness. AttributeNotFound 0x0a
also occurs at discovery boundaries and is not independently a defect.

The smallest next check is this peer's exported BlueZ service/characteristic
objects and readiness transition at native lookup time, tied to the known ATT
exchange. Cache, daemon discovery and native proxy timing remain hypotheses;
later corrected single-ATT setup is not historical causal proof. All five stay
OPEN; no speculative GATT production correction is justified.

### Smallest Remaining Checks

| Exact Evidence ID | Symptom / Evidence | Hypothesis and Confidence | Deciding Check / Status |
| --- | --- | --- | --- |
| January 2025 iteration 99 | CASE E44918: Sigma3 counter 140688176 at 15:00:19.433; repeated Sigma2 counter 73580410 at 15:00:21.320; final CASESession.cpp:633 timeout. | Failure before CASE completion, high confidence; why Sigma3 was not accepted remains unknown. | Correlate controller capture with responder receive/validation evidence; relevant DUT/OTBR evidence missing. OPEN, investigation owner. |
| January 2025 iteration 78 | CASE E43681 Sigma3 at 14:15:35.228 followed by secure-channel status at 14:15:35.929; native final CommandSender.cpp:343 timeout. Earlier catalog identifies subsequent encrypted CommissioningComplete. | Distinct post-CASE command-progress failure, high confidence in phase, not root cause. | Authenticate command/response capture and responder delivery; missing relevant DUT/OTBR evidence. OPEN, investigation owner. |
| PR528 enabled Ubuntu iteration 36 | Wildcard SubscribeRequest INVALID_ACTION after report/status retransmission and timeout; intended controller/OTBR/DUT network identities agree. | Late-state/status handling or delivery loss remain candidates; neither proved. | Correlate exact report/status exchange with handler close/reuse; historical packet capture absent. OPEN, investigation owner. |
| Wi-Fi IP PASE IncorrectState | Native exception alone does not identify protocol phase. | Discovery, initialization and transport/session hypotheses remain distinct. | Exact original call, peer-discovery evidence, PASE headers and native error origin; not an inferred BLE defect. |
| BLE-Wi-Fi a02 subscription | Separate notification/subscription-stage failure. | Native-versus-daemon cause unproved. | Exact CCCD/notification request and response, BlueZ Notify state and native completion for this peer. |
| Three BLE-Wi-Fi operational timeouts | Post-provisioning phase, separate from BLE pairing. | IPv6 reachability, publication, DNS-SD and CASE remain distinct. | Actual interface/global address and route at failure, corresponding discovery result and CASE exchange. |
| Native SIGSEGV / prolonged PASE | Crashes and long pending protocol work are distinct observations. | No new independent mechanism established. | Matching core/backtrace/build/faulting callback per crash; last actual protocol/callback progress per hang. |
| Thread/SRP/publication | Timeout does not establish a failed network layer. | Dataset, attachment, address, SRP and delivery remain separate. | Exact peer's dataset fingerprint, SRP record, operational address and routed packet timestamps. |

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
