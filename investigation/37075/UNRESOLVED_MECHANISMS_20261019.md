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

| Original ID | Attempt | Connection Frame | Service Frame | Verified Matter Range |
| --- | --- | ---: | ---: | --- |
| 326b6e82a2407b74 | a03 | 42 | 62 | 0x003d-0x0042 |
| 9b2a44b24023d8e5 | a05 | 35 | 53 | 0x0049-0x004e |
| f47c1cab6351cf41 | a06 | 40 | 60 | 0x004f-0x0054 |
| 27790c2fe89dcbd1 | a07 | 33 | 52 | 0x0055-0x005a |
| 415e90edd5f1e1b4 | a08 | 35 | 54 | 0x005b-0x0060 |

No radio activity, wrong selected peer and no Matter primary service do not
explain these five failures. Native CHIP-service selection nevertheless fails.
All five original consoles specifically report `BluezConnection.cpp:109`,
`Ble Error 0x0000040F` and `CHIP service (...) not found` for that peer.
This is the service-selection error, distinct from the subsequent
`No valid C1` / `No valid C2` predicates; neither characteristic error appears
in these five consoles. Retained library/source provenance is checked below;
exact lookup-time D-Bus event ordering remains unavailable.
This does not establish characteristic discovery, ServicesResolved completion,
D-Bus proxy export or native service-list correctness. AttributeNotFound 0x0a
also occurs at discovery boundaries and is not independently a defect.

The tuple boundaries above are independently verified within each response's
UUID-specific attribute group. All ranges contain six handles. Each attempt
has a distinct retained DUT PID/start tick and exactly one successful GATT
application registration. This supports restart/re-registration correlation,
not duplicate live services or cached-definition causality. Each response lists
only one Matter primary service.

#### Observed EATT Bearer Mismatch

Independent `btmon` decoding reveals enhanced-channel ATT operations omitted by
the installed `tshark` decoder. A fixed-channel-only absence claim is invalid:
a05 does send characteristic discovery. The original capture hashes match the
previous report; decoded UTC headers map exactly to original frame timestamps.

In every attempt the DUT requests PSM 0x0027 with ordered source CIDs
`[0x0041, 0x0040]`; the controller accepts with destination CIDs
`[0x0040, 0x0041]`. Thus controller TX CID 0x0040 belongs to the bearer whose
controller receive CID is 0x0041. Nevertheless the following discovery response
arrives on controller receive CID 0x0040, the other bearer:

| Attempt | Controller TX Request Frame | Wrong-Bearer RX Frame | ATT Operation | Immediate TX Channel Disconnect Frame |
| --- | ---: | ---: | --- | ---: |
| a03 | 78 | 89 | Include 0x2802; error 0x0a | 91 |
| a05 | 74 | 86 | Characteristic 0x2803; response 0x09 | 88 |
| a06 | 78 | 90 | Include 0x2802; error 0x0a | 92 |
| a07 | 68 | 80 | Include 0x2802; error 0x0a | 82 |
| a08 | 71 | 82 | Include 0x2802; error 0x0a | 84 |

There is no preceding outgoing request on the receive bearer's corresponding
TX CID 0x0041 that would explain those responses. Reverse-direction DUT requests
are separately visible, not mistaken for controller requests. `Attribute Not
Found` is normally a valid Include-discovery terminator; its wrong bearer is
the defect evidence. The a05 response is not an ATT error at all, yet produces
the same immediate teardown. No descriptor discovery is observed in these five.
L2CAP channel teardown is not an HCI link disconnection; no HCI Disconnection
Complete appears in these short retained windows.

All five native libraries match retained runtime proof SHA256
`a04c667b4adba6df6041674acf8787e54e0935b80bb0e3e46c98933af984dd11`.
The compiled revision proof is `9c797242f1a1f89dbc010255c77d38307304448a`;
the selection and endpoint files are byte-identical there and at the documented
SDK base `b1c4e7514cecc49cbffd6647504c3611b9cf6e60`. The central path gates on
Connected/ServicesResolved and selects a GattService1 with the exact owning
Device path and UUID, before examining characteristics. Its service predicate
fails, not the C1/C2 predicates. Exact lookup-entry/proxy enumeration callbacks
are not logged.

Post-failure GetManagedObjects snapshots for a07/a08 have Connected=true,
ServicesResolved=true, UUIDs=[] and zero peer GattService1/GattCharacteristic1
objects. These are not lookup-time event traces. No original object-added,
removed or property-change ordering is retained; a07's daemon journal is empty.
The packet sequence strongly supports EATT discovery abort before service
export, rather than an absent Matter service over the air. Exact daemon/kernel
responsibility for the mismatched bearer and its discovery-completion callback
remain unobserved. Do not label this a demonstrated SDK filtering race.

One deciding future smoke, only after capacity/fixture gates pass: reproduce
primary BLE-Wi-Fi with the pinned native library and the original multi-bearer
configuration, retaining both peers' HCI, bounded BlueZ discovery debug and
D-Bus ObjectManager/Device1 events, plus native lookup-time proxy paths/UUIDs.
Resolve which peer socket/CID generated the mismatched response and whether
that abort clears the database before ServicesResolved. Do not switch to one
ATT channel before observing the failure. No broad matrix, new infrastructure
or hardware execution is justified while below the protected reserve.

All five original outcomes remain OPEN. Later single-ATT success is not proof
of a corrected daemon/kernel mechanism. No production correction is validated.

The retained a04 control, original ID `ca3d300af4dc9e9e`, also moved the Matter
range, to 0x0043-0x0048, but
found the service and C1/C2 and advanced to an operational commissioning
timeout. It negotiated simultaneous two-sided enhanced-channel requests and
additional CIDs 0x0042/0x0043, unlike the five failures' single ordered pair.
This contradicts handle movement alone as sufficient explanation; it is not
proof that every enhanced-channel topology works or a complete test PASS.

#### Separate a02 Subscription Failure

Original ID `7530ec8a82f24ce5` finds the Matter service at 0x0015-0x001a,
valid C1 and C2, then fails StartNotify with D-Bus ATT error 0x0e. It is not a
missing-service failure. Its capture uses the same reversed ordered EATT CID
pair. Controller frame 156 writes handle 0x0018 on TX CID 0x0040, but frame
159's Write Response arrives on RX CID 0x0040, the other bearer. Frame 161
immediately requests channel disconnection; native StartNotify fails at
01:12:10.505 UTC, after that channel teardown response.

The C2 declaration/value are 0x0016/0x0017, and the next declaration is 0x0019;
the 0x0018 write is consistent with its CCCD, but no Find Information descriptor
response directly names that UUID in the retained trace. Do not upgrade that
inference to an observed descriptor declaration. No ATT Error Response 0x0e is
seen even in the independent enhanced-channel decode; it is the local D-Bus
failure result, not a demonstrated on-air rejection by the DUT. One bearer also
has a correctly matched concurrent write on the other channel, strengthening
the distinction between a generic broken link and the failed transaction.

This advances the same observed bearer-routing family at a later protocol
phase, without reclassifying the original outcome or validating a fix. The
smallest remaining check is the two peers' exact EATT socket/CID mapping and
BlueZ notification-completion error at the mismatched response, not another
readiness check or speculative change to SDK subscription callbacks.

#### Upstream Linux L2CAP Lead

[BlueZ issue 1094](https://github.com/bluez/bluez/issues/1094) describes a
confirmed kernel defect in the receiver of a multi-channel ECRED request.
The final [upstream correction](https://github.com/torvalds/linux/commit/b25120e1d5f2ebb3db00af557709041f47f7f3d0)
appends channels with `list_add_tail` in `__l2cap_chan_add` and excludes outgoing
or non-deferred channels in `l2cap_ecred_rsp_defer`, using
`!test_and_clear_bit(FLAG_DEFER_SETUP, &chan->flags)`. The latter prevents
identifier reuse from including an established channel in a new response.
[Linux 6.12.18](https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.12.18)
contains stable backport `5c9921f1da47c0b4f12e836ef8778f024a241ada`.

Our six captures have two SCIDs and two successful DCIDs, with a later response
on the other advertised bearer. That is compatible with inconsistent channel
association, but the numerical reversal `[65,64] -> [64,65]` alone does not
prove the upstream bug: CIDs are local, and a valid responder may allocate
them in either numerical order. In these transactions the controller is the
ECRED responder, the role directly affected by this patch; the DUT is requester.
The retained controller capture identifies Linux `6.12.47+rpt-rpi-2712`, later
than the stable fix, but release labels alone do not prove deployed code.

Read-only checks at 2026-10-19 18:50-18:53 UTC bind both peers to package
`1:6.12.47-1+rpt1~bookworm`, BlueZ `5.66-1+rpt1+deb12u2`, and loaded Bluetooth
build ID `339af1100e6808b0899e1ae97fd505bea4aa7548`. Both loaded notes match
the decompressed installed module; package verification reports no changes.
The controller boot began September 24 at 15:29:31 UTC, the DUT at 16:22:14;
October 11-12 kernel journal records have their respective current boot IDs.
No livepatch directory is present and both kernel taint values are zero.
This is boot-continuity/package provenance, not a contemporaneous socket trace.

The package changelog names Raspberry Pi commit
`359f37f0faefb712add32a39f98751aea67d5c1f`. Both accepted correction components
are present in its `net/bluetooth/l2cap_core.c` (SHA256
`40b71702ffee7a0e47d3f3c12861d3fc1cb235a67fa3e1bd3407fd56a860aaa8`). The
matching Debian patch archive was checksum-verified and contains no patch to
that file. The complete original source archive also passed its descriptor's
SHA256 and size checks in memory; its L2CAP file is byte-identical to that
commit. An absent BlueZ #1094 correction is therefore not supported.

A distinct requester-side ordering candidate exists in this same source:
`l2cap_ecred_connect` places its triggering channel first in the request, then
appends deferred channels in connection-list order. `l2cap_ecred_conn_rsp`
instead consumes response DCIDs in connection-list order without remembering
the transmitted SCID order. For connection-list `[64,65]`, triggering65,
request `[65,64]` and response `[64,65]`, it assigns DUT64 -> controller64 and
DUT65 -> controller65, contrary to the advertised positional pairs. An ATT
request sent to DUT64 would then receive a same-socket reply at controller64,
exactly the observed direction, rather than advertised controller65. This is
case B (bad internal association), not proof of case A (bad response builder)
or case C (correct association but wrong ATT socket). Actual per-socket state
was not retained. `tools/ecred_order_probe.py` compiles the hash-pinned request
builder, deferred-grouping helper and response handler unchanged, using host
stubs. The two-channel triggering65 case reproduces the wrong association;
one channel and a two-channel triggering64 control preserve positional pairs.
A three-channel triggering66 case also mismatches. These are isolated native
function checks, not execution of the loaded kernel, BlueZ or an actual DUT.
The channel-list scheduling itself was not captured; the additional teardown
evidence below strengthens the historical association finding. No accepted
correction for this distinct requester-side candidate was
identified; a generic modern-kernel upgrade is not a demonstrated fix.

The retained teardown fields supply an additional historical mapping check:
all six controller Disconnection Requests carry `(DCID65, SCID64)`, but the
matching DUT responses carry `(DCID65, SCID65)`. The pinned
`l2cap_disconnect_req` looks up the channel by the request DCID and builds the
response from `chan->scid` and `chan->dcid`, rather than echoing the request's
SCID. Under that deployed handler, this exposes DUT local65 -> controller65,
contrary to the advertised DUT65 -> controller64 pair. a02 and a03 also have
DUT-originated Disconnection Requests `(DCID64, SCID64)`, consistent with the
other erroneous DUT64 -> controller64 association. This is original wire
evidence of stored association, not a newly captured socket trace.

An independent byte check now confirms all six teardown pairs, adapter0,
HCI handle64, matching command identifiers and original frame/UTC timestamps.
It reads Bluetooth Monitor-format snoop records directly, without btmon or
tshark labels, and emits only fixed disconnect fields and file hashes. All
recorded drop counts are zero; this is not a claim of independent air coverage.
The probe now also compiles the unchanged pinned `l2cap_disconnect_req`.
Chaining that handler after the misordered ECRED assignment yields the exact
`65:64` request / `65:65` response, whereas aligned controls preserve matching
fields. Eleven malformed-format/length/drop controls are rejected. A separate
echo-only handler mutation compiled and ran but failed the intended stored-CID
assertion. The tool and original byte checks therefore support case B with
historical evidence, not merely an ATT wrong-bearer inference. Correct stored
associations plus an ATT-only socket-selection error (case C alone) do not
explain these teardown fields under the verified handler. A new dual-peer
socket trace is still needed for list scheduling and corrective validation,
not to pretend these retained original association fields are absent.

No SDK workaround, kernel change, or corrective hardware result is established
here. All six original outcomes remain OPEN.

#### Request-Index Qualification: October 20

At03:45 the proposed patch was unchanged and NOT production-qualified. The existing
probe reproduces normal and explicit ASan/UBSan execution of all 24 prior
cases plus one identifier-collision qualification case per variant. Original
and proposed executions exit zero; the original with corrective expectations
compiles and fails at the intended assertion after execution, SIGABRT.
No sanitizer findings occur in the final runs. All six original negotiation
and raw teardown checks pass; historical FAIL outcomes are not changed.

The pinned allocator wraps identifiers 1-128 without checking pending
requests. Two independent outgoing requests deliberately given the same
identifier are not isolated by either handler. The original refuses the second
channel; the proposed positional lookup also resets the first channel through
the existing duplicate-DCID path. This is conditional collision behavior, not
an observed cause of the six originals. The sent-flag guard excludes cleared
or non-outgoing channels but does NOT satisfy pending-request uniqueness.
No generic allocator redesign or unrelated kernel fix is included.

A bounded native ARM64 Kbuild check compiles the actual original/proposed
core, socket and layout objects against matching prepared 6.12.47 headers,
with verified private-header dependencies. Both variants exit zero with empty
stderr. The real channel size stays 784 bytes; conf_req moves 51->52 and
conf_len 115->116, while ident stays 50 and flags stays 176. This is not a full
subsystem link, installed module or concurrency test. Affected consumers still
require a consistent rebuild. RAM-only temporary artifacts are removed. The
existing tool's --kernel-build option retains the recipe; no second framework.

See [the qualification report](../reports/2026-10-20_03-45-39.md) for exact
flags, commands, pins, exits and unmet isolation/runtime gates. Local free disk
remains below the protected 8-GiB reserve; no physical comparison, capture
acquisition or production SDK workaround was attempted.

The [04:23 independent reproduction](../reports/2026-10-20_04-23-05.md)
reruns normal/sanitized positives and the behavioral negative plus matching
native objects. Structured output now explicitly marks pending-identifier
isolation NOT_SATISFIED and production_qualified false;25 diagnostic scenarios
do not imply qualification. At that increment the patch and historical outcomes were unchanged.

#### Reachable Collision and Narrow Guard: October 20, 12:56 UTC

The [reachability and original-host report](../reports/2026-10-20_12-56-04.md)
finds no enforced pending-identifier uniqueness: allocation wraps128->1,
sent groups are excluded from the deferred five-channel count, and40-second
channel timers do not prohibit intervening signaling. LE credit grants use the
same allocator without waiting for connection response. Two unrelated EATT
groups can therefore overlap across wrap; no collision is observed in the six
originals. The strengthened existing case executes the pinned allocator's wrap,
not a forced constant identifier, while transport/timers remain host stubs.

The isolated patch now consumes each response slot once with a local bitmap.
It prevents the demonstrated additional duplicate-DCID deletion, without
redesigning allocation or claiming full isolation of the inherited ambiguous
transaction. Twenty-five positives per variant, normal/ASan/UBSan, both
compiling behavioral negatives and matching real ARM64 objects pass. The old
unguarded index variant fails the new first-channel-survival assertion.
This resolves the demonstrated collateral-regression gate, not runtime or
production qualification. The proposal remains unapplied/undeployed; disk,
fixture ownership, consistent linked build and native GATT/StartNotify gates
remain. All historical outcomes and ledger counts are unchanged.

#### Separate Operational Discovery Failures

The original a04 `ca3d300af4dc9e9e`, a09 `dbb5d8f70aca047e` and a10
`012d5d5b000dd3b3` reach `FindOperationalForStayActive` after receiving the
ConnectNetwork response. All three report three operational-discovery failures
from `AddressResolve_DefaultImpl.cpp:124`, error `0x00000032`, before cleanup.
The native CASE error mentions Sigma1, but that string alone is not evidence
that Sigma1 was sent: the producing error is address resolution. These remain
original FAIL outcomes, separate from the EATT discovery/subscription cases.

a10 retained 48 network snapshots. It is disconnected at
2026-10-12 02:53:47.511796 UTC, associated at 02:53:57.522676 but without
captured IPv6 addresses through 02:54:37.573161. The first global IPv6 address
appears at 02:54:47.588216, with an on-link `/64` route, and persists through
the controller's 02:56:14.500719 failure and later DUT snapshots. IPv6 is
enabled (`disable_ipv6=0`, `accept_ra=2`, `autoconf=1`); no default route is
captured. A default route is not required for an on-link peer, so this alone
does not prove a routing fault. Permanent absence of a global address is
disproved for a10; timely DNS-SD publication, resolution and packet delivery
are not established. a04 has no equivalent snapshots, and a09's retained
original address is not a failure-time address/route history.

The next deciding check is the original operational instance's publication,
address-resolution result and controller/DUT IP packets during discovery,
not a BLE readiness delay or a speculative CASE fix. All three remain OPEN.

The original Ubuntu-side IP captures now provide a narrower publication check.
Each contains 84 queries for its exact DUT operational instance, but no
positive-TTL DUT SRV record during the controller's resolver window. a04 has
no matching response record in the retained observer capture. a09 first shows
DUT SRV at 02:46:59.079468 UTC, after its 02:45:46.514203 failure; a10 at
02:57:27.067753, after its 02:56:14.500719 failure. Both late bursts contain
SRV port5540/TTL120 and TTL0 withdrawals. The same structural extraction finds
six positive-TTL commissioner SRV records per capture. SRV owner fields are
split by this dissector into `dns.srv.service`, `dns.srv.proto` and
`dns.srv.name`; using only `dns.resp.name` would incorrectly omit SRV records.
These are observations on Ubuntu's Ethernet interface, not captures of either
Pi's send/receive path. Late observer visibility supports a publication or
multicast-delivery hypothesis; it does not distinguish DUT emission, Pi
reception, caching or interface handling. No CASE or setup correction follows
from this evidence alone.

The October 20 recheck confirms each retained Pi capture directory contains
HCI only, not IP ingress/egress evidence. Earlier registration and fail-safe
republishing do not distinguish no emission, wrong binding, multicast delivery
or receiver processing. The deciding experiment is one original-resolution
window with matched DUT mDNS egress, controller ingress, registration/interface
metadata and resolver entry/result events. Retain the exact instance, interface,
source address, message timing and capture-drop counts; compare each boundary
before assigning a cause. Existing capture permissions/profiles and resource
gates must pass first. No timing-only DNS-SD/CASE fix or new capture framework.

### Smallest Remaining Checks

| Exact Evidence ID | Symptom / Evidence | Hypothesis and Confidence | Deciding Check / Status |
| --- | --- | --- | --- |
| January 2025 iteration 99 | CASE E44918: Sigma3 counter 140688176 at 15:00:19.433; repeated Sigma2 counter 73580410 at 15:00:21.320; final CASESession.cpp:633 timeout. | Failure before CASE completion, high confidence; why Sigma3 was not accepted remains unknown. | Correlate controller capture with responder receive/validation evidence; relevant DUT/OTBR evidence missing. OPEN, investigation owner. |
| January 2025 iteration 78 | CASE E43681 Sigma3 at 14:15:35.228 followed by secure-channel status at 14:15:35.929; native final CommandSender.cpp:343 timeout. Earlier catalog identifies subsequent encrypted CommissioningComplete. | Distinct post-CASE command-progress failure, high confidence in phase, not root cause. | Authenticate command/response capture and responder delivery; missing relevant DUT/OTBR evidence. OPEN, investigation owner. |
| PR528 enabled Ubuntu iteration 36 | Wildcard SubscribeRequest INVALID_ACTION after report/status retransmission and timeout; intended controller/OTBR/DUT network identities agree. | ReportData pretty-print Cluster->Attribute gap83.226 seconds; checksum-verified host global OOM kills20-GB cpptools at recovery boundary. Controller status93.319 seconds after logged receipt; exact blocking mechanism unproved. | Bind controller PID/TID and exact build; monotonic pretty-print/status points, on-stall stack and memory-pressure observations. No timeout/retry change. OPEN, investigation owner. |
| Wi-Fi IP PASE IncorrectState | Native exception alone does not identify protocol phase. | Discovery, initialization and transport/session hypotheses remain distinct. | Exact original call, peer-discovery evidence, PASE headers and native error origin; not an inferred BLE defect. |
| Six BLE-Wi-Fi EATT failures, including a02 subscription | Wrong-bearer ATT replies followed by teardown contradicting advertised CID pairs. | Original bytes plus pinned disconnect handler expose DUT local65 -> controller65; requester ordering reproduces this state. Case B supported; full list scheduling unobserved. | Bounded multi-bearer dual-peer socket observation and correction at the original GATT/notification phase. Hardware remains disk-blocked; all six OPEN. |
| Three BLE-Wi-Fi operational timeouts | Post-provisioning phase, separate from BLE pairing. | IPv6 reachability, publication, DNS-SD and CASE remain distinct. | Actual interface/global address and route at failure, corresponding discovery result and CASE exchange. |
| Native SIGSEGV / prolonged PASE | Crashes and long pending protocol work are distinct observations. | No new independent mechanism established. | Matching core/backtrace/build/faulting callback per crash; last actual protocol/callback progress per hang. |
| Thread/SRP/publication | Timeout does not establish a failed network layer. | Dataset, attachment, address, SRP and delivery remain separate. | Exact peer's dataset fingerprint, SRP record, operational address and routed packet timestamps. |

The January check now binds its controller logs to SHA256
`21c2341f41f0f3675f00a2984bf16e79a2d7dba153da79dd61865dfec064ce3e`
(99) and `8e4fdfccd2c088781896fe26d10a025ad38e897b806e7ed3b240253192a37ea0`
(78). Times above are historical log-local, not newly calibrated UTC.
Repeated Sigma2 does not locate a network drop or prove responder malfunction.

The sealed PR528 iteration-36 archive is unchanged and SHA256-verified:
`e9c504ebc930461d86eb00a5e3061fa92aa56f5dc3f6790f8657845f89cbcbe8`.
On exchange4349 the controller records ReportData164633923 RX at14:46:26.814
and acknowledging StatusResponse111957036 TX at14:48:00.133. DUT order is
report TX, timeout, that status RX, then StatusResponse164633924 TX. The
controller receives the latter at14:48:00.613 and records INVALID_ACTION.
This is not an initial rejection before reporting. Failed iteration36 has34
matched report/status pairs; passing35/37 have88 each, with maximum recorded
intervals0.060/0.054 seconds versus93.319. An adjacent timestamp gap of83.226
seconds lies between controller lines53270/53271. These are historical log
timestamps, not calibrated packet/monotonic traces. Scheduling, processing,
logging and timestamp behavior remain distinct possibilities; no packet-loss
location, fix or original PASS is established.

The12:56 increment verifies the retained companion kernel.log against its
original SHA256SUMS.local entry, SHA256
`170beba30fecaccc86a8817cab237db18baa02221835c33bccba45c226074b95`.
At14:47:59 upowerd invokes OOM; at14:48:00 global OOM kills cpptools with
20,045,124 KiB anonymous RSS, no swap, normal-zone free below low watermark.
This coincides with pretty-print completion/status14:48:00.133. The kernel
stack belongs to upowerd, not the controller. No controller PID binding,
per-thread scheduler/PSI history or monotonic packet timing proves the exact
stall. Host memory pressure is now the leading observed explanation to test,
not an established Matter defect. Source/log categories place the gap in
native ReportData pretty-printing before normal callbacks/status enqueue;
the historical controller binary-to-SDK pin remains unproven. No artificial
OOM reproduction or synthetic logger infrastructure was added.

The standalone Wi-Fi PASE IncorrectState, BLE-Wi-Fi operational failures,
unattributed SIGSEGV/prolonged PASE and original Thread/SRP/routing families
remain candidates for exact dossier-ID correlation, not newly enumerated bugs.
No original OPEN ID was closed or reassigned during this turn. Multiple similar
exceptions are not evidence of independent defects or a shared root cause.
