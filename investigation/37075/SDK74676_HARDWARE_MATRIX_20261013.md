# SDK PR 74676 Hardware Matrix: Issue 37075

## Scope and Status

Requested on 2026-10-13: hardware-test the pushed BLE scanner correction with
at least ten iterations of every applicable matter-qa case for every supported
controller, DUT, and pairing-method combination. The supervised hardware workflow
started at 17:20 UTC and stopped at 23:07 UTC on a capture-ring overwrite.
The original run retained 100 native PASS and zero native FAIL. Ten of those
passes lack complete capture coverage; this is not a fully validated 100-pass
matrix. A fresh continuation started on 2026-10-14 at 00:40 UTC to execute the
remaining 22 sets / 220 slots. The user's latest instruction explicitly requires
continuing available batch work past test, setup, capture, and recovery errors.
The native queue finished at 15:25 UTC on 2026-10-14 independently of VS Code.
After the editor crash, seven already-retrieved recovery outcomes were merged
at 18:05 UTC without rerunning tests. All 320 native outcomes are accounted for:
**295 PASS and 25 FAIL**, with no missing or unstarted slots. Twenty outcomes
are explicitly separate-process recovery, not intact same-process stress.
Failure root-cause investigation remains incomplete; these counts do not
establish a regression in any tested PR.

The intended QA set is [PR 527](https://github.com/CHIP-Specifications/matter-qa/pull/527),
[PR 544](https://github.com/CHIP-Specifications/matter-qa/pull/544), and
[PR 545](https://github.com/CHIP-Specifications/matter-qa/pull/545), together with
[SDK PR 74676](https://github.com/project-chip/connectedhomeip/pull/74676).
The scanner correction was pushed as `24a1bc052a7dfd3db809e43bb0da7c93b20bfad6`.
Exact imported sources, native binary hashes, QA integration changes, and current
published heads must be verified and recorded before any result is attributed
to these revisions. PR 539 is not part of this campaign; its old coordinator
is a fixture-handling reference only.

Published pins verified before launch:

| PR | Head |
| --- | --- |
| QA 527 | `7b285397378d91fe548088f3b98e159aea58ad03` |
| QA 544 | `f0fd44536ea15030131cb8c0d119fd99dd109f8b` |
| QA 545 | `b6d58edc6980397530cc0110eeaf64d8e25b6078` |
| SDK 74676 | `24a1bc052a7dfd3db809e43bb0da7c93b20bfad6` |

QA integration snapshot: `27c32c7589d08bbb189a098acd6f308cc22779cc`, with the
previously authorized, uncommitted QA 544 live Valve LevelStep and QA 527
per-controller intended-write readback follow-ups included explicitly. No new
production QA changes or hidden readiness overrides were added. Each controller
imports an isolated copy of the corrected scanner; native libraries are reused
from the verified earlier Linux BLE-cleanup builds because this SDK correction
changes only Python. This is not a fresh native build of the new SDK head.

## Hardware and Matrix

The Ubuntu host and controller Raspberry Pi are the two controller options.
The separate Wi-Fi Raspberry Pi and Nordic nRF52840 DK are the two DUT options.
The only Thread RCP dongle remains attached to Ubuntu; the existing Ubuntu OTBR
serves both controllers. The controller and DUT Pis must be distinct identities.

| Controller | DUT | Pairing | Iterations per applicable case | Status |
| --- | --- | --- | --- | --- |
| Ubuntu | Nordic DK | BLE-Thread | 10 | All eight sets finished: 80 native PASS |
| Controller Pi | Nordic DK | BLE-Thread | 10 | All eight sets accounted for: 78 PASS / 2 FAIL |
| Ubuntu | Wi-Fi DUT Pi | On-network | 10 | All eight sets accounted for: 69 PASS / 11 FAIL |
| Controller Pi | Wi-Fi DUT Pi | On-network | 10 | All eight sets accounted for: 68 PASS / 12 FAIL |

The initial eight-case inventory is `TC_RT_1_1`, `TC_RT_1_2`, `TC_RT_2_1`,
`TC_Send_Command_Read_Write_Attributes`, `TC_Darwin_Pair`, `TC_Android_Pair`,
`TC_ON_OFF`, and `TC_LEVEL_CONTROL`: 320 planned campaign iterations if all
four cells are supported for all eight cases. Smokes and scanner-specific
hardware checks are additional and must not be double-counted as campaign slots.
All eleven case files were inventoried. Three lack prerequisites on these
fixtures and are excluded, not passed: `TC_RT_2_2` needs a second isolated
Wi-Fi or Thread network; `TC_BDX_OTA` needs a matched provider, requestor and
update artifact; `TC_Bridge_Add_Remove` needs a dynamic bridge DUT rather than
the installed all-clusters images.

BLE-Wi-Fi requires a BLE-enabled DUT image and a safe management path.
Nordic on-network tests require Thread provisioning that survives each test's
reset lifecycle; a factory-reset Thread DUT cannot advertise on IP without a
dataset. Neither condition is assumed satisfied. No same-Pi controller/DUT,
Pi-hosted OTBR, or mismatched BLE-Wi-Fi/Thread transport is included.

Both controllers passed ten native same-process sync/async scanner cycles with
normal scan expiry delivering `done`, not `error`; 19 scanner unit tests also
passed on each controller. Those native cycles found no advertising devices,
so they establish timeout and scanner reuse behavior, not device discovery or
fault coverage. Actual BLE discovery and commissioning are exercised by the
captured Nordic QA cases. Genuine error routing remains covered by unit tests.

Ubuntu's verified adapter was renumbered to `hci1`; it is selected by MAC
identity rather than assuming index zero. The Pi controller remains `hci0`.
The Wi-Fi DUT app hash is
`cbc6f50f2641ec5d93fdf074e2890ce8d5363fe3dce641e325bdfc1ad0ff947b`.

Accounting updates when each cell exits. Pending counters therefore include
active cells that have not yet produced final native accounting; the current
stage identifies what is running. Smokes, incomplete slots and campaign
iterations remain distinct. Long RT_2_1 cases retain their full timeout budget.

## Results

Updated 2026-10-14T18:08:15.418509+00:00; **COMPLETED_WITH_NATIVE_FAILURES**.

| Controller | DUT | Case | Executed | PASS | FAIL | Incomplete |
| --- | --- | --- | --- | --- | --- | --- |
| pi | nordic | TC_RT_1_1 | 10 | 10 | 0 | 0 |
| pi | nordic | TC_RT_1_2 | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_Android_Pair | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_Darwin_Pair | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_LEVEL_CONTROL | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_ON_OFF | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_RT_1_1 | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_RT_1_2 | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_RT_2_1 | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_Send_Command_Read_Write_Attributes | 10 | 10 | 0 | 0 |
| pi | nordic | TC_Android_Pair | 10 | 10 | 0 | 0 |
| pi | nordic | TC_Darwin_Pair | 10 | 10 | 0 | 0 |
| pi | nordic | TC_LEVEL_CONTROL | 10 | 10 | 0 | 0 |
| pi | nordic | TC_ON_OFF | 10 | 10 | 0 | 0 |
| pi | nordic | TC_RT_2_1 | 10 | 8 | 2 | 0 |
| pi | nordic | TC_Send_Command_Read_Write_Attributes | 10 | 10 | 0 | 0 |
| pi | rpi | TC_Android_Pair | 10 | 10 | 0 | 0 |
| pi | rpi | TC_Darwin_Pair | 10 | 10 | 0 | 0 |
| pi | rpi | TC_LEVEL_CONTROL | 10 | 10 | 0 | 0 |
| pi | rpi | TC_ON_OFF | 10 | 10 | 0 | 0 |
| pi | rpi | TC_RT_1_1 | 10 | 9 | 1 | 0 |
| pi | rpi | TC_RT_1_2 | 10 | 0 | 10 | 0 |
| pi | rpi | TC_RT_2_1 | 10 | 9 | 1 | 0 |
| pi | rpi | TC_Send_Command_Read_Write_Attributes | 10 | 10 | 0 | 0 |
| ubuntu | rpi | TC_Android_Pair | 10 | 10 | 0 | 0 |
| ubuntu | rpi | TC_Darwin_Pair | 10 | 10 | 0 | 0 |
| ubuntu | rpi | TC_LEVEL_CONTROL | 10 | 10 | 0 | 0 |
| ubuntu | rpi | TC_ON_OFF | 10 | 10 | 0 | 0 |
| ubuntu | rpi | TC_RT_1_1 | 10 | 10 | 0 | 0 |
| ubuntu | rpi | TC_RT_1_2 | 10 | 0 | 10 | 0 |
| ubuntu | rpi | TC_RT_2_1 | 10 | 9 | 1 | 0 |
| ubuntu | rpi | TC_Send_Command_Read_Write_Attributes | 10 | 10 | 0 | 0 |

Native totals: **295 PASS / 25 FAIL**; 0 slots without native outcomes; 0 unstarted.
Retained original outcomes: 100. New continuation scope: 220. Smokes and scanner probes are separate.
Capture errors, setup failures and retries are retained explicitly; no evidence gap is waived.

## Current Failure Dispositions: 2026-10-16

These dispositions supersede the historical next-fix recommendations below,
not the original **295 PASS / 25 FAIL**, targeted outcomes, capture gaps or
tested source pins. **ADDRESSED** means the identified code defect has a PR
fix; it does not mean merged, retrospectively passed or fully hardware-cleared.

Execution addendum, 2026-10-17: the [targeted Pi full-load comparison](RT12_TARGETED_ATTRIBUTION_20261017.md)
is closed with four executed diagnostic iterations, all FAIL. Baseline/current
and map isolation each failed all 15 read tasks; serialization returned 13 tasks
and raised errors in two, but did not pass the iteration. This demonstrates
concurrency sensitivity, not a full-load fix or equal failure rates. The map
alias defect is independently fixed locally with 107 tests passing. The five
historical generic comparison failures now have exact PR548 metadata/scene
attribution; their original outcomes remain FAIL. Closed evidence is sealed,
capture loss is explicit and the Wi-Fi fixture is released. Nordic endurance
was still the original process at 68/68 PASS in the latest read-only check.

| Recorded Failure / Defect | Current Disposition | Remaining Work |
| --- | --- | --- |
| F02, F14, F25 and T01: SecurePairing reset callback never requested | **ADDRESSED** by [QA550](https://github.com/CHIP-Specifications/matter-qa/pull/550), head `2b0feed`, with [QA549](https://github.com/CHIP-Specifications/matter-qa/pull/549): exclude the unreachable stage in both modes and require observed target plus successful reset | Nine stage/reset unit tests; combined callback/stage smoke plus ten iterations passed 11/11 in the [follow-up ledger](PR539_ITERATION_ACCOUNTING_20261013.md). This newer fix was not in the original matrix. |
| F04-F13, F15-F23 and T02-T11: genuine concurrent native reads time out | **OPEN** | [QA548](https://github.com/CHIP-Specifications/matter-qa/pull/548) addresses invalid comparison/fresh-readback predicates, not these native timeouts. Matched upstream and combined-PR full-load runs still fail before comparison; reduced-cohort success is not full-load clearance. |
| F24: subscription report not received within 120 seconds | **OPEN** | No demonstrated fix for subscription delivery under this load. Do not equate it with the earlier Valve write-verification defect. |
| Secondary cleanup errors in F06/F08/F11/F12/F15/F23 | **ADDRESSED** at the lifecycle/error-preservation layer by [QA527](https://github.com/CHIP-Specifications/matter-qa/pull/527); 52 cleanup regressions | The primary native read failures remain open. Fail-closed termination after incomplete teardown is still intentional; expanded hardware validation remains pending. |
| F03: on-network Wi-Fi PASE Incorrect state | **OPEN** | Not a BLE-scanner path; SDK74676 does not establish its cause or correction. |
| F01: prolonged PASE interrupted by the outer deadline | **OPEN** | The execution-abort attribution is established; the underlying hang is not fixed by changing accounting or increasing the deadline. |
| BLE scanner stop/start error masking and retained local state | **ADDRESSED** by [SDK74676](https://github.com/project-chip/connectedhomeip/pull/74676), current head `6ebed18`; 59 ordinary and nine isolated native tests | Original hardware pins above are unchanged. This is not BlueZ daemon recovery, native protocol recovery or a fix for the original missing CASE response after AddNOC. |
| C01: btmon crash and missing HCI segment | **INSTALLED / LIVE SMOKE VERIFIED** on 2026-10-16; historical loss unchanged | The null-connection correction passed the established privileged installation and real HCI growth/readability/clean-stop gate. This is local capture-tool proof, not endurance coverage or a completed SDK PR fix. See the [new verification record](RT21_ENDURANCE_RT12_INVESTIGATION_20261016.md#pi-capture-gate). |

The [current QA defect dispositions](PR539_FAILURE_ANALYSIS_20261011.md#current-failure-dispositions)
also distinguish the corrected Valve and callback-ownership defects from
unproven historical crash causality. The original investigation below applies
to its recorded source snapshots, not these newer follow-up heads.

The [macOS native lifetime test step](https://github.com/project-chip/connectedhomeip/actions/runs/38905295778/job/116987956577)
passed on current SDK head `6ebed18`. This is additional scanner lifecycle
validation, not a rerun of this hardware matrix or evidence of BlueZ recovery.

## Failure Classification

### Native Failure Investigation

The 25 native FAIL records were decoded and checked against their individual
controller logs. Nineteen Wi-Fi RT_1_2 failures are native `ReadClient.cpp:756`
timeouts (`0x32`) during concurrent reads, not readback-value mismatches. The
remaining Ubuntu Wi-Fi RT_1_2 slot 10 fails waiting 120 seconds for subscription
reports. Three RT_2_1 discovery failures follow a selected `SecurePairing` reset
stage; the other Nordic RT_2_1 failure has no native exception and needs separate
timeout/termination analysis. Pi Wi-Fi RT_1_1 slot 4 fails PASE with `Incorrect
state` (`0x03`). Classification below is refined only where evidence supports a
likely cause; a timeout alone does not establish a tested-PR regression.

| Controller | DUT | Case | Native FAIL |
| --- | --- | --- | --- |
| Controller Pi | Nordic DK | TC_RT_2_1 | 2 |
| Ubuntu | Wi-Fi DUT Pi | TC_RT_1_2 | 10 |
| Ubuntu | Wi-Fi DUT Pi | TC_RT_2_1 | 1 |
| Controller Pi | Wi-Fi DUT Pi | TC_RT_1_1 | 1 |
| Controller Pi | Wi-Fi DUT Pi | TC_RT_1_2 | 10 |
| Controller Pi | Wi-Fi DUT Pi | TC_RT_2_1 | 1 |

### Individual Native Failure Dispositions

Iterations below are campaign slot numbers. Recovery slots keep their original
slot identity, but their native iteration number is 1 in a separate process.
No original FAIL is removed, reclassified as PASS, or replaced by a rerun.

| ID | Controller | DUT | Case | Slot | Symptom | Category | Confidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| F01 | Pi | Nordic | RT_2_1 | 6 | Batch deadline interrupted blocked PASE; no native exception | 3; underlying hang remains 6 | High for abort, low for hang cause |
| F02 | Pi | Nordic | RT_2_1 | 9, recovery | SecurePairing reset target missed; discovery found no device | 4 | High |
| F03 | Pi | Wi-Fi Pi | RT_1_1 | 4 | PASE Incorrect state, 0x03 | 6 | High for symptom, low for cause |
| F04 | Pi | Wi-Fi Pi | RT_1_2 | 1 | Concurrent ReadClient timeout, 0x32 | 6 | High for symptom, low for cause |
| F05 | Pi | Wi-Fi Pi | RT_1_2 | 2 | Concurrent ReadClient timeout, 0x32 | 6 | High for symptom, low for cause |
| F06 | Pi | Wi-Fi Pi | RT_1_2 | 3 | Concurrent read timeout; cleanup also ended the process | 6 | High for symptom, low for cause |
| F07 | Pi | Wi-Fi Pi | RT_1_2 | 4, recovery | Concurrent ReadClient timeout, 0x32 | 6 | High for symptom, low for cause |
| F08 | Pi | Wi-Fi Pi | RT_1_2 | 5, recovery | Concurrent read timeout; cleanup also ended the process | 6 | High for symptom, low for cause |
| F09 | Pi | Wi-Fi Pi | RT_1_2 | 6, recovery | Concurrent ReadClient timeout, 0x32 | 6 | High for symptom, low for cause |
| F10 | Pi | Wi-Fi Pi | RT_1_2 | 7, recovery | TH-15/TH-16 concurrent read timeout | 6 | High for symptom, low for cause |
| F11 | Pi | Wi-Fi Pi | RT_1_2 | 8, recovery | Concurrent read timeout; cleanup also ended the process | 6 | High for symptom, low for cause |
| F12 | Pi | Wi-Fi Pi | RT_1_2 | 9, recovery | Concurrent read timeout; cleanup also ended the process | 6 | High for symptom, low for cause |
| F13 | Pi | Wi-Fi Pi | RT_1_2 | 10, recovery | Concurrent ReadClient timeout, 0x32 | 6 | High for symptom, low for cause |
| F14 | Pi | Wi-Fi Pi | RT_2_1 | 5 | SecurePairing reset target missed; discovery found no advertisement | 4 | High |
| F15 | Ubuntu | Wi-Fi Pi | RT_1_2 | 1 | Concurrent read timeout; cleanup also ended the process | 6 | High for symptom, low for cause |
| F16 | Ubuntu | Wi-Fi Pi | RT_1_2 | 2, recovery | Concurrent ReadClient timeout, 0x32 | 6 | High for symptom, low for cause |
| F17 | Ubuntu | Wi-Fi Pi | RT_1_2 | 3, recovery | Concurrent ReadClient timeout, 0x32 | 6 | High for symptom, low for cause |
| F18 | Ubuntu | Wi-Fi Pi | RT_1_2 | 4, recovery | TH-5/TH-6/TH-9 concurrent read timeout | 6 | High for symptom, low for cause |
| F19 | Ubuntu | Wi-Fi Pi | RT_1_2 | 5, recovery | Concurrent ReadClient timeout, 0x32 | 6 | High for symptom, low for cause |
| F20 | Ubuntu | Wi-Fi Pi | RT_1_2 | 6, recovery | Concurrent ReadClient timeout, 0x32 | 6 | High for symptom, low for cause |
| F21 | Ubuntu | Wi-Fi Pi | RT_1_2 | 7, recovery | Concurrent ReadClient timeout, 0x32 | 6 | High for symptom, low for cause |
| F22 | Ubuntu | Wi-Fi Pi | RT_1_2 | 8, recovery | Concurrent ReadClient timeout, 0x32 | 6 | High for symptom, low for cause |
| F23 | Ubuntu | Wi-Fi Pi | RT_1_2 | 9, recovery | Concurrent read timeout; cleanup also ended the process | 6 | High for symptom, low for cause |
| F24 | Ubuntu | Wi-Fi Pi | RT_1_2 | 10, recovery | Subscription reports did not arrive within 120 seconds | 6 | High for symptom, low for cause |
| F25 | Ubuntu | Wi-Fi Pi | RT_2_1 | 1 | SecurePairing reset target missed; discovery found no advertisement | 4 | High |

#### Targeted Rerun Failures

These are additional outcomes from the separate forty-slot rerun, not replacements
for F01-F25. T01 repeats the established missed-reset defect; T02-T11 remain
unattributed timeout failures. Recovery slots are separate-process native iteration 1.

| ID | Controller | DUT | Case | Slot | Symptom | Category | Confidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T01 | Pi | Nordic | RT_2_1 | 5 | SecurePairing reset target missed; discovery found no device | 4 | High |
| T02 | Pi | Wi-Fi Pi | RT_1_2 | 1 | Concurrent read timeout | 6 | High for symptom, low for cause |
| T03 | Pi | Wi-Fi Pi | RT_1_2 | 2 | Concurrent read timeout | 6 | High for symptom, low for cause |
| T04 | Pi | Wi-Fi Pi | RT_1_2 | 3 | Concurrent read timeout | 6 | High for symptom, low for cause |
| T05 | Pi | Wi-Fi Pi | RT_1_2 | 4 | Concurrent read timeout | 6 | High for symptom, low for cause |
| T06 | Pi | Wi-Fi Pi | RT_1_2 | 5, recovery | Concurrent read timeout | 6 | High for symptom, low for cause |
| T07 | Pi | Wi-Fi Pi | RT_1_2 | 6, recovery | Concurrent read timeout | 6 | High for symptom, low for cause |
| T08 | Pi | Wi-Fi Pi | RT_1_2 | 7, recovery | Concurrent read timeout | 6 | High for symptom, low for cause |
| T09 | Pi | Wi-Fi Pi | RT_1_2 | 8, recovery | Concurrent read timeout | 6 | High for symptom, low for cause |
| T10 | Pi | Wi-Fi Pi | RT_1_2 | 9, recovery | Concurrent read timeout | 6 | High for symptom, low for cause |
| T11 | Pi | Wi-Fi Pi | RT_1_2 | 10, recovery | Concurrent read timeout | 6 | High for symptom, low for cause |

Capture incident C01 is separate: Nordic RT_2_1 segment 015 lost Pi HCI coverage
when BlueZ `btmon` crashed. This is category 3 with high confidence, not a native
test failure. Passing slot 3 overlaps that gap and remains diagnostic context.
The original dispositions total one category-3 abort, three category-4 failures,
and twenty-one category-6 failures; the targeted native dispositions add one
category-4 and ten category-6 failures. No category 1, 2 or 5 attribution has been
established. C01 does not change any native outcome count.

#### Evidence and Attribution

F02/F14/F25 fail after step 5 chooses `SecurePairing`, without the target-reset
callback firing. Successful pairing then leaves the DUT commissioned and not
commissionably advertising. The harness immediately performs commissionable
discovery anyway. Native stage-start delivery begins at `ReadCommissioningInfo`
on the explicit PASE-then-Commission path. This same missed-reset behavior was
reproduced using the pre-QA527 baseline `75b91ea` and the pinned QA527 version,
for both stage-start and stage-completion choices. The earlier investigation is
corroborated by a fresh four-control captured-method probe saved as
`/home/feasel/qa-mar6/sdk74676-analysis-20261014/stage-callback-probe.json`.
This is an offline method-level reproduction, not full hardware A/B testing.
QA545 verifies reset commands that actually execute; it cannot verify a reset
never requested.
This is a pre-existing stage-selection/assertion defect, not clearly in scope of
the current cleanup, XML-constraint, Nordic-readiness or BLE-scanner PRs.

F01 is an execution-induced FAIL: the worker's 18,120-second outer deadline
sent Ctrl+C while the sixth iteration was blocked in native PASE. The controller
log ends in `TestAbortAll` from `handle_ctrl_c`, while the result has no native
exception. The reason native PASE failed to complete is still category 6; simply
increasing the timeout would not establish a fix. Future batch accounting must
mark supervisor-induced outcomes as aborted, distinct from natural test failures,
and retain the native stack and original counter rather than silently dropping it.

F04-F13/F15-F23 reach concurrent reads after multi-controller commissioning and
subscription. Individual controller logs retain native `ReadClient.cpp:756`
timeouts, not the older invalid cross-fabric equality comparison. The Linux DUT
uses fifteen additional controllers here; the controller logs reach roughly
hundreds of MB per iteration and DUT logs include retransmissions and DNS-SD
resource errors. These are observations, not proof that load, logging, the SDK,
or the harness caused the timeouts. F24 instead stops in subscription-report
verification before concurrent reads. Reduced-load or reduced-log controls and
an equivalent baseline are needed before attributing these to a PR or claiming
a methodological fix. No controller-count reduction or timeout exemption has
been used to turn a failure into a pass.

F03 fails PASE on the no-BLE Wi-Fi DUT with `Incorrect state`. That terminal
code alone does not distinguish a transient commissioning-window/readiness
problem from controller or DUT session state. BLE scanner changes are not on
this on-network pairing path; this remains an investigated category 6 failure,
not an established category 1/2 regression.

#### Corrections and Targeted Reruns

No native failure has yet been established as category 1 or 2, so there is no
evidence-backed change to push to those PRs at this point. A separate harness
follow-up for F02/F14/F25 should either drive SecurePairing through the matching
pairing-status callback or exclude unsupported target stages, and must reject
successful commissioning when the selected reset target was never reached.
That would be a new, explicitly scoped fix, not a claim that current QA527 or
QA545 already handles this path.

Category 3 fixes are segmented capture before ring wrap, creation of transfer
destination parents before each transfer, reconciliation from verified native
records, and explicit distinction of aborted versus natural native failures.
These fix evidence/accounting behavior, not the unresolved read or PASE symptoms.
The original result totals stay 295 PASS / 25 FAIL; reruns use a separate namespace.

The affected sets eligible for ten-iteration targeted reruns are Pi-to-Nordic
RT_1_2 (original ring loss), Pi-to-Nordic Send Command/Read/Write (initial result
transfer failure), Pi-to-Nordic RT_2_1 (abort/recovery transfer errors), and
Pi-to-Wi-Fi RT_1_2 (recovery transfer errors). Do not rerun unrelated completed
sets or the category 4/6-only sets as if a fix had been applied. Record actual
rerun execution and outcomes separately before declaring those corrections
hardware-validated.

The requested rerun service `sdk74676-targeted-20261014` was launched on
2026-10-14. Its separate one-iteration Nordic commissioning smoke passed with
native exit zero, complete segmented capture proofs and successful nested result
retrieval. The four ten-iteration sets completed in the order Send
Command/Read/Write, Nordic RT_1_2, Wi-Fi RT_1_2, Nordic RT_2_1, all on the Pi
controller. Native QA/SDK sources, controller counts, interaction expectations,
Thread dataset and installed firmware are unchanged. Final results and the
remaining capture gap are recorded at the end of this document. The smoke is
additional proof, not one of the forty requested rerun slots.

### Recorded Stop: Category 3

The original run had zero native iteration failures. It had one batch
execution failure, classified with high confidence as **category 3: capture
configuration/retention flaw**, not an observed defect in the four tested PRs.

The Pi-to-Nordic `TC_RT_1_2` ten-iteration set returned native process exit zero
with ten PASS records. Its capture ran from 22:25:52 to 23:07:40 UTC. The Ubuntu
helper's bounded 16-file ring retained sequence numbers 4 through 19 in both
the original and retrieved copies: original segments 1 through 3 were
overwritten. Capture validation correctly refused to certify complete coverage,
raising `AssertionError: Missing capture or possible ring overwrite`.

Both original capture helpers stopped normally with child exit zero and no
cleanup errors; the original coordinator and completion-hook services exited.
This is evidence loss from an insufficient whole-set capture budget, not a
native test FAIL or demonstrated protocol regression. Retain all ten native
PASS outcomes, but mark that set's capture coverage incomplete. The other nine
finished sets have complete capture proofs: **90 native PASS with complete
capture proofs, plus 10 native PASS with incomplete capture coverage**.

At the original stop, the remaining six Pi-to-Nordic sets and all sixteen
Wi-Fi-DUT sets were unstarted: 22 sets, 220 slots. The original external seal
contains 1169 files and remains unchanged. Completed native sets, including
the capture-incomplete Pi RT_1_2 passes, are not rerun or double-counted.

### Unattended Continuation

User service `sdk74676-rest220-20261013` executed the remaining work, with the
three long RT_2_1 sets placed after the shorter sets. Each normal ten-iteration
set retains its single controller process and storage. Native failures are
retained, not retried. If a process ends without all native outcomes, recovery
attempts for the missing slots run after other sets and are explicitly marked
as separate-process recovery, not equivalent same-process stress coverage.

Capture rotates after three minutes or eight packet files, before the installed
16-file ring limit. Segment stop/start gaps and failed/missing captures are
recorded; no uninterrupted-capture claim is made. Capture errors do not prevent
native execution or later sets. No privileged-helper policy has changed.
Known Pi workers run in bounded user systemd units; no overlapping worker is
launched while a prior remote worker remains active or its ownership is unknown.
All 314 continuation capture segments have complete proofs. This does not
repair the original run's lost capture segments or remove recorded rotation gaps.

Seven early recovery results were initially missing from the ledger because
the already-running coordinator could not create new local transfer parents.
Their native results and logs were retrieved and cross-checked without reruns;
the retrieval-error placeholders and recovery receipts remain preserved.
Reconciliation waited until the coordinator stopped to avoid racing its in-memory
rows. All twenty missing original slots now have native recovery outcomes.

New private results are in `/home/feasel/qa-mar6/sdk74676-rest220-20261013` and
its corresponding Pi directory. Its combined ledger retains the original 100
outcomes and adds only continuation outcomes. Per-set errors are retained
privately, while the Results section updates automatically. Service
`sdk74676-rest220-20261013-completion` watches completion without polling and
seals the final evidence. Campaign-only key cleanup requires all native slots
finished and no outstanding Pi worker. Successful detailed logs are pruned only
after verified native PASS accounting and readable, non-overwritten segment
proofs; failed sets and incomplete captures retain their detailed evidence.

Each actual failure will include its cell, native iteration, exception and
supporting evidence, confidence, and one of these classifications:

1. Likely introduced by the current unmerged code changes.
2. Likely a harness or SDK flaw that the current open PRs or intended work
   should have fixed but did not.
3. Likely a batch-execution or fixture-configuration flaw, not a harness PR defect.
4. Likely a pre-existing harness flaw, not clearly in scope of an existing PR.
5. Likely a pre-existing SDK flaw, not clearly in scope of an existing PR.
6. Uncertain; requires deeper investigation.

Setup failures, interrupted slots, and native iteration failures are reported
separately. No timeout alone establishes a stale-session or SDK regression.

## Evidence and Retention

### Verified Failure Preservation and Success Pruning

Private analysis artifacts are under
`/home/feasel/qa-mar6/sdk74676-analysis-20261014`:

- `failure-index.json` maps F01-F25 to each native summary, decoded exception,
   slot/recovery identity and original failed-file SHA-256 entries.
- `stage-callback-probe.json` records the baseline/pinned four-control reset
   reproduction. The runtime evidence for F02/F14/F25 also confirms the selected
   callback never fires before successful commissioning and failed discovery.
- `success-retention-receipt.json` retains compact proof for all 320 outcomes
   plus hashes of the 377 success-only files deleted locally: 1,441,845,409 bytes.
- `pi-success-retention-receipt.json` records 618 success-only files deleted on
   the controller Pi: 1,619,866,432 bytes. Remote native PASS records were checked
   before deletion; the retained ledger is not counted a second time.
- `protected-success-hci.json` lists 53 success-only root-owned HCI originals,
   totaling 5,292,856 bytes, that remain because the installed helper has no prune
   capability. Deleting those requires an administrator-approved helper action;
   no arbitrary privileged deletion or policy expansion was performed.

All 75 failed-iteration files remain locally and were verified against the
original seal after pruning. All 42 failed-iteration files on the Pi also passed
before/after checksum verification. Failed-set shared consoles, traces, metadata,
captures and diagnostic state remain: shared files can include successful setup
or control traffic and are retained as failure evidence, not success-only logs.
Standalone successful-run details were checked separately; none remained for
additional deletion. Compact native result records and immutable provenance
remain. The original seals were not rewritten: deletion receipts explain their
intentionally absent success-only files, while every failed-file hash stays valid.
Total additional space reclaimed is 3,061,711,841 bytes (about 2.85 GiB).

New private run data belongs outside the Git tree, under a fresh campaign root
in `/home/feasel/qa-mar6/`. Keep compact immutable result/provenance records
for successful iterations, then delete their detailed logs and traces once
accounting and capture cleanup are verified. Preserve failure logs, relevant
capture windows, native records, hashes, and enough adjacent context to classify
the failure. Do not prune unrelated or active campaigns.

This Markdown report is deliberately uncommitted and must appear dirty in the
workspace Git status. No raw trace, credential, controller storage, or Thread
dataset is to be added to the Git tree or exposed in this report. The shared
OTBR dataset and RCP remain unchanged; capture uses the installed profile-based
noninteractive helper, with one owner per shared resource.

User services `sdk74676-hardware-20261013` and
`sdk74676-hardware-20261013-closure` supervise execution and event-driven
finalization independently of VS Code. Finalization restores hashed immutable
PASS accounting, prunes permitted successful packet originals, seals retained
evidence, and removes the two exact campaign-only DUT key authorizations after
a fully executed matrix. Incomplete campaigns retain credentials for recovery.
Successful copied traces are pruned after verified capture cleanup; root-owned
Pi capture originals remain protected because the installed helper has no prune
action. No privilege-policy changes are made to bypass that boundary.
## Targeted Methodology Reruns


Updated 2026-10-15T01:35:56.996297+00:00; **TARGETED_RERUN_COMPLETED_WITH_FAILURES**.

Separate reruns of four category-3-affected sets; original 320 outcomes unchanged.
Same pinned production code; transfer parents and segmented capture corrected.
Supervisor-induced aborts are reported separately, not as natural protocol failures.

| Controller | DUT | Case | Executed | PASS | Native FAIL | Aborted |
| --- | --- | --- | --- | --- | --- | --- |
| pi | nordic | TC_RT_1_2 | 10 | 10 | 0 | 0 |
| pi | nordic | TC_RT_2_1 | 10 | 9 | 1 | 0 |
| pi | nordic | TC_Send_Command_Read_Write_Attributes | 10 | 10 | 0 | 0 |
| pi | rpi | TC_RT_1_2 | 10 | 0 | 10 | 0 |

0 requested slots without outcomes. Private evidence: `/home/feasel/qa-mar6/sdk74676-targeted-20261014`.
Recovery process lifetimes, capture rotation gaps and any infrastructure errors remain explicit.

### Verified Targeted Completion

All 40 requested slots have native outcomes: **29 PASS / 11 FAIL**, with zero
supervisor-induced aborts and zero missing slots. The separate one-iteration
methodology smoke passed and is not included in those totals. The original
320 outcomes remain unchanged at 295 PASS / 25 FAIL.

- Pi-to-Nordic command/read/write and RT_1_2 each passed 10/10.
- Pi-to-Nordic RT_2_1 passed 9/10. Slot 5 selected a reset during
   `SecurePairing`, never reached the target callback, completed commissioning,
   then failed commissionable discovery. This repeats the established category-4
   harness gap; it does not establish a new PR regression.
- Pi-to-Wi-Fi RT_1_2 failed all ten slots with concurrent-read timeout
   signatures. Slots 1-4 ran in the original process; slots 5-10 ran in six
   separate recovery processes after that process ended. These remain category 6;
   ten accounted outcomes do not constitute ten uninterrupted stress iterations.

All 2,192 originally sealed files, totaling 9,493,712,089 bytes, passed checksum
verification before additional retention cleanup. All 40 outcomes and the
separate smoke were checked against controller-Pi native summaries. Campaign
keys were revoked, no campaign workers or helper captures remained active on
either host, and the UART relay released the Nordic port.

### Remaining Capture Gap

Of 106 segmented capture proofs, 105 are complete. In Nordic RT_2_1 segment
015 (`r220-20261014-224451-015`), Pi `btmon` exited with signal 11 shortly after
starting at 2026-10-14 22:44:51 UTC. The segment ended at 22:47:52 UTC. Ubuntu
packet capture continued successfully; the Pi HCI proof remains incomplete.
The failed proof was not rewritten as successful. Its original HCI file and
capture status were retrieved and retained. Nordic RT_2_1 slot 3, a passing
iteration overlapping the capture failure, is retained as diagnostic context.
Normal segment stop/start gaps also remain explicitly recorded.

This is a category-3 capture-tool failure, separate from the eleven native
test failures. The affected set is not fully capture-verified. A capture-tool
correction has been prepared and regression-tested as described below; its
administrator installation and live verification remain pending. No production
PR, privilege policy, firmware, or dataset was changed to bypass this failure.

### Capture Tool Correction

C01 is reproducible offline on the verified controller Pi. The retained 673-byte
trace starts mid-connection; its sixteenth record is an ATT Read By Type request.
BlueZ 5.66's `att_read_type_req` passes an absent connection to
`att_get_conn_data`, which dereferences it. A debugger confirms SIGSEGV in the
decoder. Display, priority, color and time options do not avoid the crash.

A standalone build of the matching upstream BlueZ 5.66 release reproduced the
crash in all ten replays. Adding a null-connection check before that call passed
all ten replays of the identical trace on the same Pi. This skips only unavailable
decoder state; the monitor writes raw HCI records before decoding them. No capture
filter or packet content was changed. The distribution Bluetooth daemon and
`/usr/bin/btmon` remain untouched.

The personal capture-helper source also now checks child survival before and
after a one-second startup window, before declaring readiness. Its fixed Pi
capture executable is `/usr/local/bin/btmon`, which must be administrator-owned
and protected under the existing trust checks. All twenty helper security and
lifecycle tests pass. No additional helper action, sudo permission, interface,
capability, recovery operation or automatic restart was added.

Private source, replay results, hashes and administrator installation instructions
are staged under `/home/feasel/qa-mar6/btmon-capture-fix-20261015` on Ubuntu and
`/home/feasel/btmon-capture-fix-20261015` on the controller Pi. On 2026-10-16,
the established privileged installation completed without changing the profile,
capability or privilege scope. A fresh real-HCI capture grew from 292 to 731
bytes, decoded eight HCI records and stopped with child exit 0; the production
Bluetooth daemon PID was unchanged. The retrieved raw capture matches its receipt
hash. See the [live gate and pending endurance scope](RT21_ENDURANCE_RT12_INVESTIGATION_20261016.md#pi-capture-gate).
The original failed trace, 105/106 complete proofs, native totals and seals are
unchanged; an offline replay cannot repair historical capture loss.

### Targeted Retention

Post-run receipts preserve the original seal and compact native outcomes while
recording deletion of 52 local success-only files (101,679,391 bytes) and 132
controller-Pi success-only files (960,350,878 bytes). All 33 failed-iteration
files plus three files for the capture-affected passing control remain on each
host and passed before/after hash checks. Shared failed-set consoles, traces,
captures and UART context remain. Twenty additional root-owned success-only Pi
HCI originals, totaling 48,635 bytes, were inventoried but not deleted.

Private receipts are `post-run-retention-receipt.json` and
`pi-post-run-retention.json` under the targeted root. They explain intentional
success-only deletions without modifying the original `final-seal.json`.
