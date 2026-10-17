# RT_2_1 Endurance and RT_1_2 Investigation

Execution update, 2026-10-17: [targeted RT_1_2 attribution](RT12_TARGETED_ATTRIBUTION_20261017.md)
records the completed Pi baseline/current/map-isolation/serialized-read set:
four executed iterations, four FAIL, no incomplete slots. Serialization changed
read-task errors from 15/15 to 2/15 but did not pass the test. The map alias has
a demonstrated fix published in PR548 `e8fcf30` and two added regressions;
all 107 tests pass. The active endurance snapshot retains `a550450`.
All five generic historical mismatches now have exact metadata/scene references.
The separate Wi-Fi fixture and capture closed cleanly, with packet loss and
unverified authenticated decoding retained as limitations. The Nordic run was
not interrupted: original PID/start identity, 76 executed, 75 PASS, one FAIL and
24 unexecuted at 15:39 UTC. Iteration 75 failed in initial step-2 PASE
establishment, before selecting a reset target; its evidence and preceding
control are sealed. Iteration 76 passed; its closed successor evidence is
sealed separately. All 75 selected reset targets have matching callbacks;
457 closed capture segments have clean closure proofs. Reset acknowledgment
and gap-free capture coverage remain unproved. A separate serial response-shape
probe completed with FAIL; its diagnostic verifier missed a cache-update
precondition. The corrected separately counted probe also failed its two reads,
but all 13 returned mappings passed 29 fresh written-value checks each. Both
Pi attempts closed with exact fixture/key cleanup. Neither affected Nordic.
The original status and plan below remain historical, not current pending work.

Status as of 2026-10-16T16:48:47Z. This is a new verification effort, not a
continuation or recount of the closed matrices. Raw evidence, controller storage,
datasets and capture files remain private under `/home/feasel/qa-mar6`.

## Native Endurance

Ubuntu controller to Nordic DK: the captured, one-iteration native RT_2_1 smoke
passed with exit 0 at 16:43:57Z. Its seven capture segments closed successfully;
offline decoding found 60,476 frames, including 2,450 BLE ACL and 682 IPv6
packets. Segment boundaries are retained; this is not gap-free or authenticated
Matter-decryption proof.

The 100-iteration RT_2_1 process then started. Native PID `1421846` has matching
recorded start ticks; supervisor service `rt21-endurance-20261016.service` owns
its worker and UART relay. At the status timestamp, **0/100 completed**, with no
native FAIL recorded. The smoke is separate and is not iteration 1 of this set.
Live accounting and eventual closure are in the private campaign root:
`/home/feasel/qa-mar6/rt21-endurance-20261016`.

Both iteration-count fields are 100. Normal factory resets, assertions and
interaction timeouts are unchanged. A separate 1,800-second no-completed-iteration
watchdog, bounded overall service lifetime, capture health checks and 8 GiB disk
reserve can interrupt the run. An interruption, native FAIL, native process exit,
capture defect and unexecuted slot are recorded separately. No automatic recovery
process contributes to the 100-count result. Python fault dumps and inherited
core limits are enabled; host Apport routing does not guarantee a retrievable
native core/backtrace. Endurance success will not establish historical SIGSEGV
causality.

A separate bounded `rt21-closeout-20261016.service` observer leaves the active
source untouched. After the run service closes, it writes
`external-closeout.json`, separates post-interruption native outcomes from
pre-interruption accepted outcomes, and stops only an orphaned capture identified
by this campaign's own start receipt. Such a segment remains coverage-incomplete;
cleanup does not certify lost coverage. Three focused accounting checks pass.

The DK remains J-Link `001050208117`; the separate RCP remains
`8388F563A730D925`. UART boot logs contain the DUT security-test-mode warning.
The live complete Thread dataset fingerprint matches the established fixture.
No firmware, OTBR, dataset or production SDK change was made.

| QA PR | Published Head Used |
| --- | --- |
| 539 | `b99759a62df56be3f5d5c5dd9505db0eb3760f58` |
| 547 | `6e93374eeec7cc7170f066bc257250fb0f222707` |
| 548 | `a5504501078b50ecf71ad70aa84d9d8415f5af43` |
| 549 | `dbab50bc77e8f596eec82023cb7627377989df13` |
| 550 | `2b0feed0f2ee5dd789ba131f62112c32a8019902` |

The fresh immutable combined source passed all 164 existing five-PR regression
tests. PR550 supplies the shared RT_2_1 implementation including PR549's callback
changes; both regression suites are retained. The previously verified scanner
and native runtime are held constant and re-hashed, not freshly rebuilt from the
latest SDK head. Ubuntu native SHA-256 remains
`01ccbe6c4b2f6c6c17a275b409ffe1ae61b652dbb687bc8cb89181ae4b23079a`.

Next physical runs, not yet launched: Pi to Nordic 100, Ubuntu to Wi-Fi Pi 100,
then Pi to Wi-Fi Pi 100. They must acquire the fixture serially and verify their
own source/runtime/DUT identities. No competing hardware test is running.

## Full-Load Wi-Fi Evidence

All four retained upstream/PR runs used 15 additional controllers. The private
`rt12-investigation-20261016/full-load.json` retains exact source-log hashes,
line references, timestamps as logged, controller order and event categories.

| Original Run | Preceding Subscription State | First Read Failure | Native Result |
| --- | --- | --- | --- |
| baseline-1 | 120-second report timeout; four controllers missing reports | Read barrier not reached | FAIL |
| current-1 | All reports arrived after 110.18 seconds | TH-2, 163.084 seconds after read barrier; 14/15 reads failed | FAIL |
| current-2 | All reports arrived after 116.21 seconds | TH-3, 141.849 seconds after read barrier; 14/15 reads failed | FAIL |
| baseline-2 | All reports arrived after 105.17 seconds | TH-2, 151.564 seconds after read barrier; 15/15 reads failed | FAIL |

The three read windows contain approximately 227-254 MB and 1.88-2.10 million
log lines, dominated by native Automation (`ATM`) and `DMG` output. Resubscription
attempts occur in the retained runs. These are measured correlations, not proof
of logging starvation, resource exhaustion, packet loss or an SDK regression.
Expected `UnsupportedRead` decode-status messages are excluded from read-task
failure classification. The extractor has eight focused regression checks.

The retained DUT logs also distinguish normal packet-chunk rollback from actual
resource/transport errors. In `current-2`, there are 1,790 packet-boundary
rollbacks, 96 DNS-SD parse `No memory` errors and three overlapping-CASE Busy
replies. The inspected resolver returns that error when its fixed address array
is full; these messages do not establish host heap exhaustion. Upstream logs
contain the same categories. Their first original line/epoch references and log
hashes are in private `dut-transport.json`; fresh cross-host clock calibration
and packet-level causality are still required.

The five-PR snapshot calls the old shared
`cleaning_up_the_paired_controller` from RT_1_2's `finally`. Its exception handler
calls `mark_iteration_failure_sync_mobly_and_summary_data` and raises
`TestCaseExit`, replacing the primary failure. Published QA527
`bd92c969f862251c01456df41c5ad56851324402` changes that exact helper, but is not
in this snapshot. No duplicate cleanup fix was introduced; a future integration
must verify primary-error preservation through the actual RT_1_2 call path.

Controlled experiments remain unexecuted: additional-controller cohorts
2/4/8/12/15; fixed 15 with serialized or bounded-batch reads; fixed 15 with
subscription activity changed; fixed 15 with logging overhead changed. Change
one factor per comparison, retain the native workload/settings as the control,
record CPU/RSS/FD, retransmission and capture-loss data, and align clocks before
cross-host timing conclusions. Reduced cohorts are diagnostic only. Acceptance
still requires the original 15-controller workload, assertions and interaction
timeouts. A matched Pi-controller upstream/PR comparison is also pending.

## Demonstrated Aliasing

The actual mapping method deep-copied once and assigned the same nested mutable
map to every controller. A real subscription callback changed a sibling's
attribute value. Two new regressions failed on the original helper and passed
when the deep copy was moved inside the controller loop. All 166 existing-plus-
new tests pass in `/home/feasel/qa-mar6/rt12-alias-candidate-20261016`.

This narrow candidate is not published and is not installed in the active
endurance source. It repairs map isolation only; it does not establish the cause
of the native read/subscription timeouts or any historical failed outcome.

## Exact Historical Reconciliation

All five original comparison FAILs retain their IDs and outcomes. Their logged
paths now match demonstrated PR548 rules, so only these mechanisms are
**ADDRESSED**, not reclassified as historical PASS:

| Failure ID | Iteration | Exact Logged Path and Original Log Lines |
| --- | ---: | --- |
| `2dc88704967e9345` | smoke 1 | Endpoint 1, Identify cache `matter.clusters.Attribute.DataVersion`: 780854, 780857, 780859 |
| `6ec3f8548b8a83e9` | 2 | Endpoint 1, ScenesManagement.FabricSceneInfo: 778955, 778958; Identify cache DataVersion: 778960 |
| `0d6bf96729f5927d` | 3 | Endpoint 1, Identify cache DataVersion: 780082, 780084, 780086 |
| `81d2781f125d012e` | 8 | Endpoint 1, Identify cache DataVersion: 777552, 777555, 777557 |
| `bb57845dfbe57338` | 9 | Endpoint 1, Identify cache DataVersion: 777203, 777206, 777208 |

Current controls include `test_cache_versions_do_not_change_attribute_equality`
and `test_fabric_scene_info_may_differ_across_fabrics`, plus same-fabric,
missing-value, real-attribute-difference and malformed-value negative controls.
Original log paths and line numbers are retained in the private
`historical-five-paths.json` and the
[failure dossier](../pr539-failure-evidence/FAILURES.md).

All 66 older Ubuntu BLE outcomes (55 PASE IncorrectState, 11 empty discovery)
selected `--ble-controller 0`. The later working fixture explicitly resolves
`hci1` by MAC. This supports fixture-selection attribution, not proof of every
historical adapter enumeration or a scanner defect. No new scanner repair was
started. The five BLE-Wi-Fi GATT/service failures remain separate from three
operational IPv6/DNS-SD/CASE timeouts and one BlueZ subscription failure. The
isolated on-network PASE IncorrectState and supervisor-interrupted Nordic PASE
hang remain separate unresolved incidents.

## Pi Capture Gate

The established privileged installation procedure completed on the verified
controller Pi. Installed root-owned `/usr/local/bin/btmon` SHA-256 is
`8993b38f627eed04eac06dab481d879d5c52efab875169808060e26fcb8feb63`.
The existing helper verifies `controller-hci`; no profile, privilege scope,
capability, production BlueZ daemon or `/usr/bin/btmon` change was introduced.

At 16:35:00-16:35:01Z, a fresh owned Pi HCI discovery capture grew from 292 to
731 bytes, decoded eight real HCI records, and stopped with child exit 0 and no
helper error. Bluetooth daemon PID stayed `1341075`. Retrieved raw capture
SHA-256 matches the receipt:
`34018b42e96aba4773111e5344b1376f442fe9dd52a5dc924a1957c6e828b90e`.
Private source/receipts are in `btmon-capture-fix-20261015/live-20261016`.

This clears the installed/live-smoke gate, not endurance capture coverage or
historical C01 loss. The original 105/106 complete proofs and all native totals
remain unchanged.