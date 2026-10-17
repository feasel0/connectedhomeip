# PR539 and PR547-550 Full Matrix: Issue 37075

## Current Resolution

Execution update, 2026-10-17: [targeted Pi attribution](../37075/RT12_TARGETED_ATTRIBUTION_20261017.md)
completed separately from the untouched Nordic endurance campaign. All four
diagnostic iterations failed. Baseline/current/map-isolation failed all 15
reads; serialization returned 13 tasks and raised errors in two. Evidence is
sealed and that fixture attempt closed. Exact historical metadata/scene
attribution and map isolation published in PR548 `e8fcf30` are documented there.
A separate single-iteration serial response-shape diagnostic failed with three
read errors and 12 returned mappings; its value-verifier observer had a
cache-update precondition defect. The corrected separately counted probe also
failed, but its 13 returned mappings each passed 29 fresh written-value checks.
Both attempts are closed. Neither is included in the four original attempts;
the six combined attempts are six native FAILs, not a successful matrix.
This does not clear full-load reliability.

Reconciled 2026-10-16. **FIXED** describes a defect repaired in a published PR,
not a retrospective PASS or an upstream merge. **OPEN** identifies remaining
investigation. The original matrix is closed at 302/320 executed, 300 PASS,
two FAIL and 18 unexecuted; the four failed full-load A/B runs and three
supplemental smokes are separate. The campaign pins below are historical,
not the latest PR heads.

| Failure / Incident | Current Status | Fix or Remaining Work |
| --- | --- | --- |
| Original Ubuntu/Wi-Fi-Pi RT_1_2 read timeout, then unpair timeout | **OPEN** | Primary reads fail before the comparator. Upstream reproduces the family; exact harness/SDK/fixture ownership and cleanup masking are unresolved. Not fixed by PR548. |
| Original Pi-controller/Wi-Fi-Pi RT_1_2 read timeout, then unpair timeout | **OPEN** | Matched Pi baseline/current both failed all 15 concurrent reads; map isolation alone did not repair it. Serialization returned 13 tasks and failed two, but the iteration still failed. Exact ownership and comparative frequency remain unresolved. |
| Full-load A/B: baseline subscription-report timeout | **OPEN** | Four of 15 controllers lacked all 29 reports; investigate subscription delivery under load. No demonstrated PR fix. |
| Full-load A/B: concurrent-read timeouts and later cleanup masking | **OPEN** | Reproduced on baseline and PR snapshot before comparison; preserve primary error and determine load/transport/fixture ownership. |
| First small-cohort smoke: live Wi-Fi PacketUnicastRxCount rejected | **FIXED** | PR548 `a550450`: explicit nullable uint32 traffic-counter policy; focused negative controls and final physical smoke pass. |
| Wi-Fi-only smoke: Ethernet TimeSinceReset rejected | **FIXED** | PR548 `a550450`: measured elapsed-time bound plus explicit uint64 packet-counter domains; final physical smoke passes. |
| Missing fresh written readback could reuse a matching cache | **FIXED** | PR548 `91c7269`, retained in `a550450`: per-controller fresh presence/decode/value checks. Final smoke records two verifier returns, 29 successful attributes each. |
| Launch 1 missing isolated fixture dependency | **RESOLVED (campaign-only)** | Coordinator explicitly loads the existing dependency; four coordinator tests and the completed matrix verify recovery. Not a production PR fix. |
| Three Pi controller-HCI capture-stop failures | **OPEN** | Capture children exited `-11`; historical evidence collection failed. Later clean Ubuntu captures do not repair those failures or establish the Pi cause. |

The [review resolution](PR_REVIEW_20261013.md#current-resolution) marks R1-R5,
Valve generation, unreachable stage selection and the other published fixes
as **FIXED**, with commit/evidence references. The [historical failure queue](FAILURES.md#remaining-work)
retains the still-open BLE and native-crash investigations. The five formerly
generic corrected-rerun read failures now have verified metadata/scene attribution.

Remaining coverage gaps are not extra failed iterations: matched Pi-controller
failure-frequency comparison, no physical multi-entry Thread-table churn, unverified
authenticated Matter packet decryption, and the excluded fixture capabilities
listed below. Neither a corrected small-cohort PASS nor green CI resolves
full-load reliability. Original outcomes and raw evidence are unchanged.

## Status

Fresh matrix requested on 2026-10-14. Preparation started with zero new hardware
outcomes; live results below are authoritative as execution proceeds.
Historical campaigns are not included in this campaign's counts.

Protocol: `/home/feasel/Documents/prompts/Testing assets.md`.
Ten iterations per applicable case, controller, DUT, and commissioning method.
Ubuntu hosts the single existing OTBR and Thread RCP throughout.

## Published Pins

| PR | Head |
| --- | --- |
| QA 539 | `1eba744fd0b9ad60cdf2a89c73e5d1b4684e6b09` |
| QA 547 | `6e93374eeec7cc7170f066bc257250fb0f222707` |
| QA 548 | `9a003ab5cd7852ee407dd90b97791b806d7aabb3` |
| QA 549 | `dbab50bc77e8f596eec82023cb7627377989df13` |
| QA 550 | `2b0feed0f2ee5dd789ba131f62112c32a8019902` |

Live GitHub heads matched clean local worktrees before preparation. The combined
source snapshot, imported source paths, SDK runtime, firmware and dataset proof
must be recorded separately; a QA pin alone does not prove those prerequisites.

## Planned Coverage

Expected baseline: eight applicable cases across four cells, ten iterations per
set, 320 campaign slots. Final applicability is checked against the actual
snapshot and installed DUT capabilities before launch.

| Controller | DUT | Commissioning |
| --- | --- | --- |
| Ubuntu | Nordic nRF52840 DK | BLE-Thread |
| Controller Pi | Nordic nRF52840 DK | BLE-Thread |
| Ubuntu | Separate Wi-Fi DUT Pi | On-network |
| Controller Pi | Separate Wi-Fi DUT Pi | On-network |

Cases: RT_1_1, RT_1_2, RT_2_1, Send_Command_Read_Write_Attributes, Darwin_Pair,
Android_Pair, ON_OFF and LEVEL_CONTROL. Smokes, reruns, incomplete slots and
separate-process recovery are reported separately, never substituted for a
completed same-process ten-iteration set.

The pinned inventory contains 11 scripts; all eight planned entry-point paths
exist, including the case-sensitive `TC_Level_Control.py` path. Three scripts
are explicitly skipped for the current four fixture cells, not counted as PASS:

| Script | Missing Prerequisite |
| --- | --- |
| RT_2_2 | Thread path changes network, on-mesh prefix and OTBR state; no second OTBR/RCP is deployed. On-network path requires configured Ethernet/static-network mutation; the configured Ethernet link on the Wi-Fi DUT is not active. |
| BDX_OTA | Configured OTA provider and image artifacts are absent; no matched provider/requestor/update fixture is provisioned. |
| Bridge_Add_Remove | Both provisioned DUTs are all-clusters applications, not a controllable dynamic bridge fixture. |

Private exact inventory, nested configuration-presence and Ethernet checks are
recorded in `live-fixture-context.json` and `excluded-prerequisites.json`.
BLE-Wi-Fi and Nordic on-network remain outside the available reset/commissioning
fixtures; they are not silently substituted for the four exercised cells.

## Failure Disposition

Preserve each failure as it appears and investigate during the remaining batch.
New failures default to category 6 until deciding evidence supports attribution.

1. Likely introduced by the five unmerged PRs.
2. Likely harness or SDK flaw that belongs within an open PR's intended scope.
3. Likely batch execution or fixture-handling flaw, rather than production code.
4. Likely pre-existing harness flaw outside the open PRs' scope.
5. Likely pre-existing SDK flaw outside the open PRs' scope.
6. Uncertain; deeper investigation needed.

Record each failure's case, topology, iteration, symptom, evidence location,
category, confidence and disposition. In-scope fixes require a focused regression,
validation, and a push only to the existing appropriate feasel0 fork branch.
Original failures remain failures after a corrected rerun. Never mutate an active
campaign's source snapshot to introduce a fix.

## Retention

Keep summaries and success counts. After each closed set, delete exclusive
successful-iteration logs, captures, storage and archived duplicates. Retain
failed, interrupted, cleanup-failed, uncertain and shared failure evidence.
Private logs and traces remain outside the repository; this summary remains an
uncommitted dirty file. Preserve existing user-edited historical reports.

## Current Checks

Prelaunch Nordic MCP inventory identified DK `001050208117` and separate RCP
`8388F563A730D925`. The DUT UART was free, the existing OTBR reported leader,
and the installed thread-lab capture policy verified. Free host disk was 26 GiB;
the coordinator enforces an 8 GiB boundary before starting each new set.

Preparation passed 134 focused tests on Ubuntu and 134 on ARM64. The integration
uses the exact published PR539 base, PR547 and PR548 files, and PR550's reset and
callback ownership implementation exercised by PR549's callback controls.
No unpublished production QA overlay is included.

Private campaign root: `/home/feasel/qa-mar6/pr539-five-matrix-20261014`.
Both controllers import isolated copies of the already-verified scanner/runtime.
The fixed SDK scanner correction is held constant and is not one of these five
QA PRs. Native library hashes and security-test-mode strings verified on both
hosts; this is runtime reuse, not a new SDK or Nordic firmware build.

Retry 2 runs under the supervised named user service. The independent evidence
watcher verifies immutable first-observed failure snapshots with SHA-256 and
references matching retained capture segments; these live snapshots are not
represented as final run or gap-free packet seals. Both Pis report synchronized
clocks; measured offsets are bounded by their recorded SSH round-trip uncertainty.
The complete live Thread dataset hash matched the expected fixture before launch.

No native failure or PR fix was observed during preparation. New PR fixes must
be validated independently and recorded against their own revision before push.

## Launch Failure Preservation

Launch 1 failed before native execution: `ModuleNotFoundError` while importing
the isolated fixture suite's `run_readiness_batch` dependency. Category **3**:
campaign packaging, not a production QA or SDK failure. Zero of 320 slots ran.
The original supervisor traceback, launch/source proof, and zero-outcome ledger
are retained privately under `launch-attempts/01`. The inactive coordinator now
loads the established fixture dependency explicitly; its actual suite-construction
regression passes with all **4 coordinator tests**. The five QA pins are unchanged.
## Live Results


Updated 2026-10-15T18:37:48.949696+00:00; **CLOSED**.

Campaign: 302/320 executed, **300 PASS / 2 FAIL**.
Private evidence: `/home/feasel/qa-mar6/pr539-five-matrix-20261014`. Supervisor: `pr539-five-matrix-20261014.service`.

| Controller | DUT | Case | Executed | PASS | FAIL | Process Exit |
| --- | --- | --- | --- | --- | --- | --- |
| pi | nordic | TC_Android_Pair | 10 | 10 | 0 | 0 |
| pi | nordic | TC_Darwin_Pair | 10 | 10 | 0 | 0 |
| pi | nordic | TC_LEVEL_CONTROL | 10 | 10 | 0 | 0 |
| pi | nordic | TC_ON_OFF | 10 | 10 | 0 | 0 |
| pi | nordic | TC_RT_1_1 | 10 | 10 | 0 | 0 |
| pi | nordic | TC_RT_1_2 | 10 | 10 | 0 | 0 |
| pi | nordic | TC_RT_2_1 | 10 | 10 | 0 | 0 |
| pi | nordic | TC_Send_Command_Read_Write_Attributes | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_Android_Pair | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_Darwin_Pair | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_LEVEL_CONTROL | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_ON_OFF | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_RT_1_1 | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_RT_1_2 | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_RT_2_1 | 10 | 10 | 0 | 0 |
| ubuntu | nordic | TC_Send_Command_Read_Write_Attributes | 10 | 10 | 0 | 0 |
| pi | rpi | TC_Android_Pair | 10 | 10 | 0 | 0 |
| pi | rpi | TC_Darwin_Pair | 10 | 10 | 0 | 0 |
| pi | rpi | TC_LEVEL_CONTROL | 10 | 10 | 0 | 0 |
| pi | rpi | TC_ON_OFF | 10 | 10 | 0 | 0 |
| pi | rpi | TC_RT_1_1 | 10 | 10 | 0 | 0 |
| pi | rpi | TC_RT_1_2 | 1 | 0 | 1 | 1 |
| pi | rpi | TC_RT_2_1 | 10 | 10 | 0 | 0 |
| pi | rpi | TC_Send_Command_Read_Write_Attributes | 10 | 10 | 0 | 0 |
| ubuntu | rpi | TC_Android_Pair | 10 | 10 | 0 | 0 |
| ubuntu | rpi | TC_Darwin_Pair | 10 | 10 | 0 | 0 |
| ubuntu | rpi | TC_LEVEL_CONTROL | 10 | 10 | 0 | 0 |
| ubuntu | rpi | TC_ON_OFF | 10 | 10 | 0 | 0 |
| ubuntu | rpi | TC_RT_1_1 | 10 | 10 | 0 | 0 |
| ubuntu | rpi | TC_RT_1_2 | 1 | 0 | 1 | 1 |
| ubuntu | rpi | TC_RT_2_1 | 10 | 10 | 0 | 0 |
| ubuntu | rpi | TC_Send_Command_Read_Write_Attributes | 10 | 10 | 0 | 0 |

### New Failures

| ID | Symptom | Category | Current Resolution | Evidence |
| --- | --- | --- | --- | --- |
| pi/rpi/TC_RT_1_2/1 | Concurrent SDK reads time out with 0x32, then unpair timeout masks the primary error | 6 | **OPEN**; exact ownership uncertain; matched Pi-controller A/B not done | `/home/feasel/matter-pr539-five-matrix-20261014/runs/combined-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-15-2026_03-38-24-598/TC_RT_1_2/summary.json` |
| ubuntu/rpi/TC_RT_1_2/1 | Concurrent SDK reads time out with 0x32, then unpair timeout masks the primary error | 6 | **OPEN**; upstream reproduces this family, but root cause remains uncertain | `/home/feasel/qa-mar6/pr539-five-matrix-20261014/runs/combined-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-15-2026_03-12-01-040/TC_RT_1_2/summary.json` |

## Focused Wi-Fi Attribution Check

Started 2026-10-16 at 02:47 UTC, separately from the closed matrix above.
Private evidence: `/home/feasel/qa-mar6/rt12-ab-20261016`.
The comparison uses current upstream `52f3a168841e0fc4940d6c79ece77bd1ccd96730`
against the five published PR diffs, including PR539 `b99759a` and PR548
`91c7269`. PR550's shared callback implementation is exercised by both its
own tests and PR549's original lifetime tests. All 150 focused tests pass
against the exact combined source snapshot.

The first diagnostic pair requests one native RT_1_2 iteration per variant
on the Ubuntu controller and identity-verified Wi-Fi DUT Pi. It reuses the
same verified native controller, scanner, DUT binary and original workload.
Only iteration count and the campaign-owned DUT KVS path differ from the
original configuration; neither timeouts nor retries were increased.

The first pair closed at 03:02 UTC: two executed, zero PASS, two FAIL.
Both used 15 additional controllers and both captures stopped cleanly.

| Variant | Primary Failure | Furthest Phase | Cleanup | Resolution |
| --- | --- | --- | --- | --- |
| Upstream baseline | Subscription-report timeout after 120 seconds; TH-13 through TH-16 each still lacked all 29 reports | Subscription verification; concurrent reads not entered | All 15 unpairs completed | **OPEN** |
| Current five PRs | SDK read timeout on 14 of 15 concurrent reads | Concurrent reads; comparator and fresh-readback verification not entered | All 15 unpairs completed | **OPEN** |

The first pair alone was inconclusive because baseline did not reach the
corresponding failing read phase. The reversed-order pair closed at 03:19 UTC:

| Variant | Primary Failure | Furthest Phase | Cleanup | Resolution |
| --- | --- | --- | --- | --- |
| Current five PRs, attempt 2 | SDK concurrent-read timeouts on 14 of 15 controllers | Concurrent reads, before comparison or fresh-readback verification | Unpair timeout masked primary failure in native summary | **OPEN** |
| Upstream baseline, attempt 2 | SDK concurrent-read timeouts on all 15 controllers | Concurrent reads, before comparison | Same unpair-timeout masking sequence | **OPEN** |

Both reversed attempts received and verified all 29 expected subscription
attributes on all 15 controllers first. Thus the five PRs are not required to
trigger the original read-then-cleanup timeout failure family. This is evidence
for a pre-existing harness/SDK/fixture path, not proof of its precise root cause
or proof that the PRs cannot affect its frequency. The original Pi-controller
cell has not been independently A/B-tested.

Diagnostic totals are four executed, zero PASS, four FAIL, separate from the
original matrix. All four captures stopped with child exit zero. Original
matrix counts remain unchanged. Category 1 or 2 is not established; resolving
pre-existing harness versus SDK/fixture ownership remains open. No current
physical run yet validates PR548's fresh-readback guard. A smaller-controller
smoke is being assessed only as supplemental guard coverage, never as a
replacement for these failed full-load outcomes.

## PR548 Diagnostics Correction And Guard Smoke

The preceding fresh-readback limitation describes the full-load checks ending
at 03:19 UTC. Three separate, explicitly reduced-cohort smokes followed, each
using two actual additional controllers rather than the DUT's advertised 15.
They retain the real production writes, concurrent reads, comparison, cache
updates and per-controller written-value verification. Only cohort construction
and non-invasive coverage observation are overridden.

| Supplemental Source | Native Outcome | Deciding Evidence | Resolution |
| --- | --- | --- | --- |
| Published PR548 `91c7269` | FAIL | Reads completed; strict comparison rejected live Wi-Fi `PacketUnicastRxCount`; fresh-readback verifier not reached | **FIXED** in PR548 `a550450`; original FAIL retained |
| Wi-Fi-only correction | FAIL | Reads completed; strict comparison rejected Ethernet `TimeSinceReset`; fresh-readback verifier not reached | **FIXED** in PR548 `a550450`; original FAIL retained |
| Combined diagnostics correction, PR548 `a5504501078b50ecf71ad70aa84d9d8415f5af43` | PASS | Both responses reached and returned from the real fresh-readback verifier; 29 successful attributes each, zero skipped | Verification PASS; reduced cohort only |

The final smoke ended at 04:32:19 UTC on 2026-10-16. Its native result is one
executed, one PASS, zero FAIL; zero controller read-task errors were present.
The private launcher's broad `read_timeout_before_cleanup` heuristic is a false
positive for this passing run, not a controller-read failure. Native outcome,
actual error lines and recorded verifier coverage determine this attribution.
All three supplemental captures stopped cleanly. The final capture's detailed
child status is retained in its private stop record; `dumpcap.log` records
60,260 captured packets and zero reported drops on all three interfaces.
The campaign-owned SSH authorization was removed and its private key deleted.

The two comparator omissions are demonstrated category-2 false failures, fixed
narrowly on the existing PR548 branch. Five nullable uint32 Wi-Fi traffic
counters and two non-null uint64 Ethernet packet counters may change while
retaining presence, decoding, nullability and domain checks. Ethernet
`TimeSinceReset` uses the measured read window like uptime. Stable unrelated
attributes, error counters, link state and explicit written-value checks remain
strict. No whole-cluster or all-numeric exemption was introduced.

All 105 RT_1_2 tests pass, preserving the preceding 91 and adding 14 focused
Wi-Fi/Ethernet regressions. All five PR suites pass together: 164 tests on the
exact final immutable combined snapshot. Ruff, isort, autopep8, editor checks
and `git diff --check` pass. The commit was pushed only to
`feasel0/matter-qa:fix/rt12-read-cache-metadata`, updating existing PR548;
no new branch or PR was created.

Upstream PR checks for exact head `a5504501078b50ecf71ad70aa84d9d8415f5af43`
are completed successfully: Ruff job `116812665510` and Restyled job
`116812665702`. The published QA worktree is clean. The existing PR body now
records the current test coverage and hardware limitations, without changing
its title or draft state.

Supplemental totals are three executed, one PASS, two FAIL. They do not replace
the four failed full-load A/B iterations or alter the original matrix's 302
executed, 300 PASS, two FAIL and 18 unexecuted iterations. The full-load timeout
family remains unresolved; no unchanged-frequency or all-five reliability claim
is justified. The Pi-controller failure still lacks a matched A/B, and physical
multi-entry Thread-table churn was not exercised by this smoke.

Private final evidence is under
`/home/feasel/qa-mar6/rt12-ab-20261016/current-guard-smoke-diagnostics`.
`guard-coverage.json` records the two real verifier calls and returns;
`diagnostics-fix-source.json` pins the exact two corrected source files.
