# PR539 Transport-Aware Readiness Fix Validation

This report covers the user-approved follow-up to the BLE prerequisite issue.
It does not replace the historical matrix or failure-attribution reports.
At the original validation snapshot, the QA changes were uncommitted and had
not been published to PR539. At that time, read-only metadata showed the PR
open and non-draft, from
`feasel0/matter-qa:fix/post-reset-commissioning-readiness-38750` to upstream
`main`, still at the recorded committed head. No PR-state change was made then.

## Current Dispositions: 2026-10-16

The readiness prerequisite/discriminator defect is **ADDRESSED** in published
[QA539](https://github.com/CHIP-Specifications/matter-qa/pull/539), head
`b99759a62df56be3f5d5c5dd9505db0eb3760f58`: 36 readiness tests and 22 passing
unprovisioned BLE-Wi-Fi outcomes. Publication is no longer an outstanding action.
Disconnected SSH resets remain outside that hardware workflow.

The [current per-defect table](PR539_FAILURE_ANALYSIS_20261011.md#current-failure-dispositions)
supersedes the chronological pending-work notes below. Valve generation
(QA547), invalid read comparisons/fresh-readback checks (QA548), callback
ownership (QA549), and missed SecurePairing reset selection (QA550) are
**ADDRESSED** as code defects. The [outcome ledger](PR539_ITERATION_ACCOUNTING_20261013.md)
records 11/11 valve and 11/11 final callback/stage outcomes. QA548's current
head `a550450` has 105 CPU tests and a bounded two-controller fresh-readback
smoke; full-load native failures remain **OPEN**. Historical SIGSEGV causality
also remains **OPEN**. These are not blanket merge-readiness or full-matrix
clearance claims. Earlier source snapshots, failed attempts and seals below
remain historical evidence, not current PR status.

## Implementation

- Raspberry Pi BLE-Wi-Fi and BLE-Thread commissioning use native BLE discovery,
  without a preceding IP DNS-SD prerequisite or an additional PASE session.
- BLE leaves the post-reset IP prerequisite pending. A later explicit
  on-network pairing operation still checks for a matching open advertisement.
- Primary pairing selects the operation's commissioning method, including a
  supplied commissioning-info override. Secondary pairing explicitly selects IP.
- A focused follow-up test exposed a secondary-window discriminator mismatch
  after BLE. The hook now accepts the actual opened window's discriminator.
  The test failed before that repair and all 36 focused tests passed afterward.
- Reset/startup behavior, discovery budget, native cancellation cleanup and
  the passive IP readiness predicate are unchanged.

The modified QA snapshot is based on committed head
`9dccf415b4019ba2db94d04f9199d27ae4477602`, with four changed files: the Raspberry
Pi adapter, base pairing boundary, existing readiness unit tests and README.
The deployed ARM snapshot's changed-file hashes were checked against the
modified worktree. Exact hashes are retained in private `source-proof.json`.

## Verified Results

| Validation | Result | Scope |
| --- | --- | --- |
| Focused readiness suite, Ubuntu x86-64 | 36 tests passed | BLE/IP selection, reset/manual/secondary boundaries, timeout and cancellation |
| Same suite, Pi1 native ARM64 | 36 tests passed on final source | Separate hash-verified snapshot includes secondary-window discriminator repair |
| Configured Ruff check, final-source Python changes | Passed with Ruff 0.17.0 | Exactly three changed Python files; four worktree hashes match the hardware-tested snapshot; isolated tool environment |
| Native ARM BLE/Wi-Fi DUT build and deployment | Passed | BLE and WPA enabled, Ethernet disabled; dependencies, CLI, test-mode warning and binary hash verified |
| Pi2 connected autonomous recovery preflight | Passed | Normal-user service restores the original Wi-Fi profile; temporary lingering recorded for cleanup |
| Ubuntu controller to Pi2 DUT, on-network smoke | 1/1 passed | Production Raspi adapter and primary pairing |
| Ubuntu controller to Pi2 DUT, on-network cycles | 20/20 passed | Ten direct resets and ten wrapper resets |
| Pi1 controller to Pi2 DUT, on-network smoke | 1/1 passed | Production Raspi adapter and primary pairing |
| Pi1 controller to Pi2 DUT, on-network cycles | 20/20 passed | Ten direct resets and ten wrapper resets |
| Pi1 controller to Nordic DUT, BLE-Thread RT_1_1 | 1/1 smoke and 10/10 campaign passed | High-level commissioning |
| Pi1 controller to Nordic DUT, BLE-Thread Darwin | 1/1 smoke and 10/10 campaign passed | Manual PASE, two fabrics and subscriptions |
| Pi1 controller to Nordic DUT, BLE-Thread Android | 1/1 smoke and 10/10 campaign passed | Manual PASE and operational interactions |
| Final-source Pi1 to genuinely unprovisioned Pi2, primary BLE-Wi-Fi | 1/1 smoke and 10/10 focused cycles passed | No preceding IP prerequisite; primary CASE and enhanced-window secondary IP CASE |
| Same final-source fixture, manual BLE-Wi-Fi | 1/1 smoke and 10/10 focused cycles passed | Production manual PASE boundary followed by provisioning and secondary IP pairing |
| Final-source Ubuntu to Nordic, corrected adapter selection | 71/80 campaign iterations executed: 56 passed, 15 failed; nine unexecuted after a crash | Sixteen closed capture windows; failures and crash retained, not publication clearance |

All 42 completed Pi-DUT iterations verified exactly one post-reset readiness
discovery, one successful DUT PASE handshake, one newly commissioned fabric
and a successful CASE attribute read. Launch delays varied between zero, one
and two seconds. Both controller hosts completed native unpair cleanup.
Controller and DUT application logs are retained; these focused Pi cycles did
not collect IP packet captures.

The 33 Nordic outcomes have six closed capture windows containing Pi BLE ACL
and IPv6 traffic, with no capture cleanup errors. The complete OTBR dataset was
unchanged. These hardware runs used the first modified-source snapshot, before
the adjacent secondary-window discriminator repair. That snapshot and its
hashes remain preserved. The final-source ARM unit suite and focused physical
BLE-Wi-Fi validation now pass.

The first offline attempt failed its no-association/no-IP assertion before the
DUT app launched. Its capture had zero Pi BLE ACL packets and is not a native
commissioning outcome. The original profile was restored and verified through
SSH. The worker now explicitly disconnects Wi-Fi and waits for the unprovisioned
condition; the retry uses a fresh identifier and preserves the initial evidence.

The next three primary BLE-Wi-Fi smokes failed, with automatic restoration of
the original Pi2 profile and a clean DUT exit in each case. The second attempt
failed in BlueZ subscription; its native error was ATT `0x0e`, but that error
was not observed on air. The third failed in GATT service discovery. Both Pis
initially lacked the SDK-documented BlueZ `-E -P battery` options. Separate,
owned service overrides now provide those options, preserving the original
configuration for restoration. The fourth attempt completed BLE PASE and Wi-Fi
provisioning, then timed out in `FindOperationalForStayActive`. Its closed
capture contains 308 Pi BLE ACL packets and 335 IPv6 packets, with no capture
cleanup errors. This is not a complete commissioning pass.

A short, recovery-protected inspection confirmed that the unmanaged interface
has IPv6 enabled and autoconfiguration enabled, but router-advertisement
acceptance disabled. It also exposed an immediate-restoration race: the original
profile was activated before NetworkManager made the interface available. The
independent ten-minute watchdog restored the profile after that initial failure.
The repaired worker waits for device availability; a second inspection restored
the original profile in 6.7 seconds without launching a DUT app.

Actual commissioning attempts now temporarily enable router-advertisement
acceptance and restore its recorded original value afterward. Completion can use
the DUT's actual operational IPv6 address, with the trusted SSH host key and
machine ID still checked; no link-local interface is inferred. Focused recovery
and address-selection checks passed. The fifth and sixth primary smokes again
failed at native GATT service discovery, before exercising the IPv6 repair.
The fifth capture contains the Matter service UUID `0xfff6` and confirms an LE
connection, despite the SDK reporting that service absent. The two unpaired
lab peers remained connected after app exit. Removing only those peer records
before the sixth smoke did not fix the missing-service result. No paired or
bonded record was removed. The seventh smoke failed with BlueZ reporting
`ServicesResolved=true`, an empty UUID list and no exported peer GATT service
objects. Packet directions confirm that the DUT returned the Matter service
UUID, rather than that UUID coming from reverse discovery of the commissioner.
The seventh worker exited cleanly and restored the original profile. This
rules out an SDK object-manager race as the sole explanation, but does not yet
establish the daemon's failure cause. The persistent peer cache has no attribute
database; additional ATT channels are present in the failure capture.

A separate commissioner-only BlueZ configuration will test the documented
single-ATT-channel setting while preserving the original configuration. Its
dry run verifies that only `GATT.Channels` changes and that the remote guards
compile. The first installation preflight failed before changing system files;
its following eighth smoke nevertheless started with the previous configuration
and reproduced the empty service-object state. That attempt must not be counted
as evidence for the single-channel hypothesis. The coordinator now separates
configuration and smoke execution to prevent another fail-open handoff.
The guarded installation then passed before the ninth smoke. The original
commissioner configuration remained unchanged; the separate root-owned
configuration and owned service override selected `GATT.Channels=1`. A single
bounded helper restart was performed with captures closed. BlueZ exported the
Matter service, BLE PASE succeeded, and commissioning advanced to
`FindOperationalForStayActive`, where it again timed out. Its capture has 290
Pi BLE ACL packets and 436 IPv6 packets and closed without cleanup errors; the
DUT exited cleanly and restored its original profile. This is a useful GATT
result, not a full commissioning pass or proof of the remaining timeout's cause.

The next smoke adds private periodic association, IPv6 address, route and
kernel-state snapshots; its focused disconnected/associated checks passed and
the deployed worker's hash and Pi syntax were verified. An absent-peer D-Bus
wording variation stopped its initial preflight before any worker launched.
The guard now confirms absence using successful object-manager enumeration,
with a focused check proving that a failed property query on an existing object
is still rejected. No paired-device protection was relaxed.

The tenth smoke again completed PASE but timed out in operational discovery.
Its network snapshots identified association and a later ULA, but no link-local
address: unmanaged `wlan0` had `addr_gen_mode=1`, disabling link-local generation.
The worker now temporarily selects normal kernel link-local generation and
restores both its recorded address-generation mode and router-advertisement
setting. The eleventh native probe passed both fabric flows, but its old
coordinator could not signal completion through a link-local address; its
watchdog closeout is retained as a failed fixture gate, not a fully closed pass.

The coordinator now uses previously measured DUT global addresses with the
same interface identifier, retaining strict SSH host-key and machine-ID checks
and the original IPv4 fallback. It does not infer a link-local scope. With these
repairs, both twelfth-attempt smokes and all twenty focused cycles passed. Each
of the 22 outcomes verified zero IP readiness calls before BLE, retained pending
IP readiness, actual enhanced-window discriminator 1281, and successful CASE
reads on both fabrics. Every owned DUT exited cleanly, received its completion
signal, restored Wi-Fi and closed a capture with BLE ACL and IPv6 traffic.
These are autonomous offline-reset boundary tests with fresh per-cycle KVS,
not full offline SSH reset integration, persistent-controller stress or native
protocol-unpair coverage.

An independent preparation check verified final-source hashes and exactly the
eight setup-affected Ubuntu/Nordic case configurations with ten campaign slots
each. It did not start hardware or replace the preserved passing results.
Ubuntu inspection then confirmed the verified controller at `/org/bluez/hci1`,
powered and idle, while old commands selected absent `hci0`. One bounded
Bluetooth recovery was performed before correcting selection; no repeated
restart was needed. Native MAC-selected timeout, same-process fresh scan and
public discovery checks passed with exact original controller-library hash and
closed captures. The isolated final-source runner now selects native index 1
only for Ubuntu. Its real RT_1_1 smoke passed and the eight affected campaigns
finished with the original dataset and preserved historical results.

| Ubuntu/Nordic Case | Smoke | Ten-Iteration Campaign |
| --- | --- | --- |
| RT_1_1 | Passed | 10/10 passed |
| Darwin | Passed | 10/10 passed |
| Android | Passed | 10/10 passed |
| RT_2_1 | Passed | One passed, then process exit -11; nine unexecuted |
| RT_1_2 | Failed | 0 passed, 10 failed |
| Send_Command_Read_Write_Attributes | Passed | 5 passed, 5 failed |
| OnOff | Passed | 10/10 passed |
| LevelControl | Passed | 10/10 passed |

The campaign accounting is 80 requested, 71 executed, 56 passed, 15 failed and
nine unexecuted. All eight smokes also executed: seven passed and one failed.
RT_1_2 reports cross-fabric concurrent-read mismatches and subscription-value
verification failures. Bulk reports write-value verification failures. RT_2_1
crashed after its first passing iteration. These match previously identified
failure categories, but their remaining fixes must stay separate from PR539.
The inspections do not count as commissioning iterations. No SDK source
workaround has been added to the QA changes.

## Separate Defect Follow-Up

The following work is isolated from PR539 on branches created from upstream
`main` at `52f3a168841e0fc4940d6c79ece77bd1ccd96730`. The existing arithmetic
constraint-parser worktree and its pre-existing changes were not modified.

| Defect | Focused Validation | Hardware Status |
| --- | --- | --- |
| Valve DefaultOpenLevel ignores live LevelStep | Eight tests and Ruff passed; draft [PR547](https://github.com/CHIP-Specifications/matter-qa/pull/547), head `6e93374`; new-head Ruff and Restyled passed | Bulk smoke and ten campaign iterations all passed; two captures closed with BLE ACL and IPv6 traffic |
| RT_1_2 compares cache metadata, fabric-scoped state and changing observations as equal values | Forty-nine tests and Ruff passed; draft [PR548](https://github.com/CHIP-Specifications/matter-qa/pull/548), head `2017ee0`; ACL and fabric-descriptor controls retain same-fabric equality, path checks, shared values and typed list shapes | Seven preserved smokes failed successively at IdentifyTime, UTCTime, DeviceLoadStatus, Thread traffic counters/uptime, neighbor/route tables, cross-fabric ACLs, then OperationalCredentials.Fabrics; read v8 smoke and conditional-ten gate pending |
| RT_2_1 registers locally owned ctypes no-ops and misses cleanup on early errors | Six tests and Ruff passed; draft [PR549](https://github.com/CHIP-Specifications/matter-qa/pull/549), head `dbab50b`; successful-pairing controls now invoke the live selected callback | Separate smoke passed; original callback campaign completed ten iterations: nine passed, one failed, process exit 1; no process crash observed, but historical crash attribution remains unproven |
| RT_2_1 selects SecurePairing although native commissioning emits neither selected callback | Four tests and Ruff passed; separate draft [PR550](https://github.com/CHIP-Specifications/matter-qa/pull/550), head `599142e`; both modes exclude only SecurePairing and unreached targets still fail explicitly | Combined smoke passed, first campaign interrupted with zero completed iterations, exact-source continuation completed 9/10; fresh combined v3 smoke and conditional-ten gate pending |

Hardware snapshots explicitly combine the unpublished final PR539 changes
with the isolated fix under test and the Valve fix. They are not standalone
upstream-main validation or PR539-only outcomes. The callback snapshot does
not include the read-comparison changes. Each snapshot has its own source
hash manifest, fresh controller storage and preserved private evidence.
The failed read smokes did not start ten-iteration campaigns. New affected
reruns do not replace the original 71 executed/56 passed/15 failed counts.
The RT_2_1 smoke took eighteen minutes. Its actual ten-iteration runner limit
is five hours, with an additional five-minute outer-supervisor margin, rather
than the smoke's thirty-minute limit. No active-source or deadline change
was needed. Read snapshot v6 preserves strict topology comparison while
validating live table observations; it will not compete for the fixture.
The guarded event-driven handoff waits for the current queue to exit, then
checks recorded closure, live helper inactivity, UART release and the dataset
before starting v6's smoke. No competing hardware process is launched while
the callback campaign owns the fixture.

The callback campaign ended at 19:46:09 UTC on 2026-10-12. Iteration 8 failed
in BLE discovery after the random commissioning-stage reset operation. Its
allowlisted events show a request to reset during `SecurePairing`, no target
start-callback event, successful commissioning, then `No Matter Device found`.
This supports a separate stage-selection/control-flow investigation, not an
adapter-recovery claim or a callback-lifetime regression. Both callback captures
closed without cleanup errors, owned relays closed, the UART was released and
the dataset remained unchanged. The guarded read-v6 handoff then started with
its exact owner verified. That smoke failed at 19:51:57 UTC on cross-fabric ACL
value equality, with all resources closed and no campaign started.

The read follow-up allows distinct valid ACL list shapes across different
compressed fabric identities, retaining same-fabric equality, missing-path and
shared-attribute failures. The separate stage-selection fix excludes only
`SecurePairing` start selection and requires observation of the selected reset
callback; missing callbacks cannot be treated as successful coverage. Both
immutable follow-up snapshots passed source-hash and configuration checks plus
52 combined tests: ten callback/stage tests and 42 read tests. The serial runner
will close the callback-plus-stage gate before starting read v7. Original failed
snapshots and the original matrix accounting remain unchanged.

### Editor Crash Recovery

Fresh inspection after the reported VS Code crash found no surviving batch,
native owner or UART relay. The combined callback/stage smoke completed
successfully, with process exit zero. The ten-iteration attempt had started but
had no final result or completed iteration records: ten requested, zero executed,
zero passed, zero failed and ten unfinished. Its exact termination signal is
unrecorded; this interruption is not classified as a protocol failure or pass.
Read v7 had not started.

The interrupted attempt's exact Ubuntu and Pi1 capture tokens were gracefully
closed through the installed profile helper and their evidence retrieved.
Original run directories, logs and the passed smoke remain unchanged. A separate
interruption record retains the unfinished accounting. The continuation has a
fresh directory and controller storage, with identical source hashes, and reuses
only the verified passing smoke prerequisite; it does not repeat or recount it.

The resumed batch started at 21:18:10 UTC on 2026-10-12 under an owned user
service independent of VS Code terminals. Its live native PID and start time
were verified. It runs the callback/stage ten-iteration gate, verifies capture
closure and UART release, then runs read v7's smoke and conditional ten-iteration
gate serially. The 52 focused tests and both configuration checks passed again
at startup. No active snapshot, firmware, deadline or Thread dataset was changed.
Hardware clearance and PR539 publication remain pending.

### Completed Continuation And Follow-Up

The resumed callback/stage campaign ended at 00:17:41 UTC on 2026-10-13 with
ten executed, nine passed, one failed and process exit 1. There was no process
crash. Iteration 3 selected SecurePairing completion and the target-observation
guard failed explicitly. The prior exclusion covered only start notifications.
The numeric stage ID matches the SDK; its AutoCommissioner advances directly
to the next stage without the SecurePairing status callback. PR550 now excludes
SecurePairing in both modes while retaining every other candidate and both
missing/nonmatching callback failures. The revised control failed before the
selector repair and all four tests passed afterward.

Read v7 then ran after verified capture closure and UART release. Its smoke
ended at 00:23:18 UTC with one failure at OperationalCredentials.Fabrics and
no ten-iteration campaign. PR548 now validates the fabric-filtered SDK table
shape across distinct compressed fabric identities, retaining same-fabric
equality, path presence, shared attributes and unmodified responses. Seven new
controls reproduced the comparison gap; all 49 tests passed after the repair.
Both completed attempts closed their captures and relays, released the UART and
retained the unchanged dataset. Neither result is a clean publication gate.

The two follow-ups were pushed only to their existing fork branches, not PR539.
Fresh immutable callback/stage v3 and read v8 snapshots passed 59 focused tests,
source hashes and configuration checks. Their smoke/conditional-ten hardware
gates remain pending; the source-tested snapshots and all earlier failures are
retained separately.

All four isolated worktrees pass autopep8 2.3.2, isort 9.0.2 and Ruff checks.
The changed read and callback/stage slices passed focused tests before their
new snapshots were staged. The earlier 49-test formatting proof remains
preserved for its original source heads, not substituted for the newer changes.
Running and queued hardware snapshots were not rewritten. All four separate
PRs remain drafts, with pending hardware validation explicitly disclosed.
The current PR548, PR549 and PR550 heads passed GitHub Ruff and Restyled.
PR550's project-label job failed separately from those code/style checks;
the repository's missing project-map script remains an uncleared workflow
condition. No workflow edits were included in these fixes.

PR547's initial Restyled failure was repaired with only continuation indentation
and a final newline. Its initial project-label workflow failure came from an
already missing project-map script, unrelated to Valve generation. That workflow
also contains an exposed hardcoded PAT, which was not used or copied into public
summaries and should be revoked/rotated separately. Neither workflow was changed
in the feature PRs. CI logs were retained only in redacted private staging.

## Remaining Gates

- Genuine unprovisioned Pi BLE-Wi-Fi primary and manual boundary coverage is
  complete on final source: two smokes and twenty focused cycles. Its scope is
  described above; it does not establish full offline SSH-reset integration.
- Ubuntu-to-Nordic setup repair passed and the affected rerun is reconciled.
  The clean-rerun gate is not met: fifteen failures and nine unfinished slots
  remain in that historical run. Its four source changes were uncommitted and
  unpublished at the snapshot; they are now published as recorded above.
  Separate follow-up fixes do not replace those original failed outcomes.
- Nordic uses its existing platform adapter, not the Raspberry Pi adapter.
  Its BLE tests can detect pairing-boundary regressions but cannot establish
  physical correctness of the Raspberry Pi BLE readiness hook.
- The optional `test_pairing_cleanup` module is absent from this QA revision.
  Its preflight import failed; no test from another revision was substituted.

## Evidence And Ownership

Private evidence root:
`/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011`.
The corresponding Pi1 directory contains the isolated deployed snapshot.
Historical exports, logs and sealed archives were not changed.

Pi-DUT closeout verified the app stopped, removed exactly the two new restricted
SSH authorization entries while preserving unrelated entries, and deleted both
owned private test keys. Nordic captures and owned UART/forwarding processes
were closed at the end of the runs.
The shared Ubuntu OTBR remained leader with SRP running; its complete dataset
fingerprint matched the historical fixture before Nordic commissioning.

BLE-Wi-Fi closeout verified inactive owned workers/timers and DUT, the original
Wi-Fi profile active and original IPv6 settings restored. Private Wi-Fi
credentials were removed locally and on Pi1; Pi2 lingering returned to its
recorded `no`. Only hash-verified owned BlueZ overrides and the separate
single-ATT configuration were removed; both Pis' original effective daemons
are running. Final campaign resource checks, an allowlisted evidence seal and
removal of the eight temporary PR539 VS Code tasks are complete. All sixteen
owned helpers are inactive with exit zero; the DUT UART and owned relays are
unowned/closed, discovery is idle and the live dataset hash is unchanged.
Every pre-existing task and input was compared against the preserved objects.
Raw private evidence and unrelated historical failed capture units are retained.
These configuration changes are private fixture preparation, not PR539 content.

The allowlisted archive contains only selected counts, source hashes and
verified closure flags; it excludes logs, credentials, storage and packet data:
`allowlisted-final-summary-20261012-151127.tar.gz`.
SHA-256: `eaa6420e42975f10443e29f572f1414cb4ecf2d37cb0aeef7d8b261e5a3b7188`.

An additive metadata-only seal contains eight completed separate attempts:
the Valve smoke/campaign, six failed read smokes and the original callback
smoke/campaign. It preserves their distinct results and source hashes without
replacing the original matrix or claiming current live-fixture closeout.
Only `validation.json` and `sha256.json` are included; archive members and
checksums were verified on readback. Raw logs, packets and storage are excluded.
Archive: `allowlisted-separate-completed-20261012-201316.tar.gz`.
SHA-256: `31fa8c522fcf14c9b28d6d7eb9af7de22ee0f4d4023a50fb99dfa02cc1506d68`.
The callback-plus-stage continuation and read v7 are closed, with the v3/v8
follow-up gates pending. Neither those completed attempts nor the interrupted
attempt is in that earlier seal.
The completed v6 handoff task was removed;
one owned read-only status task remains until final hardware closeout.

This is partial validation, not full-matrix clearance or approval to publish,
undraft, or declare PR539 ready for review.