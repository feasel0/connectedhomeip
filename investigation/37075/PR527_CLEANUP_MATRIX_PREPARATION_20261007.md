# PR527 Cleanup Matrix Results

## Crash Continuation (2026-10-10)

The user requested retaining every completed set, repeating the interrupted set,
and executing all sets not yet begun. Previous run `p527-batch120-20261010-0134`
stopped at 06:21 UTC; its **471-file seal** independently verifies. All six
Ubuntu ten-iteration sets completed and are retained, including their failures:

| Ubuntu Set | PASS | FAIL |
| --- | ---: | ---: |
| TC_RT_1_2 | 10 | 0 |
| TC_RT_2_1 | 7 | 3 |
| TC_Send_Command_Read_Write_Attributes | 10 | 0 |
| TC_Darwin_Pair | 10 | 0 |
| TC_Android_Pair | 10 | 0 |
| TC_RT_1_1 | 10 | 0 |
| **Completed Ubuntu Total** | **57** | **3** |

Pi RT_1_2 was interrupted: seven PASS, one recorded FAIL coincident with the
coordinator abort, and two incomplete. That attempt is preserved separately,
not combined with the replacement set. The other five Pi sets were unstarted.
The failed Ubuntu capture log states that **wpan0 was no longer attached**;
the existing host journal shows no new boot, so the exact reported crash
mechanism is not inferred. Capture completeness is not claimed for that interval.

Fresh continuation **`p527-resume120-20261010-2350`** completed under the independent
ordinary-user service `p527-resume120-20261010-2350.service`. It retained the six
completed Ubuntu ledgers and executed exactly **six fresh Pi sets / 60 slots**:
repeat RT_1_2 from iteration 1, then RT_2_1, Send_Command_Read_Write_Attributes,
Darwin_Pair, Android_Pair and RT_1_1, ten iterations each. The combined target
remains **120 slots**, not 180. Each fresh set has its own new storage; its
controller process and storage persist across its ten iterations.

Essential source/runtime/firmware/dataset and both fabric-lifecycle checks
passed. The continuation ended **2026-10-11 04:10:47 UTC**, after about
**4 hours 24 minutes**, with status **FULL120_COMPLETED_WITH_FAILURES** and no
coordinator error. Every fresh Pi set passed **10/10**, independently verified
against the remote native summaries. Combined with the retained Ubuntu sets:

| Final Scope | PASS | FAIL | Incomplete | Unstarted |
| --- | ---: | ---: | ---: | ---: |
| Ubuntu: six retained sets | 57 | 3 | 0 | 0 |
| Pi: six fresh sets | 60 | 0 | 0 | 0 |
| **Combined 120 Slots** | **117** | **3** | **0** | **0** |

There are no setup failures or coordinator-aborted sets in the combined result.
The three retained failures are Ubuntu RT_2_1 iterations **1, 3 and 4**, each
reporting **No Matter Device found**. They are not waived or retried. Pi RT_2_1
completed all ten iterations, establishing continuation on that host for this
campaign, not eliminating the Ubuntu failures.

The **447-file continuation seal** independently verifies. All **eight new
capture phases** completed; both hosts' captures flushed and exited 0. Local
coordinator/relay owners and all six remote native owners are absent, and the
service is inactive. The old failed Ubuntu capture was copied into the new
evidence namespace without changing the previous seal. The interrupted Pi
attempt remains separate and is not double-counted in the 120-slot result.
All four published PR heads and the explicit uncommitted follow-ups are unchanged.

## RT_1_2 Root-Cause Follow-Up (2026-10-09)

The user authorized fixing the repeatable Ubuntu RT_1_2 failures before rerunning
the full batch. The private runner had forced **1.4.2 XML** on both hosts.
That XML marks the eleven ColorControl white-point/primary attributes writable;
the pinned SDK's **1.6 and 1.7 XML mark them read-only**, matching the running
code-driven server. New runs explicitly select **1.6 XML**, with the choice
recorded in every invocation rather than silently modifying old configurations.

QA544's existing worktree now has an **uncommitted follow-up** in
`attribute_value_generator.py`: generate valve DefaultOpenLevel values from
the legal range, the actual live LevelStep, and the 100-percent exception.
The change is replayed in the combined QA527/544/545 checkout and guarded by
SHA-256 `6a54323afd485defdfb2a5c26a2825c0ad0e4bd5cf2402e27d1230f128a43119`.
Fifteen focused regressions pass locally. No skip/failure verification policy,
PR head, branch, commit, firmware or Thread dataset was changed.

Fresh captured smoke `p527-rt12fix-20261009-2338` ran under an ordinary-user
systemd service. Both native runtimes, both 14-test suites and both fabric
lifecycle probes passed. Ubuntu RT_1_2 then failed before sending its bulk write:
the first follow-up treated XML default LevelStep string `"1"` as live state.
That native FAIL is preserved in an independently verified **81-file seal**;
both hosts' captures flushed, exited 0 and were retrieved. The follow-up now
reads LevelStep through the controller callback instead, with a regression for
that exact XML-default/live-value distinction.

Second smoke **`p527-rt12fix-20261009-2345`** ended with one native Ubuntu FAIL,
exit 1, no coordinator abort, setup failure or incomplete slot. The corrected
bulk writes succeeded: all four controllers verified all 29 selected attributes,
and subscription reports arrived in 33.05 seconds. The later concurrent phase
failed because whole wildcard results were compared across fabrics:
ScenesManagement.FabricSceneInfo contained different fabric indices, and Identify
data versions advanced between reads. Both are legitimate differences, not
evidence of mismatched shared written values. Its **81-file seal** independently
verified; captures flushed and exited 0, and all owned processes are stopped.

QA527 now also has an **uncommitted RT_1_2 follow-up**, replayed in the combined
checkout. Each controller's concurrent read is checked against the intended write
payload using the existing strict verifier, including rejected-write failures and
quieter-reporting tolerance. Writable cache entries are cleared between controllers
so missing reads cannot reuse previously verified values. Wildcard reads remain;
there is no fabric-data exemption list. The script SHA-256 is
`108d0ab7eff73606ee55af61d538739baa62ee75d7259bae08ca44b0186ecbeb`.
All **56 QA527 cleanup/read-back tests** and **15 QA544 constraint tests** pass
against the combined runtime; both hosts passed these **71 snapshotted tests**.

The write coverage change is explicit: **42 old paths become 29**, with no new
paths. Eleven ColorControl paths are now read-only. The other two are
UserLabel.LabelList on endpoints 0 and 1: 1.6 adds a description-only constraint
marker, so the existing collector's description-constraint exclusion applies.
That exclusion policy was not relaxed. These are not 42-path-equivalent results
and do not establish conformance to unimplemented description constraints.

Third smoke **`p527-rt12fix-20261009-2356`** completed under ordinary-user systemd
with **one native RT_1_2 PASS on each host**, both exit 0, including concurrent
operations. Both fabric lifecycle probes passed. Its **121-file seal** independently
verified; all captures flushed and exited 0, and all owned processes stopped.
User lingering was already enabled; no privileged policy change was needed.

Workflow **`p527-full120-20261010-0010`** stopped at Ubuntu's two-iteration
RT_2_1 continuation gate. All six Ubuntu one-iteration smokes passed. The first
continuation iteration also passed; the second is **incomplete**, not a recorded
native iteration FAIL. The native async runner's **1,800-second total-test limit**
canceled it during the wrong-PIN subtest. A single RT_2_1 smoke took about
17.5 minutes, so the same 30-minute budget was insufficient for two iterations.
The wrapper did not abort, and no segmentation fault was recorded. This does
not yet establish successful second-iteration cleanup or continuation.
All **286 evidence files** independently verified against the seal; all nine
capture phases flushed and exited 0 on both hosts, and owned processes stopped.
The six Pi case smokes and Pi continuation were unstarted in this workflow.
Its **120 campaign slots remain unstarted**.

The private runner now gives continuation smokes **3,600 seconds**, with a
3,800-second outer coordinator budget. One-iteration (1,800 seconds) and
ten-iteration campaign (12,300 seconds) native budgets are unchanged. The exact
total-test budget is recorded in each new private invocation. Scope, accounting,
capture-failure gates and timeout-margin checks pass; test expectations and
published source pins were not changed by this timeout correction.

Workflow **`p527-full120-20261010-0113`** was deliberately canceled at the user's
request to start the actual full batch immediately. Ubuntu RT_1_2 had passed;
RT_2_1 was still running. Cancellation retained its native FAIL record, wrapper
abort flag and child exit **-11 (SIGSEGV)** together, not as an ordinary independent
test failure. Its **119-file seal** independently verified; captures flushed and
exited 0, and all owned processes stopped. No campaign slots started in that run.

The user explicitly requested: "have you started the full  batch yet?  if not
start it now". Fresh batch **`p527-batch120-20261010-0134`** launched under
`p527-batch120-20261010-0134.service`, independently of the editor. It performs
essential fresh PR/runtime/source/firmware/ownership/dataset checks and both
fabric-lifecycle probes, then starts the exact **120 campaign slots** without
repeating the remaining readiness smokes. The exact authorization is recorded;
unfinished case-smoke and RT_2_1 continuation gates remain **unverified**, and
`all_five_gates_passed` remains false. This is an explicitly authorized diagnostic
batch, not a claim that readiness passed. QA527/544 follow-ups remain explicit,
uncommitted snapshots; all four published PR heads remain unchanged.
Actual launch verified: coordinator **FULL120_RUNNING**, `full_batch_started=true`,
stage **ubuntu-TC_RT_1_2-campaign**, supervisor PID **3756539** with verified
start ticks/cgroup, live native owners, a nonempty campaign console and running
capture. Campaign outcomes are pending; no completed-slot count is claimed yet.
Each ten-iteration campaign retains one controller process and storage file.
Native campaign failures are preserved while the matrix continues; capture,
ownership, missing-ledger and timeout failures still stop the workflow.
The service has a 60-hour total bound covering existing per-case timeouts;
each capture segment remains bounded by the installed helper's policy.
Readiness and full-batch completion are **not yet claimed passed**.
The historical interrupted 120-slot run and its accounting below are unchanged.

## Editor Interruption (2026-10-09)

At **23:15 UTC**, live inspection found no coordinator, native test process,
UART relay or Pi forwarding process for run `p527-20261009-202448`. RT_2_1's last
console write was **21:11:56 UTC**, over two hours earlier. The saved
`FULL120_RUNNING` flag was stale; the earlier status report did not establish
live process ownership. The user reported a VS Code crash/restart, but the exact
termination signal was not recorded.

The batch is now **INTERRUPTED_EDITOR_RESTART**. Ubuntu RT_1_2 completed all
ten iterations with the known verification failures. RT_2_1 has no final native
ledger or recorded iteration outcomes: its ten allocated slots are incomplete,
not native FAILs. The other **100 slots were not started**, including every Pi
campaign. Totals reconcile to **10 FAIL + 10 incomplete + 100 unstarted = 120**.

Both independent systemd capture jobs survived the editor failure. Their exact
owned units were gracefully stopped, both capture children exited 0, and evidence
was retrieved. The interrupted run now has a **131-file SHA-256 seal**, with
`coordinator-before-editor-interruption.json` preserving the old ledger and
`editor-interruption.json` recording observed process/log/capture facts. No DUT
reset, OTBR change or automatic test relaunch occurred during recovery.

The status task now reports live coordinator/relay owners, native PID/start-time
matching, console age and partial native outcomes. Future batch execution needs a
supervisor outside VS Code, such as a user systemd service: persistent capture
services alone do not protect a terminal-hosted QA coordinator from editor exit.

## Diagnostic Batch Launch (2026-10-09)

The user explicitly requested proceeding with the full batch after the failed
readiness smoke. Run `p527-20261009-202448` launched as **FULL120_RUNNING**: six selected
cases, ten iterations each, on Ubuntu and Pi, using the combined QA527/544/545
checkout and the SDK74676 fix. The first Ubuntu RT_1_2 campaign began at
**20:26:36 UTC**. Fresh PR-head checks, both native runtimes and both captured
fabric-lifecycle probes passed before the campaign launch.

This is an authorized diagnostic run, not a claim that all readiness gates passed.
The known failed RT_1_2 smoke and unperformed continuation checks remain recorded;
their readiness booleans remain false. Native case failures are retained and the
matrix proceeds, but capture/ownership failures, missing native ledgers and
coordinator timeouts still stop an infrastructure cascade. Test expectations,
production QA, source pins, firmware and the complete Thread dataset are unchanged.
Each ten-iteration campaign keeps one controller process and storage file.

Current artifacts are private under the follow-up preparation directory at
`rerun-runs/p527-20261009-202448`. `coordinator.json` records authorization and
campaign-level accounting; `future-runs` contains Ubuntu results and
`pi-retrieved/future-runs` contains retrieved Pi results. Totals update after each
campaign finishes; an active campaign is not a completed result. The existing
`PR527: Inspect Smoke Progress` task reports this latest run without disrupting it.
Final completion, capture cleanup and a final evidence seal are not yet claimed.

## Previous Readiness Outcome (2026-10-09)

Fresh run `p527-20261009-194725` stopped at the first current-image RT_1_2 smoke.
The full rerun remains **0/120**, not started. No password input was required:
the generic capture helper works on both hosts even with cached sudo authorization
ignored. All four live PR heads remained exact, open and draft, and both native
controller runtime hashes/imports/ABI/lifecycle checks passed again.

Both current-image fabric lifecycle probes passed: commissioned CASE fabric
tables survived reboot, and factory reset removed the old fabric. Captures contain
264 BLE ACL packets for each host's lifecycle probe and actual IPv6 traffic.
The complete live Thread dataset remained unchanged. The approved Identify fix
is verified: all four IdentifyTime writes succeeded, all four controllers verified
endpoints 2/3/4, and every subscription report arrived in **43.2 seconds**.

The new native failure is `Attribute verification failed for 48 attributes across
controllers.` Each controller reports 30 verified values, zero value mismatches
and 12 skipped rejected writes. Eleven ColorControl attributes return
`UnsupportedWrite`; the current server treats these white-point/primary attributes
as read-only. `ValveConfigurationAndControl.DefaultOpenLevel=77` returns
`ConstraintError`; the observed `LevelStep=2` requires an even value (or 100).
The pinned verifier explicitly exempts only `KNOWN_ISSUE` skips, so these rejected
writes remain failures. Expectations, source pins and production QA were not changed.
Further progress requires aligning writable-attribute selection and generated
values with the selected SDK fixture, not ignoring rejected writes.

This is one native FAIL, exit 1, with no setup failure, coordinator abort or
incomplete smoke slot. The remaining eleven one-iteration smokes and both
same-process RT2_1 continuation checks were not started. Fresh evidence is sealed
under the private preparation's `rerun-runs/p527-20261009-194725`; all **74 file
checksums verified**. Both hosts' captures were gracefully stopped and retrieved,
and all owned QA, UART relay and SSH tunnel processes were confirmed stopped.
The OTBR remains leader; no network, RCP, unrelated application or PR state changed.

The generic helper and personal skill are complete. The private coordinator is
partially hardware-validated; detached Pi QA cases and the full batch have not yet
been exercised. Current status is in `five-gates-progress.json`; the exact sealed
run ledger is `coordinator.json`, with offline diagnosis in
`rt12-current-image-analysis.json`. Historical evidence below remains preserved.

## Historical Readiness Outcome (Earlier 2026-10-09)

The conditional **120-slot rerun has not started**. A new Ubuntu RT_1_2 smoke
failed with a native `Timeout waiting for subscription reports after 120.0 seconds`.
Three other Ubuntu smokes passed: Darwin, Android and RT_1_1. The remaining eight
one-iteration smokes and both same-process RT2_1 continuation checks were not run;
the fifth readiness gate is not passed.

Both isolated native controllers are built and verified: Ubuntu x86-64 and Pi
ARM64 each pass 73 combined QA regressions and seven scanner regressions. Both
also passed real native timeout, rejected BlueZ stop, completion, scanner release
and same-process fresh-scan checks. The stop-rejection probe duplicates an actual
StopDiscovery call through a test-only GIO interposer; its first linkage failure
was retained and corrected, not attributed to the SDK.

The safely flashed Nordic image passed commissioned CASE fabric-table preservation
across `kernel reboot` and factory-reset clearing on both controller hosts through
the PR545 adapter. Real commissioning captures contain BLE ACL traffic on both
hosts, and runtime fixed-key warnings were verified in both commissioner logs and
the DUT UART. The complete live Thread dataset remains unchanged.

RT_1_2 progressed past payload construction and commissioned four additional
controllers. A write response is present, but TH-2 through TH-5 each still awaited
three subscription reports at timeout. The native record is FAIL, process exit is
1, and no coordinator timeout occurred. Offline replay identified the exact missing
paths as `Identify.IdentifyTime` on endpoints 2, 3 and 4 on every controller.
Structured decoding of the actual bulk WriteResponse shows `kFailure` for all
three paths, while endpoint 1 succeeded. The unmodified tracker still awaited
the failed-write paths. The Nordic app registered an Identify instance only on
endpoint 1; the other advertised endpoints had no instance.

With explicit user approval, a fixture-only change registers independent Identify
instances on endpoints 2, 3 and 4 without sharing endpoint 1's LED callbacks.
The matched incremental build passed, adding 96 bytes of flash and 256 bytes of
RAM. The old HEX and ELF were preserved. The new merged-image SHA-256 is
`669012a78ea9439e28d80fed6c3c65025ac3467718694ec963c06cb7453faf0b`.
Range-only programming and read-back verification passed on DK `001050208117`;
the 32 KiB settings partition was byte-identical before and after programming.
The DK was reset to normal execution. The new image has **not yet passed hardware
smokes or fabric-lifecycle gates**; earlier lifecycle proofs apply to the old image.

The earlier capture-authorization pause is resolved. A repo-independent,
root-owned, profile-based capture helper is installed on Ubuntu and the controller
Pi. Both passed noninteractive verification with cached sudo authorization ignored,
and live start/status/graceful-stop checks. The first Ubuntu cleanup failure is
preserved as incomplete evidence; adding CAP_KILL to the root worker fixed its
normal-user dumpcap cleanup. These short passive checks do not prove commissioning
coverage. Normal runs now use only the installed helper with `sudo -n`.

A private coordinator preserves old evidence through fresh run namespaces, checks
the exact PR heads and runtime hashes, and redoes both current-image lifecycle
gates, all twelve one-iteration smokes and both same-process continuation checks.
It starts the exact 120-slot batch only after all five gates pass. Pi case runs
are detached from SSH, and capture stop/retrieval and native accounting are checked.
The preparation's `five-gates-progress.json` and run-specific `coordinator.json`
are the current machine-readable status, rather than the historical paragraphs.

No pinned production QA code, subscription expectations or published PR heads
were changed. The full batch remains at **0/120**.

Private failure evidence is sealed under the follow-up preparation directory at
`failure-evidence/rt12-subscription-timeout-20261009`: all 47 file checksums verified,
manifest SHA-256 `df066027d63e338cacc948e069ff274232b8f2fe8df9f258afdd8e2230977246`.
The earlier foreground capture was accidentally interrupted by a terminal-tool
check and flushed with zero reported drops; its gap and packets are retained.
The replacement detached captures covered the live gates and smokes. Owned
captures were gracefully flushed, and the UART relay and Pi tunnel were stopped.
The working OTBR, network, unrelated applications and older sealed evidence remain
unchanged. All four required PR heads were rechecked and remain open and draft.

The sections below retain the historical preparation and original-matrix record;
their earlier pending-build and missing-capture statements are not current state.

## Requested Scope

Exact QA head: `e72960479fafcb959b783e4780b7aa743f218155`, clean isolated
worktree at `/home/feasel/qa-mar6/matter-qa-527`. No PR528 or PR539 overlay.

Each of the nine affected scripts requires ten BLE-Thread iterations with
Ubuntu as controller and ten with Raspberry Pi as controller, always using a
Nordic DUT: 18 campaigns and 180 requested iterations.

- `TC_Darwin_Pair`
- `TC_Android_Pair`
- `TC_RT_1_1`
- `TC_RT_1_2`
- `TC_RT_2_1`
- `TC_RT_2_2`
- `TC_Bridge_Add_Remove`
- `TC_BDX_OTA`
- `TC_Send_Command_Read_Write_Attributes`

The user's latest instruction supersedes the all-fixtures-first staging
decision: run all iterations currently possible without an alternate Thread
network. The selected matrix is **120 requested hardware iterations**, ten
per case per controller for the six currently runnable cases below.

## Results

Both controller matrices finished. Ubuntu ran from **2026-10-08 01:41:21 to
07:22:08 UTC**; Pi ran from **07:22:08 to 11:18:13 UTC**. All 120 selected
slots were processed despite failures. There are **100 native iteration
outcomes: 60 PASS and 40 FAIL**, plus **20 pre-loop setup failures**. Three
native FAIL records were generated when the coordinator timed out and sent
SIGINT; these are not normally completed protocol iterations. The original
summaries report zero unfinished slots, but that does not erase this limitation.

Each controller recorded 30 PASS, 20 FAIL, and 10 setup failures.

| Case | Ubuntu | Pi |
| ---- | ------ | -- |
| `TC_Darwin_Pair` | Iterations 1-10 PASS | Iterations 1-10 PASS |
| `TC_Android_Pair` | Iterations 1-10 PASS | Iterations 1-10 PASS |
| `TC_RT_1_1` | Iterations 1-10 PASS | Iterations 1-10 PASS |
| `TC_RT_1_2` | Iterations 1-10 FAIL | Iterations 1-10 FAIL |
| `TC_RT_2_1` | Logical iterations 1-10 FAIL | Logical iterations 1-10 FAIL |
| `TC_Send_Command_Read_Write_Attributes` | Slots 1-10 failed before the loop | Slots 1-10 failed before the loop |

### Observed Failure Reasons

- `TC_RT_1_2`, both hosts, iterations 1-10: the recorded primary error is
  **"Write operation failed."** This identifies the failing operation, not
  its root cause or attribution to the cleanup changes.
- `TC_RT_2_1`, Ubuntu logical iterations 1-7 and Pi logical iterations 1-10:
  discovery recorded **"No Matter Device found"**. Ubuntu segments 1-7 and
  nine Pi segments also exited with signal 11 (segmentation fault); native
  FAIL records were retained before those exits.
- `TC_RT_2_1`, Ubuntu logical iterations 8-10: the coordinator hit its time
  bound, sent SIGINT, and recorded exit 124. Native errors say
  **"Execution is stopped by Ctrl+C"**. These were coordinator aborts, not
  manual cancellation or three normally completed discovery failures.
- Send/Read/Write, Ubuntu slots 1-10: initial commissioning failed after three
  retries, with BLE/PASE **`CHIP Error 0x00000003: Incorrect state`**. The
  iteration loop was never reached.
- Send/Read/Write, Pi slots 1-10: Mobly reported
  **`matter_xml_root is not set in TC_Send_Command_Read_Write_Attributes config.`**
  This is a run-configuration error: the XML root was placed in general
  settings, but this test requires its own testcase setting. These are not
  ten executed command/read/write iterations or evidence of a cleanup regression.

Discovery required ten separate native process segments per controller after
fatal exits. The same per-campaign storage was retained, but process restarts
limit continuous controller-session stress coverage. Native iteration numbers
restart inside each segment; the verified inventory preserves both native and
logical identifiers. No production cleanup fix or firmware change was made
while collecting the matrix. Attribution to PR527, known issues or another
failure remains unestablished and is the next investigation step.

The initial Pi monitor exited with status 1 due to a console-file creation
race. The detached campaign survived and was monitored through completion
without a duplicate launch; both coordinators exited 0 after processing their
slots, despite test failures. Neither coordinator exit means the tests passed.
The preserved launcher's end file marks the first monitor's end, not Pi completion.

Selected cases: `TC_Darwin_Pair`, `TC_Android_Pair`, `TC_RT_1_1`,
`TC_RT_1_2`, `TC_RT_2_1`, and `TC_Send_Command_Read_Write_Attributes`.

Excluded from this execution: `TC_RT_2_2` needs an alternate Thread network;
`TC_Bridge_Add_Remove` needs bridge-capable Nordic firmware/adapter operations;
`TC_BDX_OTA` needs matching Nordic OTA artifacts and native provider apps.
The latter two are separate fixture blockers, not Thread-network requirements.

The original 180-iteration preparation manifest remains a staging snapshot.
Current selection and outcomes are recorded in private
`ubuntu-selection.json`, `pi-selection.json`, per-campaign
progress/results, and each controller's matrix summary. Never count excluded
cases or startup-only failures as executed iterations. Preserve all native
failure evidence and continue the selected matrix despite test failures.

## Completed Preparation

- All 52 focused pairing/cleanup regressions passed on both Ubuntu and the
  native ARM64 Pi controller.
- Deployed the exact QA snapshot to
  `/home/feasel/matter-pr527-cleanup-matrix-20261007-2050/qa` and verified
  imported QA and native Matter module paths. Archive SHA256:
  `14cf86547380083db0eaa2b7bfedbe673ceae2d3dced652c52c94387af45dd09`.
- Prepared and checked 18 private YAML files under
  `/home/feasel/qa-mar6/pr527-cleanup-matrix-20261007-2050`.
- Both general and direct per-test overrides explicitly select ten iterations
  and `max_consecutive_identical_failure_attempts: 0`.
- Recorded per-script SHA256, QA head, commissioning method and requested
  counts in the manifest; staging state is waiting for required fixtures.
- Existing live complete OTBR dataset matches the preserved PR528 dataset;
  fingerprint `ed2e96c79a37c1f8af308d0867c3adaa3ebf186b5b6d65dc3777617debc04d39`.
- Controller Pi identity and native Python 3.13.16/BLE adapter verified.
- DUT DK `001050208117` and sole local RCP `8388F563A730D925` identified through
  nRF Connect. The second Pi has no attached USB/serial Thread radio and no
  active secondary OTBR interface was observed.
- User confirmed that the nRF52840 dongle and OTBR stay on Ubuntu for both
  controller hosts; neither Pi has a Thread radio. Pi BLE-Thread commissioning
  does not require a Pi-hosted OTBR. Updated and validated the controller,
  local OTBR and Pi OTBR skills with that explicit topology.
- Started temporary, exclusive UART broadcasting and authenticated loopback
  forwarding. Verified the real Nordic shell discriminator/passcode and exact
  live dataset equality through the Pi endpoints; preserved preflight output.
  The initial services were stopped after preparation. New owned services
  were started and reverified for the active selected matrix.
- Prepared a full-matrix coordinator and sequential launcher; their accounting
  self-test and shell syntax checks passed. Setup failures are recorded
  separately and are never counted as completed hardware iterations.
- Added explicit case selection and tested six cases/60 iterations per
  controller. Deployed the updated coordinator to Pi and passed its native
  self-test. Logs, traces, UART output and OTBR snapshots are retained;
  packet/HCI capture coverage is not established.

The generated configs are **staging templates, not runnable approval**. In
particular, shipped example secondary-network credentials and OTA paths must
be replaced with verified fixture inputs before those campaigns may start.

## Fixture Gates

| Test | Required Preparation |
| ---- | -------------------- |
| `TC_RT_2_2` | A live alternate Thread network, complete private dataset, reachable border router, and adapters implementing prefix update/reboot. The existing shared Ubuntu OTBR solves controller connectivity, not this network-switch prerequisite. Do not substitute the primary dataset or use shipped example credentials. |
| `TC_Bridge_Add_Remove` | A bridge-capable Nordic DUT image and real add/remove adapter commands. Stock `NordicDut` inherits unimplemented operations. The local NCS v3.3.0 Matter Bridge application lists nRF5340-class boards and does not list the connected nRF52840 DK. A verified custom DK implementation remains an alternative, not an existing fixture. |
| `TC_BDX_OTA` | DFU-enabled Nordic firmware, a matching download-only OTA artifact and event trigger, plus native provider apps for Ubuntu and ARM64 Pi. The configured example provider/image paths are absent. SDK documentation supports DFU on the existing DK, but it has not been built or validated for this campaign. |

The running `otbr-37075`, its network, DUT firmware, other Pi applications and
prior evidence were not changed. The selected matrix is finished, and both
owned forwarding services have been stopped. The final complete live dataset
still matches the starting fingerprint. No DUT or OTBR recovery reset was
performed during evidence retrieval.
nRF Connect reports no registered applications and no
installed toolchain for its listed SDK; a matched build environment must be
resolved before firmware preparation.

## Execution and Evidence Contract

For the selected cases whose fixture gates pass, run sequentially with one owner of the shared DUT and
fresh storage per campaign, preserving controller state within its ten
iterations. Keep every campaign console, native JSON trace, summary,
iteration record, DUT UART log, UTC bound and exit status. Collect bounded
OTBR/kernel/Bluetooth evidence and verify actual packet-capture privileges;
do not claim unavailable captures.

Ordinary iteration failures must not stop subsequent iterations or campaigns.
The configurable identical-failure safeguard is disabled. The production
harness also has explicit `TestCaseExit` paths on fatal cleanup/fixture errors;
those require a logged recovery/continuation policy without weakening the
cleanup code being evaluated. Do not silently count truncated or startup-only
attempts as ten executed iterations.

Retain original failure messages, tracebacks and nearby successful controls;
seal and checksum failure artifacts before any recovery reset can erase
evidence. At completion, reconcile actual iteration numbers/outcomes against
the 120 selected iterations, keeping the other 60 originally requested slots
explicitly excluded/blocked, and list every failure with its observed stage/error.
Root-cause investigation and attribution to PR527, known issues or new failures
follow the complete matrix; do not fix production code mid-campaign.

## Retained Evidence

Private root: `/home/feasel/qa-mar6/pr527-cleanup-matrix-20261007-2050`.
Pi originals remain at `/home/feasel/matter-pr527-cleanup-matrix-20261007-2050`;
the retrieved copy is in `pi-retrieved` under the private Ubuntu root.
All **1,183 Pi file checksums** were verified after authenticated retrieval.

`verify_results.py` reconciled every selected slot against native JSON records,
Mobly setup failures and process exits. Its `verified-results.json` includes
all 60 nonpass slots, exact evidence locations, native/logical identifiers,
three timeout-aborted slots and sixteen segmentation-fault exits.

Original consoles, native traces, per-iteration DUT logs, continuous UART,
configs, storage, OTBR snapshots, and bounded host/OTBR log queries are retained.
Failed cases and their preceding successful RT_1_1 control are preserved in a
private `failure-evidence.tar.gz`; `SHA256SUMS.local` seals the stable local
evidence. Raw dataset/storage/logs must not be shared as a public attachment.

There are no IP/HCI captures or authenticated packet-decryption results.
Bounded journal queries are preserved with their coverage/permission limits;
empty or inaccessible journals are not proof of an error-free host. Dataset
equality alone does not establish DUT attachment, routing or session freshness.

## Post-Run Failure Analysis (2026-10-08)

This analysis supersedes the earlier unknown-cause descriptions where noted.
The sealed originals and the report copy inside the failure archive remain
unchanged; no production fix, firmware change or hardware rerun was performed.

| Failure group | Classification | Evidence |
| ------------- | -------------- | -------- |
| RT_1_2, both hosts, iterations 1-10 (20 records) | Confirmed QA generator bug, not a DUT write failure | Payload generation for BooleanStateConfiguration.CurrentSensitivityLevel passes `SupportedSensitivityLevels - 1` to `int()`, raising ValueError before the bulk write. |
| RT_2_1, Ubuntu 1-7 and Pi 1-10 (17 records) | Invalid test execution caused by unsupported reboot command | UART reports `kernel: command not found`; the adapter still claims reboot completion. After wrong-passcode testing stops BLE advertising, the required reboot never happens. |
| RT_2_1, Ubuntu 8-10 (3 records) | Timeout-aborted, infrastructure-contaminated/inconclusive | These later segments stall at initial discovery and are aborted by the coordinator; they do not reproduce the seventeen wrong-passcode-stage failures. |
| Send/Read/Write, Pi setup slots 1-10 | Confirmed campaign configuration error | Testcase-level `matter_xml_root` is missing, although the general setting exists. The same missing testcase setting is present in Ubuntu's YAML but Ubuntu fails earlier. |
| Send/Read/Write, Ubuntu setup slots 1-10 | Confirmed BLE scanner-state blocker; original timeout cause unresolved | In every segment, the first scan times out; retries two and three log `BLE scan already in progress` and fail with Incorrect state. Not command/read/write coverage. |

The generator failure was reproduced offline using the unchanged QA generator,
with no DUT/BLE/network. Its constraint resolver only resolves strings prefixed
`attribute:` or `compute:`; the bare XML expression reaches integer conversion
unchanged. All twenty iteration logs have this same primary failure. This is a
real QA software defect, not merely an incorrectly chosen numeric test value.

All seventeen discovery segments reaching the wrong-passcode phase contain
rejected `kernel reboot` commands in DUT UART. Initial discovery and
commissioning succeed, so these are not seventeen initial fixture-discovery
failures. The adapter sleeps and logs completion without verifying command
success, fresh boot or renewed advertising. The configured command and missing
per-case smoke/readiness validation are campaign-preparation mistakes; the
adapter's false success is also a QA robustness defect. These results do not
demonstrate faulty DUT discovery after a successful reboot.

### Real Cleanup Defect: Callback Lifetime

The sixteen segmentation faults are a separate real software problem, not
sixteen additional failed-slot records. All end at `ReadCommissioningInfo` on
the **next native iteration**, immediately after native
`ScriptDevicePairingDelegate::OnCommissioningStageStart` logs its stage.
They occur after a first iteration's failure has already been recorded, rather
than merely during process exit.

`TC_RT_2_1._cleanup_discovery_state` constructs temporary ctypes no-op callbacks
and registers them without retaining Python references. The actual installed
SDK setters do not retain them either. Native code stores raw function pointers
and invokes the stage-start pointer at exactly the logged crash location.

An offline lifetime check executed the unchanged cleanup method through the
installed SDK setters with a non-owning native registration stand-in. Weak
references confirmed that **both callbacks are released after cleanup**. No
freed pointer was invoked. This confirms a defect in PR527's cleanup and is a
very strong explanation for the sixteen matching crashes; a repaired hardware
rerun is still needed to confirm crash elimination. Existing MagicMock-based
tests retain callback call arguments and therefore mask this ownership problem.

### Remaining Limits and Next Gates

Ubuntu's bounded kernel log also records global OOM pressure during the run;
the recorded killed processes are `cpptools`, not QA or OTBR. This is an
infrastructure caveat, not established causation of the timeouts. No equivalent
host-health conclusion can be drawn from Pi's empty journals.

Before claiming validation of the remaining cleanup paths: retain/reset native
callbacks safely with lifetime-aware regression coverage; use a verified
supported reboot command and require UART boot/advertising confirmation; fix
the XML expression generator and testcase XML configuration; establish fresh
BLE discovery and a passing case-specific smoke on a stable host. Investigate
Ubuntu's first commissioning scan timeout separately from the secondary
Incorrect-state retry failures. Do not interpret these sixty nonpass slots as
sixty independent DUT defects or as evidence that all PR527 cleanup is correct.

## PR527 Follow-Up Fix (2026-10-08)

Pushed commit `7b285397378d91fe548088f3b98e159aea58ad03` to the existing
`fix/darwin-pair-failure-safe-cleanup` branch on `feasel0/matter-qa` for PR527.
The remote branch hash was verified and the worktree is clean.

Discovery cleanup now clears both native callback registrations with typed null
function pointers instead of temporary Python no-op callbacks. Native delegates
already guard null pointers before invocation. The new regression exercises the
actual SDK setters with a non-owning native stand-in that records only raw
addresses, checking repeated cleanup after garbage collection. It failed before
the fix and passed afterward. All **53 cleanup regressions**, changed-file Ruff,
and editor diagnostics passed. Hardware crash-elimination verification is pending.

The XML expression generator defect and Nordic adapter's unverified/false reboot
success remain separate software follow-ups, not fixed by this PR527 commit.
The unsupported reboot command and missing testcase XML setting are campaign
setup corrections for a fresh run. Ubuntu scan/retry state and discovery hangs
remain investigations. No new campaign or changes to sealed evidence were made.

## Separate QA PRs and Investigation (2026-10-08)

Two separate QA fixes are published against `main`, both now **OPEN and DRAFT**
at the user's request, pending verification:

- [PR544: Resolve arithmetic XML attribute constraints safely](https://github.com/CHIP-Specifications/matter-qa/pull/544),
  commit `f0fd44536ea15030131cb8c0d119fd99dd109f8b`.
  Parses a restricted arithmetic AST, resolves attribute references and numeric
  operands, and rejects unresolved/non-numeric bounds instead of relaxing them.
  Nine unit tests, Ruff and editor diagnostics pass.
- [PR545: Verify Nordic reset and reboot UART responses](https://github.com/CHIP-Specifications/matter-qa/pull/545),
  commit `b6d58edc6980397530cc0110eeaf64d8e25b6078`.
  Sends each command once, requires fresh boot evidence and subsequent advertising
  for factory-reset/advertising operations, propagates command/UART/readiness
  failures, and serializes response reads with logging. The response timeout is
  30 seconds by default. Eleven unit tests, Ruff and editor diagnostics pass.
  Firmware must provide the documented UART markers; successful verification
  against corrected firmware is still pending.

All three fork heads, including PR527's `7b285397378d91fe548088f3b98e159aea58ad03`,
were verified with `git ls-remote`. An isolated, detached private integration
checkout at `/home/feasel/qa-mar6/matter-qa-527-integration` includes exactly that
PR527 revision plus these two cherry-picks. Its commit is
`27c32c7589d08bbb189a098acd6f308cc22779cc`; all **73 combined regressions** pass
(53 cleanup plus 9 parser plus 11 Nordic). No existing PR539/backend changes were
folded into these branches.

### Fresh Preparation and Firmware Blocker

Private staging at `/home/feasel/qa-mar6/pr527-followup-preparation-20261008`
contains twelve campaign configs and twelve separate one-iteration smoke configs.
It also contains two separate two-iteration RT2_1 continuation-smoke configs,
one per controller, to exercise next-iteration callback and scanner cleanup.
The testcase-level `matter_xml_root` is corrected for Send/Read/Write on both hosts,
using each host's configured XML root. Campaign counts remain 10 with failure-stop
limits zero at general and selected testcase levels. Revision pins, script hashes,
fresh future storage paths and the original dataset fingerprint are recorded.
Structured YAML round-trip, privacy, count/XML and original-config-preservation
checks pass. The manifest explicitly says **BLOCKED_PREFLIGHT** and zero executed
hardware iterations; these are prepared inputs, not a deployed or passing fixture.

Live nRF Connect shell queries to DK `001050208117` showed root commands `help`
and `matter`. `matter help` has no reboot command; `matter device` exposes only
factory reset and commissioning-window open/close. Thus neither `kernel reboot`
nor a guessed `matter reboot` is a supported fabric-preserving reboot on this
image. Factory reset is not a valid substitute. The old reboot setting is not
declared fixed: the running image needs a supported reboot capability or an
explicitly supported hardware-reset backend, followed by fresh boot/readiness
verification. No image was built/flashed and no fabrics were intentionally reset.

nRF Connect has no registered application build. Its only listed SDK reports
v3.3.0 at `/home/feasel/ncs/v3.1.1` without an installed toolchain, whereas retained
DUT boots identify v3.4.0. A matching build/image provenance must be recovered
before replacing firmware; an arbitrary available SDK is not a correction.
The owned nRF serial terminal was closed by the user, and `fuser /dev/ttyACM0`
confirmed no remaining owner. Exclusive UART/Bluetooth ownership must be checked
again immediately before any QA reader or live smoke.

### Newly Discriminated SDK Failure Paths

All ten Ubuntu Send/Read/Write setup consoles contain the same immediate sequence:
first BLE scan timeout, `StopDiscovery` rejection with
`org.bluez.Error.InProgress: Operation already in progress`, then two
`BLE scan already in progress` retry failures. `ChipDeviceScanner::StopScan`
returns on the stop error before resetting local scanner state or delivering
`OnScanComplete`. This explains the secondary incorrect-state cascade. The reason
for the first no-match timeout and BlueZ's stop rejection remains unresolved.

All three Ubuntu RT2_1 discovery hangs (logical slots 8-10) also contain that
stop-discovery error before the coordinator interrupt. Slot 8 already logged a
matching DUT advertisement, so its hang is not evidence of absent advertising.
The SDK synchronous BLE iterator waits on an unbounded `queue.get()`. Its error
callback ignores scan errors, and the native scan timer relies on successful
`StopScan` for completion notification. The failed stop can therefore leave the
iterator blocked well beyond its advertised scan timeout.

A hardware-free probe against the actual installed `matter.ble.scan_devices`
confirmed that its error callback supplies no completion sentinel. A mocked-native
probe also confirmed that early `DiscoverSync` generator closure deletes only
the adapter list, not the native scanner. Thus PR527's generator-close log alone
does not prove native scanner release. The installed Python iterator is byte-equal
to the inspected SDK source. Both probes and Ruff pass; they do not reproduce
BlueZ's underlying error or prove hardware recovery. These SDK completion/state
and interrupted-cleanup paths need a separate remedy, not an unrelated addition
to either of the two QA PRs.

Current host inspection found roughly 4 GiB available RAM with no swap; `cpptools`
held roughly 14 GiB RSS. This supports a host-pressure gate, not attribution of
the recorded failures to OOM. No unrelated processes or host policies were changed.
HCI/IP capture coverage is still absent from the old run, so the adapter-level
cause cannot be inferred from its logs alone.

### Remaining Gates

Before the later exact same **six cases x 10 x two controllers (120 slots)** batch:
validate the SDK scan-completion/cleanup fix; establish supported reboot firmware
and UART handoff; deploy/verify the pinned integration on Pi; revalidate the full
live Thread dataset unchanged; verify capture privileges and host stability; and
pass case-specific smokes on both controllers. Hardware callback-crash elimination
is still unverified. No new full batch or hardware smoke has started. The original
1773-file evidence checksum manifest was rechecked successfully and remains sealed.

## Draft SDK Fix and Rerun Gates (2026-10-08)

[SDK PR74676: Make Linux BLE scan teardown failure-safe](https://github.com/project-chip/connectedhomeip/pull/74676)
is **OPEN and DRAFT**, with published commit
`9c797242f1a1f89dbc010255c77d38307304448a`. It is isolated on
`fix/ble-scan-failure-cleanup` in
`/home/feasel/matter-oct14/connectedhomeip-ble-scan-fix`, based on current upstream
`master`, without the reproduction branch's unrelated changes. GitHub REST
confirmed this state and the two QA PRs' conversion to draft; their heads did not
change. The SDK fork hash was independently verified.

Native `StopScan` now resets local scanner state and notifies completion even
when BlueZ stop fails, preserving the error and avoiding a false success message.
The Python synchronous iterator ends on scan error, bounds queue waiting with a
monotonic scan deadline, and deletes the native scanner in `finally` before
releasing the adapter list. This covers normal completion, missing completion,
early generator closure and iteration exceptions. It does not prove BlueZ's
underlying adapter state recovered, nor impose a hard deadline on native teardown.

Seven new hardware-free regressions reproduced the previous failures and pass
afterward. All **42 SDK Python controller tests** pass, including those seven;
the existing CI job discovers them automatically. Ruff, editor diagnostics,
touched-function clang-format and diff checks pass. The native scanner compiles
against the PR headers with the existing configured Linux target's flags and
generated configuration, to a separate object in the new worktree. This is not
a clean full controller build or native BlueZ fault-injection test. Neither host's
installed controller was replaced and no hardware test started.

### Required Before the Full Batch

1. Recover the matching Nordic image/build provenance and toolchain. Supply a
  supported fabric-preserving reboot capability, and prove reboot preserves
  commissioned fabrics while factory reset clears them. Verify fresh boot and
  the appropriate advertising/operational readiness; do not substitute reset
  for reboot or assume a newly typed shell command exists.
2. Apply the SDK fix to the pinned fixture SDK baseline and build/install isolated
  native controller libraries for both Ubuntu x86-64 and Pi ARM64. Verify ABI,
  imports, hashes and security-test-mode parity with the DUT. Shadowing only the
  Python module leaves the native stale-state bug unchanged. Run native failure
  checks that cover rejected stop, completion and a subsequent fresh scan.
3. Deploy and verify the exact QA integration containing corrected PR527 plus
  PR544 and PR545 on both hosts. Keep the corrected testcase XML roots and the
  unchanged six-case, ten-iteration, no-stop matrix settings. Use fresh storage
  per campaign, retaining it across iterations and any process continuation.
4. Establish a stable host and exclusive UART/Bluetooth ownership, verify the full
  live Thread dataset unchanged, and prove HCI/BlueZ/IP/UART captures actually
  work. Address host-memory pressure before scaling; do not attribute its prior
  OOM events to the failures without evidence.
5. Pass each case's smoke on both hosts, then consecutive RT2_1 iterations in one
  native process. Exercise wrong-PIN/reset/failed-discovery cleanup and show no
  hangs, stale-scan retries or callback crashes on the next iteration. If BlueZ
  rejects shutdown or first discovery still fails, diagnose the captured first
  failure before launching the matrix.
6. Start only the agreed **six cases x 10 x two controllers = 120 slots** after
  those gates pass. Retain every failure's diagnostics and reconcile requested
  slots, native outcomes, setup failures and coordinator aborts separately.

Passing these gates makes the rerun meaningful and removes known blockers; it
cannot guarantee that a stress batch finds no further defects. The two QA PRs
and SDK PR remain draft until their verification is satisfactory. Preparation
still says **BLOCKED_PREFLIGHT**, records the new SDK pin and zero executed
hardware iterations, and does not claim its native controller builds are ready.

### Five-Gate Execution Pause (2026-10-09)

Recovered the retained builder's exact NCS commit
`99553055607b2e9885fbc80ccd11fa9da81c2df0`, Zephyr commit
`bf801e4e3d19e1ffa76164346480cb7734dd2800`, GCC 14.3.0 toolchain, and GN
selection. Configured a separate `out/pr527-nordic-reboot` build with a private
kernel-reboot overlay, keeping thread monitoring/manipulation and panic disabled.
Installed SDK-pinned ZAP `v2026.09.09` separately after retaining the failed
missing/outdated-generator probes. Compilation reached Matter step 911/1793
without a compiler error, but was interrupted by an assistant status command
after a tool background handoff. Compilation is incomplete, not firmware-ready.
The owned builder container is stopped; no image was flashed. The original
merged-image SHA-256 remains
`5617e2df9939a2627ba6c10131cdaea2fe2c21311aceaff5fbf885f5990d6a1a`.

Created detached `connectedhomeip-pr527-fixture` at the pinned `b1c4e7514ce`
baseline and replayed only SDK fix `9c797242f1a` without committing. All seven
focused scanner regressions passed against that source. Neither native
controller has yet been rebuilt or installed. Authenticated Pi inventory
reverified machine ID `ef72df43fba94793ab724dc3013cec17`, ARM64 and glibc 2.36.

Local capture authorization blocks further execution:
`sudo -n /usr/bin/dumpcap -D` returned `sudo: a password is required`.
No host permissions or policies were changed. User-controlled authentication
must be performed directly in the terminal; no password should pass through
chat. Private `five-gates-progress.json` records this pause and retained build
logs. Live reboot/fabric checks, native rejection/retry checks, current dataset
and capture checks, and both-host smokes remain pending. Zero new hardware
iterations and no full batch were started. QA544, QA545 and SDK74676 remain
draft; this phase made no PR-state changes.

The user subsequently authorized the full six-case, ten-iteration, two-host
120-slot rerun once all five readiness gates pass, explicitly requiring QA
PR527/544/545 and SDK PR74676. This removes the need for another batch-approval
handoff after readiness is proven; it does not waive any gate or resolve the
capture-authentication blocker. Recheck PR heads, actual native libraries and
runtime imports before launch, retain every failure, and reconcile all slots.

### Five-Gate Progress (2026-10-09 05:04 UTC)

The matched Nordic build completed. Its merged-image SHA-256 is
`ca5609fe1903b16894bbc13f97863ec74e01aeb3be9e4bbcdd8d044d6164d201`;
FLASH usage is 865996 bytes and RAM usage is 197812 bytes. Partition definitions
match the original, and the image excludes settings storage. nRF Connect could
not flash the unregistered build, so the verified `nrfjprog` fallback programmed
and verified only the selected DK with sector erase, without chip erase, recovery
or an implicit reset. The complete settings range was byte-identical before and
after programming while halted. The original build and RCP were not changed.

Fresh hardware boot and a real `kernel reboot` passed, retaining the advertised
operational identity. This is not yet CASE fabric-table preservation proof or
proof that factory reset clears fabrics; those checks remain required.

The isolated Ubuntu controller build, wheel installation, dependency checks,
QA base-class import and seven scanner regressions passed. The installed library
is x86-64, resolves all dependencies, requires GLIBC 2.34 on the GLIBC 2.35 host,
and contains the fixed-key warning. Its SHA-256 is
`01ccbe6c4b2f6c6c17a275b409ffe1ae61b652dbb687bc8cb89181ae4b23079a`.
All 73 combined QA regressions passed in this new runtime. An initial probe
aborted after initializing only the native layer; a subsequent incomplete
lifecycle probe also failed. Both failures were retained, and the corrected
native-init/storage/stack/shutdown lifecycle passed with fresh storage.

The Pi has a separate checksum-verified source snapshot and environment. Its
initial Pigweed check rejected the absence of Git metadata. Pigweed's documented
vendored-source option suppresses only that inapplicable root check; all other
environment checks now pass. Native ARM64 compilation is running, not yet
verified as a successful controller build or hardware runtime.

Current QA PR527/544/545 heads still match the pinned integration inputs. SDK
PR74676 advanced to `e6ffaf7f8b3f337e42650ca325bc8e8f990a6163`; the only delta
from the controller input `9c797242f1a` is C++ assignment line wrapping. An exact
source comparison proves there are no other changes. Record both revisions,
not a claim that these binaries were compiled from the new head. All four PRs
remain draft, with no PR-state changes in this phase.

The full 107-byte live Active Dataset matches the pinned SHA-256
`ed2e96c79a37c1f8af308d0867c3adaa3ebf186b5b6d65dc3777617debc04d39`;
OTBR remains leader with SRP running. The single UART bridge and owned packet
capture are active. A closed segment contains Thread and infrastructure IPv6
traffic, but no BLE LE-meta or ACL packets. Commissioning-window capture coverage
is not proved. Ubuntu's adapter still reports discovery active with an unknown
owner; no unknown scan, Bluetooth service or unrelated process was stopped.

All live native rejection/recovery, CASE fabric/reset, twelve case-smoke and
same-process RT2_1 continuation gates remain incomplete. Zero QA hardware
iterations and no full 120-slot rerun have started. The existing authorization
remains conditional on all gates passing, not waived by these partial results.