# PR539 Hardware Validation

Date: 2026-10-11 UTC. Status: PR matrix and focused baseline runs concluded;
evidence integrity checks and cleanup verified. This is not a passing merge gate.

## Current Failure Dispositions: 2026-10-16

This report preserves the original snapshot: 238 campaign outcomes, 70 campaign
FAILs and nine smoke FAILs. A later fix does not change those counts. Use the
[current per-defect dispositions](PR539_FAILURE_ANALYSIS_20261011.md#current-failure-dispositions)
for remaining work rather than the historical follow-up requests below.

| Original Finding / Follow-Up | Current Disposition |
| --- | --- |
| IP prerequisite before unprovisioned BLE and secondary-window mismatch | **ADDRESSED** by [QA539](https://github.com/CHIP-Specifications/matter-qa/pull/539), published head `b99759a`; 36 tests and 22 passing unprovisioned BLE-Wi-Fi outcomes in the [later validation](PR539_BLE_READINESS_FIX_VALIDATION_20261011.md). The genuine unprovisioned follow-up is no longer untested. |
| Valve write verification and invalid cross-controller equality | **ADDRESSED** as specific predicates by [QA547](https://github.com/CHIP-Specifications/matter-qa/pull/547) and [QA548](https://github.com/CHIP-Specifications/matter-qa/pull/548). Real native read/subscription timeouts remain **OPEN**, not comparison failures. |
| Local ctypes callbacks can be collected | **ADDRESSED** by [QA549](https://github.com/CHIP-Specifications/matter-qa/pull/549). Historical SIGSEGV causality remains **OPEN** without a backtrace. |
| Failure-unsafe cleanup / primary error masking | **ADDRESSED** by [QA527](https://github.com/CHIP-Specifications/matter-qa/pull/527); expanded hardware validation remains pending. |
| BLE scanner error masking/local state and fixture adapter selection | Scanner defect **ADDRESSED** by [SDK74676](https://github.com/project-chip/connectedhomeip/pull/74676); wrong adapter selection corrected in the fixture. Original PASE/BlueZ causality and daemon recovery remain **OPEN**. |

The original source pins, baselines, exceptions and evidence limits below
describe that run, not the current PR heads or a full-matrix clearance.

## Scope

- PR539: `9dccf415b4019ba2db94d04f9199d27ae4477602`.
- Pre-PR baseline: `39388edd3608cf95563904b04d6d13a0300e8ffc`.
- Ubuntu and Pi1 run the native Matter Python controller, with fixed runtimes
  held equal between revisions on each host.
- Pi2 runs the Linux DUT over its existing Wi-Fi connection, using on-network
  commissioning. Its installed DUT has BLE disabled.
- The Nordic nRF52840 DK uses BLE-Thread commissioning through Ubuntu OTBR.
  The separate nRF52840 RCP dongle and OTBR remained on Ubuntu. No firmware was
  flashed and the live Thread dataset was kept unchanged.
- Target: ten iterations per case and fixture, preserving the controller
  process and storage within each campaign. One-iteration smokes are separate.

## PR Matrix

All 32 cells were attempted. There are 238 recorded campaign outcomes:
168 passes and 70 failures. Twenty-three cells reached ten iterations, five
stopped early, and four were setup-blocked. The 320-iteration target has 82
unfinished slots: 42 in started campaigns and 40 in blocked cells.

The table shows passes/failures, not requested/executed counts. An asterisk
means the campaign stopped early; missing iterations are not counted as failures.

| Case | Ubuntu -> Pi2 | Pi1 -> Pi2 | Ubuntu -> Nordic | Pi1 -> Nordic |
| --- | ---: | ---: | ---: | ---: |
| TC_RT_1_1 | 10/0 | 10/0 | 0/10 | 10/0 |
| TC_RT_1_2 | 0/4* | 0/1* | Blocked | 0/10 |
| TC_RT_2_1 | 1/0* | 1/0* | 0/10 | 1/0* |
| TC_Send_Command_Read_Write_Attributes | 8/2 | 6/4 | Blocked | 1/9 |
| TC_Darwin_Pair | 10/0 | 10/0 | 0/10 | 10/0 |
| TC_Android_Pair | 10/0 | 10/0 | 0/10 | 10/0 |
| TC_ON_OFF | 10/0 | 10/0 | Blocked | 10/0 |
| TC_LEVEL_CONTROL | 10/0 | 10/0 | Blocked | 10/0 |

PR smokes: 32 requested, 28 recorded outcomes, 19 passes, nine failures, and
four setup failures without iteration outcomes. These are excluded from the
238 campaign outcomes.

## Failure Evidence

- Ubuntu-to-Nordic campaigns failed before secure pairing. BlueZ
  `StopDiscovery: InProgress` preceded `Incorrect state`. All 12 capture
  segments for that fixture contain no controller BLE ACL traffic.
- The pre-PR baseline commissioning smoke failed and its ten-iteration
  Ubuntu-to-Nordic campaign also finished 0/10 with the same signature. This
  symptom therefore does not require PR539; its root cause is not established.
- One bounded Bluetooth-service restart was performed using the installed
  lab helper, after preserving diagnostics and stopping captures. The separate
  post-recovery baseline smoke still failed, now reporting `BLE adapter
  unavailable` despite BlueZ reporting the adapter powered. The recovery
  campaign also finished 0/10. It is separate from the original PR and baseline
  totals; no second restart was attempted.
- Three discovery campaigns exited with SIGSEGV after one passing iteration:
  both Pi2-DUT controller combinations and Pi1-to-Nordic. The test registers
  local no-op ctypes callback objects that the SDK setters do not retain.
  This is a plausible callback-lifetime defect, not a proven crash backtrace.
  The pre-PR baseline Ubuntu-to-Pi2 campaign reproduced the same SIGSEGV after
  one passing iteration; the crash therefore does not require PR539.
- Multi-admin failures report subscription/read mismatches and cleanup
  timeouts. Bulk-operation failures report attribute write verification.
  The discovery, multi-admin, and bulk scripts are byte-for-byte identical
  between baseline and PR539. That alone does not establish causal attribution.
- Ubuntu kernel evidence includes a Python segfault at 14:46:38 UTC and a
  separate `cpptools` OOM kill at 16:16:15 UTC. The latter is retained as an
  infrastructure caveat, not an explanation for every failure. The Pi kernel
  query returned no entries, so a Pi crash backtrace is unavailable.

## Focused Baselines

These are separate ten-requested-iteration campaigns, not additions to the
PR matrix. Each had a separate one-iteration smoke, excluded below.

| Controller / DUT / Case | PR Pass / Fail | Baseline Pass / Fail | Baseline Exit |
| --- | ---: | ---: | ---: |
| Ubuntu / Nordic / TC_RT_1_1 | 0/10 | 0/10 | 1 |
| Ubuntu / Pi2 / TC_RT_2_1 | 1/0* | 1/0* | -11 |
| Ubuntu / Pi2 / Bulk Read/Write | 8/2 | 4/6 | 1 |
| Pi1 / Nordic / Bulk Read/Write | 1/9 | 6/4 | 1 |

Baseline campaigns recorded 31 outcomes: 11 passes and 20 failures, with
nine unfinished discovery iterations. Four baseline smokes recorded one pass
and three failures. The separate post-recovery baseline added ten failures
and one failing smoke; it is not included in these baseline counts.

BLE failure, discovery crash, and bulk-write verification failure occur
without PR539. This does not prove every PR failure is unrelated, nor that the
different bulk-write pass rates represent an improvement or regression. Tests
use randomized operations and small, sequential samples. Multi-admin has no
matched hardware baseline in this campaign and remains unattributed.

## Evidence Limits

The 60 PR capture segments closed without cleanup errors and are readable.
Including baseline and recovery runs, 70 closed segments passed the readability
audit with no observed ring overwrite. Final SHA-256 manifests cover 2,783 closed
evidence files, excluding private controller storage and invocation/configuration
files. These are private integrity records, not redacted public packet bundles.
One original full-ring validation rejection is preserved, with a separate
reconciliation proving that all original ring files 1 through 16 were retained.
Its separate recount found 33,170 IPv6 packets and 136 Pi BLE ACL packets.

Successful Pi-to-Nordic commissioning captures contain BLE and IPv6 traffic.
Both successful Darwin controller campaigns have 30 runtime security-test-mode
warnings, with corresponding warnings retained in Nordic UART logs. Packet
readability, packet counts, and warning strings are not authenticated protocol
decryption; full packet-level PASE/CASE validation remains unproven.

At this snapshot, the focused readiness suite passed 29 tests on Ubuntu and 29 on ARM64. A
six-scenario CPU-only probe found that pending Pi reset readiness requires IP
discovery before BLE commissioning. Genuine unprovisioned BLE-Wi-Fi was not
tested by this matrix; the later passing follow-up is recorded above. The Pi2
on-network tests in this original matrix do not cover that condition.

TC_RT_2_2 needs a second isolated network/OTBR; bridge add/remove needs a
compatible bridge DUT; BDX/OTA needs staged provider/requestor artifacts. Those
prerequisites were not available. Real iOS/Android ecosystem controllers were
not used; the Darwin/Android-named scripts use the Python controller.

## Private Artifacts

Full results, source exports, controller/DUT logs, captures, and closed-file
SHA-256 manifests are retained under
`/home/feasel/qa-mar6/pr539-full-testing-20261011`.
Controller storage, dataset material, packet payloads, and temporary SSH keys
must not be included in public evidence. Historical bundles remain unchanged.
No PR539 or SDK production source was changed during this matrix.

No hardware campaign is still running. Both exact campaign-owned SSH
authorization lines and both campaign private keys were removed. Unrelated
authorizations and retained storage/evidence were preserved. The Pi2 DUT is
stopped, the Nordic UART has no owner, and Ubuntu OTBR remains leader with the
unchanged dataset. The PR539 worktree is clean.

The campaign is concluded with limitations, not successful completion of all
requested iterations. Its original follow-up requests are reconciled above;
current unresolved native failures and validation limits remain separate from
the addressed code defects.