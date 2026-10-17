# PR539 Pi Controller / Nordic DUT Validation

## Current Dispositions: 2026-10-16

This report is a chronological record of several superseded designs, not a
single current-source validation. Use the [current defect dispositions](PR539_FAILURE_ANALYSIS_20261011.md#current-failure-dispositions)
and [transport-aware follow-up](PR539_BLE_READINESS_FIX_VALIDATION_20261011.md)
for the current published QA539 head `b99759a` and remaining coverage.

| Recorded Failure / Follow-Up | Current Disposition |
| --- | --- |
| Cached open advertisement accepted immediately after revoke | **RETAINED DESIGN LIMITATION**: the 2026-10-09 passive revision intentionally accepts cached matching records and leaves authentication to commissioning. Earlier live-PASE passes do not establish freshness of the current passive gate. No instantaneous revocation guarantee is claimed. |
| Active readiness PASE consumes DUT admission before actual pairing | **ADDRESSED** by the passive QA539 design: current readiness does not perform the temporary PASE handshake. The intermediate fail-safe-abort probe is historical, not the current solution. |
| One-second discovery restarts prevent candidate resolution | **ADDRESSED** by retaining the SDK discovery window; the review-driven revision below records a passing smoke and 20/20 reset/pair cycles. |
| Recovery probe removes the same fabric twice | Local probe follow-up completed: later smoke/reset runs below record a single removal. Not an outstanding production failure or a reason to rewrite the original failed recovery summary. |
| IP prerequisite before unprovisioned BLE; secondary-window discriminator mismatch | **ADDRESSED** in later published [QA539](https://github.com/CHIP-Specifications/matter-qa/pull/539); 36 tests and 22 passing unprovisioned BLE-Wi-Fi outcomes. Disconnected SSH-reset integration remains outside that workflow. |

Original failures, source hashes, 17/19/29-test milestones and private bundles
below remain associated with their actual historical source snapshots.

## Initial Investigation

One physical BLE/Thread commissioning smoke and one separate recovery check were
run on 2026-10-07. This exercised the exact PR539 discovery method against
Nordic advertisements, not the Raspberry Pi DUT app-restart/reset integration or
a Pi-hosted Nordic UART reset loop. PR539 production code was not changed.

- QA revision: `01fc97d9d2b46920b142a355c5d65e63f9ef4f8d`.
- Controller SDK revision: `b1c4e7514cecc49cbffd6647504c3611b9cf6e60`.
- Controller Pi machine ID: `ef72df43fba94793ab724dc3013cec17`; Debian 12,
  ARM64, glibc 2.36, native Python 3.13.16.
- A second authenticated Pi was inventoried and left unchanged.
- Nordic DUT: nRF52840 DK `001050208117`, Ubuntu-owned J-Link UART.
- Separate OTBR RCP: `8388F563A730D925`; existing network preserved.
- DUT reset and fresh BLE advertising were observed through nRF Connect.
- Runtime boot reported NCS `v3.4.0-99553055607b` and Zephyr
  `v4.4.0-bf801e4e3d19`. No firmware was flashed or read back during this test.
- Live complete Thread dataset was validated and transferred privately. Dataset,
  controller storage and raw logs are not included in this report.

## Controller Verification

Native compilation and wheel installation succeeded. The SDK installer then
exited 127 because an unseeded uv environment lacked its expected `bin/pip`.
Reinstalling pip restored the entry point; installation was finished without
rebuilding C++ or overwriting the original build log.

The ARM64 native library loaded with resolved dependencies and contained the
fixed-key security-test-mode warning. Real PASE/CASE traffic succeeded against
the DUT. All eight PR539 readiness unit tests passed on the Pi.

Native controller SHA256:
`4a70f7d450d88126affeb3c24fac8bd277493155517844779ae702d6e85d89ac`.

QA source archive SHA256:
`38d0ce5b21c8678fca0c4bfd1c661c15098d6991275b432569db1d1d24eed34c`.

## Hardware Results

Primary smoke: `14:50:45.616275` to `14:51:05.913599` UTC.

| Check                                  | Result                                    |
| -------------------------------------- | ----------------------------------------- |
| Pi BLE/Thread commissioning            | Passed                                    |
| CASE BasicInformation reads            | Passed                                    |
| Initially closed window rejected       | Passed; 5.002 s                           |
| Open window discovered by PR539 method | Passed; 1.207 s, discriminator 3840, CM=2 |
| Immediately revoked window rejected    | Failed; readiness accepted cached CM=2    |
| Fabric cleanup in primary smoke        | Not reached after failure                 |

The primary run is not an all-pass validation: four checks passed, one failed,
and one was not reached. Native Avahi logs show cache-derived CM=2 despite a
CASE WindowStatus read of zero. The DUT logged successful SRP withdrawal about
300 ms after the revoke response, after readiness had already returned.

Recovery: `14:52:51.143548` to `14:53:32.823839` UTC, using a private copy of
the primary controller storage. CASE reads passed, and the revoked window was
rejected for 5.002 s after network convergence. Explicit RemoveFabric returned
NOCResponse status zero and fabric index one at `14:52:58.389` UTC; the DUT
rebooted uncommissioned and resumed BLE advertising.

The recovery script subsequently called UnpairDevice, causing a second remote
fabric-removal attempt and a timeout. This was a probe defect, not failure of
the successful RemoveFabric operation. The raw recovery summary remains failed
and unchanged. The duplicate call was removed locally and compile/lint checked;
the corrected cleanup script was not rerun on hardware.

## Limitations and Evidence

DNS-SD open-mode discovery alone does not guarantee freshness or current PASE
acceptance immediately after a state transition. A fresh-readiness safeguard
requires further design and Raspberry Pi DUT lifecycle validation before a
broader PR539 correctness claim.

IP capture was unavailable: dumpcap had listed capabilities but was not
executable by this user. Pi btmon failed with Operation not permitted. No IP or
HCI packet-coverage claim is made. Full Pi console/storage, OTBR logs, build and
installation logs, summaries and exit records are retained privately under
`/home/feasel/qa-mar6/hardware-539-20261007`; no passwords were transferred.

Personal skills were updated with verified SSH/bootstrap, dataset CRLF,
discovery-cache, cleanup-API and capture-permission lessons. The Nordic was left
uncommissioned; the OTBR and the second Pi were not reconfigured.

## Live-PASE Hardening and Revalidation

The earlier failed summaries and sealed evidence remain unchanged. Subsequent
uncommitted PR539 hardening requires a live PASE handshake, bounds discovery and
handshake by the overall deadline, checks the configured discriminator, and
releases the probe on success, timeout and cancellation. All 17 focused tests
passed on Ubuntu and the native Pi controller; lint and compile checks passed.

Fresh Nordic smoke: `16:29:03.967475` to `16:29:31.976370` UTC. All six checks
passed: BLE/Thread commissioning, CASE reads, initially closed-window rejection,
enhanced-window live PASE, immediate revoked-window rejection and a single
successful explicit fabric removal. The enhanced window used its returned PIN.
The open-window gate completed in 1.729 s. After revocation, discovery still
returned the same cached CM=2 record, but the gate correctly rejected readiness
for 5.005 s. There was no fixed settling delay and no duplicate UnpairDevice.

Tested Raspi source SHA256:
`e7d46d2a47ac8ce299b54cc939940f9e1f66079ea4eae488115ffaa9490cafb5`.
Raw console, controller storage, source snapshot and summary are retained
privately under the new `pr539-live-readiness-20261007` campaign. No new packet
capture coverage is claimed.

The second Pi is now the selected Linux DUT fixture with identity-verified,
restricted Pi-to-Pi SSH. At this stage its native app build was in progress;
the real reset loop had not yet run and PR539 remained draft.

## DUT-Side Probe Cleanup and Final Validation

The first native reset-harness attempt stopped before DUT setup because the SDK
configuration field is `setup_passcodes`, not `passcodes`. The second reached
the first real reset and readiness handshake, but immediate commissioning failed:
successful PASE closed the DUT's PASE admission and armed its fail-safe. Local
StopPairing did not reopen that window. Both failed summaries remain unchanged.

The final probe sends ArmFailSafe with expiry zero over its authenticated PASE
session, checks the successful response, then releases the local proxy. This
restores DUT-side PASE admission before actual commissioning. The SDK counts the
abort as a failed attempt, so the hook is used once after reset, not as a health
poller. All 19 focused tests passed on Ubuntu and the native Pi, including abort
ordering and failure handling. Ruff, autopep8 and isort checks passed.

Real Pi-to-Pi lifecycle: `16:55:53.409768` to `16:56:46.720126` UTC. All 20
requested resets completed, with immediate on-network commissioning and CASE
reads after each. CommissionedFabrics was exactly one in every iteration.
Controlled launch delays followed the pattern 0/2/0/1 seconds. Reset/readiness
took 0.654-2.722 s. Enhanced-window live authentication, immediate revoked-window
rejection (5.006 s), and one native UnpairDevice cleanup also passed.

Final Nordic smoke: `16:58:32.606664` to `16:59:04.535856` UTC. All six checks
passed with the same final source. Enhanced-window readiness took 1.812 s and
immediate revoked-window rejection took 5.001 s. The fabric was removed once.

Final tested/current Raspi source SHA256:
`09d5064ca50d8cc5225feb3f055c53ee7ca5ef0b657c8033771fee15bc56f4bb`.
Linux DUT ELF SHA256:
`cbc6f50f2641ec5d93fdf074e2890ce8d5363fe3dce641e325bdfc1ad0ff947b`.
Native build exit zero, target ARM64 architecture, resolved dependencies, CLI and
test-mode marker were verified. The fixture used both no-BLE GN switches.

Final run summaries, per-iteration DUT logs, controller consoles/storage and
build/deployment proof were retrieved privately and reconciled against the exact
current source. Packet capture remains a coverage limitation. This validates the
real Linux Raspi reset path plus Nordic BLE/Thread smoke, not a long Nordic UART
reset campaign or another ecosystem controller implementation.

## Publication

Follow-up commit `9d2d95bdd512f5548780730a78c319cce555860d` was pushed only to
the `feasel0` fork. Ruff and Restyled both passed on that exact published head.
[PR539](https://github.com/CHIP-Specifications/matter-qa/pull/539) was marked
ready for review with the verified testing results and probe limitations in its
description. Human review approval remains required.

## Review-Driven Revision: 2026-10-09 UTC

The preceding live-probe results are historical and do not validate this revision.
After independent review, the user selected a non-invasive discovery prerequisite,
unchanged commissioning retry limits, and a discovery attempt budget with awaited
native cleanup rather than an absolute wall-clock guarantee.

The revised gate runs once after reset, including direct reset callers and existing
initial commissioning retries. It collects candidates without stopping on the first
closed record, accepts matching open advertisements including legacy bare link-local
addresses, and leaves PASE authentication to actual commissioning. Cached records
can satisfy the prerequisite. No temporary PASE, fail-safe abort or local session
release is performed. The standalone script runner retains its legacy reset delay.

Fresh validation used the same identity-verified native Pi controller and Linux DUT
binaries, in a separate private directory with fresh controller storage. The first
smoke failed before commissioning: restarting discovery every second prevented
resolution from yielding candidates. That failed run remains preserved. Using the
SDK's default discovery window corrected this without adding commissioning retries.
A new two-cycle smoke then passed.

Final run: `2026-10-09T03:08:22.478377Z` to `03:10:40.425714Z`.

- 20 requested, executed and passed cycles: ten direct resets, ten wrapped resets.
- Every cycle invoked production `pair_dut`, with launch delays of 0/2/0/1 seconds.
- Exactly one discovery check and one DUT PASE handshake per cycle.
- CASE SoftwareVersion and CommissionedFabrics reads passed; fabrics equaled one.
- Final single UnpairDevice passed; overall exit status was zero.
- 29 focused tests passed on Ubuntu and native ARM64; whole-repository Ruff,
  compilation, formatter, YAML, whitespace and editor checks passed.

Exact tested Raspi SHA256:
`057dae9c84b1db464d9f2fa9c2df62d0623f667f597c5ba3503747721ad255a7`.
QA base-class SHA256:
`76cd368172f3a77346a1c42510ff70f599482f67ab115c1c8ac176a99e59ba56`.
All eight changed files were hash-verified on the controller before the final run.

Private retrieved hardware bundle:
`/home/feasel/qa-mar6/pr539-review-fixes-20261008/evidence.tar.gz`.
SHA256: `9c7b711b168ab1b9c0d4a069157a14415403d58ffc7038f0a84d6325b46b5367`.
Source snapshots, failure/success summaries, DUT logs and console/exit records are
retained. All older sealed bundles remain unchanged. Only the new run-owned SSH
authorization and key pair were removed; the fixture DUT is stopped. No Nordic,
OTBR, ecosystem-controller hardware or packet-capture validation is claimed here.

The revised implementation was published as
`9dccf415b4019ba2db94d04f9199d27ae4477602`, pushed only to the `feasel0` fork.
PR539's description now records passive discovery, the cleanup allowance and the
new production-pairing validation rather than the superseded probe guarantees.
