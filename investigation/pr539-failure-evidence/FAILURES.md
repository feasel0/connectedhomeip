# PR539 Failure Evidence and Investigation Queue

Updated UTC: 2026-10-13T16:00:29.353554+00:00

Local working dossier. Not committed. Raw evidence contains keys/payloads and stays outside this repository. Existing originals, failed attempts, incomplete slots and historical archives are never deleted or rewritten by this updater.

158 individually identified failed hardware outcomes. Process/setup incidents and CPU-proven PR defects are separate, not extra FAIL iterations.

Investigation order: PR539, current methodology, pre-existing harness, pre-existing SDK, then uncertain. Current batch is closed; continue investigating remaining failures in this order. Classification is a hypothesis unless explicitly proved.

## Current Resolution

Resolution reconciled 2026-10-17 against published PR539/547/548/549/550 fixes and exact historical path extraction. **FIXED** means the identified defect is repaired in the PR, not merged upstream and not that an original FAIL became PASS. **OPEN** means no demonstrated fix for that exact mechanism. Fixture workarounds alone do not establish a PR fix.

Of the 158 historical failed outcomes below, **80 map to FIXED mechanisms; 78 remain OPEN**. Native crashes and infrastructure/review issues are separate, not extra failed iterations. Catalog IDs and original evidence remain intact; verified v9 and corrected-rerun IDs display their exact fabric-index or metadata/scene attribution.

Latest fixes and subsequent evidence: [review resolution](PR_REVIEW_20261013.md#current-resolution) and [full-matrix resolution](FULL_MATRIX_20261014.md#current-resolution). These reports also cover findings and campaigns newer than this historical catalog.

## Remaining Work

| OPEN Failure Family | Historical Outcomes | Next Action |
| --- | ---: | --- |
| Offline BLE-Wi-Fi a02: subscription failure | 1 | Inspect HCI, BlueZ services and commissioner/DUT logs together. |
| Offline BLE-Wi-Fi GATT failures | 5 | Verify exported peer services, ServicesResolved, effective daemon arguments and HCI events. |
| Ubuntu BLE fixture: empty discovery | 11 | Correlate HCI coverage and native controller index against the exact failed source/configuration. |
| Concurrent read timeout replaced by cleanup timeout | 3 | Preserve the primary read error when cleanup fails; investigate full-load concurrency/subscriptions and SDK/fixture ownership. The Pi-controller cell still needs matched attribution. |
| Offline BLE-Wi-Fi operational timeout | 3 | Correlate provisioning, actual IPv6 addresses, DNS-SD and CASE establishment rather than repeating BLE pairing. |
| Ubuntu BLE fixture: PASE IncorrectState | 55 | Inspect the indexed capture and adapter-selection provenance before drawing SDK conclusions. |

- **OPEN:** exact native SIGSEGV root cause; PR549 repairs the proven callback lifetime defect, but no deciding native backtrace attributes every crash.
- **FIXED:** independent controller-map aliasing is repaired in PR548 `e8fcf30` with per-controller deep copies; two regressions fail before and pass after, with all 107 RT_1_2 tests passing. Published to the feasel0 fork and GitHub head verified. Native timeout causality is still open. See [targeted execution](../37075/RT12_TARGETED_ATTRIBUTION_20261017.md).
- **OPEN:** CI project-label workflow/token remediation and historical fixture closeout gaps.
- **OPEN:** newer full-load read/subscription/cleanup timeouts and remaining coverage gaps. Patched Pi btmon has a live discovery-capture proof, not retroactive repair of the historical HCI losses or full commissioning coverage.

## Evidence Locations and Preservation

- Historical originals: `/home/feasel/qa-mar6/pr539-full-testing-20261011`
- Follow-up originals: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011`
- Pi1 retained counterpart: `/home/feasel/matter-pr539-ble-readiness-fix-20261011`
- Independent private content-addressed copies: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/failure-preservation/objects`
- [Preservation manifest](preserved-files.json) maps every copied original to SHA-256, byte count and archived copy. [Structured catalog](catalog.json) provides exact unique IDs and classifications.
- Only closed run evidence is copied. Active captures and growing logs are linked but deferred until closure. Credential/controller-storage files remain in their private original locations and are deliberately excluded from copies.
- Copy integrity is checked against originals. A changed preserved original or missing copy is an error, not silently accepted. Capture readability is not authenticated Matter decryption.
- Preserved closed files: 2414. Preservation notes: none.

Historical sealed archives: `final-summary-20261011-202835.tar.gz` (SHA-256 `58134c99e22f3dbcd4952f51f89f02e2a2d874a73367767dbc27f18a8b748c5e`) under the historical root; `allowlisted-final-summary-20261012-151127.tar.gz` (`eaa6420e42975f10443e29f572f1414cb4ecf2d37cb0aeef7d8b261e5a3b7188`) and `allowlisted-separate-completed-20261012-201316.tar.gz` (`31fa8c522fcf14c9b28d6d7eb9af7de22ee0f4d4023a50fb99dfa02cc1506d68`) under the follow-up root. Earlier seals do not cover newer or active attempts.

Hardware: Ubuntu or Pi1 native Python controller; Pi2 Wi-Fi/on-network or genuinely unprovisioned BLE-Wi-Fi DUT; Nordic DK 001050208117 uses BLE-Thread through Ubuntu OTBR and RCP 8388F563A730D925. No new firmware or dataset change. Darwin/Android test names are not physical ecosystem controllers.

## 1. Probably Due to PR539

Failed hardware outcomes in this category: 0.

### FIXED: PR539-CPU-01: IP prerequisite before BLE

Resolution: **FIXED** in PR539 `e9f5f6b`, retained in `b99759a`.

Confirmed by extracted production readiness method and six-scenario CPU probe: pending Pi reset required an IP advertisement before BLE-Wi-Fi provisioning could occur. Repaired hook bypasses IP only for BLE and leaves the later IP prerequisite pending. No hardware FAIL is conclusively attributed to this defect.
Evidence: `/home/feasel/qa-mar6/pr539-full-testing-20261011/failure-probes.json`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/transport-prerequisite.json`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/check_transport_prerequisite.py`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/final-source/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-final-validation.json`. Final-source primary/manual smokes and twenty cycles passed.

### FIXED: PR539-CPU-02: Secondary commissioning-window discriminator

Resolution: **FIXED** in PR539 `e9f5f6b`, retained in `b99759a`.

Repaired secondary path forwards on-network transport and the actual opened-window discriminator rather than relying on the primary configuration. Focused controls and physical two-fabric boundary cycles verify this behavior; do not count CPU controls as hardware failures.
Evidence: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/final-source/qa/src/matter_qa/unit_tests/test_raspi_readiness.py`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/final-source/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-final-validation.json`. Matching PR539 four-file change was published in e9f5f6b7e8b1cfb1280f35f6b1c2d03237f0be2e at the user's request. Fresh review findings are recorded in [PR review](PR_REVIEW_20261013.md); publication does not establish merge clearance.
## 2. Probably Due to Current Testing Methodology

Failed hardware outcomes in this category: 75.


### OPEN: Offline BLE-Wi-Fi a02: subscription failure

Resolution: **OPEN**. No published fix establishes resolution of this exact mechanism.

Historical diagnosis (not current work): A real commissioning smoke failed in the BLE/BlueZ path. Fixture service configuration and cached unpaired-peer state were repaired. Exact native-versus-BlueZ root cause is unproved.

Next deciding check: Inspect HCI, BlueZ services and commissioner/DUT logs together.

#### Failure 7530ec8a82f24ce5: early offline BLE-Wi-Fi, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a02`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a02/controller/summary.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a02/dut/bluez-journal.private.log`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a02/dut/dut.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/wifi-primary-smokes-01-a02.console.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/captures/wifi-primary-smokes-01-a02`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-final-validation.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: setup favored; exact Bluetooth/IPv6 mechanism not fully proved. Evidence status: closed; eligible for preservation.


### OPEN: Offline BLE-Wi-Fi GATT failures

Resolution: **OPEN**. No published fix establishes resolution of this exact mechanism.

Historical diagnosis (not current work): a03 and a05-a08 could not discover valid Matter GATT services. a08 did not actually apply the intended single-ATT configuration because its launcher failed open. Later corrected fixture passed 22 final-source cycles. This does not prove the specific root cause of every historical GATT failure.

Next deciding check: Verify exported peer services, ServicesResolved, effective daemon arguments and HCI events.

#### Failure 326b6e82a2407b74: early offline BLE-Wi-Fi, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a03`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a03/controller/summary.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a03/dut/dut.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/wifi-primary-smokes-01-a03.console.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/captures/wifi-primary-smokes-01-a03`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-final-validation.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: setup favored; exact Bluetooth/IPv6 mechanism not fully proved. Evidence status: closed; eligible for preservation.

#### Failure 9b2a44b24023d8e5: early offline BLE-Wi-Fi, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a05`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a05/controller/summary.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a05/dut/dut.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/wifi-primary-smokes-01-a05.console.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/captures/wifi-primary-smokes-01-a05`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-final-validation.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: setup favored; exact Bluetooth/IPv6 mechanism not fully proved. Evidence status: closed; eligible for preservation.

#### Failure f47c1cab6351cf41: early offline BLE-Wi-Fi, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a06`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a06/controller/summary.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a06/dut/dut.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/wifi-primary-smokes-01-a06.console.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/captures/wifi-primary-smokes-01-a06`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-final-validation.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: setup favored; exact Bluetooth/IPv6 mechanism not fully proved. Evidence status: closed; eligible for preservation.

#### Failure 27790c2fe89dcbd1: early offline BLE-Wi-Fi, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a07`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a07/controller/summary.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a07/controller/bluez-journal.private.log`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a07/dut/dut.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/wifi-primary-smokes-01-a07.console.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/captures/wifi-primary-smokes-01-a07`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-final-validation.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: setup favored; exact Bluetooth/IPv6 mechanism not fully proved. Evidence status: closed; eligible for preservation.

#### Failure 415e90edd5f1e1b4: early offline BLE-Wi-Fi, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a08`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a08/controller/summary.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a08/dut/dut.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/wifi-primary-smokes-01-a08.console.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/captures/wifi-primary-smokes-01-a08`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-final-validation.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: setup favored; exact Bluetooth/IPv6 mechanism not fully proved. Evidence status: closed; eligible for preservation.


### OPEN: Ubuntu BLE fixture: empty discovery

Resolution: **OPEN**. No published fix establishes resolution of this exact mechanism.

Historical diagnosis (not current work): 11 original/recovery outcomes. Original RT2_1 could not discover Matter BLE; recovery still reported adapter unavailable. The RCP dongle is not the controller adapter. Later stage-selection discovery failures have a different cause and are separate.

Next deciding check: Correlate HCI coverage and native controller index against the exact failed source/configuration.

#### Failure 6a8a99bb8fbc2d27: original matrix and baseline, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-1`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-1/logs/MatterTest/ble-thread/10-11-2026_12-19-02-725/TC_RT_2_1/1/controller_log_iteration_1_2026-10-11_12-19-07.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_2_1-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_2_1-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-1/logs/MatterTest/ble-thread/10-11-2026_12-19-02-725/TC_RT_2_1/1/controller_log_iteration_1_2026-10-11_12-19-07.log:31`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 3f9414bbaf9f6dda: original matrix and baseline, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/1/controller_log_iteration_1_2026-10-11_12-20-09.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_2_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/1/controller_log_iteration_1_2026-10-11_12-20-09.log:33`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 2680d9fc607bdbcc: original matrix and baseline, iteration 2

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/2/controller_log_iteration_2_2026-10-11_12-20-59.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_2_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/2/controller_log_iteration_2_2026-10-11_12-20-59.log:16`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 6213ab44eb21a0e8: original matrix and baseline, iteration 3

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/3/controller_log_iteration_3_2026-10-11_12-21-49.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_2_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/3/controller_log_iteration_3_2026-10-11_12-21-49.log:16`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 84f043c79428ca2c: original matrix and baseline, iteration 4

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/4/controller_log_iteration_4_2026-10-11_12-22-40.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_2_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/4/controller_log_iteration_4_2026-10-11_12-22-40.log:16`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 316885f26ffaa7d2: original matrix and baseline, iteration 5

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/5/controller_log_iteration_5_2026-10-11_12-23-30.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_2_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/5/controller_log_iteration_5_2026-10-11_12-23-30.log:16`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure f28debac1866b54e: original matrix and baseline, iteration 6

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/6/controller_log_iteration_6_2026-10-11_12-24-20.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_2_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/6/controller_log_iteration_6_2026-10-11_12-24-20.log:16`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 7aff8c5ed1354930: original matrix and baseline, iteration 7

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/7/controller_log_iteration_7_2026-10-11_12-25-11.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_2_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/7/controller_log_iteration_7_2026-10-11_12-25-11.log:18`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 67bdcb409983777c: original matrix and baseline, iteration 8

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/8/controller_log_iteration_8_2026-10-11_12-26-01.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_2_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/8/controller_log_iteration_8_2026-10-11_12-26-01.log:16`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure d7f195bdbad1c7c5: original matrix and baseline, iteration 9

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/9/controller_log_iteration_9_2026-10-11_12-26-51.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_2_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/9/controller_log_iteration_9_2026-10-11_12-26-51.log:16`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure fa6ab04b3a425912: original matrix and baseline, iteration 10

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/10/controller_log_iteration_10_2026-10-11_12-27-42.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_2_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-11-2026_12-20-03-914/TC_RT_2_1/10/controller_log_iteration_10_2026-10-11_12-27-42.log:16`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.


### OPEN: Offline BLE-Wi-Fi operational timeout

Resolution: **OPEN**. No published fix establishes resolution of this exact mechanism.

Historical diagnosis (not current work): a04/a09 passed PASE/provisioning before operational discovery timeout; a10 lacked expected IPv6 link-local behavior. Temporary RA/address-generation repairs were restored at closeout. Pi2 does not need Ethernet.

Next deciding check: Correlate provisioning, actual IPv6 addresses, DNS-SD and CASE establishment rather than repeating BLE pairing.

#### Failure ca3d300af4dc9e9e: early offline BLE-Wi-Fi, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a04`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a04/controller/summary.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a04/dut/dut.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/wifi-primary-smokes-01-a04.console.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/captures/wifi-primary-smokes-01-a04`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-final-validation.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: setup favored; exact Bluetooth/IPv6 mechanism not fully proved. Evidence status: closed; eligible for preservation.

#### Failure dbb5d8f70aca047e: early offline BLE-Wi-Fi, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a09`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a09/controller/summary.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a09/dut/dut.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/wifi-primary-smokes-01-a09.console.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/captures/wifi-primary-smokes-01-a09`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-final-validation.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: setup favored; exact Bluetooth/IPv6 mechanism not fully proved. Evidence status: closed; eligible for preservation.

#### Failure 012d5d5b000dd3b3: early offline BLE-Wi-Fi, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a10/controller/summary.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a10/dut/dut.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/wifi-primary-smokes-01-a10.console.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/captures/wifi-primary-smokes-01-a10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-final-validation.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: setup favored; exact Bluetooth/IPv6 mechanism not fully proved. Evidence status: closed; eligible for preservation.


### OPEN: Ubuntu BLE fixture: PASE IncorrectState

Resolution: **OPEN**. No published fix establishes resolution of this exact mechanism.

Historical diagnosis (not current work): 55 original/baseline/recovery outcomes. BlueZ StopDiscovery InProgress and absent controller BLE ACL traffic; baseline reproduces. The final fixture inspection found the controller at hci1/index 1 while older runs selected absent hci0. Corrected commissioning cases pass. This favors setup, not proof of a particular BlueZ or SDK defect.

Next deciding check: Inspect the indexed capture and adapter-selection provenance before drawing SDK conclusions.

#### Failure 8588996a79109b9a: original matrix and baseline, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-1`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-1/logs/MatterTest/ble-thread/10-11-2026_15-16-22-872/TC_RT_1_1/1/controller_log_iteration_1_2026-10-11_15-16-48.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-ubuntu-TC_RT_1_1-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-ubuntu-TC_RT_1_1-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-1/logs/MatterTest/ble-thread/10-11-2026_15-16-22-872/TC_RT_1_1/1/controller_log_iteration_1_2026-10-11_15-16-48.log:49`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 87a85a6c954e897f: original matrix and baseline, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/1/controller_log_iteration_1_2026-10-11_15-18-10.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/1/controller_log_iteration_1_2026-10-11_15-18-10.log:49`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure c2f8c1111243cda1: original matrix and baseline, iteration 2

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/2/controller_log_iteration_2_2026-10-11_15-19-01.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/2/controller_log_iteration_2_2026-10-11_15-19-01.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure e417af69fb50c241: original matrix and baseline, iteration 3

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/3/controller_log_iteration_3_2026-10-11_15-19-51.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/3/controller_log_iteration_3_2026-10-11_15-19-51.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure c800c8e8091dd702: original matrix and baseline, iteration 4

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/4/controller_log_iteration_4_2026-10-11_15-20-41.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/4/controller_log_iteration_4_2026-10-11_15-20-41.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure ef789d779df06d11: original matrix and baseline, iteration 5

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/5/controller_log_iteration_5_2026-10-11_15-21-32.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/5/controller_log_iteration_5_2026-10-11_15-21-32.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure d14468a1250a20f5: original matrix and baseline, iteration 6

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/6/controller_log_iteration_6_2026-10-11_15-22-22.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/6/controller_log_iteration_6_2026-10-11_15-22-22.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure c924db8bd0f889ae: original matrix and baseline, iteration 7

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/7/controller_log_iteration_7_2026-10-11_15-23-12.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/7/controller_log_iteration_7_2026-10-11_15-23-12.log:38`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 0d82548aa489bc83: original matrix and baseline, iteration 8

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/8/controller_log_iteration_8_2026-10-11_15-24-02.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/8/controller_log_iteration_8_2026-10-11_15-24-02.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 5dcbd66a71248487: original matrix and baseline, iteration 9

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/9/controller_log_iteration_9_2026-10-11_15-24-53.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/9/controller_log_iteration_9_2026-10-11_15-24-53.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure e446c1bac17df3d4: original matrix and baseline, iteration 10

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/10/controller_log_iteration_10_2026-10-11_15-25-43.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-17-45-111/TC_RT_1_1/10/controller_log_iteration_10_2026-10-11_15-25-43.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 1799111f3b752bb8: original matrix and baseline, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-1`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-1/logs/MatterTest/ble-thread/10-11-2026_12-40-11-940/TC_Android_Pair/1/controller_log_iteration_1_2026-10-11_12-40-37.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Android_Pair-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Android_Pair-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-1/logs/MatterTest/ble-thread/10-11-2026_12-40-11-940/TC_Android_Pair/1/controller_log_iteration_1_2026-10-11_12-40-37.log:50`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure d41797bef0aa5d35: original matrix and baseline, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/1/controller_log_iteration_1_2026-10-11_12-41-54.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Android_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/1/controller_log_iteration_1_2026-10-11_12-41-54.log:48`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure a136d1ae323dd41b: original matrix and baseline, iteration 2

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/2/controller_log_iteration_2_2026-10-11_12-42-39.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Android_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/2/controller_log_iteration_2_2026-10-11_12-42-39.log:35`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure c054288656972f51: original matrix and baseline, iteration 3

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/3/controller_log_iteration_3_2026-10-11_12-43-24.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Android_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/3/controller_log_iteration_3_2026-10-11_12-43-24.log:41`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure f8ebead5a863f9fb: original matrix and baseline, iteration 4

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/4/controller_log_iteration_4_2026-10-11_12-44-09.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Android_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/4/controller_log_iteration_4_2026-10-11_12-44-09.log:35`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 84ac45432c00f9f8: original matrix and baseline, iteration 5

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/5/controller_log_iteration_5_2026-10-11_12-44-55.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Android_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/5/controller_log_iteration_5_2026-10-11_12-44-55.log:35`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 1bf3d64d7cd2424d: original matrix and baseline, iteration 6

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/6/controller_log_iteration_6_2026-10-11_12-45-40.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Android_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/6/controller_log_iteration_6_2026-10-11_12-45-40.log:35`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 507e04a3f5f7bd7b: original matrix and baseline, iteration 7

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/7/controller_log_iteration_7_2026-10-11_12-46-25.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Android_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/7/controller_log_iteration_7_2026-10-11_12-46-25.log:35`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 13f82a4be6307a7b: original matrix and baseline, iteration 8

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/8/controller_log_iteration_8_2026-10-11_12-47-11.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Android_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/8/controller_log_iteration_8_2026-10-11_12-47-11.log:35`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 945793c57c00e40c: original matrix and baseline, iteration 9

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/9/controller_log_iteration_9_2026-10-11_12-47-56.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Android_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/9/controller_log_iteration_9_2026-10-11_12-47-56.log:35`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 37dcad67bbb0aed5: original matrix and baseline, iteration 10

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/10/controller_log_iteration_10_2026-10-11_12-48-41.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Android_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Android_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Android_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-41-28-437/TC_Android_Pair/10/controller_log_iteration_10_2026-10-11_12-48-41.log:37`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure b94ec3a4c7ebc911: original matrix and baseline, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-1`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-1/logs/MatterTest/ble-thread/10-11-2026_12-30-50-164/TC_Darwin_Pair/1/controller_log_iteration_1_2026-10-11_12-31-15.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Darwin_Pair-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Darwin_Pair-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-1/logs/MatterTest/ble-thread/10-11-2026_12-30-50-164/TC_Darwin_Pair/1/controller_log_iteration_1_2026-10-11_12-31-15.log:51`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 38f38e4418c6b9fd: original matrix and baseline, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/1/controller_log_iteration_1_2026-10-11_12-32-32.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Darwin_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/1/controller_log_iteration_1_2026-10-11_12-32-32.log:51`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 1e00dad854fe5e99: original matrix and baseline, iteration 2

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/2/controller_log_iteration_2_2026-10-11_12-33-17.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Darwin_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/2/controller_log_iteration_2_2026-10-11_12-33-17.log:35`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 321ddd2dd408604e: original matrix and baseline, iteration 3

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/3/controller_log_iteration_3_2026-10-11_12-34-02.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Darwin_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/3/controller_log_iteration_3_2026-10-11_12-34-02.log:35`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 1c4782f7d743f35f: original matrix and baseline, iteration 4

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/4/controller_log_iteration_4_2026-10-11_12-34-48.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Darwin_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/4/controller_log_iteration_4_2026-10-11_12-34-48.log:35`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure b4a8160f7049fff3: original matrix and baseline, iteration 5

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/5/controller_log_iteration_5_2026-10-11_12-35-33.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Darwin_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/5/controller_log_iteration_5_2026-10-11_12-35-33.log:37`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 95936f2fb1f53dcb: original matrix and baseline, iteration 6

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/6/controller_log_iteration_6_2026-10-11_12-36-18.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Darwin_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/6/controller_log_iteration_6_2026-10-11_12-36-18.log:39`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure a4bb4a2c2f6c7913: original matrix and baseline, iteration 7

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/7/controller_log_iteration_7_2026-10-11_12-37-04.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Darwin_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/7/controller_log_iteration_7_2026-10-11_12-37-04.log:35`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 7d935f9c394cabcc: original matrix and baseline, iteration 8

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/8/controller_log_iteration_8_2026-10-11_12-37-49.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Darwin_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/8/controller_log_iteration_8_2026-10-11_12-37-49.log:35`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 524bfb0aa0be7e58: original matrix and baseline, iteration 9

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/9/controller_log_iteration_9_2026-10-11_12-38-34.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Darwin_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/9/controller_log_iteration_9_2026-10-11_12-38-34.log:35`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure b15ba55a9b5689d2: original matrix and baseline, iteration 10

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/10/controller_log_iteration_10_2026-10-11_12-39-20.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_Darwin_Pair-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_Darwin_Pair-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_Darwin_Pair-10/logs/MatterTest/ble-thread/10-11-2026_12-32-06-638/TC_Darwin_Pair/10/controller_log_iteration_10_2026-10-11_12-39-20.log:37`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 87c9fe2f03552d6c: original matrix and baseline, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-1`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-1/logs/MatterTest/ble-thread/10-11-2026_12-06-31-488/TC_RT_1_1/1/controller_log_iteration_1_2026-10-11_12-06-57.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_1_1-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_1_1-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-1/logs/MatterTest/ble-thread/10-11-2026_12-06-31-488/TC_RT_1_1/1/controller_log_iteration_1_2026-10-11_12-06-57.log:49`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 553a496ea727ada2: original matrix and baseline, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/1/controller_log_iteration_1_2026-10-11_12-08-19.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/1/controller_log_iteration_1_2026-10-11_12-08-19.log:51`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure ba40ddbafe007c10: original matrix and baseline, iteration 2

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/2/controller_log_iteration_2_2026-10-11_12-09-09.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/2/controller_log_iteration_2_2026-10-11_12-09-09.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure ff47adb8c12a4292: original matrix and baseline, iteration 3

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/3/controller_log_iteration_3_2026-10-11_12-10-00.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/3/controller_log_iteration_3_2026-10-11_12-10-00.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 6911e61d9c0c73d7: original matrix and baseline, iteration 4

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/4/controller_log_iteration_4_2026-10-11_12-10-50.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/4/controller_log_iteration_4_2026-10-11_12-10-50.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 67d24e011354369b: original matrix and baseline, iteration 5

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/5/controller_log_iteration_5_2026-10-11_12-11-40.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/5/controller_log_iteration_5_2026-10-11_12-11-40.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure ca13dc9249566e8e: original matrix and baseline, iteration 6

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/6/controller_log_iteration_6_2026-10-11_12-12-31.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/6/controller_log_iteration_6_2026-10-11_12-12-31.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure f0ed0adf98ec4968: original matrix and baseline, iteration 7

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/7/controller_log_iteration_7_2026-10-11_12-13-21.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/7/controller_log_iteration_7_2026-10-11_12-13-21.log:38`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure a3f457c89b3e8e1a: original matrix and baseline, iteration 8

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/8/controller_log_iteration_8_2026-10-11_12-14-12.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/8/controller_log_iteration_8_2026-10-11_12-14-12.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure a658e4a057dbdacf: original matrix and baseline, iteration 9

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/9/controller_log_iteration_9_2026-10-11_12-15-02.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/9/controller_log_iteration_9_2026-10-11_12-15-02.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 5c9a28603b3d853d: original matrix and baseline, iteration 10

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/10/controller_log_iteration_10_2026-10-11_12-15-52.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_12-07-53-953/TC_RT_1_1/10/controller_log_iteration_10_2026-10-11_12-15-52.log:36`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 5d8926a308e70e27: recovery baseline, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-1`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-1/logs/MatterTest/ble-thread/10-11-2026_15-29-19-211/TC_RT_1_1/1/controller_log_iteration_1_2026-10-11_15-29-44.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/baseline-nordic-ubuntu-TC_RT_1_1-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/captures/baseline-nordic-ubuntu-TC_RT_1_1-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-1/logs/MatterTest/ble-thread/10-11-2026_15-29-19-211/TC_RT_1_1/1/controller_log_iteration_1_2026-10-11_15-29-44.log:29`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure a53e51acd9734b89: recovery baseline, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/1/controller_log_iteration_1_2026-10-11_15-31-07.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/1/controller_log_iteration_1_2026-10-11_15-31-07.log:29`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 6cf5a8a82dc0f02c: recovery baseline, iteration 2

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/2/controller_log_iteration_2_2026-10-11_15-31-58.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/2/controller_log_iteration_2_2026-10-11_15-31-58.log:28`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 522cccb922be4296: recovery baseline, iteration 3

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/3/controller_log_iteration_3_2026-10-11_15-32-48.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/3/controller_log_iteration_3_2026-10-11_15-32-48.log:28`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 2b717d6c1fc81512: recovery baseline, iteration 4

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/4/controller_log_iteration_4_2026-10-11_15-33-38.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/4/controller_log_iteration_4_2026-10-11_15-33-38.log:30`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 3705dffcfaf0985e: recovery baseline, iteration 5

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/5/controller_log_iteration_5_2026-10-11_15-34-29.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/5/controller_log_iteration_5_2026-10-11_15-34-29.log:28`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure b930efee0cced71a: recovery baseline, iteration 6

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/6/controller_log_iteration_6_2026-10-11_15-35-19.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/6/controller_log_iteration_6_2026-10-11_15-35-19.log:28`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 2cde073e7ff361d6: recovery baseline, iteration 7

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/7/controller_log_iteration_7_2026-10-11_15-36-09.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/7/controller_log_iteration_7_2026-10-11_15-36-09.log:28`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 40500505afc76042: recovery baseline, iteration 8

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/8/controller_log_iteration_8_2026-10-11_15-37-00.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/8/controller_log_iteration_8_2026-10-11_15-37-00.log:28`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 9fc9e346b2c6c2bb: recovery baseline, iteration 9

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/9/controller_log_iteration_9_2026-10-11_15-37-50.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/9/controller_log_iteration_9_2026-10-11_15-37-50.log:28`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

#### Failure 93ebcddf6291e6c9: recovery baseline, iteration 10

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/10/controller_log_iteration_10_2026-10-11_15-38-41.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/baseline-nordic-ubuntu-TC_RT_1_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/captures/baseline-nordic-ubuntu-TC_RT_1_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-ble-recovery/runs/baseline-nordic-ubuntu-TC_RT_1_1-10/logs/MatterTest/ble-thread/10-11-2026_15-30-42-314/TC_RT_1_1/10/controller_log_iteration_10_2026-10-11_15-38-41.log:28`
- Confidence: high for fixture attribution; native-versus-BlueZ cause unresolved. Evidence status: closed; eligible for preservation.

### Setup and Infrastructure Incidents (Not Additional FAIL Outcomes)

- Initial ENOTTY launch failure: `/home/feasel/qa-mar6/pr539-full-testing-20261011/setup-failures` and `first-smoke-setup-supervisor.log` under historical root; no native iteration outcome.
- Offline a01 precondition failed before valid DUT launch: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01` and corresponding console/reconnect logs; no valid test iteration.
- a08 single-ATT fail-open configuration: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/pi1-bluez-single-att-recovery.json` and a08 controller/DUT evidence above; does not add another failure to its existing FAIL.
- RA/address-generation and recovery: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/network-inspection-01`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/network-inspection-02`, per-attempt DUT network-state files, `pi2-bluez-setup-repair.json`, `pi1-bluez-*-recovery.json`; original settings restored.
- a11 protocol PASS but fixture signaling/closeout failed: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ble-wifi-runs/wifi-primary-smokes-01-a11`. Not a fully closed PASS gate.
- Editor interruption: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-stage-integration-v2/editor-interruption.json`, retained run logs and host `*-crash-stop.json` capture records. Zero completed outcomes, ten unfinished; exact signal unknown. Durable continuation retained separately.
- Completion-watcher Python ABI setup: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/publish_separate_hardware_status.py` uses Python3.10 D-Bus bindings; wrong default interpreter was an observer/setup error, not hardware failure.
- Missing optional pairing-cleanup module: retained preflight logs under `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011`; no foreign-revision test substituted.

## 3. Pre-Existing Test Harness Problems

Failed hardware outcomes in this category: 80.


### FIXED: Read v9: OperationalCredentials CurrentFabricIndex

Resolution: **FIXED**. PR548 `7b75e7b`, retained in `a550450`: validate indexes and compare according to fabric identity; v10 passed 10/10.

Historical diagnosis (not current work): All ten v9 iterations failed at requesting-fabric indexes, with 30 identified comparisons. PR548 validates indexes in 1-254 and permits differences only across compressed fabric identities. The corrected v10 snapshot passed ten iterations; the fix was subsequently published.

#### Failure 10438225351291f9: rt12-read-integration-v9-all-five, iteration 1

- Resolution: **FIXED**. PR548 `7b75e7b`, retained in `a550450`: validate indexes and compare according to fabric identity; v10 passed 10/10.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-13-2026_10-16-08-228/TC_RT_1_2/1/controller_log_iteration_1_2026-10-13_10-17-20.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: pending. Evidence status: closed; eligible for preservation.

#### Failure 549bca9c2b00dccf: rt12-read-integration-v9-all-five, iteration 2

- Resolution: **FIXED**. PR548 `7b75e7b`, retained in `a550450`: validate indexes and compare according to fabric identity; v10 passed 10/10.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-13-2026_10-16-08-228/TC_RT_1_2/2/controller_log_iteration_2_2026-10-13_10-21-23.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: pending. Evidence status: closed; eligible for preservation.

#### Failure 5012de0fddd0dad1: rt12-read-integration-v9-all-five, iteration 3

- Resolution: **FIXED**. PR548 `7b75e7b`, retained in `a550450`: validate indexes and compare according to fabric identity; v10 passed 10/10.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-13-2026_10-16-08-228/TC_RT_1_2/3/controller_log_iteration_3_2026-10-13_10-25-20.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: pending. Evidence status: closed; eligible for preservation.

#### Failure afadff143e413fec: rt12-read-integration-v9-all-five, iteration 4

- Resolution: **FIXED**. PR548 `7b75e7b`, retained in `a550450`: validate indexes and compare according to fabric identity; v10 passed 10/10.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-13-2026_10-16-08-228/TC_RT_1_2/4/controller_log_iteration_4_2026-10-13_10-29-14.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: pending. Evidence status: closed; eligible for preservation.

#### Failure 114e6dc16ee6ae6e: rt12-read-integration-v9-all-five, iteration 5

- Resolution: **FIXED**. PR548 `7b75e7b`, retained in `a550450`: validate indexes and compare according to fabric identity; v10 passed 10/10.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-13-2026_10-16-08-228/TC_RT_1_2/5/controller_log_iteration_5_2026-10-13_10-33-09.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: pending. Evidence status: closed; eligible for preservation.

#### Failure 5a52ea1bd1faa282: rt12-read-integration-v9-all-five, iteration 6

- Resolution: **FIXED**. PR548 `7b75e7b`, retained in `a550450`: validate indexes and compare according to fabric identity; v10 passed 10/10.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-13-2026_10-16-08-228/TC_RT_1_2/6/controller_log_iteration_6_2026-10-13_10-37-03.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: pending. Evidence status: closed; eligible for preservation.

#### Failure c30adfc582b73690: rt12-read-integration-v9-all-five, iteration 7

- Resolution: **FIXED**. PR548 `7b75e7b`, retained in `a550450`: validate indexes and compare according to fabric identity; v10 passed 10/10.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-13-2026_10-16-08-228/TC_RT_1_2/7/controller_log_iteration_7_2026-10-13_10-40-57.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: pending. Evidence status: closed; eligible for preservation.

#### Failure af630d00669fe2f8: rt12-read-integration-v9-all-five, iteration 8

- Resolution: **FIXED**. PR548 `7b75e7b`, retained in `a550450`: validate indexes and compare according to fabric identity; v10 passed 10/10.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-13-2026_10-16-08-228/TC_RT_1_2/8/controller_log_iteration_8_2026-10-13_10-44-49.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: pending. Evidence status: closed; eligible for preservation.

#### Failure 8d82396f140d172f: rt12-read-integration-v9-all-five, iteration 9

- Resolution: **FIXED**. PR548 `7b75e7b`, retained in `a550450`: validate indexes and compare according to fabric identity; v10 passed 10/10.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-13-2026_10-16-08-228/TC_RT_1_2/9/controller_log_iteration_9_2026-10-13_10-48-40.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: pending. Evidence status: closed; eligible for preservation.

#### Failure 59fa1859d905f3db: rt12-read-integration-v9-all-five, iteration 10

- Resolution: **FIXED**. PR548 `7b75e7b`, retained in `a550450`: validate indexes and compare according to fabric identity; v10 passed 10/10.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-13-2026_10-16-08-228/TC_RT_1_2/10/controller_log_iteration_10_2026-10-13_10-52-32.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v9-all-five/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: pending. Evidence status: closed; eligible for preservation.


### FIXED: Read smoke v3: DeviceLoadStatus

Resolution: **FIXED**. PR548 `a550450`: typed/domain-checked device-load observations rather than blanket equality.

Historical diagnosis (not current work): DeviceLoadStruct is an observation, not necessarily identical cross-controller state. Per-fabric and global counts need different treatment. Earlier snapshot was an incomplete harness repair.

#### Failure 238b30480b528e16: rt12-read-integration-v3, iteration 1

- Resolution: **FIXED**. PR548 `a550450`: typed/domain-checked device-load observations rather than blanket equality.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v3/runs/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v3/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v3/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-12-2026_12-01-17-248/TC_RT_1_2/1/controller_log_iteration_1_2026-10-12_12-02-30.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v3/pr539-nordic-ubuntu-TC_RT_1_2-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v3/captures/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v3/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v3/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.


### FIXED: Read smoke v1: IdentifyTime

Resolution: **FIXED**. PR548 `a550450`: validated countdown drift bounded by the measured read window.

Historical diagnosis (not current work): A live countdown changes between reads. The initial metadata/fabric fix was incomplete. PR548 now bounds time-sensitive values by the measured monotonic read window rather than requiring equality.

#### Failure cb98a2f53f8a30de: rt12-read-integration, iteration 1

- Resolution: **FIXED**. PR548 `a550450`: validated countdown drift bounded by the measured read window.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration/runs/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-12-2026_11-41-33-238/TC_RT_1_2/1/controller_log_iteration_1_2026-10-12_11-42-46.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration/pr539-nordic-ubuntu-TC_RT_1_2-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration/captures/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.


### FIXED: Read smoke v5: Thread neighbor/route tables

Resolution: **FIXED**. PR548 `9a003ab`, retained in `a550450`: validate live fields and compare stable membership/topology without order dependence; physical multi-entry churn remains untested.

Historical diagnosis (not current work): Live observations changed. Typed domains and observation fields need validation, but stable topology must remain strict. No Thread dataset change or firmware workaround was used.

#### Failure b68ddc83975d39b9: rt12-read-integration-v5, iteration 1

- Resolution: **FIXED**. PR548 `9a003ab`, retained in `a550450`: validate live fields and compare stable membership/topology without order dependence; physical multi-entry churn remains untested.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v5/runs/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v5/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v5/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-12-2026_12-22-41-347/TC_RT_1_2/1/controller_log_iteration_1_2026-10-12_12-23-54.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v5/pr539-nordic-ubuntu-TC_RT_1_2-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v5/captures/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v5/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v5/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.


### FIXED: Unreachable SecurePairing reset target

Resolution: **FIXED**. PR550 `2b0feed`: excludes unreachable SecurePairing targets in both modes and propagates callback reset failures; use with PR549 ownership.

Historical diagnosis (not current work): Original callback-fix campaign iteration 8 selected SecurePairing start but no callback reset occurred; commissioning completed and later BLE discovery was empty. Exact-source continuation iteration 3 selected completion and the target-observation guard failed. AutoCommissioner advances to ReadCommissioningInfo without either selected SecurePairing notification; stage IDs match. PR550 now excludes this stage in both modes and still fails missing/nonmatching target observations.

#### Failure 7569c23c7d84fed1: rt21-callback-integration, iteration 8

- Resolution: **FIXED**. PR550 `2b0feed`: excludes unreachable SecurePairing targets in both modes and propagates callback reset failures; use with PR549 ownership.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-integration/runs/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-integration/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-integration/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-12-2026_12-46-19-055/TC_RT_2_1/8/controller_log_iteration_8_2026-10-12_14-53-41.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-integration/pr539-nordic-ubuntu-TC_RT_2_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-integration/captures/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-integration/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-integration/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure 855a15fe523ce0e1: rt21-callback-stage-integration-v2-editor-resume-20261012, iteration 3

- Resolution: **FIXED**. PR550 `2b0feed`: excludes unreachable SecurePairing targets in both modes and propagates callback reset failures; use with PR549 ownership.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-stage-integration-v2-editor-resume-20261012/runs/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-stage-integration-v2-editor-resume-20261012/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-stage-integration-v2-editor-resume-20261012/runs/pr539-nordic-ubuntu-TC_RT_2_1-10/logs/MatterTest/ble-thread/10-12-2026_17-18-22-311/TC_RT_2_1/3/controller_log_iteration_3_2026-10-12_17-54-27.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-stage-integration-v2-editor-resume-20261012/pr539-nordic-ubuntu-TC_RT_2_1-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-stage-integration-v2-editor-resume-20261012/captures/pr539-nordic-ubuntu-TC_RT_2_1-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-stage-integration-v2-editor-resume-20261012/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-stage-integration-v2-editor-resume-20261012/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.


### FIXED: Read smoke v4: Thread counters and uptime

Resolution: **FIXED**. PR548 `a550450`: explicit traffic-counter domains and measured uptime drift; error counters remain strict.

Historical diagnosis (not current work): Traffic counters advance during the test. PR548 explicitly handles 20 traffic counters and uptime while retaining strict error-counter checks.

#### Failure c9d78ba04745e521: rt12-read-integration-v4, iteration 1

- Resolution: **FIXED**. PR548 `a550450`: explicit traffic-counter domains and measured uptime drift; error counters remain strict.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v4/runs/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v4/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v4/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-12-2026_12-11-00-846/TC_RT_1_2/1/controller_log_iteration_1_2026-10-12_12-12-13.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v4/pr539-nordic-ubuntu-TC_RT_1_2-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v4/captures/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v4/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v4/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.


### FIXED: Read smoke v2: UTCTime

Resolution: **FIXED**. PR548 `a550450`: validated advancing clocks and uptime bounded by the measured read window.

Historical diagnosis (not current work): UTC/local time and uptime are advancing observations. PR548 uses the real asyncio.gather read window and validates domains; earlier snapshot remains a failed hardware smoke.

#### Failure 669047f99406dffa: rt12-read-integration-v2, iteration 1

- Resolution: **FIXED**. PR548 `a550450`: validated advancing clocks and uptime bounded by the measured read window.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v2/runs/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v2/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v2/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-12-2026_11-51-54-041/TC_RT_1_2/1/controller_log_iteration_1_2026-10-12_11-53-07.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v2/pr539-nordic-ubuntu-TC_RT_1_2-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v2/captures/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v2/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v2/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.


### FIXED: Valve verification in corrected Ubuntu/Nordic rerun

Resolution: **FIXED**. PR547 `6e93374`: step-aligned positive Valve writes; retained negative controls still reject invalid values.

Historical diagnosis (not current work): The corrected adapter rerun still rejects positive Valve writes/subscription verification. These belong to the separate pre-existing constraint-generation investigation, not the repaired PR539 readiness hook. Preserve the exact per-iteration status and generated value; case name alone is insufficient for future attribution.

#### Failure 7340a1ed44c78c6c: corrected Ubuntu/Nordic, iteration 1

- Resolution: **FIXED**. PR547 `6e93374`: step-aligned positive Valve writes; retained negative controls still reject invalid values.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/1/controller_log_iteration_1_2026-10-12_01-04-29.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure 5b68f7cc34f8e880: corrected Ubuntu/Nordic, iteration 4

- Resolution: **FIXED**. PR547 `6e93374`: step-aligned positive Valve writes; retained negative controls still reject invalid values.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/4/controller_log_iteration_4_2026-10-12_01-14-55.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure 8c2ee1471dbb2004: corrected Ubuntu/Nordic, iteration 5

- Resolution: **FIXED**. PR547 `6e93374`: step-aligned positive Valve writes; retained negative controls still reject invalid values.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/5/controller_log_iteration_5_2026-10-12_01-17-24.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure c2e882648e4ee8d6: corrected Ubuntu/Nordic, iteration 6

- Resolution: **FIXED**. PR547 `6e93374`: step-aligned positive Valve writes; retained negative controls still reject invalid values.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/6/controller_log_iteration_6_2026-10-12_01-19-53.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure 7944b2d55c688a4d: corrected Ubuntu/Nordic, iteration 7

- Resolution: **FIXED**. PR547 `6e93374`: step-aligned positive Valve writes; retained negative controls still reject invalid values.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/7/controller_log_iteration_7_2026-10-12_01-22-22.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure ae02c81bc35fb670: corrected Ubuntu/Nordic, iteration 10

- Resolution: **FIXED**. PR547 `6e93374`: step-aligned positive Valve writes; retained negative controls still reject invalid values.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/10/controller_log_iteration_10_2026-10-12_01-32-36.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure 4fc09a6eb300d738: corrected Ubuntu/Nordic, iteration 1

- Resolution: **FIXED**. PR547 `6e93374`: step-aligned positive Valve writes; retained negative controls still reject invalid values.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-12-2026_01-37-41-946/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-12_01-39-03.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure ccb500555e4657a2: corrected Ubuntu/Nordic, iteration 2

- Resolution: **FIXED**. PR547 `6e93374`: step-aligned positive Valve writes; retained negative controls still reject invalid values.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-12-2026_01-37-41-946/TC_Send_Command_Read_Write_Attributes/2/controller_log_iteration_2_2026-10-12_01-39-47.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure 831d3e79f790ffc9: corrected Ubuntu/Nordic, iteration 3

- Resolution: **FIXED**. PR547 `6e93374`: step-aligned positive Valve writes; retained negative controls still reject invalid values.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-12-2026_01-37-41-946/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-12_01-40-31.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure 54653117da611a7f: corrected Ubuntu/Nordic, iteration 8

- Resolution: **FIXED**. PR547 `6e93374`: step-aligned positive Valve writes; retained negative controls still reject invalid values.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-12-2026_01-37-41-946/TC_Send_Command_Read_Write_Attributes/8/controller_log_iteration_8_2026-10-12_01-44-53.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure a183e989d1905a8f: corrected Ubuntu/Nordic, iteration 10

- Resolution: **FIXED**. PR547 `6e93374`: step-aligned positive Valve writes; retained negative controls still reject invalid values.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-12-2026_01-37-41-946/TC_Send_Command_Read_Write_Attributes/10/controller_log_iteration_10_2026-10-12_01-46-33.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.


### FIXED: Valve DefaultOpenLevel constraint generation

Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.

Historical diagnosis (not current work): Positive-write generation ignored live LevelStep; odd generated values were rejected with ConstraintError on step-2 DUTs. The verifier counted constraint skips as failures and described a readback mismatch. Baseline reproduces. PR547 fixes generation without suppressing all rejected writes; smoke plus ten iterations passed.

#### Failure 4233970618da32b3: original matrix and baseline, iteration 1

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-1`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/ble-thread/10-11-2026_16-13-10-157/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-14-32.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/ble-thread/10-11-2026_16-13-10-157/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-14-32.log:28683`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/ble-thread/10-11-2026_16-13-10-157/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-14-32.log:57970`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/ble-thread/10-11-2026_16-13-10-157/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-14-32.log:58015`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/ble-thread/10-11-2026_16-13-10-157/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-14-32.log:58016`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 037d3bdc6ea873d8: original matrix and baseline, iteration 1

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-16-49.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-16-49.log:28688`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-16-49.log:57972`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-16-49.log:58018`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-16-49.log:58019`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure ed321192280f9536: original matrix and baseline, iteration 2

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/2/controller_log_iteration_2_2026-10-11_16-17-31.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/2/controller_log_iteration_2_2026-10-11_16-17-31.log:28641`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/2/controller_log_iteration_2_2026-10-11_16-17-31.log:57929`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/2/controller_log_iteration_2_2026-10-11_16-17-31.log:57973`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/2/controller_log_iteration_2_2026-10-11_16-17-31.log:57974`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 528bb78e792a8302: original matrix and baseline, iteration 3

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_16-18-14.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_16-18-14.log:28643`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_16-18-14.log:57949`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_16-18-14.log:57993`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_16-18-14.log:57994`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure b2969330a03ddaba: original matrix and baseline, iteration 7

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_16-21-39.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_16-21-39.log:29005`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_16-21-39.log:58364`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_16-21-39.log:58408`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_16-15-27-371/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_16-21-39.log:58409`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure c4d2959630c85e27: original matrix and baseline, iteration 1

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-1`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/on-network/10-11-2026_16-09-09-672/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-09-32.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/on-network/10-11-2026_16-09-09-672/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-09-32.log:27132`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/on-network/10-11-2026_16-09-09-672/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-09-32.log:52986`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/on-network/10-11-2026_16-09-09-672/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-09-32.log:107910`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/on-network/10-11-2026_16-09-09-672/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-09-32.log:107963`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/on-network/10-11-2026_16-09-09-672/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-09-32.log:107964`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 1075bb205330ebcb: original matrix and baseline, iteration 1

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-10-15.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-10-15.log:27132`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-10-15.log:52985`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-10-15.log:107386`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-10-15.log:107432`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_16-10-15.log:107433`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure f63a457c044175f8: original matrix and baseline, iteration 5

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/5/controller_log_iteration_5_2026-10-11_16-11-26.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/5/controller_log_iteration_5_2026-10-11_16-11-26.log:27325`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/5/controller_log_iteration_5_2026-10-11_16-11-26.log:53278`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/5/controller_log_iteration_5_2026-10-11_16-11-26.log:108104`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/5/controller_log_iteration_5_2026-10-11_16-11-26.log:108153`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/5/controller_log_iteration_5_2026-10-11_16-11-26.log:108154`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 406b4a4eed66ccbb: original matrix and baseline, iteration 7

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_16-11-59.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_16-11-59.log:27325`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_16-11-59.log:53266`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_16-11-59.log:108616`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_16-11-59.log:108670`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_16-11-59.log:108671`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure e878663d2e08783c: original matrix and baseline, iteration 8

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/8/controller_log_iteration_8_2026-10-11_16-12-13.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/8/controller_log_iteration_8_2026-10-11_16-12-13.log:27009`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/8/controller_log_iteration_8_2026-10-11_16-12-13.log:52955`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/8/controller_log_iteration_8_2026-10-11_16-12-13.log:107875`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/8/controller_log_iteration_8_2026-10-11_16-12-13.log:107932`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/8/controller_log_iteration_8_2026-10-11_16-12-13.log:107933`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure c3ce02dd0e8af80c: original matrix and baseline, iteration 9

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_16-12-27.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_16-12-27.log:27106`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_16-12-27.log:53044`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_16-12-27.log:107971`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_16-12-27.log:108023`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_16-12-27.log:108024`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 3973dd0ae9d1a730: original matrix and baseline, iteration 10

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/10/controller_log_iteration_10_2026-10-11_16-12-41.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/10/controller_log_iteration_10_2026-10-11_16-12-41.log:27106`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/10/controller_log_iteration_10_2026-10-11_16-12-41.log:53052`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/10/controller_log_iteration_10_2026-10-11_16-12-41.log:107976`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/10/controller_log_iteration_10_2026-10-11_16-12-41.log:108026`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_16-09-52-257/TC_Send_Command_Read_Write_Attributes/10/controller_log_iteration_10_2026-10-11_16-12-41.log:108027`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure aa759a84d84af7db: original matrix and baseline, iteration 1

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-1`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/ble-thread/10-11-2026_14-22-13-023/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_14-23-35.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/ble-thread/10-11-2026_14-22-13-023/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_14-23-35.log:28688`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/ble-thread/10-11-2026_14-22-13-023/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_14-23-35.log:57974`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/ble-thread/10-11-2026_14-22-13-023/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_14-23-35.log:58020`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/ble-thread/10-11-2026_14-22-13-023/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_14-23-35.log:58021`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 94f40fcf187b3ad1: original matrix and baseline, iteration 1

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_14-25-51.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_14-25-51.log:28684`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_14-25-51.log:57970`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_14-25-51.log:58016`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_14-25-51.log:58017`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 00674c818dec706c: original matrix and baseline, iteration 3

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_14-27-29.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_14-27-29.log:29201`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_14-27-29.log:58505`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_14-27-29.log:58550`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_14-27-29.log:58551`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure da521b476a9be3b6: original matrix and baseline, iteration 4

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/4/controller_log_iteration_4_2026-10-11_14-28-12.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/4/controller_log_iteration_4_2026-10-11_14-28-12.log:28659`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/4/controller_log_iteration_4_2026-10-11_14-28-12.log:57965`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/4/controller_log_iteration_4_2026-10-11_14-28-12.log:58009`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/4/controller_log_iteration_4_2026-10-11_14-28-12.log:58010`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 16da500d4264660a: original matrix and baseline, iteration 5

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/5/controller_log_iteration_5_2026-10-11_14-28-55.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/5/controller_log_iteration_5_2026-10-11_14-28-55.log:28659`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/5/controller_log_iteration_5_2026-10-11_14-28-55.log:57947`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/5/controller_log_iteration_5_2026-10-11_14-28-55.log:57992`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/5/controller_log_iteration_5_2026-10-11_14-28-55.log:57993`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 074e395fbcddfbb2: original matrix and baseline, iteration 6

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/6/controller_log_iteration_6_2026-10-11_14-29-38.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/6/controller_log_iteration_6_2026-10-11_14-29-38.log:28643`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/6/controller_log_iteration_6_2026-10-11_14-29-38.log:57929`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/6/controller_log_iteration_6_2026-10-11_14-29-38.log:57975`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/6/controller_log_iteration_6_2026-10-11_14-29-38.log:57976`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 1bc7d02c0bc10a60: original matrix and baseline, iteration 7

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_14-30-20.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_14-30-20.log:28643`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_14-30-20.log:57932`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_14-30-20.log:57978`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/7/controller_log_iteration_7_2026-10-11_14-30-20.log:57979`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 3ba4496eefc90cb6: original matrix and baseline, iteration 8

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/8/controller_log_iteration_8_2026-10-11_14-31-03.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/8/controller_log_iteration_8_2026-10-11_14-31-03.log:28643`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/8/controller_log_iteration_8_2026-10-11_14-31-03.log:57930`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/8/controller_log_iteration_8_2026-10-11_14-31-03.log:57975`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/8/controller_log_iteration_8_2026-10-11_14-31-03.log:57976`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure eba91ebaf43ef6dd: original matrix and baseline, iteration 9

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_14-31-48.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_14-31-48.log:28641`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_14-31-48.log:57927`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_14-31-48.log:57971`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_14-31-48.log:57972`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 040693617adbb71c: original matrix and baseline, iteration 10

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/10/controller_log_iteration_10_2026-10-11_14-32-31.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/10/controller_log_iteration_10_2026-10-11_14-32-31.log:28639`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/10/controller_log_iteration_10_2026-10-11_14-32-31.log:57925`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/10/controller_log_iteration_10_2026-10-11_14-32-31.log:57969`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/ble-thread/10-11-2026_14-24-29-787/TC_Send_Command_Read_Write_Attributes/10/controller_log_iteration_10_2026-10-11_14-32-31.log:57970`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 6e2576a973878949: original matrix and baseline, iteration 1

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-1`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/on-network/10-11-2026_11-47-07-825/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_11-47-26.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/on-network/10-11-2026_11-47-07-825/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_11-47-26.log:28626`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/on-network/10-11-2026_11-47-07-825/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_11-47-26.log:57874`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/on-network/10-11-2026_11-47-07-825/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_11-47-26.log:57918`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-1/logs/MatterTest/on-network/10-11-2026_11-47-07-825/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_11-47-26.log:57919`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 8c84e4bdddd8f094: original matrix and baseline, iteration 1

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_11-48-06.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_11-48-06.log:28629`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_11-48-06.log:57928`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_11-48-06.log:57973`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_11-48-06.log:57974`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure ac55308c85faf6e0: original matrix and baseline, iteration 4

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/4/controller_log_iteration_4_2026-10-11_11-48-52.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/4/controller_log_iteration_4_2026-10-11_11-48-52.log:28856`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/4/controller_log_iteration_4_2026-10-11_11-48-52.log:58213`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/4/controller_log_iteration_4_2026-10-11_11-48-52.log:58257`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/4/controller_log_iteration_4_2026-10-11_11-48-52.log:58258`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 0cc8a0695b15a282: original matrix and baseline, iteration 6

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/6/controller_log_iteration_6_2026-10-11_11-49-21.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/6/controller_log_iteration_6_2026-10-11_11-49-21.log:28872`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/6/controller_log_iteration_6_2026-10-11_11-49-21.log:58162`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/6/controller_log_iteration_6_2026-10-11_11-49-21.log:58206`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/6/controller_log_iteration_6_2026-10-11_11-49-21.log:58207`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 560d8cc3c331f646: original matrix and baseline, iteration 9

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_11-50-07.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_11-50-07.log:28916`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_11-50-07.log:58273`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_11-50-07.log:58315`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_11-47-48-274/TC_Send_Command_Read_Write_Attributes/9/controller_log_iteration_9_2026-10-11_11-50-07.log:58316`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 15ac94d215278dfa: original matrix and baseline, iteration 1

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_10-47-28-358/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_10-47-46.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_10-47-28-358/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_10-47-46.log:27135`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_10-47-28-358/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_10-47-46.log:52984`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_10-47-28-358/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_10-47-46.log:107916`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_10-47-28-358/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_10-47-46.log:107964`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_10-47-28-358/TC_Send_Command_Read_Write_Attributes/1/controller_log_iteration_1_2026-10-11_10-47-46.log:107965`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 5913846e57d93761: original matrix and baseline, iteration 3

- Resolution: **FIXED**. PR547 `6e93374`: generate DefaultOpenLevel using live LevelStep; focused controls and smoke plus ten iterations pass.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_10-47-28-358/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_10-48-19.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_10-47-28-358/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_10-48-19.log:27325`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_10-47-28-358/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_10-48-19.log:53273`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_10-47-28-358/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_10-48-19.log:108197`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_10-47-28-358/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_10-48-19.log:108249`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10/logs/MatterTest/on-network/10-11-2026_10-47-28-358/TC_Send_Command_Read_Write_Attributes/3/controller_log_iteration_3_2026-10-11_10-48-19.log:108250`
- Confidence: high. Evidence status: closed; eligible for preservation.


### FIXED: Read smoke v6: AccessControl ACL

Resolution: **FIXED**. PR548 `a550450`: validate typed fabric-filtered ACLs while preserving same-fabric equality and path checks.

Historical diagnosis (not current work): Native Read defaults fabricFiltered=True. Different compressed fabrics expose different ACL entries. PR548 validates typed ACL lists across fabrics; same-fabric equality, missing paths and shared values remain strict.

#### Failure fe31b633c7e4ae4b: rt12-read-integration-v6, iteration 1

- Resolution: **FIXED**. PR548 `a550450`: validate typed fabric-filtered ACLs while preserving same-fabric equality and path checks.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v6/runs/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v6/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v6/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-12-2026_15-46-40-028/TC_RT_1_2/1/controller_log_iteration_1_2026-10-12_15-47-52.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v6/pr539-nordic-ubuntu-TC_RT_1_2-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v6/captures/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v6/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v6/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.


### FIXED: Read smoke v7: OperationalCredentials Fabrics

Resolution: **FIXED**. PR548 `a550450`: validate typed fabric-filtered descriptor lists; shared attributes remain strict.

Historical diagnosis (not current work): Fabric-filtered FabricDescriptorStruct lists differ across fabrics. Seven new controls reproduced the gap; 49 tests pass after the repair. Read v8 failed at a different attribute, NOCs.

#### Failure 89371c239f489034: rt12-read-integration-v7, iteration 1

- Resolution: **FIXED**. PR548 `a550450`: validate typed fabric-filtered descriptor lists; shared attributes remain strict.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v7/runs/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v7/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v7/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-12-2026_20-18-01-299/TC_RT_1_2/1/controller_log_iteration_1_2026-10-12_20-19-14.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v7/pr539-nordic-ubuntu-TC_RT_1_2-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v7/captures/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v7/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v7/hardware-summary.json`
- Deciding log references: See raw logs; no fabricated line reference.
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.


### FIXED: Read smoke v8: OperationalCredentials NOCs

Resolution: **FIXED**. PR548 `e0b6f61`, retained in `a550450`: typed cross-fabric NOCs and scene decode-failure checks; negative regressions pass.

Historical diagnosis (not current work): The closed smoke compared one typed NOC entry for fabric index 2 against one for fabric index 3, with no decode failure. Native Read defaults fabricFiltered=True and the SDK list encoder filters entries to the accessing fabric. The unchanged PR548 comparator rejects typed differing cross-fabric NOC lists but accepts identical lists in a CPU control. This is a likely incomplete pre-existing harness repair, not a demonstrated PR539 readiness or SDK failure.

#### Failure 137a000b88bfd888: rt12-read-integration-v8, iteration 1

- Resolution: **FIXED**. PR548 `e0b6f61`, retained in `a550450`: typed cross-fabric NOCs and scene decode-failure checks; negative regressions pass.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v8/runs/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v8/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v8/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-13-2026_00-06-29-264/TC_RT_1_2/1/controller_log_iteration_1_2026-10-13_00-07-42.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v8/pr539-nordic-ubuntu-TC_RT_1_2-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v8/captures/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v8/source-proof.json`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v8/hardware-summary.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt12-read-integration-v8/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/console.log:453255`
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.


### FIXED: Cross-controller comparison of non-equivalent reads

Resolution: **FIXED**. PR548 `a550450` includes SDK metadata identity and validated fabric-dependent scene comparison; unrelated shared values remain strict.

Historical diagnosis (not current work): Original failures name Identify DataVersion or ScenesManagement FabricSceneInfo. Reads are non-atomic and fabrics legitimately expose different scene records. Actual comparator methods reproduce false positives with stable positive controls. Do not ignore all attributes or all data versions by name.

#### Failure f0d3d21aca6d02c7: original matrix and baseline, iteration 1

- Resolution: **FIXED**. PR548 `a550450` includes SDK metadata identity and validated fabric-dependent scene comparison; unrelated shared values remain strict.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-1`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-11-2026_13-01-51-552/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_13-03-05.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_RT_1_2-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_RT_1_2-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-11-2026_13-01-51-552/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_13-03-05.log:135683`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-11-2026_13-01-51-552/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_13-03-05.log:222844`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-11-2026_13-01-51-552/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_13-03-05.log:222845`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-11-2026_13-01-51-552/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_13-03-05.log:223087`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-11-2026_13-01-51-552/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_13-03-05.log:440340`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 37331fc895586cf8: original matrix and baseline, iteration 1

- Resolution: **FIXED**. PR548 `a550450` includes SDK metadata identity and validated fabric-dependent scene comparison; unrelated shared values remain strict.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_13-08-49.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_13-08-49.log:135362`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_13-08-49.log:222523`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_13-08-49.log:222524`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_13-08-49.log:222766`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_13-08-49.log:435175`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 58c391713c3d5c1d: original matrix and baseline, iteration 2

- Resolution: **FIXED**. PR548 `a550450` includes SDK metadata identity and validated fabric-dependent scene comparison; unrelated shared values remain strict.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/2/controller_log_iteration_2_2026-10-11_13-12-48.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/2/controller_log_iteration_2_2026-10-11_13-12-48.log:133455`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/2/controller_log_iteration_2_2026-10-11_13-12-48.log:220496`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/2/controller_log_iteration_2_2026-10-11_13-12-48.log:220497`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/2/controller_log_iteration_2_2026-10-11_13-12-48.log:220738`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/2/controller_log_iteration_2_2026-10-11_13-12-48.log:433094`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 20ebad9e14f2724e: original matrix and baseline, iteration 3

- Resolution: **FIXED**. PR548 `a550450` includes SDK metadata identity and validated fabric-dependent scene comparison; unrelated shared values remain strict.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/3/controller_log_iteration_3_2026-10-11_13-16-42.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/3/controller_log_iteration_3_2026-10-11_13-16-42.log:133677`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/3/controller_log_iteration_3_2026-10-11_13-16-42.log:220718`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/3/controller_log_iteration_3_2026-10-11_13-16-42.log:220719`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/3/controller_log_iteration_3_2026-10-11_13-16-42.log:220960`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/3/controller_log_iteration_3_2026-10-11_13-16-42.log:434024`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/3/controller_log_iteration_3_2026-10-11_13-16-42.log:434027`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure e46f046653ecf730: original matrix and baseline, iteration 4

- Resolution: **FIXED**. PR548 `a550450` includes SDK metadata identity and validated fabric-dependent scene comparison; unrelated shared values remain strict.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_13-20-37.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_13-20-37.log:133376`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_13-20-37.log:220332`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_13-20-37.log:220333`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_13-20-37.log:220575`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_13-20-37.log:434236`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 56245cb9dcc9da8a: original matrix and baseline, iteration 6

- Resolution: **FIXED**. PR548 `a550450` includes SDK metadata identity and validated fabric-dependent scene comparison; unrelated shared values remain strict.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/6/controller_log_iteration_6_2026-10-11_13-27-05.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/6/controller_log_iteration_6_2026-10-11_13-27-05.log:133622`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/6/controller_log_iteration_6_2026-10-11_13-27-05.log:220664`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/6/controller_log_iteration_6_2026-10-11_13-27-05.log:220665`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/6/controller_log_iteration_6_2026-10-11_13-27-05.log:220909`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/6/controller_log_iteration_6_2026-10-11_13-27-05.log:434446`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 7120e85b8f96734a: original matrix and baseline, iteration 10

- Resolution: **FIXED**. PR548 `a550450` includes SDK metadata identity and validated fabric-dependent scene comparison; unrelated shared values remain strict.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/10/controller_log_iteration_10_2026-10-11_13-38-37.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/10/controller_log_iteration_10_2026-10-11_13-38-37.log:133678`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/10/controller_log_iteration_10_2026-10-11_13-38-37.log:220720`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/10/controller_log_iteration_10_2026-10-11_13-38-37.log:220721`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/10/controller_log_iteration_10_2026-10-11_13-38-37.log:220965`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/10/controller_log_iteration_10_2026-10-11_13-38-37.log:433582`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/10/controller_log_iteration_10_2026-10-11_13-38-37.log:433585`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure ca211df391d24077: original matrix and baseline, iteration 2

- Resolution: **FIXED**. PR548 `a550450` includes SDK metadata identity and validated fabric-dependent scene comparison; unrelated shared values remain strict.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/2/controller_log_iteration_2_2026-10-11_10-00-09.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-rpi-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-rpi-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/2/controller_log_iteration_2_2026-10-11_10-00-09.log:32745`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/2/controller_log_iteration_2_2026-10-11_10-00-09.log:991550`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/2/controller_log_iteration_2_2026-10-11_10-00-09.log:2121093`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/2/controller_log_iteration_2_2026-10-11_10-00-09.log:2121094`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/2/controller_log_iteration_2_2026-10-11_10-00-09.log:2122322`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/2/controller_log_iteration_2_2026-10-11_10-00-09.log:4545286`
- Confidence: high. Evidence status: closed; eligible for preservation.


### FIXED: Valve subscription verification

Resolution: **FIXED**. PR547 `6e93374`: fixes the identified LevelStep/ConstraintError mechanism, not the independent controller-map aliasing concern.

Historical diagnosis (not current work): Same LevelStep/ConstraintError mechanism as bulk writes, repeated across secondary controllers. The independent per-controller map also had a pre-existing aliasing defect; it is not established as the cause of these particular failures.

#### Failure fde3c4190a4549cb: original matrix and baseline, iteration 5

- Resolution: **FIXED**. PR547 `6e93374`: fixes the identified LevelStep/ConstraintError mechanism, not the independent controller-map aliasing concern.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/5/controller_log_iteration_5_2026-10-11_13-24-34.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/5/controller_log_iteration_5_2026-10-11_13-24-34.log:133693`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/5/controller_log_iteration_5_2026-10-11_13-24-34.log:220690`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/5/controller_log_iteration_5_2026-10-11_13-24-34.log:220734`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/5/controller_log_iteration_5_2026-10-11_13-24-34.log:220735`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 10575eabecc41ba0: original matrix and baseline, iteration 7

- Resolution: **FIXED**. PR547 `6e93374`: fixes the identified LevelStep/ConstraintError mechanism, not the independent controller-map aliasing concern.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/7/controller_log_iteration_7_2026-10-11_13-31-03.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/7/controller_log_iteration_7_2026-10-11_13-31-03.log:133662`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/7/controller_log_iteration_7_2026-10-11_13-31-03.log:220658`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/7/controller_log_iteration_7_2026-10-11_13-31-03.log:220702`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/7/controller_log_iteration_7_2026-10-11_13-31-03.log:220703`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 75f472d8faba38c1: original matrix and baseline, iteration 8

- Resolution: **FIXED**. PR547 `6e93374`: fixes the identified LevelStep/ConstraintError mechanism, not the independent controller-map aliasing concern.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/8/controller_log_iteration_8_2026-10-11_13-33-35.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/8/controller_log_iteration_8_2026-10-11_13-33-35.log:134539`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/8/controller_log_iteration_8_2026-10-11_13-33-35.log:221535`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/8/controller_log_iteration_8_2026-10-11_13-33-35.log:221579`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/8/controller_log_iteration_8_2026-10-11_13-33-35.log:221580`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 8ef97f71bcfcf96b: original matrix and baseline, iteration 9

- Resolution: **FIXED**. PR547 `6e93374`: fixes the identified LevelStep/ConstraintError mechanism, not the independent controller-map aliasing concern.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/9/controller_log_iteration_9_2026-10-11_13-36-06.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-nordic-pi-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-nordic-pi-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/9/controller_log_iteration_9_2026-10-11_13-36-06.log:134611`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/9/controller_log_iteration_9_2026-10-11_13-36-06.log:221526`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/9/controller_log_iteration_9_2026-10-11_13-36-06.log:221575`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-11-2026_13-07-36-816/TC_RT_1_2/9/controller_log_iteration_9_2026-10-11_13-36-06.log:221576`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 6971f4b0fd7713f9: original matrix and baseline, iteration 1

- Resolution: **FIXED**. PR547 `6e93374`: fixes the identified LevelStep/ConstraintError mechanism, not the independent controller-map aliasing concern.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-1`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_11-09-33-934/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-09-53.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-rpi-pi-TC_RT_1_2-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-rpi-pi-TC_RT_1_2-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_11-09-33-934/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-09-53.log:561085`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_11-09-33-934/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-09-53.log:1069257`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_11-09-33-934/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-09-53.log:1069299`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_11-09-33-934/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-09-53.log:1069300`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 8305944a6f607c7b: original matrix and baseline, iteration 1

- Resolution: **FIXED**. PR547 `6e93374`: fixes the identified LevelStep/ConstraintError mechanism, not the independent controller-map aliasing concern.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-56-14.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-rpi-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-rpi-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-56-14.log:32751`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-56-14.log:990456`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-56-14.log:2136213`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-56-14.log:2136255`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-56-14.log:2136256`
- Confidence: high. Evidence status: closed; eligible for preservation.

#### Failure 05736bb66e94a146: original matrix and baseline, iteration 3

- Resolution: **FIXED**. PR547 `6e93374`: fixes the identified LevelStep/ConstraintError mechanism, not the independent controller-map aliasing concern.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/3/controller_log_iteration_3_2026-10-11_10-07-23.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-rpi-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-rpi-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/3/controller_log_iteration_3_2026-10-11_10-07-23.log:32931`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/3/controller_log_iteration_3_2026-10-11_10-07-23.log:1002437`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/3/controller_log_iteration_3_2026-10-11_10-07-23.log:2117981`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/3/controller_log_iteration_3_2026-10-11_10-07-23.log:2118023`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/3/controller_log_iteration_3_2026-10-11_10-07-23.log:2118024`
- Confidence: high. Evidence status: closed; eligible for preservation.


### FIXED: Five verified corrected-rerun metadata/scene comparisons

Resolution: **FIXED**. PR548 `a550450`: actual SDK DataVersion metadata and typed fabric-dependent scene comparison; all 15 observed paths attributed and 107 focused tests pass. Original FAIL outcomes remain unchanged.

Historical diagnosis (not current work): The five identified Ubuntu/Nordic failures contain 15 logged comparison paths: Identify.DataVersion and, in iteration 2, ScenesManagement.FabricSceneInfo. Exact original log lines were extracted on 2026-10-17 without exporting values. PR548 handles actual SDK metadata identity and typed cross-fabric scene lists; this resolves the recorded predicates, not hypothetical later comparisons.

#### Failure 2dc88704967e9345: corrected Ubuntu/Nordic, iteration 1

- Resolution: **FIXED**. PR548 `a550450`: actual SDK DataVersion metadata and typed fabric-dependent scene comparison; all 15 observed paths attributed and 107 focused tests pass. Original FAIL outcomes remain unchanged.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-12-2026_00-57-57-717/TC_RT_1_2/1/controller_log_iteration_1_2026-10-12_00-59-10.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_RT_1_2-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_RT_1_2-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-12-2026_00-57-57-717/TC_RT_1_2/1/controller_log_iteration_1_2026-10-12_00-59-10.log:780854`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-12-2026_00-57-57-717/TC_RT_1_2/1/controller_log_iteration_1_2026-10-12_00-59-10.log:780857`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-1/logs/MatterTest/ble-thread/10-12-2026_00-57-57-717/TC_RT_1_2/1/controller_log_iteration_1_2026-10-12_00-59-10.log:780859`
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure 6ec3f8548b8a83e9: corrected Ubuntu/Nordic, iteration 2

- Resolution: **FIXED**. PR548 `a550450`: actual SDK DataVersion metadata and typed fabric-dependent scene comparison; all 15 observed paths attributed and 107 focused tests pass. Original FAIL outcomes remain unchanged.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/2/controller_log_iteration_2_2026-10-12_01-07-05.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/2/controller_log_iteration_2_2026-10-12_01-07-05.log:778955`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/2/controller_log_iteration_2_2026-10-12_01-07-05.log:778958`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/2/controller_log_iteration_2_2026-10-12_01-07-05.log:778960`
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure 0d6bf96729f5927d: corrected Ubuntu/Nordic, iteration 3

- Resolution: **FIXED**. PR548 `a550450`: actual SDK DataVersion metadata and typed fabric-dependent scene comparison; all 15 observed paths attributed and 107 focused tests pass. Original FAIL outcomes remain unchanged.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/3/controller_log_iteration_3_2026-10-12_01-11-01.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/3/controller_log_iteration_3_2026-10-12_01-11-01.log:780082`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/3/controller_log_iteration_3_2026-10-12_01-11-01.log:780084`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/3/controller_log_iteration_3_2026-10-12_01-11-01.log:780086`
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure 81d2781f125d012e: corrected Ubuntu/Nordic, iteration 8

- Resolution: **FIXED**. PR548 `a550450`: actual SDK DataVersion metadata and typed fabric-dependent scene comparison; all 15 observed paths attributed and 107 focused tests pass. Original FAIL outcomes remain unchanged.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/8/controller_log_iteration_8_2026-10-12_01-24-53.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/8/controller_log_iteration_8_2026-10-12_01-24-53.log:777552`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/8/controller_log_iteration_8_2026-10-12_01-24-53.log:777555`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/8/controller_log_iteration_8_2026-10-12_01-24-53.log:777557`
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

#### Failure bb57845dfbe57338: corrected Ubuntu/Nordic, iteration 9

- Resolution: **FIXED**. PR548 `a550450`: actual SDK DataVersion metadata and typed fabric-dependent scene comparison; all 15 observed paths attributed and 107 focused tests pass. Original FAIL outcomes remain unchanged.
- Run: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/9/controller_log_iteration_9_2026-10-12_01-28-44.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/pr539-nordic-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/captures/pr539-nordic-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/source-proof.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/9/controller_log_iteration_9_2026-10-12_01-28-44.log:777203`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/9/controller_log_iteration_9_2026-10-12_01-28-44.log:777206`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_1_2-10/logs/MatterTest/ble-thread/10-12-2026_01-03-17-134/TC_RT_1_2/9/controller_log_iteration_9_2026-10-12_01-28-44.log:777208`
- Confidence: likely; retained probes and logs. Evidence status: closed; eligible for preservation.

### Pre-Existing CI Workflow Incidents

Project-label workflow references missing project-map script and contained an exposed hardcoded PAT. Never use, print or copy that token; revoke/rotate separately. Metadata/redacted CI evidence: `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ci-pr547` and retained PR547-550 status checks. All four follow-ups are now non-draft at the user's request. Initial Restyled formatting failures were repaired in those follow-up PRs, not SDK/hardware failures.
## 4. Pre-Existing SDK Problems

Failed hardware outcomes in this category: 0.

No failure is currently classified as a sufficiently established pre-existing SDK defect. The SDK callback notification contract explains a harness assumption; it is not itself a demonstrated SDK bug. Bluetooth/native interactions and concurrent read limits remain uncertain below.
## 5. Cannot Classify With Confidence

Failed hardware outcomes in this category: 3.


### OPEN: Concurrent read timeout replaced by cleanup timeout

Resolution: **OPEN**. No published fix establishes resolution of this exact mechanism.

Historical diagnosis (not current work): Three original Pi-DUT outcomes: concurrent reads time out before unpairing also times out, replacing the primary error with TestCaseExit. The separate 2026-10-16 Ubuntu/Wi-Fi matched check reproduces this failure family on upstream and the five-PR snapshot. Exact harness/SDK/fixture ownership and the original Pi-controller attribution remain unresolved; the PR548 diagnostics fix does not repair transport timeouts.

Next deciding check: Preserve the primary read error when cleanup fails; investigate full-load concurrency/subscriptions and SDK/fixture ownership. The Pi-controller cell still needs matched attribution.

#### Failure 6a489e4009b8b9d5: original matrix and baseline, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-rpi-pi-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-rpi-pi-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:561149`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1069136`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1069137`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1070143`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1725499`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1725516`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1725558`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1725576`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1726431`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1727043`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1727565`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1731212`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1731228`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1731244`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1731260`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1731276`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1731292`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1731308`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1731324`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_11-13-35-153/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_11-13-54.log:1736695`
- Confidence: low/provisional. Evidence status: closed; eligible for preservation.

#### Failure fdb053f0ac731847: original matrix and baseline, iteration 1

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-rpi-ubuntu-TC_RT_1_2-1.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-rpi-ubuntu-TC_RT_1_2-1`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:32751`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:990388`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:2287764`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:2287765`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:2288771`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4355723`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4355740`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4355756`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4356732`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4357898`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4359198`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4375648`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4375665`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4375814`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4375831`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4375847`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4375863`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4375879`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4375895`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4375911`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-1/logs/MatterTest/on-network/10-11-2026_09-47-56-656/TC_RT_1_2/1/controller_log_iteration_1_2026-10-11_09-48-19.log:4387419`
- Confidence: low/provisional. Evidence status: closed; eligible for preservation.

#### Failure 6c551116aba0c8d9: original matrix and baseline, iteration 4

- Resolution: **OPEN**. Investigation remains open; retain the original failure.
- Run: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10`
- Structured result: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/result.json`
- Controller/DUT iteration logs: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log`
- Supervisor/console: `/home/feasel/qa-mar6/pr539-full-testing-20261011/pr539-rpi-ubuntu-TC_RT_1_2-10.supervisor.log`
- BLE HCI and IP capture directory: `/home/feasel/qa-mar6/pr539-full-testing-20261011/captures/pr539-rpi-ubuntu-TC_RT_1_2-10`
- Source/closure proof: `/home/feasel/qa-mar6/pr539-full-testing-20261011/capture-audit.json`
- Deciding log references: `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:32745`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:990877`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:2090678`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:2090679`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:2091671`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3947121`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3947138`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3955207`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3955224`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3955271`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3955292`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3972464`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3972668`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3972685`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3972702`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3972719`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3972736`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3972752`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3972769`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3972786`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_1_2-10/logs/MatterTest/on-network/10-11-2026_09-55-50-769/TC_RT_1_2/4/controller_log_iteration_4_2026-10-11_10-11-12.log:3982168`
- Confidence: low/provisional. Evidence status: closed; eligible for preservation.

### Native Crashes: Callback Lifetime Favored, Exact Cause Unproved

Resolution: **OPEN** for exact crash attribution. The proven callback-lifetime defect is **FIXED** in PR549 `dbab50b` and retained by PR550 `2b0feed`; absence of a deciding native backtrace prevents closing every historical SIGSEGV.

Five campaign SIGSEGV incidents: three original PR539, one original baseline, one corrected Ubuntu/Nordic. Each followed one PASS and left nine unfinished slots. The actual SDK setters retain native pointers, not Python callback objects; CPU probes prove local ctypes objects can be collected. Baseline reproduces the crash. Later combined campaigns completed without SIGSEGV; this does not prove the root cause of all five incidents.
Evidence: `/home/feasel/qa-mar6/pr539-full-testing-20261011/failure-probes.json`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/ubuntu-kernel-utc.log`, `/home/feasel/qa-mar6/pr539-full-testing-20261011/pi-controller-kernel-utc.log`, `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/rt21-callback-integration` and `rt21-callback-stage-integration-v2-editor-resume-20261012`. Pi kernel query supplied no backtrace. Separate cpptools OOM event is a host caveat, not universal attribution.

| Run | Process Exit | Unfinished Slots |
| --- | ---: | ---: |
| `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/baseline-rpi-ubuntu-TC_RT_2_1-10` | -11 | 9 |
| `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-nordic-pi-TC_RT_2_1-10` | -11 | 9 |
| `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-pi-TC_RT_2_1-10` | -11 | 9 |
| `/home/feasel/qa-mar6/pr539-full-testing-20261011/runs/pr539-rpi-ubuntu-TC_RT_2_1-10` | -11 | 9 |
| `/home/feasel/qa-mar6/pr539-ble-readiness-fix-20261011/ubuntu-nordic-final/runs/pr539-nordic-ubuntu-TC_RT_2_1-10` | -11 | 9 |

Other original early exits follow already-counted read/cleanup FAILs; four blocked campaigns account for forty historical slots. Forty setup-blocked slots were subsequently run; 42 other original gaps remain outside the current affected-only queue. Do not replace incomplete accounting with fabricated FAILs.

## Automatic Additions and Next Work

Observer unit: `pr539-failure-dossier.service`. Linux inotify watches only current result/summary/capture-proof metadata, plus the batch ledger. It never resets, pairs, flashes, opens UART, changes SDK/firmware/configuration or publishes PRs. New failures default to the uncertain category unless deciding evidence matches a known mechanism. Stable IDs prevent duplicate additions; old catalog entries are never dropped.
Closed artifacts are copied privately and hash-checked. Active logs/captures are indexed first and copied after closure. Observer persists independently of VS Code and exits when its durable hardware batch closes; no polling or sleeps. Failure investigation follows the requested category order, with no automatic PR publication.
Manual refresh: `python3 investigation/pr539-failure-evidence/update_dossier.py --update`. Verification controls: `python3 investigation/pr539-failure-evidence/update_dossier.py --self-test`. Writeups and tooling are versioned on the fork-only investigation branch. Generated indexes, raw logs, private controller state and bulk preserved copies remain excluded from commits.
