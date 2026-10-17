# PR539 Iteration Accounting

Snapshot UTC: 2026-10-13T04:18:17.605296+00:00

Recorded outcomes: 550; PASS: 402; FAIL: 148.

## Current Failure Dispositions: 2026-10-16

This is an immutable outcome ledger, not a list of 148 still-unfixed defects.
Historical FAIL rows and unfinished slots are not converted to PASS when code
changes. The [current per-defect dispositions](PR539_FAILURE_ANALYSIS_20261011.md#current-failure-dispositions)
are the remaining-work index.

| Signature / Defect In This Ledger | Current Disposition |
| --- | --- |
| IP-before-BLE readiness / secondary discriminator | **ADDRESSED**: [QA539](https://github.com/CHIP-Specifications/matter-qa/pull/539); final offline boundaries retain 22/22 passes. |
| Valve DefaultOpenLevel / LevelStep write verification | **ADDRESSED**: [QA547](https://github.com/CHIP-Specifications/matter-qa/pull/547); valve-step integration retains 11/11 passes. |
| Metadata, cross-fabric and volatile-observation equality | **ADDRESSED**: [QA548](https://github.com/CHIP-Specifications/matter-qa/pull/548), current head `a550450`; 105 CPU tests and a bounded fresh-readback smoke. Genuine full-load native failures remain **OPEN**. |
| ctypes callback ownership | **ADDRESSED**: [QA549](https://github.com/CHIP-Specifications/matter-qa/pull/549). Historical SIGSEGV root-cause attribution remains **OPEN** without a backtrace. |
| Unreachable SecurePairing reset selection / reset errors | **ADDRESSED**: [QA550](https://github.com/CHIP-Specifications/matter-qa/pull/550), current head `2b0feed`; combined callback/stage v3 retains 11/11 passes. |
| Secondary cleanup failures | **ADDRESSED** at the lifecycle/error-preservation layer: [QA527](https://github.com/CHIP-Specifications/matter-qa/pull/527). Primary read/subscription timeouts remain **OPEN**. |
| BLE discovery error masking / retained local scan state | **ADDRESSED**: [SDK74676](https://github.com/project-chip/connectedhomeip/pull/74676); original BlueZ/PASE causality and daemon recovery remain **OPEN**. |

Canonical recorded QA outcomes and boundary attempts; includes nine failed BLE-Wi-Fi fixture smokes and one protocol PASS with failed closeout; excludes setup-only and unfinished slots. Count one test iteration or boundary cycle, not individual fabric handshakes. Unit tests and diagnostic scans are excluded.

## Hardware

| Configuration | Executed | PASS | FAIL |
| --- | ---: | ---: | ---: |
| Pi1 -> Nordic BLE-Thread | 123 | 97 | 26 |
| Ubuntu -> Nordic BLE-Thread | 197 | 105 | 92 |
| Ubuntu -> Pi2 on-network | 107 | 93 | 14 |
| Pi1 -> Pi2 on-network | 91 | 84 | 7 |
| Pi1 -> Pi2 unprovisioned BLE-Wi-Fi | 32 | 23 | 9 |

All Nordic runs use the nRF52840 DK and Ubuntu OTBR with the separate nRF52840 RCP dongle. Pi2 remains on Wi-Fi; no Ethernet requirement. Darwin/Android script names do not denote real ecosystem controllers.

## Phases

| Phase | Executed | PASS | FAIL |
| --- | ---: | ---: | ---: |
| original matrix and baseline | 301 | 199 | 102 |
| recovery baseline | 11 | 0 | 11 |
| readiness Pi1/Nordic | 33 | 33 | 0 |
| corrected Ubuntu/Nordic | 79 | 63 | 16 |
| valve-step-integration | 11 | 11 | 0 |
| rt12-read-integration | 1 | 0 | 1 |
| rt12-read-integration-v2 | 1 | 0 | 1 |
| rt12-read-integration-v3 | 1 | 0 | 1 |
| rt12-read-integration-v4 | 1 | 0 | 1 |
| rt12-read-integration-v5 | 1 | 0 | 1 |
| rt12-read-integration-v6 | 1 | 0 | 1 |
| rt12-read-integration-v7 | 1 | 0 | 1 |
| rt12-read-integration-v8 | 1 | 0 | 1 |
| rt21-callback-integration | 11 | 10 | 1 |
| rt21-callback-stage-integration-v2 | 1 | 1 | 0 |
| rt21-callback-stage-integration-v2-editor-resume-20261012 | 10 | 9 | 1 |
| rt21-callback-stage-integration-v3 | 11 | 11 | 0 |
| on-network readiness boundaries | 42 | 42 | 0 |
| final offline BLE-Wi-Fi boundaries | 22 | 22 | 0 |
| early BLE-Wi-Fi fixture attempts | 10 | 1 | 9 |

## Attribution

No hardware FAIL is established as caused by PR539. Its IP-before-BLE prerequisite defect and secondary-window discriminator handling were repaired following focused source/CPU checks; do not add CPU checks to hardware FAIL counts.

Failures during incremental separate fixes remain attributed to those incomplete pre-existing harness repairs, not automatically to PR539. High confidence in a false test predicate is not a proved SDK bug. Crash callback lifetime is plausible and baseline-reproduced, but lacks a native backtrace.

## Every Failed Outcome

Each row identifies a unique phase/run/iteration. Original and recovery run names can coincide but refer to separate preserved directories.

| Phase | Run | Iteration | Configuration | Signature | Likely Attribution | Confidence |
| --- | --- | ---: | --- | --- | --- | --- |
| original matrix and baseline | baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-1 | 1 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10 | 1 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10 | 2 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10 | 3 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | baseline-nordic-pi-TC_Send_Command_Read_Write_Attributes-10 | 7 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | baseline-nordic-ubuntu-TC_RT_1_1-1 | 1 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 1 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 2 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 3 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 4 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 5 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 6 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 7 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 8 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 9 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 10 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-1 | 1 | Ubuntu -> Pi2 on-network | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10 | 1 | Ubuntu -> Pi2 on-network | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10 | 5 | Ubuntu -> Pi2 on-network | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10 | 7 | Ubuntu -> Pi2 on-network | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10 | 8 | Ubuntu -> Pi2 on-network | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10 | 9 | Ubuntu -> Pi2 on-network | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | baseline-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10 | 10 | Ubuntu -> Pi2 on-network | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_RT_1_2-1 | 1 | Pi1 -> Nordic BLE-Thread | multi-admin-read-mismatch | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_RT_1_2-10 | 1 | Pi1 -> Nordic BLE-Thread | multi-admin-read-mismatch | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_RT_1_2-10 | 2 | Pi1 -> Nordic BLE-Thread | multi-admin-read-mismatch | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_RT_1_2-10 | 3 | Pi1 -> Nordic BLE-Thread | multi-admin-read-mismatch | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_RT_1_2-10 | 4 | Pi1 -> Nordic BLE-Thread | multi-admin-read-mismatch | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_RT_1_2-10 | 5 | Pi1 -> Nordic BLE-Thread | multi-admin-subscription-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_RT_1_2-10 | 6 | Pi1 -> Nordic BLE-Thread | multi-admin-read-mismatch | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_RT_1_2-10 | 7 | Pi1 -> Nordic BLE-Thread | multi-admin-subscription-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_RT_1_2-10 | 8 | Pi1 -> Nordic BLE-Thread | multi-admin-subscription-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_RT_1_2-10 | 9 | Pi1 -> Nordic BLE-Thread | multi-admin-subscription-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_RT_1_2-10 | 10 | Pi1 -> Nordic BLE-Thread | multi-admin-read-mismatch | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-1 | 1 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10 | 1 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10 | 3 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10 | 4 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10 | 5 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10 | 6 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10 | 7 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10 | 8 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10 | 9 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-pi-TC_Send_Command_Read_Write_Attributes-10 | 10 | Pi1 -> Nordic BLE-Thread | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Android_Pair-1 | 1 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Android_Pair-10 | 1 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Android_Pair-10 | 2 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Android_Pair-10 | 3 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Android_Pair-10 | 4 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Android_Pair-10 | 5 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Android_Pair-10 | 6 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Android_Pair-10 | 7 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Android_Pair-10 | 8 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Android_Pair-10 | 9 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Android_Pair-10 | 10 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Darwin_Pair-1 | 1 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Darwin_Pair-10 | 1 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Darwin_Pair-10 | 2 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Darwin_Pair-10 | 3 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Darwin_Pair-10 | 4 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Darwin_Pair-10 | 5 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Darwin_Pair-10 | 6 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Darwin_Pair-10 | 7 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Darwin_Pair-10 | 8 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Darwin_Pair-10 | 9 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Darwin_Pair-10 | 10 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_1_1-1 | 1 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_1_1-10 | 1 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_1_1-10 | 2 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_1_1-10 | 3 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_1_1-10 | 4 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_1_1-10 | 5 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_1_1-10 | 6 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_1_1-10 | 7 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_1_1-10 | 8 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_1_1-10 | 9 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_1_1-10 | 10 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_2_1-1 | 1 | Ubuntu -> Nordic BLE-Thread | ble-discovery-empty | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_2_1-10 | 1 | Ubuntu -> Nordic BLE-Thread | ble-discovery-empty | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_2_1-10 | 2 | Ubuntu -> Nordic BLE-Thread | ble-discovery-empty | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_2_1-10 | 3 | Ubuntu -> Nordic BLE-Thread | ble-discovery-empty | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_2_1-10 | 4 | Ubuntu -> Nordic BLE-Thread | ble-discovery-empty | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_2_1-10 | 5 | Ubuntu -> Nordic BLE-Thread | ble-discovery-empty | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_2_1-10 | 6 | Ubuntu -> Nordic BLE-Thread | ble-discovery-empty | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_2_1-10 | 7 | Ubuntu -> Nordic BLE-Thread | ble-discovery-empty | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_2_1-10 | 8 | Ubuntu -> Nordic BLE-Thread | ble-discovery-empty | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_2_1-10 | 9 | Ubuntu -> Nordic BLE-Thread | ble-discovery-empty | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_2_1-10 | 10 | Ubuntu -> Nordic BLE-Thread | ble-discovery-empty | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| original matrix and baseline | pr539-rpi-pi-TC_RT_1_2-1 | 1 | Pi1 -> Pi2 on-network | multi-admin-subscription-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-rpi-pi-TC_RT_1_2-10 | 1 | Pi1 -> Pi2 on-network | multi-admin-cleanup-timeout | Not sure; pre-existing SDK/test interaction favored | low/provisional |
| original matrix and baseline | pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-1 | 1 | Pi1 -> Pi2 on-network | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10 | 1 | Pi1 -> Pi2 on-network | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10 | 4 | Pi1 -> Pi2 on-network | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10 | 6 | Pi1 -> Pi2 on-network | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-rpi-pi-TC_Send_Command_Read_Write_Attributes-10 | 9 | Pi1 -> Pi2 on-network | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-rpi-ubuntu-TC_RT_1_2-1 | 1 | Ubuntu -> Pi2 on-network | multi-admin-cleanup-timeout | Not sure; pre-existing SDK/test interaction favored | low/provisional |
| original matrix and baseline | pr539-rpi-ubuntu-TC_RT_1_2-10 | 1 | Ubuntu -> Pi2 on-network | multi-admin-subscription-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-rpi-ubuntu-TC_RT_1_2-10 | 2 | Ubuntu -> Pi2 on-network | multi-admin-read-mismatch | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-rpi-ubuntu-TC_RT_1_2-10 | 3 | Ubuntu -> Pi2 on-network | multi-admin-subscription-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-rpi-ubuntu-TC_RT_1_2-10 | 4 | Ubuntu -> Pi2 on-network | multi-admin-cleanup-timeout | Not sure; pre-existing SDK/test interaction favored | low/provisional |
| original matrix and baseline | pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10 | 1 | Ubuntu -> Pi2 on-network | bulk-write-verification | likely a pre-existing flaw | high |
| original matrix and baseline | pr539-rpi-ubuntu-TC_Send_Command_Read_Write_Attributes-10 | 3 | Ubuntu -> Pi2 on-network | bulk-write-verification | likely a pre-existing flaw | high |
| recovery baseline | baseline-nordic-ubuntu-TC_RT_1_1-1 | 1 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| recovery baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 1 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| recovery baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 2 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| recovery baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 3 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| recovery baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 4 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| recovery baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 5 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| recovery baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 6 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| recovery baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 7 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| recovery baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 8 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| recovery baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 9 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| recovery baseline | baseline-nordic-ubuntu-TC_RT_1_1-10 | 10 | Ubuntu -> Nordic BLE-Thread | pase-incorrect-state | likely a flaw our test setup | high for fixture attribution; native-versus-BlueZ cause unresolved |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_RT_1_2-1 | 1 | Ubuntu -> Nordic BLE-Thread | read comparison | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_RT_1_2-10 | 1 | Ubuntu -> Nordic BLE-Thread | Valve constraint | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_RT_1_2-10 | 2 | Ubuntu -> Nordic BLE-Thread | read comparison | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_RT_1_2-10 | 3 | Ubuntu -> Nordic BLE-Thread | read comparison | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_RT_1_2-10 | 4 | Ubuntu -> Nordic BLE-Thread | Valve constraint | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_RT_1_2-10 | 5 | Ubuntu -> Nordic BLE-Thread | Valve constraint | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_RT_1_2-10 | 6 | Ubuntu -> Nordic BLE-Thread | Valve constraint | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_RT_1_2-10 | 7 | Ubuntu -> Nordic BLE-Thread | Valve constraint | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_RT_1_2-10 | 8 | Ubuntu -> Nordic BLE-Thread | read comparison | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_RT_1_2-10 | 9 | Ubuntu -> Nordic BLE-Thread | read comparison | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_RT_1_2-10 | 10 | Ubuntu -> Nordic BLE-Thread | Valve constraint | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10 | 1 | Ubuntu -> Nordic BLE-Thread | Valve constraint | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10 | 2 | Ubuntu -> Nordic BLE-Thread | Valve constraint | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10 | 3 | Ubuntu -> Nordic BLE-Thread | Valve constraint | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10 | 8 | Ubuntu -> Nordic BLE-Thread | Valve constraint | pre-existing QA harness | likely; source probes and retained hardware evidence |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-10 | 10 | Ubuntu -> Nordic BLE-Thread | Valve constraint | pre-existing QA harness | likely; source probes and retained hardware evidence |
| rt12-read-integration | pr539-nordic-ubuntu-TC_RT_1_2-1 | 1 | Ubuntu -> Nordic BLE-Thread | IdentifyTime | pre-existing QA harness | likely; source probes and retained hardware evidence |
| rt12-read-integration-v2 | pr539-nordic-ubuntu-TC_RT_1_2-1 | 1 | Ubuntu -> Nordic BLE-Thread | UTCTime | pre-existing QA harness | likely; source probes and retained hardware evidence |
| rt12-read-integration-v3 | pr539-nordic-ubuntu-TC_RT_1_2-1 | 1 | Ubuntu -> Nordic BLE-Thread | DeviceLoadStatus | pre-existing QA harness | likely; source probes and retained hardware evidence |
| rt12-read-integration-v4 | pr539-nordic-ubuntu-TC_RT_1_2-1 | 1 | Ubuntu -> Nordic BLE-Thread | Thread counters/UpTime | pre-existing QA harness | likely; source probes and retained hardware evidence |
| rt12-read-integration-v5 | pr539-nordic-ubuntu-TC_RT_1_2-1 | 1 | Ubuntu -> Nordic BLE-Thread | NeighborTable/RouteTable | pre-existing QA harness | likely; source probes and retained hardware evidence |
| rt12-read-integration-v6 | pr539-nordic-ubuntu-TC_RT_1_2-1 | 1 | Ubuntu -> Nordic BLE-Thread | fabric-filtered ACL | pre-existing QA harness | likely; source probes and retained hardware evidence |
| rt12-read-integration-v7 | pr539-nordic-ubuntu-TC_RT_1_2-1 | 1 | Ubuntu -> Nordic BLE-Thread | fabric-filtered Fabrics | pre-existing QA harness | likely; source probes and retained hardware evidence |
| rt12-read-integration-v8 | pr539-nordic-ubuntu-TC_RT_1_2-1 | 1 | Ubuntu -> Nordic BLE-Thread | fabric-filtered NOCs | pre-existing QA harness | likely; source probes and retained hardware evidence |
| rt21-callback-integration | pr539-nordic-ubuntu-TC_RT_2_1-10 | 8 | Ubuntu -> Nordic BLE-Thread | SecurePairing callback selection | pre-existing QA harness | likely; source probes and retained hardware evidence |
| rt21-callback-stage-integration-v2-editor-resume-20261012 | pr539-nordic-ubuntu-TC_RT_2_1-10 | 3 | Ubuntu -> Nordic BLE-Thread | SecurePairing callback selection | pre-existing QA harness | likely; source probes and retained hardware evidence |
| early BLE-Wi-Fi fixture attempts | wifi-primary-smokes-01-a02 | 1 | Pi1 -> Pi2 unprovisioned BLE-Wi-Fi | BlueZ subscription | Test setup/methodology favored | GATT/BlueZ root not fully resolved |
| early BLE-Wi-Fi fixture attempts | wifi-primary-smokes-01-a03 | 1 | Pi1 -> Pi2 unprovisioned BLE-Wi-Fi | GATT service discovery | Test setup/methodology favored | GATT/BlueZ root not fully resolved |
| early BLE-Wi-Fi fixture attempts | wifi-primary-smokes-01-a04 | 1 | Pi1 -> Pi2 unprovisioned BLE-Wi-Fi | operational discovery/IPv6 timeout | Test setup/methodology favored | fixture networking implicated; not a proved SDK defect |
| early BLE-Wi-Fi fixture attempts | wifi-primary-smokes-01-a05 | 1 | Pi1 -> Pi2 unprovisioned BLE-Wi-Fi | GATT service discovery | Test setup/methodology favored | GATT/BlueZ root not fully resolved |
| early BLE-Wi-Fi fixture attempts | wifi-primary-smokes-01-a06 | 1 | Pi1 -> Pi2 unprovisioned BLE-Wi-Fi | GATT service discovery | Test setup/methodology favored | GATT/BlueZ root not fully resolved |
| early BLE-Wi-Fi fixture attempts | wifi-primary-smokes-01-a07 | 1 | Pi1 -> Pi2 unprovisioned BLE-Wi-Fi | GATT service discovery | Test setup/methodology favored | GATT/BlueZ root not fully resolved |
| early BLE-Wi-Fi fixture attempts | wifi-primary-smokes-01-a08 | 1 | Pi1 -> Pi2 unprovisioned BLE-Wi-Fi | GATT service discovery | Test setup/methodology favored | GATT/BlueZ root not fully resolved |
| early BLE-Wi-Fi fixture attempts | wifi-primary-smokes-01-a09 | 1 | Pi1 -> Pi2 unprovisioned BLE-Wi-Fi | operational discovery/IPv6 timeout | Test setup/methodology favored | fixture networking implicated; not a proved SDK defect |
| early BLE-Wi-Fi fixture attempts | wifi-primary-smokes-01-a10 | 1 | Pi1 -> Pi2 unprovisioned BLE-Wi-Fi | operational discovery/IPv6 timeout | Test setup/methodology favored | fixture networking implicated; not a proved SDK defect |

## Incomplete Process Incidents

These are not extra failed iterations. A crash may follow a PASS; an early exit may follow an already-counted FAIL. Retained historical gaps are not new queued work.

| Phase | Run | Process Exit | Unfinished Slots |
| --- | --- | ---: | ---: |
| original matrix and baseline | baseline-rpi-ubuntu-TC_RT_2_1-10 | -11 | 9 |
| original matrix and baseline | pr539-nordic-pi-TC_RT_2_1-10 | -11 | 9 |
| original matrix and baseline | pr539-nordic-ubuntu-TC_LEVEL_CONTROL-1 | 1 | 1 |
| original matrix and baseline | pr539-nordic-ubuntu-TC_ON_OFF-1 | 1 | 1 |
| original matrix and baseline | pr539-nordic-ubuntu-TC_RT_1_2-1 | 1 | 1 |
| original matrix and baseline | pr539-nordic-ubuntu-TC_Send_Command_Read_Write_Attributes-1 | 1 | 1 |
| original matrix and baseline | pr539-rpi-pi-TC_RT_1_2-10 | 1 | 9 |
| original matrix and baseline | pr539-rpi-pi-TC_RT_2_1-10 | -11 | 9 |
| original matrix and baseline | pr539-rpi-ubuntu-TC_RT_1_2-10 | 1 | 6 |
| original matrix and baseline | pr539-rpi-ubuntu-TC_RT_2_1-10 | -11 | 9 |
| corrected Ubuntu/Nordic | pr539-nordic-ubuntu-TC_RT_2_1-10 | -11 | 9 |

Additional setup-only incidents: original ENOTTY setup rejection; first offline assertion before DUT launch (a01); single-ATT fail-open launch in a08; IPv6 RA/address-generation setup; editor crash interrupted a ten-iteration callback/stage run with zero completed outcomes. These are methodology/infrastructure problems, not additional native FAIL outcomes.

a11 completed primary plus secondary fabric protocol checks but failed fixture completion signaling/closeout. Its protocol PASS is included above, but it is not a fully closed PASS gate. Excluding that one ambiguous closeout gives 549 outcomes, 401 PASS and 148 FAIL.

Five native SIGSEGV campaign incidents exist: three original PR, one original baseline, and one corrected Ubuntu/Nordic rerun. Callback lifetime is the leading pre-existing-harness hypothesis; the exact native crash cause is unproved. The editor interruption is separate.

The exposed project-label workflow credential and missing project-map script are pre-existing CI issues, not hardware iteration failures. Initial Restyled formatting failures in follow-up fixes were repairable changes in those PRs, not SDK failures.

Original matrix: 82 unfinished campaign slots. Forty setup-blocked Ubuntu/Nordic slots were subsequently executed in the corrected rerun; 42 original gaps remain on other configurations. The corrected rerun separately left nine callback slots unfinished; its replacement campaign is being validated by the isolated fix. The current affected-only queue does not promise to fill every historical full-matrix gap.
