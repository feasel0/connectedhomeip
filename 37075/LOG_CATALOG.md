# Issue #37075 Log Catalog and Initial Findings

Date reviewed: 2026-09-21

## Executive summary

The primary campaign/reference evidence catalog contains **143 complete
per-iteration bundles from four test runs**:

- **136 passing iterations**
- **7 failing iterations**
- All seven failures occurred while the test was trying to complete commissioning.
- All seven ended with `CHIP_ERROR_TIMEOUT (0x32)`.
- Only four failures—October iterations 47 through 50—match the issue title's exact `AddressResolve_DefaultImpl.cpp:124` exception.
- The other three have the same high-level `CommissioningComplete` symptom but fail at different protocol stages:
  - Two `CommandSender.cpp:343` command-delivery timeouts
  - One `CASESession.cpp:633` CASE-establishment timeout

The evidence therefore does **not** represent one uniform failure. At least three distinct failure classes have been grouped under the visible symptom "`CommissioningComplete` timed out."

Three additional standalone local smoke bundles are retained under `logs/` and
are excluded from the 143-bundle campaign/reference count: the passing Darwin
smoke, an infrastructure-valid Darwin flow marked failed by the empty-analytics
configuration bug, and the passing Android smoke documented below.

The October run also has an aggregate [summary](TC_Darwin_Pair_logs/summary.json) containing JSON records for all 100 iterations. Raw controller and DUT logs were retained for only 29 of those iterations.

The September 21, 2026 local reproduction campaign adds 100 consecutive passes using an isolated `Matter37075` Thread network formed by a local OTBR and nRF52840 RCP. This supports the earlier conclusion that the October address-resolution failures depended on the DUT attaching to an unintended Thread partition rather than on `AddressResolve` itself.

## September 21, 2026 Android pairing smoke

Directory:
`logs/smoke-android-pair/MatterTest/ble-thread/09-21-2026_14-31-05-684`

The dedicated `TC_Android_Pair.py` BLE-Thread smoke used fresh controller
storage and completed successfully:

- Result: **PASS**
- Requested/completed/passed/failed: **1/1/1/0**
- Iteration duration: `97.657709` seconds
- Pairing duration: `73.380083` seconds
- Generated DUT node ID: `0x00000000044514D4`
- `ConnectNetworkResponse`: `kSuccess`
- `NOCResponse`: `kOK`
- `CommissioningCompleteResponse`: `kOK`
- Runtime `CHIP_CONFIG_SECURITY_TEST_MODE=1` warnings: PASE and CASE

The DUT attached as a child to `Matter37075` on PAN ID `0x6213`, channel 20,
and partition `0x28CA9D9E`. It discovered SRP server
`fd97:3da1:0029:8106:f251:c7ca:ee09:d27a` at DUT uptime 8582 ms, became a child
at 8600 ms, and enabled operational advertising at 8676 ms. This is the inverse
of the October exact-signature failure condition: the intended partition, SRP
server, and operational publication were all present.

### Post-`AddNOC` operational sequence

| Host time | Evidence |
|---|---|
| `14:31:50.211` | `AddNOC` returned `NOCResponse(kOK)` for fabric 1. |
| `14:31:50.388` | The `WindowStatus` read triggered operational discovery for the generated DUT node. |
| `14:31:51.361` | DNS-SD selected the DUT address after 969 ms and started CASE. |
| `14:31:51.370` | Controller sent CASE Sigma1. |
| `14:31:51.724` | Controller received CASE Sigma2. |
| `14:31:51.746` | Controller sent CASE Sigma3. |
| `14:31:52.307` | CASE became active; the security-test-mode warning was emitted. |
| `14:31:52.472` | First CASE request returned `WindowStatus(kWindowNotOpen)`. |
| `14:31:52.478` | `SerialNumber` read began on the existing CASE session. |
| `14:31:52.618` | Wildcard/global read began on the existing CASE session. |
| `14:31:59.714` | `CommissioningComplete` was sent on the same CASE session. |
| `14:32:00.286` | `CommissioningCompleteResponse(kOK)` was received. |
| `14:32:00.299` | Subscription request was sent. |
| `14:32:18.334` onward | Time Synchronization and OTA Requestor coverage ran. |
| `14:32:57.945` | `RemoveFabric` was sent; DUT cleanup succeeded. |
| `14:33:03.733` | Iteration 1 was marked `PASS`. |

Every operation after CASE establishment found the existing secure session;
there was no second DUT lookup or CASE handshake before
`CommissioningComplete`. This ordering distinguishes the Android flow from
Darwin: Android proves operational discovery, CASE, and three operational reads
before sending `CommissioningComplete`, while Darwin sends
`CommissioningComplete` as its first operational CASE command.

### Timeout and error classification

No `Operational advertising failed` line, fatal, panic, assertion, hard-fault,
or watchdog marker appeared. Two timeout events were non-terminal and unrelated
to the successful DUT commissioning transition:

1. A framework startup lookup for default node ID `0x12344321` expired after
  45 seconds with `AddressResolve_DefaultImpl.cpp:124`. It was not the
  generated DUT node ID. The DUT's independent lookup resolved approximately
  306 ms later, and CASE plus `CommissioningComplete` succeeded.
2. `AnnounceOTAProvider` timed out in `CommandSender.cpp:378` at
  `14:32:54.089`. The DUT had logged `Failed to finalize command response: 3`.
  The matter-qa helper explicitly caught the timeout as an unimplemented
  optional operation, and the remaining Time Synchronization, OTA attribute,
  analytics, fabric-removal, and reset operations passed.

Classification: **not an issue #37075 reproduction**. The primary post-`AddNOC`
operational transition succeeded. A separate 100-iteration Android campaign is
the recommended next run, but it was not started as part of this smoke test.

## September 21, 2026 local 100-iteration campaign

Directory: `logs/stress-darwin-pair-100/MatterTest/ble-thread/09-21-2026_10-08-13-523`

The run completed before the development-session crash. Its persisted summary reports:

- Start: `2026-09-21T10:08:13.533129`
- End: `2026-09-21T12:22:04.835324`
- Wall-clock duration: approximately 2 hours, 13 minutes, 51 seconds
- Result: **PASS**
- Requested/completed/passed/failed: **100/100/100/0**
- Mean iteration duration: `80.05199583` seconds
- Mean pairing duration: `55.63721903` seconds
- Iteration-duration range: `78.841255` to `83.242719` seconds
- Pairing-duration range: `54.450735` to `58.787224` seconds

Every iteration retained its JSON result, controller log, and DUT UART log. Cross-run validation found:

- 200 controller-side `CommissioningCompleteResponse` records, exactly two per iteration, all with `errorCode = 0 == kOK`.
- 200 DUT-side `GeneralCommissioning: Received CommissioningComplete` records, exactly two per iteration.
- 300 controller-side security-test-mode warnings, corresponding to PASE and both CASE paths in every iteration.
- No DUT fatal, panic, assertion, hard-fault, bus-fault, or watchdog markers.

Thread state was stable for all 100 iterations:

| Marker | Result |
|---|---|
| Network name | `Matter37075` in 100/100 iterations |
| PAN ID | `0x6213` in 100/100 iterations |
| Channel | 20 in 100/100 iterations |
| Partition ID | `0x28CA9D9E` in 100/100 iterations |
| SRP server | `fd97:3da1:0029:8106:f251:c7ca:ee09:d27a` in 100/100 iterations |
| Thread role | Child in 100/100 iterations |
| Operational advertising enabled | 100/100 iterations |
| Operational advertising failed | 0 iterations |

One `AddressResolve_DefaultImpl.cpp:124: CHIP Error 0x00000032: Timeout` line appeared during iteration 1, but it was not an iteration failure or a failed post-`AddNOC` lookup for that iteration's DUT identity. The lookup for default node ID `0x12344321` began at `10:08:13.887`, before iteration 1 began at `10:08:38.994`, and expired at `10:08:58.890`. The generated iteration-1 DUT identity was different; its operational lookup began at `10:08:59.523`, resolved successfully, established CASE, and returned `CommissioningCompleteResponse(kOK)`. No later iteration contained an operational-discovery timeout.

### After-action conclusion

The local campaign did not reproduce a terminal issue #37075 failure. It did validate the full Python-controller, BLE-Thread, local-OTBR, nRF52840-RCP, and nRF52840-DK setup under sustained factory-reset/recommission cycles. Most importantly, the DUT stayed on one intended partition with working SRP discovery and operational advertisement throughout the campaign. That is the condition absent from the four exact-signature October failures.

The lone startup timeout should be tracked separately as a framework initialization lookup for the default node ID. It does not indicate a lost `CommissioningComplete` response and should not be counted as an issue reproduction.

## What counts as an iteration bundle

A retained iteration normally has:

- `iteration.json`, containing the result and exception traceback
- A controller log
- A DUT UART log
- Optionally, one or more packet captures and OTBR logs

The JSON result was checked against the raw controller log for every retained iteration. There are no JSON/raw-log disagreements.

## Inventory by test run

### January 28, 2025 evidence

Directory: `37075_Issue_reference_logs`

This set contains **13 iteration bundles**. Every bundle includes:

- Per-iteration JSON
- Controller log
- DUT log
- Controller-side packet capture

No OTBR-side capture or OTBR service log is present.

| Result | Iterations |
|---|---|
| PASS | 1, 74, 75, 76, 77, 79, 80, 97, 98, 100, 101 |
| FAIL | **78, 99** |

This gives 11 passes and 2 failures. The most useful local comparisons are:

- 74, 75, 76, 77, **78 fail**, 79, 80
- 97, 98, **99 fail**, 100, 101

#### Iteration 78

The [iteration summary](37075_Issue_reference_logs/78/iteration.json) reports:

- Result: `FAIL`
- Failed operation: second-fabric `CommissioningComplete`
- Final exception: `src/app/CommandSender.cpp:343: CHIP Error 0x00000032: Timeout`
- Duration: approximately 170 seconds

Raw-log sequence:

1. Operational DNS-SD resolution returned an address.
2. CASE Sigma1, Sigma2, and Sigma3 completed.
3. The CASE session became active.
4. The controller sent the encrypted `CommissioningComplete` invoke.
5. No invoke response completed before `CommandSender` timed out.

Available capture: [controller capture](37075_Issue_reference_logs/78/controller_tcpdump_2025-01-28_14-14-17.pcap)

Classification:

- Confirmed failed iteration: **yes**
- Failed during `CommissioningComplete`: **yes**
- `0x32 Timeout`: **yes**
- Exact issue-title address-resolution exception: **no**
- Failure phase: encrypted command delivery after successful CASE

#### Iteration 99

The [iteration summary](37075_Issue_reference_logs/99/iteration.json) reports:

- Result: `FAIL`
- Failed operation: second-fabric `CommissioningComplete`
- Final exception: `src/protocols/secure_channel/CASESession.cpp:633: CHIP Error 0x00000032: Timeout`
- Duration: approximately 199 seconds

Raw-log sequence:

1. Operational DNS-SD resolution returned an address.
2. The controller sent Sigma1 and received Sigma2.
3. The controller sent Sigma3.
4. The DUT repeated Sigma2, indicating that it did not receive or accept Sigma3.
5. CASE never became active and eventually timed out.

Available capture: [controller capture](37075_Issue_reference_logs/99/controller_tcpdump_2025-01-28_14-58-59.pcap)

Classification:

- Confirmed failed iteration: **yes**
- Failed while attempting `CommissioningComplete`: **yes**
- `0x32 Timeout`: **yes**
- Exact issue-title address-resolution exception: **no**
- Failure phase: CASE handshake after Sigma3 transmission

#### Limitation of iterations 78 and 99

The DUT logs include the successful first-fabric commissioning but stop before the relevant second-fabric failure. The controller captures show what reached or left the controller, but without an OTBR-side or 802.15.4 capture they cannot identify the exact network drop point.

### February 26, 2025 iteration 7

Directory: `ble_thread_iter_7_fail`

This run contributes one retained bundle.

The [iteration summary](ble_thread_iter_7_fail/iteration.json) reports:

- Result: `FAIL`
- Failed operation: second-fabric `CommissioningComplete`
- Final exception: `src/app/CommandSender.cpp:343: CHIP Error 0x00000032: Timeout`
- Duration: approximately 284 seconds

Artifacts:

- [Controller log](ble_thread_iter_7_fail/controller_log_iteration_7_2025-02-26_12-54-51.log)
- [DUT log](ble_thread_iter_7_fail/Dut_log_7_2025-02-26T12_54_51_207298.log)
- [Controller capture](ble_thread_iter_7_fail/controller_tcpdump_2025-02-26_12-54-51.pcap)
- [OTBR capture](ble_thread_iter_7_fail/OTBR_ON_SHH_tcp_dump_2025-02-26_12-54-51.pcap)
- [OTBR agent log](ble_thread_iter_7_fail/iter_7_otbr_agent_service_log.txt)

This is the richest individual bundle because it contains both controller- and OTBR-side captures.

Raw-log and packet-capture sequence:

1. First-fabric commissioning completed successfully.
2. The second controller requested a session for fixed node ID `0x12344322`.
3. `OperationalSessionSetup` moved directly from state 1 to state 5, proving that an existing CASE session was reused instead of starting a fresh operational lookup and CASE handshake.
4. The controller sent the encrypted command to `fd5c:ece7:589:1:8c0d:4946:fa5:eb26`.
5. The current DUT's OMR address was `fd5c:ece7:589:1:b808:da10:9c1c:4ffe`.
6. The controller and OTBR captures show all retransmissions going to the old address.
7. The current DUT could not receive or answer a command addressed to the old peer address.

Classification:

- Confirmed failed iteration: **yes**
- Failed during second-fabric `CommissioningComplete`: **yes**
- `0x32 Timeout`: **yes**
- Exact issue-title address-resolution exception: **no**
- Failure phase: encrypted command delivery through a stale reused CASE session

This strongly indicates a test-harness session-lifecycle defect. The second-fabric node ID is reused across factory-reset iterations, while cleanup did not reliably expire the second controller's CASE sessions and subscriptions.

### October 9, 2025 evidence

Directory: `TC_Darwin_Pair_logs`

The [run summary](TC_Darwin_Pair_logs/summary.json) reports:

- 100 scheduled iterations
- 100 completed iterations
- 96 passes
- 4 failures
- Failed iterations: 47, 48, 49, and 50
- Platform: Nordic
- Commissioning method: BLE-Thread

The summary contains JSON records for all 100 iterations. Separate raw log directories exist for only **29 iterations**.

| Result | Retained raw-log iterations |
|---|---|
| PASS | 1, 2, 3, 15, 16, 42, 43, 44, 45, 46, 51–64, 100 |
| FAIL | **47, 48, 49, 50** |

There are 25 retained passes and 4 retained failures. The other 71 iterations have result records in `summary.json` but no retained raw-log directory.

The standalone JSON files agree exactly with their corresponding records in `summary.json`.

#### Iterations 47 through 50

Iteration summaries:

- [Iteration 47](TC_Darwin_Pair_logs/47/iteration.json)
- [Iteration 48](TC_Darwin_Pair_logs/48/iteration.json)
- [Iteration 49](TC_Darwin_Pair_logs/49/iteration.json)
- [Iteration 50](TC_Darwin_Pair_logs/50/iteration.json)

All four report:

- Result: `FAIL`
- Failure while sending first-fabric `CommissioningComplete`
- Final exception: `src/lib/address_resolve/AddressResolve_DefaultImpl.cpp:124: CHIP Error 0x00000032: Timeout`

Raw controller logs confirm that operational discovery started and ran for approximately 45 seconds without producing a usable address.

DUT-side common sequence:

1. The DUT attached to Thread as a child.
2. The DUT accepted `AddNOC`.
3. The DUT attempted to advertise the new operational identity.
4. The DUT logged `Operational advertising failed: 3`.
5. The DUT never logged discovery of an SRP server.
6. The DUT never received CASE Sigma1 or `CommissioningComplete`.

#### Pass/fail differential

| Iteration | Result | Thread partition | SRP server discovered | Operational advertisement |
|---:|---|---|---|---|
| 46 | PASS | `0x7D35C043` | Yes | Successful |
| 47 | FAIL | `0x08472484` | No | Error 3 |
| 48 | FAIL | `0x7738DBB4` | No | Error 3 |
| 49 | FAIL | `0x2DF6DD12` | No | Error 3 |
| 50 | FAIL | `0x2DF6DD12` | No | Error 3 |
| 51 | PASS | `0x7D35C043` | Yes | Successful |

The four failures form one consecutive block between passing iterations 46 and 51. All passing iterations use partition `0x7D35C043` and discover SRP server `fd00:0db9:0:0:4ce7:be90:26e0:f6ce`. Each failure joins a different partition and discovers no SRP server.

This is a strong deterministic correlation:

1. The DUT joined a different Thread partition from the expected OTBR partition.
2. It could not discover the OTBR's SRP server.
3. Operational DNS-SD publication failed.
4. The controller had no operational service record to resolve.
5. Address resolution expired after 45 seconds.

Classification for every iteration from 47 through 50:

- Confirmed failed iteration: **yes**
- Failed at `CommissioningComplete`: **yes**
- `0x32 Timeout`: **yes**
- Exact issue-title address-resolution exception: **yes**
- Failure phase: operational discovery before CASE

These are the best examples of the exact failure described by the issue title.

#### October artifact limitations

There are no controller packet captures, OTBR packet captures, or OTBR service logs in this run. Every retained Bluetooth daemon log is only 17 bytes and contains no useful diagnostics.

## Consolidated failure catalog

| Run | Iteration | JSON result | Final timeout source | Commissioning phase | Exact issue-title signature |
|---|---:|---|---|---|---|
| January | 78 | FAIL | `CommandSender.cpp:343` | Second-fabric encrypted command | No |
| January | 99 | FAIL | `CASESession.cpp:633` | Second-fabric CASE handshake | No |
| February | 7 | FAIL | `CommandSender.cpp:343` | Second-fabric command on stale session | No |
| October | 47 | FAIL | `AddressResolve_DefaultImpl.cpp:124` | First-fabric operational discovery | **Yes** |
| October | 48 | FAIL | `AddressResolve_DefaultImpl.cpp:124` | First-fabric operational discovery | **Yes** |
| October | 49 | FAIL | `AddressResolve_DefaultImpl.cpp:124` | First-fabric operational discovery | **Yes** |
| October | 50 | FAIL | `AddressResolve_DefaultImpl.cpp:124` | First-fabric operational discovery | **Yes** |

Every failed JSON is corroborated by its controller traceback. Every retained passing iteration:

- Has `PASS` in its JSON summary
- Has a null exception
- Completes both `CommissioningComplete` test steps
- Does not contain one of the terminal timeout signatures present in the seven failed iterations

## Evidence usefulness ranking

### 1. October iterations 46 through 51: highest priority for the exact issue

Use iteration 46 as the immediate passing baseline, 47 through 50 as four consecutive failures, and 51 as the immediate recovery baseline.

Strengths:

- Four repetitions of the exact reported exception
- Clean pass-to-failure-to-pass transition
- Deterministic DUT-side signature
- Strong Thread partition and SRP correlation
- Direct evidence that no operational service record was published

Limitation:

- No OTBR or packet-capture evidence

These logs are sufficient to show that `AddressResolve` is reporting the final consequence, not necessarily causing the problem. There was no operational record for the controller to resolve.

### 2. February iteration 7: best packet-level evidence

Strengths:

- Controller and DUT logs
- Controller capture
- OTBR capture
- OTBR service log
- Conclusive stale peer-address evidence

This bundle is likely sufficient to fix its specific test-harness cleanup problem without another reproduction. It should not be treated as the same defect as October iterations 47 through 50.

### 3. January iterations 78 and 99: useful phase classification, incomplete root cause

Strengths:

- Immediate passing neighbors
- Controller-side packet captures
- Clear distinction between command-delivery and CASE failures

Limitations:

- DUT logs stop before the relevant second-fabric failure
- No OTBR-side or 802.15.4 capture

They establish where the controller timed out but do not identify the exact network drop point.

### 4. Remaining passing iterations: supporting baselines

- October 42 through 46 and 51 through 64 provide many normal Thread/SRP/commissioning sequences.
- October 1 through 3, 15 through 16, and 100 show that the test normally remains stable elsewhere in the run.
- January pass iterations provide controller-packet baselines around both January failures.

## Initial debugging conclusions

The existing logs are sufficient to begin analysis without immediately requesting a modified build.

### Exact October address-resolution failures

The October evidence indicates this chain:

1. The DUT attached to a different or isolated Thread partition.
2. No SRP server was available in that partition.
3. `AddNOC` installed the pending fabric but operational advertising returned error 3.
4. No later operational service record appeared.
5. The controller's lookup timed out.

The address resolver cannot find a service that was never published. A connectedhomeip robustness question remains—whether failed operational advertisement should be retried or reported more explicitly—but retrying publication cannot make a DUT reachable while it remains on a partition disconnected from the controller's OTBR.

### February stale-session failure

The February evidence indicates a separate lifecycle bug:

1. The second controller uses a fixed scoped node ID across iterations.
2. Factory reset invalidates server-side CASE state and can change the DUT's Thread address.
3. The controller retained and reused an old CASE session and peer address.
4. Cleanup should explicitly close subscriptions and expire sessions for both controllers before the next reset/recommission cycle.

### January transport failures

Iterations 78 and 99 are genuine `CommissioningComplete` failures but are not the same address-resolution failure. Existing evidence classifies their protocol stage but is insufficient to prove the packet drop location.

## Recommended investigation order

1. Analyze October 46 through 51 as the exact issue-title failure set.
2. Treat February iteration 7 as a separate test-harness session-cleanup defect.
3. Treat January iterations 78 and 99 as separate transport cases.
4. Avoid increasing the 45-second address-resolution timeout or adding a blind sleep; neither change addresses the observed partition, publication, stale-session, or packet-delivery problems.
5. Request new instrumented runs only after exhausting the current logs, and tailor any added diagnostics to the remaining unresolved failure class rather than collecting generic logs.

### Concrete starting sequence

Begin with the October **46 → 47 → 51** comparison:

1. Iteration 46 is the immediate passing baseline. Compare its controller and DUT logs to establish the expected Thread attachment, SRP discovery, operational advertisement, address resolution, CASE, and `CommissioningComplete` sequence.
2. Iteration 47 is the first exact-signature failure. Identify the first divergence from iteration 46, rather than starting at the final 45-second `AddressResolve` timeout.
3. Iteration 51 is the immediate recovery baseline. Confirm that the conditions missing in iteration 47 return when the test passes again.
4. Expand the comparison to iterations 48 through 50. Iterations 49 and 50 are especially useful because both joined partition `0x2DF6DD12`, showing that the failure condition persisted across an iteration boundary.

This sequence is the best first investigation because it combines four repetitions of the exact issue signature with clean passing iterations immediately before and after the failure block. Its main limitation is the absence of OTBR logs and packet captures.

After the October investigation:

1. Analyze February iteration 7 independently. It has the most complete packet-level evidence, but represents stale CASE-session and peer-address reuse rather than the issue-title `AddressResolve` failure.
2. Defer January iterations 78 and 99 until the October and February classes are understood. They are genuine `CommissioningComplete` failures, but the available evidence only localizes them to command delivery and CASE establishment respectively.

## October detailed investigation

### Earliest pass/fail divergence

The controller supplied the same 109-byte Thread Operational Dataset in iterations 46 through 51. The dataset's SHA-256 prefix is `9d3f2cbfa7a50d90` in every iteration. Its relevant values are:

| Field | Supplied value |
|---|---|
| Active Timestamp | 1 |
| Network Name | `OpenThreadGRL` |
| Network Key | `00112233445566778899AABBCCDDEEFF` |
| Extended PAN ID | `1111111122222222` |
| PAN ID | `0x1234` |
| Channel | 15 |
| Mesh-local prefix | `fd78:246f:5c18:134c::/64` |

This rules out an iteration-specific controller credential difference. In each iteration, the DUT first installs these values. Before or during attachment, the active dataset then changes away from the supplied values.

| Iteration | Result | Final name | Final PAN | Final channel | Final Extended PAN ID | Final partition | OMR address | SRP |
|---:|---|---|---|---:|---|---|---|---|
| 46 | PASS | `Thread Cert 9.2` | `0xFACE` | 23 | `000DB80000000000` | `0x7D35C043` | Yes | Yes |
| 47 | FAIL | `GRL` | `0xAFCE` | 22 | `000DB80000000000` | `0x08472484` | No | No |
| 48 | FAIL | `GRL` | `0xFACE` | 21 | `000DB80000000000` | `0x7738DBB4` | No | No |
| 49 | FAIL | `GRL` | `0xABCD` | 22 | `000DB80000000000` | `0x2DF6DD12` | No | No |
| 50 | FAIL | `GRL` | `0xABCD` | 22 | `000DB80000000000` | `0x2DF6DD12` | No | No |
| 51 | PASS | `Thread Cert 9.2` | `0xFACE` | 23 | `000DB80000000000` | `0x7D35C043` | Yes | Yes |

Iteration 47 is the clearest single differential:

1. The DUT installs `OpenThreadGRL`, PAN `0x1234`, Extended PAN ID `1111111122222222`, and channel 15.
2. While detached, its channel and PAN change to channel 22 and `0xAFCE`.
3. It attaches as a child with a parent-supplied dataset named `GRL`, Extended PAN ID `000DB80000000000`, mesh-local prefix `fd00:db9::/64`, and partition `0x08472484`.
4. The Network Commissioning `ConnectNetworkResponse` nevertheless reports success because Thread link attachment succeeded.
5. This partition supplies no OMR address and no SRP server.
6. `AddNOC` later cannot publish the operational identity, and controller resolution expires.

Iteration 46 follows the same sequence until parent selection, but attaches to partition `0x7D35C043`. That partition supplies an OMR address and SRP server `fd00:0db9::4ce7:be90:26e0:f6ce`; operational publication, address resolution, CASE, and `CommissioningComplete` then succeed. Iteration 51 restores the same passing conditions.

The correlation remains perfect across every retained iteration from 42 through 64:

- All 19 passes attach to `Thread Cert 9.2` on partition `0x7D35C043`, discover the expected SRP server, and have no operational-advertisement failure.
- All four failures attach to a `GRL` partition, discover no SRP server, and log `Operational advertising failed: 3`.

Iterations 49 and 50 both attach to partition `0x2DF6DD12` even though the DUT is factory-reset and rebooted between attempts. This rules out DUT persistent state as the simplest explanation and instead points to an external Thread parent that remained available across both iterations.

### Interpretation of the Thread behavior

The final dataset is supplied by the attached Thread network rather than retained from the factory-reset DUT. The most likely explanation is that multiple nearby Thread routers or test networks share certification-style credentials. Names such as `GRL` and `Thread Cert 9.2`, the repeated Extended PAN ID `000DB80000000000`, and deterministic alternate PAN/channel/partition combinations support this interpretation.

Because the same Network Key is usable on these nearby partitions, the DUT can authenticate to a parent other than the intended OTBR's parent. It then adopts that parent's newer Active Dataset. Only partition `0x7D35C043` has connectivity to the expected OTBR infrastructure.

This remains a strong inference rather than packet-level proof. The October artifacts contain neither an 802.15.4 capture nor an OTBR log, so they cannot identify the parent device that supplied each alternate dataset or show the Thread Dataset exchange on the air.

### Why Network Commissioning reports success

The OpenThread Network Commissioning implementation at the issue's reported SDK revision `f8d457a446456d5df1e750e728ea48e8fce9d989` behaves as follows:

1. `ConnectNetwork()` verifies that the requested Extended PAN ID matches the staged dataset.
2. It installs that dataset and enables Thread.
3. `_OnThreadAttachFinished()` reports `kSuccess` when the OpenThread role becomes attached.
4. It does not require discovery of an SRP server, an OMR address, or reachability of the commissioner/OTBR.
5. It does not compare the final parent-supplied Active Dataset with the complete dataset originally installed.

Iteration 47 demonstrates this behavior directly: `ConnectNetworkResponse` reports `kSuccess` after attachment to the unusable partition. Extended PAN ID validation alone would not distinguish the observed pass and failure partitions, because all final datasets report `000DB80000000000`.

Changing this behavior is not yet justified as an SDK fix. Thread attachment itself succeeded, and the available private Matter specification was not accessible during this analysis to establish whether `ConnectNetwork` is required to validate border-router or operational-service reachability. A full-dataset equality check would also reject the passing path, whose final parent-supplied dataset legitimately differs from the staged dataset.

### Source of `Operational advertising failed: 3`

Error 3 is `CHIP_ERROR_INCORRECT_STATE`, not an SRP protocol response. The same behavior exists at the issue's reported SDK revision:

1. The platform DNS-SD advertiser enters `kInitializing` during startup.
2. On OpenThread, initialization waits for the initial SRP host-removal operation to complete.
3. That completion callback requires an available SRP server.
4. Without an SRP server, the advertiser is not initialized when `AddNOC` calls `AdvertiseOperational()`.
5. The advertiser's initialized-state check returns `CHIP_ERROR_INCORRECT_STATE`, which produces the numeric error 3 in the DUT log.

`AddNOC` treats operational advertisement as best effort, so the NOC command succeeds and commissioning proceeds to operational discovery. This is why the controller eventually reports `AddressResolve_DefaultImpl.cpp:124` rather than an `AddNOC` error.

The SDK already contains a delayed-initialization retry path. If SRP initialization later succeeds, the platform posts `kDnssdInitialized`; `DnssdServer::StartServer()` then calls `AdvertiseOperational()` again. Therefore, the hypothesis that publication permanently fails only because `AddNOC` raced SRP initialization is not supported by the source.

The failed DUT logs stop immediately after BLE disconnect and contain a literal `stop_logging` command, so they do not cover the controller's following 45-second lookup interval. They prove that no SRP server was available before `AddNOC`, but cannot directly prove that one was never discovered later. The controller's lack of any operational DNS-SD result does prove that no reachable operational service appeared during its lookup.

### Current root-cause assessment

The October failure is best classified as a **test-lab Thread topology or credential-isolation failure**, not an address-resolver defect:

1. The test provisions a static certification-style dataset.
2. The DUT intermittently selects one of several parent-supplied datasets/partitions that appear to share credentials.
3. The unintended partition has no reachable SRP server or OMR path to the controller's infrastructure.
4. Operational advertisement cannot start there.
5. The controller accurately times out because the operational service never becomes discoverable.

No connectedhomeip code change is supported by the current evidence. In particular, increasing the resolver timeout, adding a delay before `CommissioningComplete`, or adding another advertisement call at `AddNOC` would not repair attachment to an isolated partition.

### Most decisive validation and information request

The highest-value next test is to give the intended OTBR and DUT a unique, freshly generated Thread Network Key and dataset that are not shared with any nearby certification equipment. The test harness should use the intended OTBR's current complete Active Dataset rather than a static dataset. If the four-failure pattern disappears, it confirms the topology/credential-collision diagnosis.

If the testing team can reproduce the failure, collect:

1. The intended OTBR's complete Active Dataset immediately before commissioning.
2. The DUT's complete Active Dataset immediately after attachment.
3. An inventory of active Thread routers/test fixtures on channels 15, 21, 22, and 23, including Network Key ownership and partition IDs.
4. The intended OTBR service log and an 802.15.4 capture spanning dataset installation through the full 45-second operational lookup.
5. The selected parent's identity and the SRP-server/Network Data observed by the DUT.
6. DUT logging that remains active until the controller finishes or times out; do not stop logging when BLE disconnects.

Until that validation is run, the exact external parent remains unidentified. The existing evidence is nevertheless sufficient to exclude `AddressResolve` as the initiating fault and to avoid an unsupported SDK timeout or retry patch.
