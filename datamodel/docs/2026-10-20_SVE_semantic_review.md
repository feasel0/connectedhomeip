# Matter 1.7 SVE Semantic Review

**Checkpoint:** 2026-10-20 UTC. All 20 changed XML files reviewed; candidate remains private scratch, not an accepted release model.

## Inputs and Decision Boundary

| Input | Exact value |
|---|---|
| SDK and prior reference XML | `24fafe816f7a5db9aeb514d6504ff6b57384b4f1` |
| Prior model specification | `214e40c9d51cfe89050eae68ca5b76238fcfa332` |
| Candidate specification | `eea0ffce8fe9e4951a4558a6e6c6362b307e0334` |
| Scraper | Alchemy `v1.7.10`, unchanged from prior model |
| Selection | Existing SDK `Current` list; no blanket `in-progress` selection |

The source changes below are verified against the two exact specification commits, not a 1.6.1 comparison. The source locators are private-repository paths and old/current line numbers, supplied for authorized reviewers. This document summarizes derived changes, not private specification prose or XML. Source fidelity and milestone approval are separate decisions.

**Ballot evidence gap:** no applicable ballot email, approved include list, release tag, or release-coordinator confirmation was available in the supplied documents or authorized local document search. Therefore no change is declared SVE-approved. The untagged master warning remains expected for this experiment, not resolved release provenance. Suggested owner: release coordinator with data-model/specification leads; obtain the exact milestone SHA/tag and list before G0/G5 can pass.

The selected list has **40 entries / 39 unique flags**, including duplicate `pqc`. Its SHA-256 is `2d190f992eda73c411d33a8c355adeb883605cffec0873079bc5cf223fb2c3fd`, calculated from ordered UTF-8 JSON with separators `(',', ':')` and no trailing newline:

```text
access-closure, add-core-modes, add-humidity-controller, ambientsensorfusion,
ambientsensingunion, audio-messages, camera-av-analytics, cameras-remote-zones,
CurrentHue-scenable, deprecate-im-revision-field, device-location,
electrical-sensor-alarm, energy-auxswitch-device-type,
energy-electrical-protection, groups-soft-deprecation, hrap-pdc, hrap-proxy,
humidistat, hvac-critical-protection, nv-persist-updates, octstr-length-limit,
onoff-q-improvement, pqc, predictive-occupancy, q-phase-3, powerrange, pqc,
proximity-ranging, encrypted-advertising-data, remove-nonvolatile-PS,
resource-medium, scenes-fixes, smoke-concentration-tcr,
streaming-casting-speakers, tariff-externalid,
thermostat-min-setpoint-duration, thermostat-sensors, tstatmode, uwb-ranging,
obsolete
```

The duplicate is a recorded configuration observation, not a demonstrated extraction failure. No flags were changed on that basis.

## Coverage and Maturity

There are 14 cluster, five device-type, and one global XML changes. No XML file, cluster/device ID, or name/ID mapping was added or removed. **Every declared revision is unchanged.** Revision-policy approval for substantive changes is still a specification-owner question. `spec_sha` changes and removal of the old `spec_tag` are separate provenance changes, not two additional XML changes.

The following maturity classifications distinguish cluster-level provisional status from provisional conditions on individual elements:

| XML stem | Revision old/new | Cluster maturity old/new | Total provisional nodes old/new |
|---|---|---|---|
| ClosureControl | 2 / 2 | Non-provisional / non-provisional | 2 / 2 |
| ClosureDimension | 2 / 2 | Non-provisional / non-provisional | 3 / 3 |
| DeviceEnergyManagement | 5 / 5 | Non-provisional / non-provisional | 7 / 7 |
| ElectricalProtectionAlarm | 1 / 1 | Provisional / provisional | 1 / 1 |
| GeneralCommissioningCluster | 2 / 2 | Non-provisional / non-provisional | 6 / 6 |
| Group-Key-Management-Cluster | 4 / 4 | Non-provisional / non-provisional | 3 / 2 |
| Humidistat | 1 / 1 | Provisional / provisional | 1 / 1 |
| ModeBase | 3 / 3 | Abstract, non-provisional / unchanged | 3 / 3 |
| ModeSelect | 2 / 2 | Non-provisional / non-provisional | 0 / 0 |
| Mode_Thermostat | 1 / 1 | Non-provisional / provisional | 0 / 2 |
| NetworkCommissioningCluster | 3 / 3 | Non-provisional / non-provisional | 6 / 6 |
| ProximityRanging | 1 / 1 | Provisional / provisional | 3 / 3 |
| PushAVStreamTransport | 3 / 3 | Non-provisional / non-provisional | 4 / 4 |
| ThermostatUserInterfaceConfiguration | 2 / 2 | Non-provisional / non-provisional | 0 / 0 |

The five changed device types retain revisions 3, 3, 3, 4, and 2 respectively and their non-provisional device-type status. NetworkInfraManager retains two element-level provisional nodes; the other four have none. The global bitmap has no cluster revision or provisional nodes. GKM loses the provisional condition belonging to its retired attribute, not cluster maturity. Thermostat Mode adds cluster maturity and a provisional COREMODES condition.

## Four Priority Investigations

### Group Key Management

**File:** `clusters/Group-Key-Management-Cluster.xml`. **Source:** `src/data_model/Group-Key-Management-Cluster.adoc`, old lines 303/324; current lines 70/250/254. **Classification:** source-aligned removal; needs release/spec decision and independent regression coverage. Ledger: GKM-01.

- Removes `GroupcastAdoptionStruct` and its Boolean `GroupcastAdopted` field with fabric-scoped metadata. Struct count is 4 -> 3.
- Attribute `0x0004` changes from list-valued `GroupcastAdoption` to untyped disallowed `DoNotUse`; removes its entry, access, nonvolatile/provisional metadata and GCAST-dependent conformance. Attribute entries stay 5 -> 5; commands stay 6 -> 6.
- **Neither CS nor GCAST is removed from the feature list.** The earlier apparent feature deletion counted a nested conformance reference. Current source reserves the old attribute ID and determines adoption using Groups cluster revision >= 5.
- Pinned ZAP `group-key-mgmt-cluster.xml:64` already omits the retired API. `GroupKeyManagementCluster.cpp:738` already uses the Groups-revision predicate. No new deletion-related implementation drift was demonstrated.
- `TestGroupKeyManagementCluster.cpp:532` derives expected behavior from the same predicate; this is not an independent revision-boundary proof. Add separate no-Groups, revision-below-5, revision-5, and forbidden-attribute tests. Ask specification owner about unchanged revision/history; do not restore obsolete XML by inference.

### Closure Dimension

**File:** `clusters/ClosureDimension.xml`. **Source:** `src/app_clusters/ClosureDimension.adoc`, old lines 409/481; current 356/430/759. **Classification:** source-aligned encoded-unit correction, SDK/ZAP drift, boundary-test gap. Ledger: CDIM-01.

- `RangePercent100thsStruct.Max` upper bound changes 100 -> 10000. `Resolution` and `StepValue` default/minimum change 0.01 -> 1, expressing integer hundredths rather than fractional percentages.
- Removes an empty descriptive constraint from `Step.Speed`; its optional-SP conformance remains. Access/grouped command provisional conditions and revision 2 are unchanged; those commands were not newly added by this diff.
- Generated `Percent100ths` is integer-valued (`ClosureDimension/Structs.h:65`), and runtime already checks maximum 10000 (`ClosureDimensionCluster.cpp:429`). ZAP `closure-dimension-cluster.xml:173` still permits default 0 and lacks minimum 1.
- Existing tests exercise valid configurations and full scale. Resolution/step zero, one, maximum, and out-of-range configuration need targeted checks. A zero configuration flowing toward modulo was a static risk observation, **not an executed crash reproduction**; no implementation fix is claimed.

### Device Energy Management

**File:** `clusters/DeviceEnergyManagement.xml`. **Source:** `src/app_clusters/DeviceEnergyManagement.adoc`, old line 1893; current lines 2043/2062. **Classification:** source-aligned command contract; parser implementation/test gap and specification-example question. Ledger: DEM-01/02.

- Only `PowerRangeAdjustRequest` (`0x08`) changes. Its `MinPower`/`MaxPower` fields go from mandatory nullable to optional non-null with choice `a+` (at least one). Defaults 0 and 2^62 disappear.
- `MinPower` gains AbsMinPower..AbsMaxPower bounds. `MaxPower` gains maxOf(MinPower, AbsMinPower)..AbsMaxPower. `Duration` goes from maximum-only 86400 to range 1..86400. Cause is unchanged.
- Four added `<attribute>` nodes are **constraint references**, not four new attributes: top-level attributes remain 9 -> 9. `PowerRangeAdjustStruct` is unaffected; PRA/provisional markings and revision 5 remain.
- ZAP `device-energy-management-cluster.xml:206`, generated `Commands.h:381`, runtime handler `DeviceEnergyManagementCluster.cpp:828`, and tests near line 461 already use optional fields. Current source examples near 2043 still use null; specification owner should reconcile examples with the table, not force the generated model back to nullable.
- A direct pinned-parser probe preserves MinPower's simple reference bounds and MaxPower's upper bound but drops **both representations of MaxPower's lower bound** (`min_value` and `min_value_ref` are `None`) despite `maxOf` being present in XML. Neither cluster parse reports a problem. This is confirmed consumer information loss, not malformed XML. A dedicated expression representation/consumer regression is needed; no speculative AST redesign was made.

### Thermostat Mode

**File:** `clusters/Mode_Thermostat.xml`. **Source:** `src/app_clusters/Mode_Thermostat.adoc`, old line 111; current lines 50/80/175. **Classification:** source-aligned overlays/maturity, generation access discrepancy, parser inheritance defect, SDK ACL drift. Ledger: TMODE-01/02/03.

- Adds explicit overlays for existing commands IDs 0/1/2 (`ChangeToMode`, its response, `ChangeToModeByCoreTag`); these are not new missing SDK commands. Adds cluster-level provisional marking; COREMODES changes from unspecified to provisional/optional.
- Removes the OnOff summary and explicit mandatory conditions on Label/Mode/ModeTags overlay fields. Blank overlay cells mean inheritance; ModeTags count 1..8 and attributes are unchanged. DEPONOFF remains disallowed; revision remains 1.
- Source incoming commands specify **Manage**, but candidate command overlays omit access metadata. Pinned generated Thermostat Mode `Metadata.h:51` permits **Operate**. Base Mode's changed core-tag command separately specifies Operate. Scraper and cluster owners must resolve the derived-specific Manage override, not infer it from the base or patch reference XML manually.
- Focused before/after parsing of the actual model trees produces command conformance **M / M / P,COREMODES -> O / O / O** for IDs 0/1/2. `get_conformance()` defaults missing cells to Optional; `combine_derived_clusters_with_base()` then overwrites inherited command conformance unconditionally for unknown-direction overlays. The parser returns zero cluster problems. Existing passing tests do not detect this loss.
- A consumer fix needs blank-inherits, explicit-optional, explicit-disallowed, feature-conditional, accepted/generated-command, and access-override regressions; changing the global missing-conformance fallback without distinguishing derived overlays would be speculative. `ModeBaseCluster.cpp:339`, tests near 502, and `TC_TSTATM_3_4.py:163` establish existing command implementation, not updated ACL certification. Those native/hardware tests were inspected, not executed here.

## Remaining Sixteen Files

For this table, source paths are below specification `src/`; numbers are old -> current. Unless noted, element conformance and provisional markings are unchanged, and every revision remains unchanged. Expected source-aligned changes still require ballot approval.

| File below `data_model/1.7/` | Exact change and source evidence | SDK/test assessment and classification |
|---|---|---|
| `clusters/ClosureControl.xml` | Positioning-feature summary drops percentage annotations; `app_clusters/ClosureControl.adoc:125 -> 64`. | Editorial only; no positioning behavior reversal. ZAP summary at `closure-control-cluster.xml:97` is descriptive drift only. |
| `clusters/ElectricalProtectionAlarm.xml` | SurgeProtection bit 23 summary changes sustained-overvoltage -> transient-surge meaning. Adds min 1 to ResidualCurrentFaultRatingsStruct.TrippingCharacteristic; ShortCircuitRatingsStruct.TripCurrent, TripMechanism, UltimateMaxCurrent, ServiceMaxCurrent, MaxCurrent; SurgeProtectionRatingsStruct.ProtectionClass and ProtectionType. Source old 121/303/396-401/430-431 -> current 60/242/335-340/369-370 in `app_clusters/ElectricalProtectionAlarm.adoc`. | Eight actual new minima, not new fields; zero excluded. ZAP lacks minima; runtime encodes supplied configuration without those checks. Existing positive-value tests are not zero/one boundary tests. SDK/ZAP drift and implementation/test gap, EPA-01. |
| `clusters/GeneralCommissioningCluster.xml` | TC feature summary changes ampersand to word; `service_device_management/GeneralCommissioningCluster.adoc`, old 122 -> current 57. | Editorial only. Pre-existing TC maturity questions are not introduced by this diff. |
| `clusters/Humidistat.xml` | Step `0x0006` range 0..100 -> 1..100; MistType `0x0008` loses nullable and gains 1..3. Optional SetSettings.MistType field gains a descriptive constraint, not equivalent numeric bounds. `app_clusters/Humidistat.adoc`, old 251/253/369 -> current 190/192/315, with behavior at 329-330/345-346. | ZAP still allows Step 0/MistType without min 1. Runtime already rejects Step 0, but MistType setter/persistence allow empty bitmap; tests explicitly expect zero, including attribute write. Confirm command-zero versus attribute-zero and combined capability semantics with owner. SDK/ZAP and test drift, HUM-01. |
| `clusters/ModeBase.xml` | Existing ChangeToModeByCoreTag `0x02` adds explicit Operate invoke privilege; `app_clusters/ModeBase.adoc:443 -> 382`. | Generated Thermostat Mode currently uses Operate. No new command or standalone ModeBase cluster ID inferred; derived-specific Manage issue remains separate. Source-aligned, ACL tests not run. |
| `clusters/ModeSelect.xml` | Revision-2 history changes section terminology; `app_clusters/ModeSelect.adoc:105 -> 44`. | Editorial only; no current nullability change. |
| `clusters/NetworkCommissioningCluster.xml` | WiFiSecurityBitmap bit 5 name WPA3-Matter-PDC -> IEEE8021X, covering Enterprise/PDC authentication. Bit value `0x20` unchanged; provisional mandatory conformance unchanged. `service_device_management/NetworkCommissioningCluster.adoc:161 -> 96-97`. | ZAP/API still expose `kWpa3MatterPdc`. Linux scan handling uses an internal EAP bit 7 then clears it rather than reporting bit 5, in both scan paths (`WpaSupplicantClient.cpp:268-362`). Static source/API reporting gap, not hardware proof or a new requirement to commission Enterprise. Evaluate source-compatible API naming and synthetic scan tests. NET-01. |
| `clusters/ProximityRanging.xml` | StartRangingRequest `0x00` gains response association with existing StartRangingResponse `0x01`; `app_clusters/ProximityRanging.adoc:876 -> 815`. | ZAP, generated APIs and server already agree. Tests near server test line 539 inspected, not run. Source-aligned association correction. |
| `clusters/PushAVStreamTransport.xml` | Existing MaxPreRollLen field 4 mandatory OR-condition adds AmbientContext alongside Command/Motion; `app_clusters/PushAVStreamTransport.adoc:939 -> 878-880`, descriptions old 976 -> current 918-922, under `camera-av-analytics`. | No new enum definition or field. Runtime `ValidateIncomingTransportOptions` already requires AmbientContext pre-roll; no matching AmbientContext unit case identified in inspected tests. Source-aligned plus coverage gap, PUSH-01. |
| `clusters/ThermostatUserInterfaceConfiguration.xml` | Revision history terminology only; `app_clusters/ThermostatUserInterfaceConfiguration.adoc:95 -> 34`. | Editorial only. |
| `device_types/BaseDeviceType.xml` | Node/App/Simple/Dynamic/Composed condition summaries become explicit cross-references; `device_types/BaseDeviceType.adoc:144-148 -> 81-85`. | Eligibility unchanged. Literal xref markup remains in generated summaries, but referenced targets exist in Data-Model/System-Model. Rendering contract unresolved, not a proven normative defect; RENDER-01. |
| `device_types/GenericSwitch.xml` | Revision history terminology only; `device_types/GenericSwitch.adoc:91 -> 30`. | Editorial only; no Scenes addition in this delta. |
| `device_types/NetworkInfraManager.xml` | Revision-2 history terminology only; `device_types/NetworkInfraManager.adoc:93 -> 45`. | Optional/provisional NetworkIdentityManagement and CommissioningProxy unchanged. Editorial only. |
| `device_types/RoboticVacuumCleaner.xml` | Revision-2 history wording only; `device_types/RoboticVacuumCleaner.adoc:75 -> 12`. | Revision stays 4; OperationCompletion already exists. Editorial only. |
| `device_types/ThreadBorderRouter.xml` | Revision-2 history terminology only; `device_types/ThreadBorderRouter.adoc:78 -> 16`. | Revision stays 2; separately guarded revision-3 text is not selected. Editorial only. |
| `globals/Bitmaps.xml` | PairingHintBitmap bit 21 example loses its bitwise-AND operator between two mask operands. `secure_channel/Discovery.adoc:722 -> 677` retains the operator at both source commits. | Confirmed source/output discrepancy, not intended source evolution; no wire bitmap change. Independent Alchemy output already matched candidate, so do not blame include filtering or manually patch XML. Exact extraction/entity-processing stage remains to isolate. BITMAP-01. |

Nine of these sixteen are editorial/descriptive-only; six change explicit contracts/constraints/meaning; the remaining bitmap change is an extraction discrepancy. BaseDeviceType's rendering question does not change eligibility.

## Joint Fabric Administrator PICS Warning

Cluster 1875 (`0x0753`) has this checked-in history:

| Model versions | Name / PICS |
|---|---|
| 1.0-1.3 | Absent |
| 1.4, 1.4.1 | JointFabricPKI / `JFPKI` |
| 1.4.2, 1.5, 1.5.1 | JointFabricAdministrator / `JFPKI` |
| 1.6, 1.6.1, prior and candidate 1.7 | JointFabricAdministrator / `JFADMIN` |

Both pinned specification inputs specify `JFADMIN` (`service_device_management/JointFabricAdministratorCluster.adoc`, old 99/current 34). The warning arises at the historical 1.5.1 -> 1.6 transition and **pre-exists the candidate**. A memory-only replay of the generator's cluster-PICS comparison emits the same single inconsistency for baseline and candidate; device-type parsing was stubbed for that isolated comparison, not counted as a full generation rerun.

The generator warns and then overwrites the prior value when producing a single current PICS cell, concealing version history. Version-selected tests can require `JFPKI.S` or `JFADMIN.S`; using a mismatched PICS prefix can appear as missing coverage. There is no wire-ID change or new SDK API change established by this warning. Specification/data-model owners should validate the historical transition, and tooling owners should consider version-aware presentation and transition tests. Do not normalize historical XML without approval. Ledger: JFA-01.

## Executed Validation and Limits

The existing SDK semantic-diff functions (`diff_clusters`, `diff_device_types`, provisional reports) were executed with readers redirected to the **actual prior/candidate 1.7 directories**, avoiding a misleading different-version comparison. Full XML diffs, source tracing, and focused probes supplement their narrower summaries.

| Candidate-bound suite | Executed / passed | Failed / errors / skipped |
|---|---|---|
| TestSpecParsingSupport | 15 / 15 | 0 / 0 / 0 |
| TestSpecParsingSelection | 2 / 2 | 0 / 0 / 0 |
| TestSpecParsingDeviceType | 29 / 29 | 0 / 0 / 0 |
| TestSpecParsingDataType | 26 / 26 | 0 / 0 / 0 |
| TestSpecParsingNamespace | 7 / 7 | 0 / 0 / 0 |
| Total | **79 / 79** | **0 / 0 / 0** |

Tests used unchanged pinned Python testing sources and the generated candidate ZIP, not the installed package's stale model. A private overlay and positive module/resource-path assertions proved both. Existing host controller/native modules were reused, not freshly rebuilt. A missing host `libevent_core-2.1.so.7` initially blocked execution; the existing host-local library resolved it via `LD_LIBRARY_PATH`, without system installation or test suppression. Earlier bootstrap failures are retained privately and are not model test failures.

Candidate model ZIP SHA-256: `f05aee774bbe9e0fe2ac6bb2c3a0c400034cba0cba4dc792bd0fd33d3349a272`. The original ZIP bytes used by the tests are retained; rebuilding a ZIP can change metadata/hash without changing XML.

**Not executed:** updated ZAP generation, native cluster regressions, ACL/IDM DUT tests, hardware campaigns, or certification/test-harness acceptance. Passing parsing suites do not prove enforcement of DEM expressions, inheritance fidelity, bitmap prose extraction, updated bounds, or access privileges. Focused probes reproduced information loss despite zero parser problems. No tests were weakened and no normative/generated XML, include flags, production parser code, or SDK version default was changed during this review.

## Disposition

G1 remains passed; G2 has structural/provenance evidence. G3 itemization is complete but findings and milestone policy are unresolved. G4 has 79 parsing/selection tests plus targeted diagnostic evidence, **not full implementation readiness**. G0 and G5 remain blocked on authoritative selection and review. See the [mismatch ledger](SVE_mismatch_ledger.md) for suggested owners and specific closure evidence. No finding is silently waived and no unapproved release model is published.