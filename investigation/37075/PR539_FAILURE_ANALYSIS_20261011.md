# PR539 Failure Analysis

Investigation of the completed hardware matrix, including smokes, setup blocks,
early exits, pre-PR controls, and retained tooling failures. Original results and
sealed archives are unchanged. The original investigation made no production
changes; current dispositions below account for subsequent PR fixes as of
2026-10-16. **Addressed** means the identified defect has a corresponding fix,
not that its PR is merged or every related hardware symptom is resolved.

PR: `9dccf415b4019ba2db94d04f9199d27ae4477602`.
Baseline: `39388edd3608cf95563904b04d6d13a0300e8ffc`.
The original accounting remains in
[PR539_HARDWARE_VALIDATION_20261011.md](PR539_HARDWARE_VALIDATION_20261011.md).

## Classification

"Our test setup" means fixture state, host services, launching, capture, and
missing prerequisites. "Pre-existing" includes defects in the existing QA tests
and installed controller/DUT stack, not just product defects. Labels are likely
attributions, not claims that every underlying cause has been proved.

| Likely Category | Campaign FAIL | Smoke FAIL | Additional Findings |
| --- | ---: | ---: | --- |
| Flaw in the PR | 0 | 0 | One CPU-reproduced BLE-to-IP prerequisite defect; hardware coverage missing |
| Flaw in our test setup | 40 | 4 | Four zero-outcome setup blocks; historical launcher/capture issues |
| Pre-existing flaw | 30 | 5 | Three PR SIGSEGV exits; two early multi-admin exits |
| Total recorded FAIL | 70 | 9 | Missing iterations are not FAIL outcomes |

Of the 35 likely pre-existing recorded failures, 32 have strong concrete
test-logic evidence. The other three are concurrent-read timeouts followed by
cleanup timeouts, classified provisionally with low confidence. There is no
matched hardware multi-admin baseline. Zero observed PR-attributed hardware
failures does not mean zero PR defects or a passing merge gate.

| Failure Family | Campaign FAIL | Smoke FAIL | Likely Category | Confidence |
| --- | ---: | ---: | --- | --- |
| PASE Incorrect state, Ubuntu -> Nordic | 30 | 3 | Test setup | High for fixture attribution; BlueZ/native root unresolved |
| BLE discovery returns no device, Ubuntu -> Nordic | 10 | 1 | Test setup | High for fixture attribution; error is masked by scanner |
| Bulk write verification | 15 | 2 | Pre-existing QA flaw | High |
| Multi-admin cross-controller read mismatch | 7 | 1 | Pre-existing QA flaw | High |
| Multi-admin subscription verification | 6 | 1 | Pre-existing QA flaw | High |
| Multi-admin read timeout followed by cleanup timeout | 2 | 1 | Pre-existing stack/test interaction, provisional | Low |

## Current Failure Dispositions

Reconciled on 2026-10-16 against the published PR descriptions and follow-up
evidence. **ADDRESSED** closes the identified code defect, not the historical
FAIL outcome, PR merge gate, or every similar symptom. Historical pins and
counts below remain unchanged. Only the remaining-work column is the backlog.

| Failure / Defect | Disposition And Fix | Remaining Work / Evidence Limit |
| --- | --- | --- |
| IP readiness required before unprovisioned BLE; wrong secondary-window discriminator | **ADDRESSED**: [QA539](https://github.com/CHIP-Specifications/matter-qa/pull/539); 36 readiness tests and 22 passing unprovisioned BLE-Wi-Fi outcomes | Disconnected SSH-reset integration remains outside the tested workflow. |
| Valve DefaultOpenLevel ignores live LevelStep | **ADDRESSED**: [QA547](https://github.com/CHIP-Specifications/matter-qa/pull/547); eight tests and 11 passing bulk smoke/campaign outcomes | Do not ignore arbitrary ConstraintError responses; invalid positive-write generation is the corrected defect. |
| RT_1_2 equates metadata, fabric-specific state and changing observations | **ADDRESSED**: [QA548](https://github.com/CHIP-Specifications/matter-qa/pull/548), head `a550450`; 105 CPU tests and a bounded two-controller smoke with 29 successful fresh-readback attributes per response | Full-load reliability remains open: matched upstream and combined-PR runs still fail before comparison. This is not a fix for native ReadClient timeouts. |
| Registered ctypes callbacks can be collected; error paths leave callbacks active | **ADDRESSED**: [QA549](https://github.com/CHIP-Specifications/matter-qa/pull/549); six lifetime tests and 11 passing outcomes combined with QA550 | Historical SIGSEGV causality remains **OPEN** without a native crash backtrace. |
| RT_2_1 selects SecurePairing callbacks that never fire; reset failures accepted as expected pairing failures | **ADDRESSED**: [QA550](https://github.com/CHIP-Specifications/matter-qa/pull/550), head `2b0feed`; nine stage/reset tests and 11 passing outcomes combined with QA549 | Land with or after QA549. Earlier start-only and interrupted attempts are not final-fix validation. |
| Arithmetic XML bounds fail during payload construction | **ADDRESSED**: [QA544](https://github.com/CHIP-Specifications/matter-qa/pull/544); nine parser/generator tests | Full hardware matrix not rerun; this is not a DUT write-error fix or the Valve LevelStep fix. |
| Nordic adapter reports reset/reboot success after rejected commands or fixed sleeps | **ADDRESSED**: [QA545](https://github.com/CHIP-Specifications/matter-qa/pull/545); 11 UART/reset tests, fresh boot/advertising evidence required | Corrected-firmware successful reset verification remains pending. This does not request a reset when a selected callback never fires. |
| Partial failures leak fabrics, subscriptions or sessions; cleanup masks the original failure | **ADDRESSED**: [QA527](https://github.com/CHIP-Specifications/matter-qa/pull/527); 52 cleanup regressions | Expanded hardware coverage remains pending; unreachable remote fabrics cannot be guaranteed removed. Original read/subscription timeouts remain open. |
| BLE scanner hides native errors or retains local scan state after stop failure | **ADDRESSED**: [SDK74676](https://github.com/project-chip/connectedhomeip/pull/74676), head `6ebed18`; 59 ordinary tests, nine isolated native regressions and a [successful macOS native lifetime test step](https://github.com/project-chip/connectedhomeip/actions/runs/38905295778/job/116987956577) | BlueZ may still be scanning after a failed stop. Local lifecycle/error handling is fixed, not daemon recovery or original PASE causality. |
| Ubuntu BLE PASE Incorrect state / original BlueZ failure | **PARTIALLY ADDRESSED**: scanner diagnostics/lifecycle above; wrong adapter selection corrected in the fixture | **OPEN**: original native/BlueZ root cause and recovery guarantees. A later passing fixture is not a causal proof. |
| Genuine concurrent ReadClient or subscription-report timeouts | **OPEN** | Diagnose independently of invalid comparisons and secondary cleanup errors; reduced-cohort success does not clear the original load. |
| Historical SIGSEGV in RT_2_1 | **PARTIALLY ADDRESSED**: the demonstrated callback ownership defect is fixed above | **OPEN**: establish the historical crash cause rather than assuming callback retention explains every exit -11. |
| PR528 Ubuntu iteration 36: first-fabric SubscribeRequest INVALID_ACTION | **OPEN**: [separate validation](PR528_UBUNTU_PI_NORDIC_VALIDATION_20261007.md) records matching dataset/identity and preserves the primary error | No established matching fix or packet-loss attribution. Topology validation and cleanup do not establish a subscription-delivery correction. |
| Immediate revoked-window readiness accepted a cached open record | **RETAINED DESIGN LIMITATION**: the [later passive gate](PR539_PI_NORDIC_VALIDATION_20261007.md#review-driven-revision-2026-10-09-utc) intentionally permits cached matching advertisements | Actual commissioning performs authentication. Earlier live-PASE probe passes do not prove instantaneous freshness of the current passive prerequisite; a stronger freshness guarantee is not implemented or promised. |

The [readiness/follow-up validation](PR539_BLE_READINESS_FIX_VALIDATION_20261011.md)
and [iteration accounting](PR539_ITERATION_ACCOUNTING_20261013.md) preserve the
original outcomes. The [later SDK matrix](SDK74676_HARDWARE_MATRIX_20261013.md)
tracks distinct native PASE, read, subscription and capture failures. None of
these fixes establishes that the original issue #37075 missing CASE response
after AddNOC is solved.

## PR Flaw: Addressed

**Unprovisioned BLE-Wi-Fi can be blocked by an IP-discovery prerequisite.**

**Status: ADDRESSED** by
[QA PR539](https://github.com/CHIP-Specifications/matter-qa/pull/539), published
head `b99759a62df56be3f5d5c5dd9505db0eb3760f58`. Transport-aware readiness
removes the IP prerequisite before BLE and uses the actual window discriminator
for subsequent IP pairing. The
[follow-up validation](PR539_BLE_READINESS_FIX_VALIDATION_20261011.md)
records 36 readiness tests on both controller architectures and 22 passing
unprovisioned BLE-Wi-Fi smoke/cycle outcomes. The original diagnosis follows.

After a Raspi reset, `Raspi.wait_for_commissioning_ready` requires an open
commissionable DNS-SD record with an address. `MatterQABaseTestCaseClass.pair_dut`
awaits that hook before delegating to the commissioner, regardless of
commissioning method. A BLE-advertising device without IP connectivity can
therefore time out before BLE commissioning supplies its network credentials.

The existing six-scenario CPU probe confirms zero commissioner calls for
`ble-wifi` without an IP advertisement and one call with an advertisement.
This investigation independently reproduced the readiness failure from the
exported async method. This behavior is introduced by the PR; it is not the
cause of the observed Ubuntu -> Nordic failures, whose Nordic readiness hook
is a no-op. The Pi DUT matrix used on-network commissioning with BLE disabled.

**Remaining coverage limit:** the focused unprovisioned BLE-Wi-Fi workflow now
passes, but does not cover SSH resets while the DUT is disconnected. That limit
does not reopen the corrected IP-before-BLE prerequisite defect.

## Likely Setup Flaws

### Ubuntu BLE fixture

All 40 Ubuntu -> Nordic campaign failures and four failed smokes share an
earlier BlueZ `StopDiscovery` failure with `org.bluez.Error.InProgress`.
The PASE paths finish with `Incorrect state`; the direct BLE scanner finishes
with `No Matter Device found`. They are distinct final exceptions, not two
unrelated hardware diagnoses.

The installed scanner's `OnScanError` discards the error code and signals normal
completion. This explains why the discovery test reports an empty result instead
of the preceding native scan error. It does not prove which component caused
the original BlueZ error. The original pre-PR Ubuntu -> Nordic commissioning
control also failed 0/10 with the same signature. All retained capture segments
for that original fixture lack controller BLE ACL traffic; Pi1 -> Nordic
commissioning passes.

The four zero-outcome smokes, `TC_RT_1_2`, bulk read/write, `TC_ON_OFF`, and
`TC_LEVEL_CONTROL`, fail initial pairing with the same BlueZ/PASE signature.
Their ten-iteration campaigns were not launched: 40 target slots remain
unexecuted, not 40 additional failures.

After the single bounded Bluetooth restart, a separate baseline smoke and all
ten baseline iterations still failed, but now with `BLE adapter unavailable`
despite BlueZ reporting a powered adapter. Preserve that as a separate recovery
signature, not proof that `InProgress` persisted unchanged. Adapter enumeration,
SDK adapter selection, and BlueZ ownership require a controlled fixture check;
neither another blind restart nor a PR readiness change is justified by this
evidence alone.

### Historical launcher and capture issues

- Preserved initial Ubuntu -> Pi smoke: Fabric/Invoke stdin handling raised
  `OSError: [Errno 25] Inappropriate ioctl for device`. It recorded no iteration.
  Non-interactive stdin repaired the launcher; the final commissioning cell is
  10/10. This is not a PR protocol failure.
- SSH alias/strict-host-key mismatch, an incorrect private manual setup code,
  and embedded remote Python newline quoting were preparation errors repaired
  before the affected final runs. Do not classify their retries as DUT failures.
- The capture validator rejected a full ring using a strict less-than boundary.
  Separate reconciliation proves original files 1 through 16 were retained and
  readable. Preserve the initial rejection; it is not evidence of packet loss.
- Resume initially hit existing relay-log paths. Prior owned logs were archived
  rather than overwritten. This was a supervisor restart defect, not a new test
  outcome.
- Missing counters and baseline/smoke accounting errors were reporting defects
  corrected separately. Unknown traffic counters are not zero traffic.
- Ubuntu's `cpptools` OOM kill is a host-resource caveat, not an observed QA
  process kill. Missing Pi kernel entries and unauthenticated packet decoding
  limit evidence; neither establishes a clean kernel or a protocol failure.

## Likely Pre-Existing Flaws

### Valve writes: 21 campaign failures and three failed smokes

This combines the 15 bulk and six multi-admin subscription campaign failures.
Every one identifies exactly the same path:
`EP1 ValveConfigurationAndControl.DefaultOpenLevel`, write status
`ConstraintError`. There are **zero genuine value mismatches** in these
verification summaries. Multi-admin counts the same rejected write once per
controller, producing the messages about four or fifteen failed attributes.

Every retained failed iteration generated an odd `DefaultOpenLevel`. The Pi
fixture reports `LevelStep=2`; the pinned SDK checks divisibility by LevelStep.
For example, the Ubuntu -> Pi bulk first iteration generates 11 and receives
`ConstraintError`, while the DUT reports step 2. Nordic failed values include
97 and 95; a successful write uses 14. These are not generally out-of-range
percentages: missing step-constraint handling is the likely generator flaw.
Where the individual log lacks a decoded step value, the ledger records it as
unavailable, not inferred.

`AttributeValueVerifier` labels the rejected write skipped, but
`AugmentedMatterTestBase._get_failed_verifications` excludes only `KNOWN_ISSUE`
skips. It counts the `CONSTRAINT_ERROR` skip as failure and the caller reports
it as a value mismatch. A CPU probe reproduces that exact predicate. This is
both a generation/constraint problem and a misleading failure diagnosis; it
is not a reason to ignore all failed writes indiscriminately.

The deciding generator, verifier, constraint registry, and caller are identical
between exports. Bulk baseline campaigns reproduce ten such failures, plus two
failed baseline smokes. Random even/odd generated values explain the observed
pass-rate differences much better than a readiness regression; the sample is
not a randomized comparison proving a performance difference.

**Next change:** generate step-compliant values for positive writes, and keep
explicit negative ConstraintError tests separate from successful readback checks.

### Cross-controller comparisons: seven campaign failures and one failed smoke

The comparator requires equality of complete read results across fabrics and
separately executed reads. Every recorded mismatch names either
`Identify.DataVersion` or `ScenesManagement.FabricSceneInfo`.

On Nordic, five campaign iterations include different fabric scene records;
three include Identify data-version differences, with two iterations containing
both. The Ubuntu -> Pi campaign mismatch and Nordic smoke mismatch are
Identify data versions. The scene records differ in `fabricIndex`, and Identify
versions can advance while its timer changes. Whole-record equality is not a
valid universal assertion here. Minimal CPU records reproduce both failures,
with an identical-input positive control that compares equal.

This is an unchanged test predicate with concrete false-positive evidence,
not attribution based only on equal source files. The controller endpoint map
also has a separate pre-existing aliasing defect: one deep copy is assigned to
every controller. That undermines independent subscription verification but
does not explain the actual recorded constraint skips by itself.

**Next change:** compare appropriate stable/non-fabric-scoped attributes and
maintain independent controller maps; do not blanket-ignore all read differences.

### Concurrent-read timeout then cleanup timeout: two campaign failures, one smoke

All three affected Pi-DUT iterations report 15 concurrent read operations
failing with `ReadClient` timeouts before attempting unpairing. Cleanup then
times out too and raises `TestCaseExit`, replacing the primary error in the
final iteration summary. The two campaigns stop after four and one outcomes,
leaving six and nine iterations unexecuted.

These are real operation failures, not the false equality checks above. The
workload runs all 15 secondary controllers concurrently, alongside wildcard
subscriptions and verbose traces. Missing Python schemas for a vendor cluster
also appear repeatedly, but their causal contribution is unproved. Existing
controller/DUT limits, report processing, and host load are plausible causes.
PR readiness is once-per-reset and already complete before this phase, making
an existing stack/test interaction the best provisional category, not a proof.

**Next deciding check:** matched baseline multi-admin with the same controller
count, then reduce concurrency/subscriptions/trace volume one factor at a time.
Preserve the primary exception independently of cleanup. Do not simply extend
timeouts and declare the behavior fixed.

### Native discovery crashes: three PR campaigns

Ubuntu -> Pi, Pi1 -> Pi, and Pi1 -> Nordic `TC_RT_2_1` campaigns each record one
PASS then exit `-11` (SIGSEGV), leaving nine iterations each unexecuted. The
Ubuntu -> Pi baseline reproduces the same one-PASS/exit-11 behavior.

`factory_rest_during_commissioning` retains its initial ctypes callbacks but
replaces them with local `_noop_complete` or `_noop_start` callbacks. The SDK
setters retain only native callback pointers, not the Python callback objects.
The CPU probe calls the actual extracted setter methods and confirms callback
garbage collection after dropping the local reference. No stale pointer is
invoked by that probe.

The baseline is strong evidence that the crash does not require PR539. The
callback lifetime defect is a plausible specific cause, **not a proven crash
backtrace**. Ubuntu kernel evidence is temporally consistent with one crash;
Pi backtraces are unavailable.

**Next deciding check:** capture a native backtrace and retain no-op callbacks
through controller shutdown in an isolated diagnostic variant. Do not alter the
production PR as part of this attribution report.

## Every PR Failed Iteration

`Bulk` means `TC_Send_Command_Read_Write_Attributes`. Smoke failures are listed
separately below. The private ledger contains the canonical log path and line
numbers for each individual outcome, including all baseline/recovery failures.

| Fixture / Case | Failed Campaign Iterations | Deciding Signature |
| --- | --- | --- |
| Ubuntu -> Nordic / RT1_1 | 1-10 | BlueZ/PASE |
| Ubuntu -> Nordic / Darwin | 1-10 | BlueZ/PASE |
| Ubuntu -> Nordic / Android | 1-10 | BlueZ/PASE |
| Ubuntu -> Nordic / RT2_1 | 1-10 | BlueZ/empty BLE discovery |
| Ubuntu -> Pi / Bulk | 1, 3 | Valve ConstraintError |
| Pi1 -> Pi / Bulk | 1, 4, 6, 9 | Valve ConstraintError |
| Pi1 -> Nordic / Bulk | 1, 3-10 | Valve ConstraintError |
| Ubuntu -> Pi / RT1_2 | 1, 3 | Valve ConstraintError, repeated across 15 controllers |
| Ubuntu -> Pi / RT1_2 | 2 | Identify DataVersion |
| Ubuntu -> Pi / RT1_2 | 4 | Concurrent read then cleanup timeout |
| Pi1 -> Pi / RT1_2 | 1 | Concurrent read then cleanup timeout |
| Pi1 -> Nordic / RT1_2 | 1, 2, 3, 4, 6, 10 | Identify DataVersion or fabric scene records |
| Pi1 -> Nordic / RT1_2 | 5, 7, 8, 9 | Valve ConstraintError, repeated across four controllers |

The nine smoke failures are: Ubuntu -> Nordic RT1_1/Darwin/Android (three
PASE), Ubuntu -> Nordic RT2_1 (one BLE discovery), Pi1 -> Nordic RT1_2 (one
DataVersion), Pi1 -> Pi RT1_2 (one Valve), Ubuntu -> Pi RT1_2 (one read/cleanup
timeout), and Pi1 -> Pi plus Pi1 -> Nordic Bulk (two Valve).

The three crashes account for 27 missing campaign iterations; the two
multi-admin exits account for 15. Together with the 40 setup-blocked campaign
slots, these reconcile all 82 unexecuted target slots without inventing failures.

## Evidence And Verification

Private additive investigation artifacts reside under
`/home/feasel/qa-mar6/pr539-full-testing-20261011`:

- The classified JSON ledger contains 113 failed native outcomes: 79 PR,
  23 original baseline, and 11 separate recovery baseline. Every key is unique
  by run and iteration, and every outcome has a canonical controller log.
- Eleven distinct incomplete-process incidents: nine original PR (four setup,
  three crashes, two early exits), one baseline crash, one preserved ENOTTY
  setup failure. Early exits overlap existing failure outcomes and are not
  added to the FAIL totals.
- Five CPU mechanism probes pass: data-version comparison, fabric-scene
  comparison, constraint skip counted as failure, callback non-retention,
  BLE-Wi-Fi reset requiring IP. These extract actual methods but use minimal
  CPU fixtures; they are not physical reproductions or crash backtraces.
- Exhaustive ledger checks pass, including the precise failed Valve path,
  ConstraintError status, zero mismatch summaries, odd generated values,
  available LevelStep values, primary timeout errors, and counts of all
  crashes/setup blocks/early exits.
- The PR worktree remains clean. Original archives, raw logs, packet captures,
  private storage, and earlier failed diagnostic evidence were not rewritten.

The investigation establishes concrete existing test defects and a PR-specific
transport risk. It does not establish the underlying Ubuntu BlueZ cause or
the multi-admin timeout root cause, nor certify unprovisioned BLE-Wi-Fi,
authenticated packet decoding, or complete execution of the hardware matrix.