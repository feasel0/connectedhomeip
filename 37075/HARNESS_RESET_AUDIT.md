# Issue #37075 harness and reset methodology audit

Date: 2026-09-21

## Conclusion

The local 100-iteration `TC_Darwin_Pair` campaign used one native matter-qa
process and one in-process 100-iteration loop. It was not a shell loop or 100
separate Python invocations. Its core orchestration matches the retained
January 28, 2025 stress-team evidence:

- one long-lived Matter stack and controller process;
- one second controller created before the iteration loop;
- a randomized first-fabric DUT node ID on every iteration;
- a second-fabric DUT node ID derived once from the initial default node ID;
- two `matter device factoryreset` writes per configured reset;
- a fixed five-second sleep after each write;
- no positive reboot, BLE-advertising, Thread-detach, or factory-state readiness
  check before PASE;
- subscriptions shut down and both fabrics/sessions cleaned up in the normal
  success path; and
- iteration failures handled inside the native loop rather than by restarting
  Python.

The implementations are not byte-for-byte identical. The current harness adds
an extra ten-second wait after the pre-loop reset, a two-second delay before
successful unpair cleanup, and a configured five-second inter-iteration delay.
It also has stronger controller-session cleanup. These differences should be
recorded, but none changes the critical reset-to-next-PASE behavior: after the
second reset command, both the retained January run and the local run begin
PASE after the adapter's fixed five-second sleep with no readiness probe.

The largest difference relevant to the exact issue signature is environmental,
not orchestration: the local DUT stayed on one isolated Thread partition with a
reachable SRP server, while the retained October failures joined unintended
partitions without an SRP server and could not publish an operational record.

Decision: a native 500-iteration local campaign is justified as additional
controlled evidence. It must use the current unmodified matter-qa reset and
readiness behavior. A clean 500-run cannot prove that the historical
multi-partition condition is fixed; it shows behavior on the isolated local
Thread topology.

## Historical source provenance

Issue #37075 pins connectedhomeip commit
[`f8d457a446456d5df1e750e728ea48e8fce9d989`](https://github.com/project-chip/connectedhomeip/commit/f8d457a446456d5df1e750e728ea48e8fce9d989),
dated January 7, 2025. It does not pin a matter-qa commit.

Two historical matter-qa snapshots are therefore useful:

1. [`a58ef457f574caddef44355d30d970f614616597`](https://github.com/CHIP-Specifications/matter-qa/commit/a58ef457f574caddef44355d30d970f614616597)
   is the latest repository commit before the original January 7 controller
   log timestamp. The next reset-related commits occurred after that run.
2. [`68159a64265fe42d539e966baa55a0df1dbce585`](https://github.com/CHIP-Specifications/matter-qa/commit/68159a64265fe42d539e966baa55a0df1dbce585)
   is the closest clean snapshot matching the retained January 28 traceback:
   its second-fabric `CommissioningComplete` is at `TC_Darwin_Pair.py:204`.

The January 28 artifact is not sufficient to prove one exact clean matter-qa
SHA. Its traceback loads the test script from
`/home/ubuntu/stress_test/matter-qa`, while helpers load from a Python 3.12
installed egg under a different connectedhomeip tree. Runtime timestamps also
show no random post-iteration delay, matching the base-class behavior after
commit
[`6f1b2ebedaefec9b73c491c9d76866248419a9cf`](https://github.com/CHIP-Specifications/matter-qa/commit/6f1b2ebedaefec9b73c491c9d76866248419a9cf),
although the test-script line number matches the earlier snapshot. Historical
claims below use source plus observed logs and do not claim a stronger SHA
provenance than the evidence permits.

The local campaign used matter-qa commit
[`9e878e38f8cfc75e77d928445a06ec0f5d068da9`](https://github.com/CHIP-Specifications/matter-qa/commit/9e878e38f8cfc75e77d928445a06ec0f5d068da9).

## Proof that the local 100-run was one native process

The recovered launch command invoked `TC_Darwin_Pair.py` once, with the
100-iteration YAML supplied through `reliability_tests_arg`. It did not wrap the
test in a shell loop.

The persisted evidence agrees:

- [test_summary.yaml](logs/stress-darwin-pair-100/MatterTest/ble-thread/09-21-2026_10-08-13-523/test_summary.yaml)
  contains one `test_TC_Darwin_Pair` Mobly record and one summary with 100
  requested, 100 executed, 100 passed, and zero failed.
- [summary.json](logs/stress-darwin-pair-100/MatterTest/ble-thread/09-21-2026_10-08-13-523/TC_Darwin_Pair/summary.json)
  contains one `run_set_id` and exactly 100 iteration records, numbered 1
  through 100.
- [test_log.INFO](logs/stress-darwin-pair-100/MatterTest/ble-thread/09-21-2026_10-08-13-523/test_log.INFO)
  contains one `Starting test set`, one test-method execution, 100 iteration
  starts, and one final test-class summary.
- The run log has 101 occurrences each of `Starting to Reset Nordic as the DUT
  1` and `... DUT 2`: one two-write pre-loop reset plus one two-write reset for
  each of 100 inner iterations. A 100-process wrapper would have repeated the
  pre-loop lifecycle 100 times instead.
- One controller storage file remained open for the run, and the Matter stack
  shutdown only after iteration 100.

The current source implements this structure directly: one
`test_TC_Darwin_Pair()` method creates TH2 once and calls a nested function
decorated by `iterate_tc()`. The decorator loops from 1 through the configured
iteration count in the same process.

## Reset ordering and readiness

### Retained January 28 evidence

The best-fit historical script resets once before the loop and again at the
start of every iteration. The Nordic adapter loops twice, sends the configured
factory-reset command, and sleeps five seconds after each send. It does not
inspect serial output or wait for a boot/readiness condition.

The retained iteration-1 controller log directly records:

- iteration start: `11:55:57.740`;
- reset send 1: `11:55:57.745`;
- reset send 2: `11:56:02.746`;
- reset helper complete: `11:56:07.748`; and
- PASE attempt: `11:56:09.005`.

Each inspected retained iteration has exactly one `DUT 1`, one `DUT 2`, and one
`Reset Completed` marker. Adjacent retained iteration records begin only about
35–49 ms after the previous record ends, corroborating the absence of a
separate inter-iteration sleep in that runtime.

### Local 100-run

The current Nordic adapter has the same two-write/five-seconds-per-write
behavior and the same lack of readiness validation. Local iteration 1 records:

- iteration start and reset send 1: `10:08:38.994/995`;
- reset send 2: `10:08:43.996`;
- reset helper complete: `10:08:48.997`; and
- PASE attempt: `10:08:50.267`.

Current successful iteration ordering is:

1. shut down both subscriptions;
2. leave the CASE context;
3. wait the configured two seconds;
4. remove both commissioned fabrics and expire both controller sessions;
5. close BLE and mark the iteration passed;
6. wait the configured five seconds;
7. start the next iteration and issue two factory-reset commands, five seconds
   apart; and
8. begin PASE without a positive readiness check.

The configured `kernel reboot` command is not used on this path. The nRF Matter
shell factory-reset command itself erases persistent Matter/Thread state and
reboots the device.

### Original January 7 flow

The source closest to the original issue log used the same single-process inner
loop and the same Nordic two-write/five-second reset implementation. On a
successful iteration it performed unpair/session cleanup, then reset at the end
of the iteration, followed by a random 0–10 second delay. On a failed PASE or
CASE path it also invoked the same factory-reset helper. Thus the reset was at
the iteration boundary rather than the beginning of the next body. The January
8 `d0d9892` change introduced the configurable reset-at-iteration-start pattern
seen in the retained January 28 evidence and in the current run.

## Default-node `0x12344321` lookup

The local lookup is a current connectedhomeip test-framework side effect, not a
matter-qa iteration lookup:

1. No DUT node ID was supplied on the command line, so the framework initially
   used `0x12344321`.
2. Before the sole Mobly test method, `MatterBaseTest.setup_test()` called
   `_capture_dut_baseline()`.
3. Because commissioning was configured, baseline capture called
   `GetConnectedDevice(..., allowPASE=False, timeoutMs=5000)` for that default
   node.
4. The Python call stopped waiting after five seconds, while the native address
   resolver remained alive until its 45-second timeout.
5. The inner test later replaced the first-fabric DUT node ID with a random
   value. The stale default-node resolution expired while iteration 1 was
   running.

This happens once per Mobly test method, not once per matter-qa iteration. The
100-run contains one such lookup and no later occurrence. Both actual DUT
lookups succeeded.

The issue-pinned connectedhomeip revision predates baseline capture. Its
`setup_test()` only resets framework state and starts runner bookkeeping. Git
history attributes `_capture_dut_baseline()` to August 11, 2026 commit
[`186ba3fd686a`](https://github.com/project-chip/connectedhomeip/commit/186ba3fd686a).
The issue-era framework did create a lazy wildcard-read awaitable for the
default node in `setup_class()`, but `TC_Darwin_Pair` did not await a guard that
would execute it before replacing the node ID. The local default-node timeout
is therefore a new framework artifact and not historical issue behavior.

## Methodology comparison

| Dimension | Stress-team evidence | Local 100-run | Assessment |
| --- | --- | --- | --- |
| Controller host | Raspberry Pi 4B for BLE-Thread in the issue body; retained January paths show Ubuntu | Ubuntu laptop | Probably immaterial |
| Python | Retained January traceback shows Python 3.12 | Python 3.13.15 | Probably immaterial |
| connectedhomeip | `f8d457a446456d5df1e750e728ea48e8fce9d989` | Current workspace/controller build | Potentially significant because fixes may have landed |
| matter-qa | Exact SHA not recorded; January 28 behavior is bounded by `68159a`/`6f1b2eb` | `9e878e38f8cfc75e77d928445a06ec0f5d068da9` | Potentially significant, but directly audited |
| DUT | Nordic nRF52840 DK all-clusters | Nordic nRF52840 DK all-clusters | Essentially equivalent hardware |
| Provisioning | BLE-Thread | BLE-Thread over laptop `hci0` | Essentially equivalent |
| Native orchestration | One Python/Mobly test with an inner iteration loop | One Python/Mobly test with an inner iteration loop | Same |
| Python/storage lifetime | Persistent across iterations | Persistent across all 100 iterations | Same |
| First-fabric DUT node ID | Randomized per iteration | Randomized per iteration | Same |
| Second-fabric DUT node ID | Derived once before the loop | Derived once before the loop | Same |
| Reset command | `matter device factoryreset` | `matter device factoryreset` | Same |
| Reset writes | Two writes per adapter reset call | Two writes per adapter reset call | Same |
| Reset-to-PASE gate | Fixed five seconds after the second write; no readiness probe | Fixed five seconds after the second write; no readiness probe | Same |
| Reset placement | Original January 7: previous-iteration end; January 28: next-iteration start | Next-iteration start | Same as retained January 28; equivalent boundary operation to original run |
| Extra waits | January 28 runtime had no separate inter-iteration wait | Two seconds before cleanup, then five seconds before next iteration | Potentially significant for timing-sensitive cleanup; does not add post-reset readiness |
| Normal cleanup | January 28 removed both fabrics and expired both sessions | Removes both tracked fabrics and expires both sessions | Essentially equivalent |
| Failure cleanup | Historical code attempted cleanup/reset and continued on `ReliabiltyTestError` | Attempts cleanup and continues on `ReliabiltyTestError`; identical-failure limit disabled | Essentially equivalent |
| Baseline default-node lookup | Absent from issue-pinned framework | Once before the test body for `0x12344321` | Probably immaterial noise; can overlap iteration 1 |
| OTBR/RCP | Exact hardware/version not recorded | Local OTBR with dedicated nRF52840 Dongle RCP | Potentially significant |
| Thread isolation | Historical exact failures joined unintended partitions | Dedicated `Matter37075` network; one stable partition in 100/100 | Very significant to the exact failure mechanism |
| Dataset/SRP | Exact historical configuration unknown; failed October iterations had no SRP server | Dataset recorded; same SRP server found in 100/100 | Very significant to the exact failure mechanism |
| Security test mode | Not stated and no runtime marker in retained logs | Enabled and proved in PASE plus both CASE paths | Probably immaterial to the observed partition/publication failure |
| Packet capture | January retained run captured controller traffic; later evidence includes OTBR capture | Disabled for the local 100-run | Affects diagnostic strength, probably not behavior |
| Iteration count | Issue requested 500; retained runs include 100-iteration campaigns | 100 completed; 500 planned | Local sample was smaller |

## 500-iteration campaign controls

Use [matter-qa-nordic-500.yaml](matter-qa-nordic-500.yaml), fresh controller
storage, and a new log root. Do not modify matter-qa, add readiness probes,
restart Python between iterations, or externally reset the DUT. Keep
`max_consecutive_identical_failure_attempts: 0` so recoverable iteration
failures remain recorded and the native loop continues.

The run should be stopped only for an unrecoverable process, hardware, serial,
Bluetooth, or OTBR failure. Preserve the complete console, summary,
per-iteration controller logs, DUT logs, and storage file for after-action
analysis.

## Campaign launch record

Preflight completed on September 21, 2026:

- the 500-run YAML was semantically identical to the 100-run baseline except
  for `number_of_iterations: 500`;
- the nRF52840 DK and nRF52840 Dongle RCP were present at their stable USB
  paths;
- no other test process or host process held the DUT serial port;
- Bluetooth controller index 0 was powered, unblocked, and LE-capable;
- `otbr-37075` was running as Thread leader on the exact expected 107-byte
  active dataset;
- the OTBR SRP server was running and the expected server address
  `fd97:3da1:29:8106:f251:c7ca:ee09:d27a` was assigned;
- no conflicting `TC_Darwin_Pair` or matter-qa process was running; and
- 240 GB was free on the workspace filesystem.

One corrected native campaign process started at `2026-09-21 15:05:16 -04:00`
with:

- `--timeout 72000` (20 hours);
- fresh storage `37075/admin-darwin-pair-500.json`;
- fresh logs under `37075/logs/stress-darwin-pair-500`;
- `--ble-controller 0`;
- the asserted OTBR active dataset; and
- `37075/matter-qa-nordic-500.yaml` as `reliability_tests_arg`.

Startup evidence records one test set, one `test_TC_Darwin_Pair` method, the
expected one-time `0x12344321` baseline lookup, the pre-loop two-command reset,
creation of TH2, and the start of native iteration 1. The process remains the
sole owner of the campaign; no external iteration or reset loop is in use.

An earlier command-line attempt was rejected by `argparse` before Matter test
setup because its manually transcribed dataset contained an extra hex segment.
It performed no DUT reset, BLE operation, or test iteration. Its parser-only
console is preserved separately under
`37075/logs/stress-darwin-pair-500-prelaunch-invalid-dataset-20260921T1506`;
the corrected launch asserts both the active-dataset equality and the expected
107-byte length before invoking Python.

## Production OTBR and dataset path investigation

The public source proves two distinct production paths. They must not be
conflated when attributing a particular failure.

### Direct matter-qa Jenkins path

The Nordic Jenkins library reads
`testConfigs.network_config.thread_dataset` and passes that value unchanged as
`--thread-dataset-hex`. It warns rather than failing when the value is absent.
It does not start OTBR, call `dataset init new`, read the live active dataset,
or verify that the configured value matches the running border router.

The retained October controller logs use Jenkins workspace paths and show one
constant command-line dataset throughout the inner stress loop. This proves
that OTBR dataset generation did not occur once per `TC_Darwin_Pair` iteration.
It does not prove where the Jenkins configuration value was originally
generated or whether the border router was independently restarted while the
controller retained state.

### Test Harness adapter path

The current matter-qa Test Harness adapter delegates pairing argument creation
to certification-tool-backend's `generate_command_arguments()`. For
`ThreadExternalConfig`, it forwards `operational_dataset_hex`. For
`ThreadAutoConfig`, it uses an explicitly configured
`operational_dataset_hex` if present; otherwise it starts a
`ThreadBorderRouter`, forms a network, reads `dataset active -x`, and passes the
complete returned dataset to matter-qa.

The normal certification-tool Python suite starts/forms OTBR once during suite
setup and destroys it during suite cleanup. The matter-qa adapter can instead
start it lazily while building test arguments. In both cases the inner
100/500-iteration matter-qa loop receives one dataset; OTBR is not recreated by
each inner iteration. A later suite or backend lifecycle can recreate it.

### Current auto-configuration behavior

Current certification-tool-backend source forms the network with:

1. `dataset init new`;
2. fixed channel;
3. fixed PAN ID;
4. fixed Extended PAN ID;
5. fixed Network Key;
6. fixed Network Name; and
7. `dataset commit active`.

Its `ThreadDataset` schema exposes only those five overridden fields. It does
not expose or restore Mesh-Local Prefix, PSKc, Security Policy, or timestamps.
Consequently, repeated creation from the same visible configuration does not
guarantee a byte-identical complete Active Operational Dataset. The manual
`otbr_start.sh` path has the same `dataset init new` plus partial-override
pattern and uses a well-known Network Key.

The controller is nevertheless internally consistent with the newly formed
OTBR during one suite because the backend reads the final complete
`dataset active -x` and supplies those exact bytes. The risk appears across
OTBR/suite recreation, controller-state reuse, or RF-visible neighboring
fixtures sharing credentials—not from a dataset mismatch created inside one
matter-qa iteration.

### Prior exact reproduction and reverted fix

Certification-tool-backend commit
[`25fd46c6179d87a5d0e2a28787645c02d395e663`](https://github.com/project-chip/certification-tool-backend/commit/25fd46c6179d87a5d0e2a28787645c02d395e663)
records an independent exact reproduction:

- a first Test Harness Python test passed;
- suite teardown/restart recreated OTBR;
- previous commissioning information was reused; and
- the next run failed with CASE timeout,
  `AddressResolve_DefaultImpl.cpp:124`, and CHIP timeout `0x32`.

That commit attributed the failure to `dataset init new` randomizing the
Mesh-Local Prefix while only the five visible fields were pinned. It attempted
to derive a stable prefix from Extended PAN ID in both the managed and manual
OTBR paths. Commit
[`aa173d3a7d532a48e793feb726690c863d9759f3`](https://github.com/project-chip/certification-tool-backend/commit/aa173d3a7d532a48e793feb726690c863d9759f3)
reverted the change 27 minutes later.

The public revert message only says that it reverts the prior commit. PR
[#348](https://github.com/project-chip/certification-tool-backend/pull/348), its
reviews, inline comments, commit comments, and related certification-tool issue
[#1071](https://github.com/project-chip/certification-tool/issues/1071) contain
no rationale for removing the Mesh-Local Prefix change. The review discussion
concerns container cleanup, graceful shutdown, diagnostics, and tests. It would
be speculation to claim the prefix approach was rejected as invalid; it may
simply have been removed from an OTBR startup/reliability PR with a narrower
scope.

### Answers supported by public evidence

| Question | Publicly supported answer |
| --- | --- |
| How is OTBR started? | Jenkins/direct path: not shown in matter-qa. Test Harness auto-config path: certification-tool-backend creates an OTBR Docker container around the configured RCP. |
| What creates the dataset? | Jenkins/direct path: unknown producer; Jenkins only reads configuration. Test Harness auto-config path: `ThreadBorderRouter.form_thread_topology()`. |
| When does generation execute? | Once when the OTBR network is formed at suite/backend lifecycle, potentially lazily during argument construction; not once per inner matter-qa iteration. |
| Is `dataset init new` involved? | Yes for current certification-tool auto-config and manual `otbr_start.sh`; not proven for the retained Jenkins dataset. |
| Which generated fields are overwritten? | Channel, PAN ID, Extended PAN ID, Network Key, and Network Name. |
| Is the complete active dataset persisted? | It is read and passed to the current test, but public code does not persist and restore it as the canonical identity for a later OTBR recreation. |
| Where does `--thread-dataset-hex` come from? | Jenkins: `network_config.thread_dataset`. Test Harness: external/configured complete dataset, or live `ThreadBorderRouter.active_dataset`. |
| Can OTBR restart independently of controller state? | Yes across suite/backend/container lifecycles; public code does not enforce coupled invalidation of reused commissioning/controller state. |
| Do neighboring GRL fixtures share credentials? | Unknown from public evidence. The manual backend script's well-known key proves the tooling permits common credentials, not that all GRL fixtures use them. |
| Can neighboring networks be credential-compatible but non-identical? | Yes. Shared Network Key and Extended PAN ID with differing complete datasets can create that condition; the retained October logs already show attachment to multiple unintended partitions. |

### Remaining GRL evidence needed

The historical/current GRL production-path gap can be closed without another
stress campaign. Preserve these artifacts from one affected fixture and its
RF-visible neighbors:

1. the Test Harness project/environment config, including whether it selects
  `ThreadAutoConfig`, `ThreadExternalConfig`, or sets
  `operational_dataset_hex`;
2. the Jenkins job config and the source of
  `network_config.thread_dataset`;
3. exact certification-tool-backend, matter-qa, and Jenkins-library revisions;
4. OTBR startup logs containing every `ot-ctl dataset ...` command;
5. `dataset active -x`, `extpanid`, `networkkey`, `meshlocalprefix`,
  `partitionid`, leader data, SRP state, and OMR prefixes before and after each
  OTBR restart;
6. the exact `--thread-dataset-hex` recorded by the controller; and
7. credential-safe fingerprints of the same fields from neighboring fixtures.

Compare complete dataset bytes, not only Network Name, PAN ID, or partition
ID. Network keys should be compared as restricted evidence or keyed hashes and
must not be published in general logs.

## Independent matter-qa stale-session defect

The Thread topology failure and matter-qa cleanup failure are independent and
explain different retained failures.

Current `TC_Darwin_Pair` records cleanup responsibility only after each
`CommissioningComplete` succeeds. For both fabrics, `AddNOC` can therefore
succeed and install a fabric before the corresponding controller/node pair is
added to `list_of_commissioned_controller`. If the following
`CommissioningComplete` or another intervening operation fails, the failure
handler has an incomplete list of state to remove.

Two additional cleanup properties compound this:

- `cleanup_and_unpair_sessions()` exits its controller loop on the first
  exception, so later fabrics are not attempted and their BLE closure is not
  reached; and
- `ChipPythonControllerNode.unpair_device()` calls `ExpireSessions()` only
  after `UnpairDevice()` returns successfully, so an unpair timeout skips local
  session expiration.

Subscriptions are local variables and are shut down only on the normal path.
An exception after a subscription is created but before the normal cleanup call
can therefore leave it active. `CaseSession` does preserve the original test
exception when its failure handler also fails, but the handler itself is not
exhaustive or failure-safe.

The retained February packet evidence demonstrates the consequence rather than
merely a theoretical risk: TH2 reused the fixed second-fabric peer identity and
an old CASE session, then sent encrypted traffic to the previous DUT
incarnation's IPv6 address. This is a confirmed matter-qa state-lifecycle
defect. Randomizing TH2's node ID would hide it rather than fix it.

The narrow cleanup correction should:

1. register each controller/node pair immediately after its `AddNOC` succeeds;
2. attempt every registered controller even if an earlier unpair fails;
3. expire the node's controller sessions in `finally` around unpair;
4. close BLE and shut down every created subscription in failure-safe cleanup;
5. clear bookkeeping only after taking a snapshot of all resources to attempt;
  and
6. retain the original commissioning/test exception when cleanup also fails,
  while logging or aggregating cleanup failures.

Unit regressions should inject an unpair timeout and prove that session
expiration, later-controller cleanup, BLE closure, and subscription shutdown
are still attempted. A second regression should fail immediately after a
successful `AddNOC` and prove that the newly installed fabric is already
registered for cleanup.

## Causal and PR separation

The October evidence proves that the controller supplied one constant dataset,
the DUT later adopted several substantially different parent-supplied active
datasets, passing iterations always reached one usable environment, and failed
iterations reached environments without the required SRP/OMR path. Without the
historical intended OTBR's `dataset active -x`, it does **not** prove that the
controller bytes differed from that OTBR's active dataset at campaign start.
The supported statement is narrower:

> The stress setup allowed the DUT to attach to other credential-compatible
> Thread infrastructure instead of reliably constraining it to the intended
> OTBR.

Current evidence supports three separate change sets:

1. **matter-qa cleanup:** failure-safe fabric, session, subscription, and BLE
  cleanup. This is the first and narrowest PR.
2. **matter-qa validation/diagnostics:** when the intended OTBR is accessible,
  compare the controller-supplied complete dataset with its live active
  dataset before commissioning; after attachment, record and classify DUT and
  OTBR identity, partition, role, SRP, and OMR state. A preflight mismatch is
  infrastructure/configuration failure, not a Matter timeout.
3. **certification-tool-backend dataset authority:** replace repeated
  `dataset init new` plus partial overrides with canonical complete-dataset
  persistence/restoration and unique per-fixture credentials.

The backend defect is proven in current public source and by its prior exact
restart/reused-commissioning reproduction. It is not yet proven to be the
producer of the retained October Jenkins dataset. That remaining provenance
gap affects historical attribution, not whether the current backend behavior
needs a regression and correction.

### Root-fix direction

The preferred certification-tool-backend fix is to make one complete Active
Operational Dataset the canonical run/testbed state: generate it once, read the
exact `dataset active -x`, persist it, pass those exact bytes to controllers,
and restore those exact bytes after OTBR recreation. Do not reconstruct the
same logical testbed with `dataset init new` plus a subset of overrides.

Each RF-visible fixture should also have unique Thread credentials. Add a
regression that forms the network, records the complete active dataset,
restarts OTBR, verifies byte identity, reuses commissioning, and proves
operational discovery plus CASE. Pinning only Mesh-Local Prefix is a useful
narrow regression target, but complete-dataset persistence avoids future gaps
when other generated TLVs matter.