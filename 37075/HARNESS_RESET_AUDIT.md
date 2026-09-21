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