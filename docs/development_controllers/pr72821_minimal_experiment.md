# PR 72821: Reduced BLE Fallback Experiment

Date: 2026-10-20. Issue: project-chip/connectedhomeip#72252.

## Recommendation

Use the reduced implementation with the follow-up corrections described below:
asynchronous Disconnect, pending-until-terminal Linux connect cancellation, and
normal factory-restart state reset. The held-reply fallback probe demonstrates
that Disconnect responsiveness is relevant to this PR. B alone is insufficient:
an executed teardown test reports a commissioner use-after-free under ASan.

The final candidate retains no global request registry, delegate-destruction
tracking, full Linux event generations, or asynchronous Connect. It is integrated
as `fa4963d16ad` on the existing PR branch, without rewriting its history or
creating another PR. Normal singleton-backed factory shutdown/restart is tested;
arbitrary destruction of a layer/delegate during backend work is not supported.
Physical commissioning and general delayed-event equivalence to C remain
unqualified.

The original A/B/C/D comparison below is historical. Its 13-case results and
size counts describe D before the follow-up, not the final PR implementation.

## Revisions

| Variant | Revision | Meaning |
| --- | --- | --- |
| A | `c0747b78f00f61b4c36d20db474fc9721b437f5d` | Upstream baseline |
| B | `2be76f9678543b9a62d4797ef7775a7d38b5872e` | Initial six-file correction |
| C | `c6010b2f8c461857f9bfe81921a33d2d026fa68f` | Published expanded implementation |
| D | `fd3d1ae14240b6d1a75a1f568759c08d292d38a9` | Initially qualified reduced implementation |
| Follow-up | `7b5757e8fce` | Reduced candidate plus measured Disconnect, cancellation and restart corrections |
| PR integration | `fa4963d16ad` | Same source tree on the original PR branch, parent C |

D consists of `607dc3dd7f926b0c355dd99af0ac3c565991a714` followed by
`fd3d1ae14240b6d1a75a1f568759c08d292d38a9`, on
`experiment/pr72821-minimal`, based directly on B. This report is committed
after the tested implementation so its exact revision can be recorded.

Separate B and C worktrees supplied comparison builds. Their production
implementation was preserved; test-access hooks and the common test source were
supplied locally. Local dependency symlinks and environment setup are not part of
D's commits. The published PR ref was verified at C after the initial comparison.
The follow-up was subsequently integrated on that original branch.

## Implementation Size

This table records the initial comparison; final follow-up counts appear below.

Counts are `git diff --numstat A REV -- src`, excluding paths containing
`/tests/`. Header-only test friendship in production headers is included, making
the production count conservative. Reports, test sources, and local build setup
are excluded. A has no diff against itself.

| Variant | Production files | Added lines | Removed lines | Changed lines |
| --- | ---: | ---: | ---: | ---: |
| A | 0 | 0 | 0 | 0 |
| B | 3 | 36 | 5 | 41 |
| C | 15 | 602 | 95 | 697 |
| D | 8 | 134 | 17 | 151 |

D reduces production changed lines by approximately 78% relative to C. B's
"six files" includes tests; only three of its files are production files.

| D production file | Added | Removed |
| --- | ---: | ---: |
| `src/ble/BleLayer.cpp` | 72 | 8 |
| `src/ble/BleLayer.h` | 14 | 0 |
| `src/controller/CHIPDeviceController.cpp` | 4 | 0 |
| `src/controller/SetUpCodePairer.cpp` | 25 | 5 |
| `src/platform/Linux/BLEManagerImpl.cpp` | 13 | 3 |
| `src/platform/Linux/BLEManagerImpl.h` | 2 | 0 |
| `src/platform/Linux/bluez/ChipDeviceScanner.cpp` | 2 | 1 |
| `src/platform/Linux/bluez/ChipDeviceScanner.h` | 2 | 0 |

## Behavioral Specification

The common source is `src/controller/tests/TestBleFallback.cpp`.
Initial comparison SHA-256:
`961307f073242c22cef502ad6786f4874102303c771325fc6fb6e2813ce88da3`.
The comparison worktrees include this source and compile it against their own
controller, BLE layer, and Linux implementation.

The fallback test starts real commissioner UDP PASE against IPv6 loopback port 9.
It installs the pairer as the commissioner delegate, injects the concurrent BLE
discovery result, and drives UDP failure through the commissioner's real
`OnSessionEstablishmentError` path. The pairer then selects the deferred candidate
and uses the actual `NewBleConnectionByDiscriminator` interface. A backend test
double delivers a distinct new connection. Assertions observe:

- One close of the discarded connection and no write through that connection.
- A fresh request with the expected long discriminator.
- The new connection recorded by PASE establishment and an actual BLE write.
- No access to a retired connection and no unwanted PASE write after cancellation.
- Immediate BLE use without an additional scan or premature close.

Discovery and terminal results are injected deterministically; this is not a
radio/DNS-SD integration test. The BLE write starts transport/PASE establishment;
the fixture does not complete a cryptographic peer handshake or commissioning.

Successful backend cancellation suppresses its terminal callbacks. Failed
cancellation deliberately leaves the operation active and permits one late
success or error. Tests do not manufacture callbacks after successful backend
cancellation and claim them as required behavior. The Linux queued-start and
StopDiscovery cases exercise the real Linux manager/scanner separately.

| Behavior | B | C | D | Evidence and conclusion |
| --- | --- | --- | --- | --- |
| Original borrowed-pointer failure | Corrected | Corrected | Corrected | Established queueing negative control fails the two deferred-BLE regressions; not repeated |
| Complete UDP-to-fresh-BLE fallback | PASS | PASS | PASS | Real controller UDP setup, error callback, discriminator reconnect, new connection and write |
| Immediate BLE path | PASS | PASS | PASS | No scan and no discard before PASE use |
| Cancellation before fallback | PASS | PASS | PASS | Candidate cleared and no reconnect started |
| Cancellation during fallback | FAIL | PASS | PASS | B does not cancel the active reconnect backend |
| Late success after failed cancellation | FAIL | PASS | PASS | B does not release the unused connection; C/D close it without PASE writes |
| Late error and subsequent pairing | FAIL | PASS | PASS | C/D detach caller, retire terminal work, and allow the next request |
| Commissioner teardown | ASan UAF | PASS | PASS | Late error after normal Shutdown/destruction with shared BLE layer surviving |
| Subsequent pairing after cancellation | FAIL | PASS | PASS | C/D do not overlap a canceled live backend with a new request |
| Another commissioner sharing the layer | FAIL | PASS | PASS | Owner-specific cancel avoids canceling another commissioner's request |
| Canceled queued Linux start | Not reached in final B ASan run | PASS | PASS | Queue A, cancel A, queue B, drain actual event loop; no old callback and exactly one new callback |
| Remote StopDiscovery error after local detach | Not qualified separately on B | PASS | PASS after correction | Actual private D-Bus Adapter1.StopDiscovery call returns injected BlueZ error; local scanner inactive and next request accepted |
| Global request registry | Absent | Present | Absent | Not required for the tested commissioner-lifetime boundary |
| Full Linux event generation tracking | Absent | Present | Queued-start identity only | General delayed GLib/event isolation remains unqualified on D |
| Async BlueZ Connect/Disconnect | Absent | Present | Absent | No claim of equivalent responsiveness under a held remote RPC |

B's ASan executable ran the first nine cases, with six behavioral failures,
then aborted in the tenth case on UAF. The final success-after-destruction and
Linux cases were therefore not executed by that run. No complete B pass count
is claimed. C/D's final common suite contains 13 cases, including the later
StopDiscovery regression.

## Necessary Local Corrections

1. Preserve B's ownership repair: queue reconnectable parameters and the
   discriminator rather than the borrowed object; close the discarded object;
   retain immediate consumption when no PASE attempt is active.
2. When releasing the device in PASE establishment, the commissioner asks the
   BLE layer to cancel only its own pending request.
3. The surviving BLE layer retains single-request callback state. Cancellation
   detaches the caller before invoking the backend. If cancellation fails, the
   layer remains busy until the terminal result; an unused success is closed.
   Terminal state is cleared before invoking a live caller, permitting reentry.
4. A small Linux request counter invalidates a queued scan-start lambda after
   cancellation. Successful cancellation clears the local scan configuration.
5. Scanner state becomes initialized after successful local notification
   detachment, even if the remote StopDiscovery call fails. The manager treats
   that locally quiescent state as canceled, instead of permanently retaining a
   busy request. A failed notification detachment is still propagated.
6. Initiate Disconnect asynchronously without capturing a connection or endpoint.
   The deferred-discovery close must not await a remote reply on the Matter loop.
7. Linux connecting cancellation cancels its GIO operation but returns BUSY:
   a terminal event may already be queued or may be produced by cancellation.
   The detached layer rejects replacement until the terminal result retires it.
8. Successful layer initialization resets callback state, and Linux shutdown
   retires scan state along with its timers. These are required by the executed
   normal factory shutdown/restart regression, not arbitrary layer destruction.

The commissioner cannot implement all of item 3 alone: the old API handed its
raw application pointer to the backend, and offered no owner-specific detach
operation. Merely checking a commissioner flag still dereferences a destroyed
commissioner; unconditional cancellation can affect another controller. The
small shared-layer wrapper addresses this boundary without allocated request
records or changing delegate destructors.

## Expanded Component Assessment

Classifications concern necessity for this PR, not whether an improvement has
merit. Existing code paths and injected regressions are not physical crash
reproductions.

| Component from C | Classification | Evidence and disposition |
| --- | --- | --- |
| Reconnectable parameters and discarded-link cleanup | REQUIRED | Original ownership mechanism; retained unchanged from B |
| Caller callback detachment, owner-aware cancel and pending single-request exclusion | REQUIRED | B's executable failures and commissioner UAF; implemented locally in D |
| Global request identity registry | NOT ESTABLISHED | C/D pass common lifetime cases without it in D; shared layer survives the unfinished request |
| Platform-delegate destructor/lifetime registry | NOT ESTABLISHED | Not needed for tested commissioner teardown; D requires the delegates to survive backend work |
| BLE-layer shutdown/reinit callback identity | BROADER THAN NORMAL FACTORY RESTART | Follow-up resets normal restart state and tests stopped-loop factory teardown; arbitrary late callbacks into destroyed/replaced layers remain unsupported |
| Single-device versus multi-discriminator coordination | REQUIRED for single-request exclusion | D retains a busy guard so a multi-result request cannot replace a live single-result request; no new multi-result ownership system |
| Queued Linux scan-start invalidation | REQUIRED | Actual queued cancellation/replacement regression; small counter retained in D |
| Full scan-result and terminal-event generation tagging | UNDETERMINED | C protects additional delayed-event orderings; the common D tests do not prove all GLib-to-Matter races safe |
| Scanner StopDiscovery failure retirement | REQUIRED with D's pending-request guard | D before final correction becomes stranded after local unsubscribe plus remote error; final D and C pass actual injected RPC |
| Asynchronous BlueZ Connect | SEPARATE ISSUE | Synchronous RPC existed in A and discriminator reconnect already existed; C's held-RPC test demonstrates responsiveness improvement, not necessity of async for this ownership correction |
| Asynchronous BlueZ Disconnect | REQUIRED BY FOLLOW-UP EVIDENCE | Actual deferred-discovery close stalls Matter progress with a held reply on initial D; unchanged C and the small async correction pass |
| Adapter-removal cleanup | SEPARATE ISSUE | General platform error retirement, predating this queueing strategy; not reproduced in D's scoped sequence |
| Already-connected-device handling | SEPARATE ISSUE | Existing reconnect backend behavior; C's generated-proxy test covers the independent cached-state/no-new-notification case |
| Stale completion after failed cancellation with commissioner gone | REQUIRED | B ASan failure; D detaches caller and blocks replacement until terminal result |
| Completion after layer or delegate destruction | SEPARATE ISSUE | Broader lifetime boundary; D explicitly does not support unfinished backend work outliving the layer/delegates |

StopDiscovery recovery and queued-start invalidation repair pre-existing Linux
problems, but become required companions to D's safe pending-request exclusion:
otherwise an ordinary cancel/retry sequence can be stranded or misattributed.
The report does not use automated review suggestions alone as evidence.

## Validation

This table records the initial comparison, not the final follow-up totals.
All results below are executed binaries with exit zero, except the intentional
baseline failures described separately. ASan used `ASAN_OPTIONS=detect_leaks=1`.
No sanitizer diagnostics or GLib criticals occurred in final C/D qualification.

| Variant/configuration | Executed binaries and passing cases | Total |
| --- | --- | ---: |
| D native | TestBleFallback 13; TestSetUpCodePairer 12; TestAutoCommissioner 34; TestBleLayer 37; TestBleEndPoint 3; TestBtpEngine 23 | 122 |
| D ASan/leak | TestBleFallback 13; TestSetUpCodePairer 12; TestBleLayer 37 | 62 |
| D BLE-disabled | TestBleFallback 1 configuration check; TestSetUpCodePairer 11 | 12 |
| C native | TestBleFallback 13; TestSetUpCodePairer 19; TestBleLayer 53; TestBLEManagerImpl 11 | 96 |
| C ASan/leak | Same four binaries and counts | 96 |

Three existing AutoCommissioner tests remain disabled. They are not counted as
passes. C's TestBLEManagerImpl includes its real private peer-to-peer D-Bus
Connect/Disconnect, scanner-error and generated-proxy tests. D's common suite
contains its applicable Linux queued-start and real StopDiscovery-error tests;
C's internal-generation-specific tests were not copied into D as requirements.

### Reproduction Commands

Use the existing SDK build environment and ZAP v2026.09.09. Each worktree's GN
arguments use `chip_build_tests=true`, `is_clang=true`, `symbol_level=0`, and
`chip_support_thread_meshcop=false`, with GCC 11 library selection through
`--gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/11` in target compile/link flags.
Normal builds set `chip_enable_ble=true`; ASan additionally sets `is_asan=true`.
True BLE-disabled builds set both `chip_enable_ble=false` and
`chip_config_network_layer_ble=false`. Thread Meshcop was not qualified.

From the D worktree, generate these configured build directories and run:

```sh
ninja -C out/native -j4 \
  src/controller/tests:TestBleFallback \
  src/controller/tests:TestSetUpCodePairer \
  src/controller/tests:TestAutoCommissioner \
  src/ble/tests:TestBleLayer src/ble/tests:TestBleEndPoint \
  src/ble/tests:TestBtpEngine
ninja -C out/asan -j4 src/controller/tests:TestBleFallback \
  src/controller/tests:TestSetUpCodePairer src/ble/tests:TestBleLayer
ninja -C out/no-ble -j4 src/controller/tests:TestBleFallback \
  src/controller/tests:TestSetUpCodePairer
./out/native/tests/TestBleFallback
ASAN_OPTIONS=detect_leaks=1 ./out/asan/tests/TestBleFallback
./out/no-ble/tests/TestSetUpCodePairer
```

The remaining binaries in the table were executed directly from the corresponding
`out/CONFIG/tests/` directory, not inferred from successful compilation. For C,
build and run the four listed binaries, including
`src/platform/tests:TestBLEManagerImpl`, in native and ASan configurations.
Formatting used clang-format 16.0.6, and `git diff --check` passed.

### Retained Failure Evidence

B's executed ASan result included:

```text
TestBleFallback.StopDuringFallbackCancelsBackend: FAILED
TestBleFallback.FailedCancellationLateSuccessClosesConnection: FAILED
TestBleFallback.FailedCancellationLateErrorIsTerminal: FAILED
TestBleFallback.SubsequentPairingAfterSuccessfulCancellation: FAILED
TestBleFallback.FailedCancellationDoesNotReplaceLiveRequest: FAILED
TestBleFallback.OtherCommissionerCannotCancelOwnedFallback: FAILED
TestBleFallback.DestroyWithFailedCancellationLateError:
ERROR: AddressSanitizer: heap-use-after-free
SUMMARY: ... chip::Controller::DeviceCommissioner::OnDiscoveredDeviceOverBleError(void*, chip::ChipError)
Executable exit: 1
```

D before scanner retirement correction failed
`LinuxStopDiscoveryFailureDoesNotStrandNextPairing`. The private peer returned
`org.bluez.Error.Failed: Injected StopDiscovery failure`; the local scanner
remained scanning, cancel returned an error, and the next request was rejected.
After the two localized production changes, the same real RPC was observed
exactly once and all 13 common tests passed normally and under ASan. C also
passed this final test unchanged.

Earlier comparison setup encountered missing test-access hooks/dependencies;
those compilation failures were fixed in the test harness and are not counted
as behavioral regressions. The original queueing negative control and 19-test
registry-bypass experiment were accepted as completed evidence, not repeated.

## Follow-up Qualification and PR Integration

This continues from report commit `f806578a302` without repeating the complete
A/B/C/D investigation. Candidate `7b5757e8fce` is integrated as
`fa4963d16adb94080e8d5db2d14ec0051cdbd93f`, with C as its parent, on
`feature/segfault-OnDiscoveredDeviceOverBle`. The integrated `src` tree was
verified identical to the candidate before committing. No global registries,
delegate-destructor changes, asynchronous Connect, or full Linux event generations
were restored. The report remains only on the experimental branch.

### Held Disconnect in the Actual Deferred Path

`DeferredDisconnectDoesNotBlockControllerProgress` starts real UDP PASE, then
schedules the real pairer's BLE-discovery callback on the Matter system layer.
Its discarded-link close reaches the actual `BluezConnection::CloseConnection`
and generated Device1 proxy through the test platform delegate. An authenticated
private peer-to-peer GDBus server holds the actual Disconnect message. Another
Matter task must progress before the peer replies. The peer allows 500 ms for
that progress and then returns an injected UnknownObject/device-disappearance
error; the proxy timeout is five seconds.

- Initial D: 13 pass, one intended failure; progress-before-reply is false and
   the dispatch records approximately 501 ms. This is dispatcher blocking, not
   a physical BlueZ failure reproduction.
- Unchanged C production with the identical 14-case probe source: 14 pass.
- D with only the small asynchronous Disconnect correction: 14 pass.

The test destroys the BluezConnection while the reply is outstanding. The
asynchronous completion uses only GIO's retained proxy, not the destroyed
connection or endpoint. The final version also runs under ASan/leak detection.
The test does not separately assert proxy-finalization timing or error logging.
Comparison logs are locally retained as `/tmp/pr72821-disconnect-{d,c}.log` and
`/tmp/pr72821-disconnect-corrected.log`; these paths are not published raw logs.

### Real Linux Cancellation Notifications

The first cancellation probe holds an actual generated Device1.Connect RPC and
calls the real endpoint cancellation. GIO cancellation causes the real
ConnectDevice failure path to post a manager event. Before correction, Linux
reported successful cancellation, allowed replacement, and the old failure
notified the replacement (`newCallbacks == 1`, expected zero). Thus the missing
isolation was demonstrated using a backend-produced event, not just a fabricated
callback after successful cancellation. The failure remains in
`/tmp/pr72821-cancel-d.log`.

The final `LinuxCancelledConnectFailureCannotCompleteReplacement` checks BUSY
both before and after the canceled RPC returns, until the real event queue is
drained. Neither detached caller is notified, and a new request is accepted
afterward. The queued scan-start identity is invalidated in test setup so that
an unrelated scan-start error cannot supply the apparent terminal event.

`LinuxQueuedSuccessAfterCancellationClosesDiscardedLink` uses the actual manager
success-event producer, actual platform queue, real connection and generated
Disconnect proxy. Cancellation detaches the caller and rejects replacement;
dispatch closes the unclaimed connection exactly once and then permits retry.
An explicit condition-variable wait observes the Disconnect request. This does
not exercise radio discovery or full service-resolved/GATT initialization.

Connecting cancellation now reports BUSY instead of promising quiescence.
Typically the canceled RPC supplies the terminal event; a successful Connect
awaiting services can remain pending until the existing 20-second connection
timer. This is not a new hard responsiveness guarantee if the event loop or
another synchronous backend operation is blocked. Multi-event timeout races and
arbitrary GLib event orderings are not generally qualified by these cases.

### Normal Factory Lifetime

The Linux manager and its BleLayer/delegates are process-lifetime singleton
objects. Factory system-state shutdown drops its pointer rather than deleting
that layer, and the documented shutdown contract stops the Matter event loop
before shutting down controllers/system state. Platform shutdown stops the
scanner, endpoint, object manager and GLib loop. The tests retain the shared
layer while commissioner destruction delivers a late result.

`LinuxFactoryShutdownWithQueuedCancelledCompletion` additionally queues an
actual manager failure notification, cancels the request, and shuts down the
commissioner and factory without dispatching that notification. It checks the
same layer survives and the caller is not notified, then initializes the factory
and commissioner again and starts/cancels a fresh request. The initial restart
probe failed with a stranded layer BUSY flag; after resetting that flag it
exposed stale manager connecting state. Resetting initialized callback state
and retiring scan state during shutdown makes the same test pass. This supports
normal teardown/restart, not callbacks surviving arbitrary backend/layer reuse.

### Final Branch Gates and Size

All following binaries were freshly built and executed in the original-branch
worktree after integration, with the same GN arguments documented above.
The integrated test source SHA-256 is
`d2fdde1ee9cfb63a64f92ad809f22fc7ac7389c813dd144d9879e58ed6ab2e78`.

| Configuration | Passing cases | Total |
| --- | --- | ---: |
| Native | TestBleFallback 17; TestSetUpCodePairer 12; TestAutoCommissioner 34; TestBleLayer 37; TestBleEndPoint 3; TestBtpEngine 23 | 126 |
| ASan, detect_leaks=1 | TestBleFallback 17; TestSetUpCodePairer 12; TestBleLayer 37 | 66 |
| True BLE-disabled | TestBleFallback 1; TestSetUpCodePairer 11 | 12 |

Three pre-existing AutoCommissioner cases remain disabled and are not counted
as passes. No final sanitizer/leak diagnostics or GLib criticals were observed.
Touched follow-up files pass clang-format 16 dry-run, editor diagnostics report
no errors, and staged `git diff --check` passes. Initial fresh-build attempts
stopped before compilation because GN was not on PATH and an ignored Pigweed
environment wrapper was absent; local setup was corrected before these gates.
Local environment/dependency symlinks are excluded from both commits.

Against A, the final PR has 17 changed files, +1079/-34 lines in total. Production
has 11 changed files, +160/-29 lines: 189 changed lines versus C's 697, a 72.9%
reduction. The integration commit relative to C changes 22 files, +955/-1616,
replacing implementation-specific tests with the 17-case fallback/lifecycle
suite while retaining the original pairer and baseline BLE coverage.

The original PR is retained, non-draft, targeting master; no merge or history
rewrite is performed. Its description must report only the final gates and
explicit limits, linking this experimental report for comparison details rather
than inheriting C's larger test counts or its prior CI result.

## Physical Qualification and Remaining Limits

The nRF Connect inventory identified DK `001050208117` and a separate RCP
device. No local owner was visible on ttyACM0/1/2. However, the separate
Pi-to-Nordic endurance ownership record remained present and no fixture release
was established by this experiment. Neither a UART absence check nor an old
owner record proves current campaign liveness or permits taking over the DUT.
No flash, reset, new serial reader, or physical commissioning was performed.
The original hardware failure remains unreproduced in this investigation.

D requires the shared BLE layer and its delegates to outlive unfinished backend
work, and relies on successful platform cancellation suppressing callbacks.
Failed cancellation keeps a request busy until its terminal result; there is no
forced replacement if a broken backend never terminates. General delayed GLib
events after successful cancellation, cached already-connected proxy behavior,
adapter removal, held Connect responsiveness, and arbitrary layer/delegate
destruction remain unqualified. The follow-up qualifies only the held Disconnect
and normal factory teardown/restart paths described above. C offers additional
protection outside these boundaries. Thread Meshcop and other platform backends
were not qualified.

The evidence supports the smaller D approach for the original ownership problem
and the exercised cancellation paths. It does not support an unconditional claim
that C's extra behavior is unnecessary everywhere, or that D has completed
physical BLE qualification. Retain these as explicit review/release limitations
rather than silently expanding this PR again.