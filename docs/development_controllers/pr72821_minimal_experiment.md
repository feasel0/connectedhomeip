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
as `fa4963d16ad`, followed by the localized queued-restart correction
`9291e84c148`, on the existing PR branch without rewriting its history or
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
| Queued restart correction | `9291e84c148` | Reject an old queued BLE terminal event while a new request is connecting |

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

## Queued Completion After Normal Restart

Review of `fa4963d16ad` found a gap in the earlier factory-restart qualification:
the test started and canceled a replacement request but did not run the event
loop while that replacement was connecting. POSIX platform shutdown requires
the loop to be stopped, but neither shutdown nor initialization clears the
singleton's `mChipEventQueue`. Stopping and joining GLib does not discard events
already posted to that queue. There is no queue-discard lifecycle guarantee.
The tested replacement state is reachable: GLib's `OnDeviceScanned` sets
`kConnecting` before acquiring the Matter stack lock, whereas the Matter loop
drains device events after handling system-layer work. A new scan can therefore
reach connecting state before the preserved event is dispatched.

The existing `LinuxFactoryShutdownWithQueuedCancelledCompletion` test now drains
the real platform queue after restart with the replacement marked connecting.
Without the correction, the old failure event calls the replacement once and
retires its pending ownership: 16 cases pass and this case fails. The retained
local failure summary is `/tmp/pr72821-restart-queue-red.log`.

Correction `9291e84c148` stamps only the two BLE connection-terminal event types
with the existing request counter, advances that counter at shutdown, and checks
it before using a queued completion. The existing counter is atomic for its
GLib-producer/Matter-consumer accesses. Stale success-event connection pointers
are not dereferenced after shutdown. This does not clear unrelated platform
events or restore a global registry, delegate lifetime tracking, full scan-event
generation system, or asynchronous Connect.

The corrected test verifies the old event leaves both callers untouched, the
replacement remains pending, its own terminal event reaches it once, and another
request can start. The same original-branch suites pass again: 126 native,
66 ASan/leak, and 12 true BLE-disabled cases, with the same three pre-existing
disabled AutoCommissioner cases excluded. Formatting, diagnostics and diff
checks pass. General delayed callbacks produced after a new request starts,
other event types, arbitrary layer/delegate destruction and physical BLE remain
outside this localized qualification. The previous section's source hash/counts
and CI statement describe `fa4963d16ad`, not this correction.

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

## CodeRabbit Follow-up and Independent Candidate Assessment

Correction `22ee84d9c9081fdca57eed4d8d57ab44205b6f9d` follows
`d0e1d6fa90120441a29ea3df498731efa758dda8` on the original PR branch.
It changes five files, with two production behavior changes and focused tests.
No general BLE request registry, delegate lifetime tracking, asynchronous
Connect, or independent candidate fix is included.

### Active Connect Cancellable

`ConnectDeviceImpl` reads the endpoint's cancellable on the GLib thread for
each synchronous Connect attempt. Cancellation can run on the Matter thread.
Resetting the shared `GAutoPtr` there races its reader; GIO's ownership of a
particular in-flight call does not make concurrent access to that C++ owner
safe. The correction retains `g_cancellable_cancel` but removes the reset.
The next serialized Connect installs a new cancellable.

The existing real private-D-Bus held-Connect test now retains the observed
token, cancels twice, drains the detached terminal event, and performs another
real held Connect with a distinct, initially uncancelled token. Before the fix,
the token-ownership assertion fails: the endpoint's pointer is null. After the
fix all 17 fallback cases pass, including both Connect attempts. This is an
executed regression for the ownership contract, not an observed ASan UAF or a
proof of arbitrary concurrent Connect callers being supported.

### Completion During Closing Versus Shutdown

An added layer regression starts a request, indicates closing, detaches its
callbacks through cancellation, and delivers success while the delegate is
still alive. Before the fix it closes zero links rather than one. The fix
permits `CloseUnclaimedConnection` in initialized or disconnecting state.
The existing Linux queued-success case now exercises this ordering through
the actual manager event producer, preserved event queue, real connection and
generated asynchronous Disconnect proxy. It observes exactly one Disconnect,
no detached-caller callback, and successful reinitialization/retry.

The guard against cleanup in uninitialized state remains intentional. A new
test verifies no delegate call after `BleLayer::Shutdown`. Delegates are not
owned by the layer; that alone does not guarantee their lifetime after shutdown.
`BLEManager::Shutdown` first shuts down its layer, then its platform backend.
Normal factory shutdown requires a stopped Matter loop and stops the GLib
backend. Already posted Linux terminal events can survive the queue, but the
existing restart request tags reject stale success before dereferencing its
connection and reject stale failure before notifying a replacement. This does
not authorize direct callbacks into a destroyed layer or stopped backend.
The supported closing interval is fixed without removing the shutdown guard.

### Executed Qualification

| Configuration | Passing cases | Total |
| --- | --- | ---: |
| Native | fallback 17; pairer 12; AutoCommissioner 34; layer 39; endpoint 3; BTP 23 | 128 |
| ASan, detect_leaks=1 | fallback 17; pairer 12; layer 39 | 68 |
| Both BLE flags disabled | fallback configuration 1; pairer 11 | 12 |
| Platform BLE off, network BLE on | fallback configuration 1; pairer 12 | 13 |

Three pre-existing AutoCommissioner cases remain disabled and excluded.
clang-format 16, editor diagnostics and diff checks pass. Physical BLE,
Thread Meshcop and other platform backends remain unqualified. New-head CI
is not inferred from local tests or earlier-head CI.

### Independent Upstream Candidates

Assessment uses freshly fetched upstream master
`869cc2999fd67b3449e5a77dd3e8ef1e7e51f830`, verified against the upstream
remote ref, in a separate detached worktree. No #72821 commit is its base.
Repository PR searches for `BluezEndpoint`, `ServicesResolved`, and
`chip_config_network_layer_ble` found no obvious existing fix for these two
specific candidates; this is not an exhaustive proof that none exists.

**Already-connected, service-resolved proxy.** Upstream's successful
`ConnectDeviceImpl` returns without creating or reporting a connection. Device
addition/property notifications drive `HandleNewDevice`; an already tracked
device is explicitly rejected there. Thus success alone does not promise a
new terminal notification if no notification follows. However, normal
`ChipDeviceScanner::StartScanImpl` first attempts to remove known Matter
devices. A production reproduction must establish how a connected proxy
survives that removal and whether its existing connection is owned elsewhere.
Unconditionally replaying `HandleNewDevice` neither handles an already tracked
connection nor establishes safe reuse. A complete regression needs the cached
BlueZ object/GATT model, scan/removal ordering, and an ownership policy, not
only a successful Connect stub. No normal-path runtime defect or sufficiently
small, ownership-safe correction was established in this assessment. No draft
PR is created for this candidate; it remains a documented investigation item.

**Platform BLE enabled, network BLE disabled.** The unmodified upstream
configuration accepts GN generation but compiling Linux `BLEManagerImpl.cpp`
fails with 11 missing BLE event-member errors. The same errors occur outside
#72821. `src/platform/device.gni` defaults `chip_enable_ble` to
`chip_config_network_layer_ble`, while `ChipDeviceEvent` deliberately excludes
its BLE payloads when the network layer is disabled. The converse override is
therefore inconsistent with the current implementation; GN accepting an
override does not establish it as a supported product configuration. No
documented contract or existing test requiring that combination was found.
Supporting it needs a defined transport/event contract; merely widening event
guards would not establish useful semantics. No draft support PR is created.
An explicit configuration diagnostic can be considered independently once
the intended contract is confirmed.

## Darwin Normal Browsing Follow-up

The follow-up starts at `22ee84d9c9081fdca57eed4d8d57ab44205b6f9d` and
publishes the behavioral correction as `ddcc209d02f54353668d65cc36af17d9c9fd10f4`.
Final head `b1521ac41dcfd8fe3e214feea6c7dfde149d3a2c` adds only the missing
final newline in the new test reported by Restyled job 118937623178; the
terminal-byte check and formatting check pass after that correction.
It does not repeat the previous BLE infrastructure comparison or alter the
common pending-request architecture.

### Reachability and Upstream Comparison

`BleScanMode::kDefault` explicitly replaces an existing BLE operation;
`kPreWarm` explicitly does not. `MTRCommissionableBrowser::Start` invokes
normal `StartBleScan` without a commissioning-in-progress restriction, and
its `Stop` invokes `StopBleScan`. Darwin's `StartScan` stops and replaces a
connecting `MTRBleConnection`. The stopped connection loses its timer and
central-manager delegate without dispatching its connection callback. A
single-device request still searching for its discriminator therefore gives
a supported, radio-independent ordering: request, normal browse, stop browse,
new request. No discovered peripheral or physical connection is required to
reach the lost terminal result.

The Darwin implementation before this follow-up is identical to the pinned
upstream `869cc2999fd67b3449e5a77dd3e8ef1e7e51f830`. Dropping the original
callback is pre-existing. The persistent `CHIP_ERROR_BUSY` on the next request
is introduced by this PR's single-request ownership tracking: stopping a
browser cannot retire the abandoned layer request.

An ignored C++ probe includes each worktree's actual `TestBleLayer` fixture
and links its actual `BleLayer`. It models the source-observed backend stop
without a terminal callback; it does not execute CoreBluetooth or Objective-C.
The same callback-dropping probe passes upstream and fails only the PR's
second-request assertion. Two controls deliver the terminal error using the
actual context captured by the platform delegate: ordinary retry and retry
from inside the error callback. Both controls pass on both implementations.
An initial reentrant control incorrectly supplied the layer rather than
upstream's caller context; that invalid control was corrected and rerun, and
is not counted as a product failure. Final probe totals are upstream 39 pass;
PR 41 pass and the one intentionally failing dropped-callback check.

### Narrow Correction and Coverage

`StartScan` retains the replaced operation, stops it, installs the requested
browser, and then dispatches `BLE_ERROR_APP_CLOSED_CONNECTION` to the old
operation. Existing callback clearing makes this terminal notification
single-shot. Installing the browser first permits a callback-driven retry
to reuse it without subsequently being overwritten by `StartScan`.
Normal replacement remains supported; prewarm behavior is unchanged. No
registry, common-layer relaxation, or unrelated Darwin enhancement is added.

Three Darwin-only tests in `TestDarwinBleConnection.mm` use the real delegate
and layer with a substituted central-manager allocation, without starting a
physical Bluetooth manager. They cover normal browsing/stop/retry and old
callback suppression, reentrant retry, and prewarm preservation. They are
registered only for Darwin with both BLE layers enabled. Native compilation
and execution were pending at the first follow-up closeout; the qualification
below supersedes that limitation, but does not qualify physical Bluetooth.

Fresh local checks after the follow-up pass 68 native tests (layer 39,
fallback 17, pairer 12), and the same 68 under ASan with `detect_leaks=1`.
No sanitizer/leak or GLib-critical diagnostics were observed. clang-format 16,
GN formatting/generation, editor diagnostics and scoped diff checks pass.
The earlier 128-native/25-disabled totals above apply to the parent head;
they are not additional fresh executions for this Darwin follow-up.

The parent's Linux `python_lib` job 118910032177 completed successfully,
including build/native, Python, payload and credential tests. At this first
closeout, new-head CI was pending and Restyled job 118939026466 passed
after the newline repair. Native Apple qualification was not yet available.
Gemini had not produced a new review following request 6302735819.
There are no new Gemini findings to assess and no separate speculative PR.
The PR remains unmerged. Physical BLE, CoreBluetooth delivery, Thread Meshcop
and other platform backends remain unqualified.

## Native Darwin Qualification and Framework TSan Diagnosis

### Test-only Compilation Correction

The simulated Darwin build on `b1521ac41dcfd8fe3e214feea6c7dfde149d3a2c`
failed because Pigweed equality assertions try to format Objective-C and
dispatch-source pointers through `const void *`. Five pointer equality or
inequality assertions in the new test have the same issue. Commit
`b66db8f83ff8c1a6ac6868a024b317bca3d69e36` changes all five to boolean
comparisons. Scalar and CHIP_ERROR equality checks are retained. There is
no production-code change, and browsing replacement, stale callback,
reentrant retry and prewarm coverage are preserved.

### Executed Apple Qualification

Fork workflow run 39529817926, native job 118992885242, compiled target
`src/platform/tests:TestDarwinBleConnection.mm` on a macOS ARM64 runner and
executed its real Objective-C++ test executable. All three cases pass:

- `NormalBrowsingRetiresPendingRequest`
- `BrowsingReplacementAllowsReentrantRetry`
- `PrewarmPreservesPendingRequest`

The workflow runs only on the existing experimental branch, not in #72821.
To avoid cancelling the unchanged-head framework rerun, the Apple checkout
starts from published `b1521ac41dc`, applies only the committed assertion
correction, and requires `git write-tree` to equal
`278ae53c5988e10f5b3dcbcf5c9fe7e9e6218ec8`, the exact source tree of
`b66db8f83ff`. That identity check passed before bootstrap and compilation.
The executable exited zero and the workflow positively required each named
case to pass. There were no additional compile, link or runtime corrections.
The central-manager test substitution avoids physical radio operations;
this is native Darwin lifecycle qualification, not accessory interoperability.

Fresh portable checks also pass: 39 layer, 17 fallback and 12 pairer cases,
68 total, plus the same 68 with ASan and `detect_leaks=1`. clang-format 16,
the final-newline byte check and scoped diff checks pass.

### Exact Framework Failure

Original TSan job 118945849675 (run 39513209315, attempt 1) exited 65.
Its ordinary job log did not identify a test. Artifact 12310192358,
`darwin-framework-test-logs-tsan`, contains the XCTest result bundle.
The separate Apple `xcresult` job 118992885303 used `xcrun xcresulttool`
to decode it: 468 passed, one failed, two skipped. The sole failure is
`MTRAsyncWorkQueueTests/testRunItem`, asserting that `weakItem` is nil at
line 59. The retained object is described as `<MTRAsyncWorkItem 30 complete>`.
The reported failure is an XCTest assertion, not a TSan data-race report.

Baseline TSan job 118916713521 on `22ee84d9c90` passed. The actual
`MTRAsyncWorkQueue.mm`, its header, and `MTRAsyncWorkQueueTests.m` are
byte-identical between that baseline and `b1521ac41dc`. The test fulfills
its expectation inside a global-queue ready handler. That handler's
completion block retains the work item; fulfilling the expectation does not
prove the enclosing dispatch block has returned and released its captures.
The immediate teardown weak-reference assertion is therefore timing-sensitive
even after the item has completed. No BLE-specific failure or data race was
identified, and no queue or production behavior is modified for this result.
The unchanged-head TSan rerun, job 118985983726 (attempt 2 of the original
run), completed successfully at 2026-10-21T02:06:45Z. Its exact head remains
`b1521ac41dcfd8fe3e214feea6c7dfde149d3a2c`. Together with the successful
baseline and the failure's asynchronous retention window, this supports an
intermittent pre-existing lifetime assertion rather than an attributable BLE
regression. The original failure is preserved; success does not erase it.

Only after that rerun completed was the assertion-only commit
`b66db8f83ff8c1a6ac6868a024b317bca3d69e36` pushed to the existing fork
feature branch. The upstream PR API confirms that head, OPEN, non-draft and
unmerged. The experimental workflow and this report remain outside #72821.

## Delayed Darwin Error and Ownership Reviews

### Native Ordering Reproduction and Local Correction

Copilot review 4332342309 identified a second, distinct Darwin ordering issue.
With no browser, the object-based connection entry point asynchronously queues
`CHIP_ERROR_INCORRECT_STATE`. Cancellation previously returned success without
invalidating that block. The layer could accept request B, after which A's
queued trampoline used the same layer pointer to invoke and clear B's state.

Test-only commit `91f7c73d3e78bdb3b6dd6ce3da9bfa811c7ee477` adds
`CanceledObjectErrorDoesNotRetireReplacement`. One real Matter-queue block
queues A, cancels A and starts B; a second synchronous block executes after
the queued error. Apple run 39537958230, native job 119018891410, compiled
and executed the test. The three browsing/prewarm cases passed; the new case
failed its no-error-to-B and B-remains-busy assertions. This is an executed
native regression rejection, not a compile failure or portable simulation.

Correction `54af63db0d926b8442973262c1605556b60c3891` adds a cancellation
count to the Darwin delegate. The deferred rejection captures the original
callback and count; `CancelConnection` increments the count, and the queued
block calls back only if it still matches. This state is used only by that
Darwin deferred-error branch. There is no global registry, common-layer
ownership relaxation, Linux production change, or generalized event redesign.
Delegates must still outlive unfinished queued backend work.

Positive Apple run 39538831501, native job 119021650077, verified the exact
corrected checkout, compiled/linked the executable and passed all seven cases:

- `NormalBrowsingRetiresPendingRequest`
- `BrowsingReplacementAllowsReentrantRetry`
- `PrewarmPreservesPendingRequest`
- `CanceledObjectErrorDoesNotRetireReplacement`
- `ObjectErrorsRemainAsynchronousAndReusable`
- `CanceledObjectErrorDoesNotConsumeFreshObjectError`
- `NormalCancellationAllowsFreshRequest`

The additional queued-object control places a marker between A's old rejection
and B's new rejection: A must remain suppressed while B remains pending, and
B must then receive exactly one error. The normal delivery control proves
errors remain asynchronous across fresh requests. The cancellation control
checks timer cleanup, no callbacks on successful cancellation and fresh
connection completion. Existing browsing replacement and prewarm tests are
preserved. These are native Objective-C++ lifecycle/queue tests with a
substituted central manager, not physical CoreBluetooth commissioning.

### Callback Context and Post-completion Cancellation

`mConnectionAppState` is the opaque caller callback context for tracked
single-result discriminator/object requests, with the layer substituted for
null. It is not an owned allocation. The backend receives the surviving layer
pointer; the terminal trampoline retrieves the original context, clears the
saved state, and then calls the caller. Owner-specific cancellation matches
that saved context, preventing one commissioner from canceling another.
Cancellation detaches it even if the platform operation must still drain.
Plural-discriminator requests forward their context directly and do not use
this slot. A short field comment documents both roles without changing its
representation. Direct reply to Cecille: review reply 4332767728.

`ReleaseCommissioneeDevice` attempts owner-specific cancellation only for
`mDeviceInPASEEstablishment`. Success and error trampolines clear the pending
flag, context and callbacks before notifying the commissioner. Consequently
the subsequent `CancelBleIncompleteConnection(this)` does not match and is
a successful no-op, including when invoked inside the success callback.
This terminal operation is platform BLE connection establishment, not necessarily
PASE completion. Established endpoint cleanup remains the existing separate
`CloseAllBleConnections` branch in `ReleaseCommissioneeDevice`.

The added portable case
`OwnerCancellationAfterCompletionPreservesEstablishedEndpoint` observes actual
callback context and backend cancellation/close counts. It proves no backend
cancellation after success or error, no cancellation of a replacement owner,
and one established endpoint close only when explicit cleanup is requested.
No commissioner behavior change was needed. Direct reply to Cecille:
review reply 4332767848.

All three threads were resolved only after direct replies and evidence.
Copilot reply 4332773948 links both executed Apple runs. Fresh corrected-head
portable results are 40 layer, 17 fallback and 12 pairer cases: 69 passed,
plus the same 69 under ASan with `detect_leaks=1`. No sanitizer/leak or
GLib-critical diagnostics were observed. All verified Linux fallback and
restart regressions remain unchanged and pass. clang-format 16, editor
diagnostics and scoped diff checks pass.

### CI and Qualification Boundary

On `b66db8f83ff`, Darwin simulated job 118997391448, Linux `python_lib`
job 118997391301 and macOS framework TSan job 119001487723 all succeeded.
Those prior-head successes are distinct from the fresh corrected-head
native Apple and portable results above.

At this publication, corrected-head Restyled job 119021329082 passes;
Darwin simulated job 119021500682 and Linux `python_lib` job 119021500583
are executing in workflow 39538731741. Framework workflow 39538731896 is
still building before its TSan tests. These gates are pending, not claimed
as corrected-head successes. The existing watcher remains attached.

No fresh Gemini review or response was present at the review closeout;
no duplicate request was sent. The PR remains OPEN, non-draft and unmerged
at `54af63db0d926b8442973262c1605556b60c3891`. Physical BLE accessory
commissioning, real CoreBluetooth delivery, Thread Meshcop and other backend
or arbitrary delegate-lifetime qualification remain outside the evidence.
