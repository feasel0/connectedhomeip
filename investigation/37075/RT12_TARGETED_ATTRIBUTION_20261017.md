# Targeted RT_1_2 Attribution: 2026-10-17

## Current Reconciliation: 2026-10-18

The Ubuntu/Nordic same-process RT_2_1 campaign is closed: 100 requested and
executed, 99 PASS, one FAIL (iteration 75), zero unfinished, native exit 0.
`finished.json.result`, `endurance.json` and the external closeout agree on all
100 native records. The older `current.json` is a stale running checkpoint,
not the completion authority. The historical running observations below remain
unchanged and must not be read as current fixture ownership.

Iteration 75's PASE failure is now attributed to cross-fixture discovery:
Nordic discriminator 3840 and the concurrently opened Wi-Fi Pi window's 4021
both map to manual-code short discriminator 15. All 12 matched message headers
and counters on exchanges 54314/54315 match that Wi-Fi DUT. Pinned
`SetUpCodePairer` starts DNS-SD discovery even for BLE commissioning. The
internal `0xAC` PAKE2 MAC failure is translated to the generic Python `0x03`
pairing failure; the latter is not proof of stale commissioner state. The
original FAIL remains FAIL. BLE completion details remain unresolved.

For the independent serialized RT_1_2 diagnostic, TH-2's last successful IM
status counter 223246083 was received by the DUT at epoch 1792242562.989;
the DUT removed the corresponding MRP entry and processed IM success. The next
TH-2 report counter 47688567 was not logged for send until 1792242569.767,
6.778 seconds later. Four explicit retransmits followed. The controller first
logged that report after its timeout and then acknowledged it. This is not a
missing acknowledgment for the previous chunk, nor packet-absence proof.

The sealed DUT log (SHA-256
`ddc01b92b90544a0eec40222ff2ecb4cc646f98443a768df4a1de94d8a19e6b8`)
adds a narrower scheduling observation: between epochs 1792242562.6 and
1792242570 there are 18 report confirmations, 18 build markers and 18 report
sends, plus continuing inbound IM statuses and standalone acknowledgments.
Every confirmation logs three reports still in flight. Pinned SDK
`24a1bc052a7dfd3db809e43bb0da7c93b20bfad6` decrements that count before
logging it, so these are repeated four-to-three credit releases. Its reporting
engine serves active handlers round-robin subject to a shared in-flight limit.
The last build marker before the late TH-2 send is at 1792242569.756, only
11 ms earlier, with no intervening build marker. These observations favor
waiting for scheduling/eligibility amid report traffic over a single
6.778-second report-construction call. The retained Linux DUT ELF is separately
bound to reproduction SHA-256
`cbc6f50f2641ec5d93fdf074e2890ce8d5363fe3dce641e325bdfc1ad0ff947b`:
`Engine::Run` at `0x52a97c` loads the in-flight field, compares against three
at `0x52a980`, and branches out on unsigned greater-than at `0x52a984`.
This verifies the deployed four-report gate independently of source defaults.
Handler-state logs still lack individual identity, so exact TH-2 queue
residence remains unproved. No SDK fix or timeout increase is justified yet.

TH-3's later Busy is distinct: subscription recovery on fabrics 2/3/4 starts
concurrent forced CASE attempts after their report timeouts. Pinned
`CASESessionManager` coalesces callers by `ScopedNodeId`, including fabric, and
`OperationalSessionSetup::Connect` queues callers while that peer is connecting.
It does not serialize the same physical DUT across different fabric peers.
TH-3 therefore shares its fabric's establishment failure before issuing an IM
ReadRequest while another fabric is accepted. Busy/backoff is consistent with
that design; evidence does not establish a lost retry or coordination defect.
The hash-matched ARM64 controller library contains automatic retry calls, so
retry support is not compiled out. Its actual
`ReadClient::EstablishSessionToPeer` call site passes one attempt (`mov w4, #1`
at `0x16732a0`, call at `0x16732ac`). Pinned source consumes that attempt before
connecting, does not replenish it for another one-attempt caller joining the
same setup, and fans failure out when no attempts remain. The subscription
failure callback then closes through its own resubscription backoff, matching
the observed 5,000/7,084/5,592 ms delays. This is an expected one-attempt
establishment plus subscription-retry sequence, not evidence of a lost automatic
retry. It does not establish that every foreground caller requested the same
budget or justify changing production retry policy.

The four decode-status attributes are deliberate UnitTesting server error
paths, not evidence of malformed value decoding. The corrected diagnostic
retains its native FAIL, 13 returned maps and two read errors; returned maps
are not silently relabeled as valid readbacks. Historical accounting remains
80 repaired-mechanism attributions and 78 open outcomes among 158 failures,
with the same five historical IDs below.

A separate Pi-controller/Nordic one-iteration captured RT_2_1 smoke started
2026-10-18 at 18:02:42 UTC and closed at 18:21:40 UTC: one executed, one PASS,
zero FAIL, native exit zero. Its closed captures contain 2,662 Pi BLE ACL packets
and 550 IPv6 packets, with no cleanup error. It uses the original immutable five-PR snapshot,
143 verified source files and the held ARM64 native controller. This tests the
controller-host factor, not all newer QA heads. A separate noncommissioning
archive-path check passed before launch. The same-process 100-iteration campaign
started at 18:22:40 UTC under user service
`pi-nordic-endurance-20261018.service`. At 18:44:52 UTC its original worker and
native child remained alive with one completed iteration, one PASS and zero
FAIL; 99 iterations were not yet complete. This is not a 100-iteration completion
or PASS claim. Seven closed capture segments were hash-verified and archived
privately on the Pi before exact local duplicates are removed. Segment rollover
has gaps and does not establish gap-free packet coverage. Known-host competing
QA/app checks run periodically; they are not global network isolation. Other
commissioning windows must remain closed.

An independent `pi-nordic-closeout-20261018.service` waits for the recorded
coordinator identity, reconciles the final ledger and performs guarded
successful-detail retention. It never starts another test. Interrupted runs are
preserved; failed iterations and adjacent controls are protected. Root-owned Pi
broker HCI copies require an administrator-reviewed prune operation and are not
reported as deleted.

The ten-PR engineering review is already complete. Remaining external gates are
QA PullApprove team configuration, QA527 Restyled infrastructure retry,
SDK74676 Gemini review and normal human approval. They are not hardware PASS
claims or reasons to rewrite the already reviewed PR descriptions.

## Historical Scope and Status: 2026-10-17

Execution is proceeding under the user's acceptance of 65 successful Nordic
endurance iterations as sufficient to start independent investigation. The
100-iteration same-process Ubuntu/Nordic run remains untouched. A read-only
check at 15:39 UTC verified 76 executed, 75 PASS, one FAIL and 24 unexecuted,
original native PID 1421846 and start ticks 221968200. The process has not exited
or been restarted. All 75 selected reset targets have matching mode/stage
callbacks, spanning 21 combinations. All 457 closed capture segments have clean
closure proofs; one segment remains open. Segment boundaries are not gap-free
coverage, and DUT reset acknowledgment is not established by the adapter's
completion message. This is not a claim of 100/100 completion.

Iteration 75 failed in step 2, during initial PASE establishment, before any
random reset-stage selection. The retained stack reaches
`_find_or_establish_pase_if_needed`, `FindOrEstablishPASESession` and
`_establishPASESession`, ending in `ChipStackError` / `0x00000003` (incorrect
state), with preceding internal/timeout errors. This is not attributed to
callback lifetime or a missing selected stage. Its original files, iteration
74 control and eight overlapping closed capture segments are sealed as 38
hash-verified files. The following iteration, 76, subsequently passed on the
same original process. Its closed files and seven overlapping closed capture
segments were sealed separately as 31 hash-verified files, without changing
the original bundle. Shared growing logs and active capture segments were not
copied or modified.

The independent controller Pi and Wi-Fi DUT Pi completed four full-load,
single-iteration diagnostic variants: four executed, zero PASS, four FAIL and
zero incomplete. This was not a broad hardware matrix. All retained
15 additional controllers and the original interaction timeouts. A single
matched pair identifies reproduction, not comparative failure frequency.

## Demonstrated Local Fix

`update_controller_endpoints_mapping` made one deep copy and assigned it to
every controller. Two tests against the actual helper failed because both
controllers shared the same nested state. Moving the deep copy inside the
controller loop gives each controller independent state.

Both regressions now pass; all 107 RT_1_2 unit tests pass. Both tests also fail
against the actual published pre-fix helper method. The two-file fix was reviewed,
committed as `e8fcf309b75db268df0e6b52e35ceb96c9e3def9`, and pushed only to the
`feasel0/matter-qa` fork's existing PR548 branch. GitHub's PR head matches that
commit. Existing non-draft status was retained. Ruff was unavailable on the
publication command's PATH; GitHub subsequently reports Ruff and Restyled PASS.
PullApprove fails because the repository's `test-plan-reviewers` team is absent,
with zero of one required approval. That infrastructure gate is unresolved.
Neither the
active Nordic snapshot nor the unchanged five-PR Pi variant was modified; both
retain PR548 `a550450`. Contribution to native timeouts remains unproved.

## Historical Mismatch Attribution

All five previously generic corrected Ubuntu/Nordic failures now have exact
original log references: 13 Identify/SDK DataVersion comparisons and two
ScenesManagement/FabricSceneInfo comparisons. Values were not exported.

| Failure ID | Iteration | Recorded Predicate |
| --- | ---: | --- |
| `2dc88704967e9345` | 1 | Identify / SDK DataVersion metadata |
| `6ec3f8548b8a83e9` | 2 | FabricSceneInfo twice; Identify / SDK DataVersion once |
| `0d6bf96729f5927d` | 3 | Identify / SDK DataVersion metadata |
| `81d2781f125d012e` | 8 | Identify / SDK DataVersion metadata |
| `bb57845dfbe57338` | 9 | Identify / SDK DataVersion metadata |

PR548 `a550450` addresses these recorded predicates. This does not establish
what a later comparison would have observed. All five original FAIL outcomes
remain FAIL; the historical dossier now maps 80/158 failed outcomes to repaired
mechanisms and leaves 78 open. Attribution is bound to those exact IDs, not
every future read mismatch. Fifteen updater tests pass, and all 15 stored log
references were checked against the extracted originals.

## Physical Experiments

| Variant | Controlled Difference | Verified Outcome |
| --- | --- | --- |
| Upstream baseline | QA `52f3a168841e0fc4940d6c79ece77bd1ccd96730` | 1 executed, 0 PASS, 1 FAIL; all 15 read tasks failed |
| Current five PRs | Same immutable composition used by endurance | 1 executed, 0 PASS, 1 FAIL; all 15 read tasks failed |
| Isolated maps | Current composition plus per-controller deep copy only | 1 executed, 0 PASS, 1 FAIL; all 15 read tasks failed |
| Serialized reads | Unchanged current composition, only read tasks serialized | 1 executed, 0 PASS, 1 FAIL; 13 tasks returned, two raised errors; maximum overlap one |

The baseline reached 15 overlapping native reads. It emitted native timeout
messages before cleanup. The controller had at least 7,191,216 KiB available
memory; maximum sampled one-minute load was 1.59. These measurements do not
support gross controller-host memory/CPU exhaustion, but do not exclude SDK
limits, DUT behavior, network effects, or unobserved short spikes.

The one-factor controls show that map isolation alone does not repair this
failure and that read concurrency affects the observed read-error count.
Thirteen returning tasks are not thirteen verified valid readbacks. These
single diagnostic attempts do not establish equal failure rates or prove
whether the remaining failure belongs to SDK processing, DUT limits,
subscription traffic or the network. No production workaround serializes the
test or weakens its assertions.

### Serialized Read Lifecycle

The sealed controller and DUT logs identify distinct mechanisms for the two
errors. Controller timestamps below are local UTC-04:00. Exchange ID, protocol,
opcode and message counter are matched across peers; SDK send logging alone
is not treated as wire delivery proof.

- TH-2 started at 09:08:50.524 and failed at 09:09:33.621 with timeout
	`0x00000032`. ReadRequest exchange `12712`, controller session `16494`,
	message counter `223246027` has matching DUT receive records. The controller
	received 28 distinct ReportData messages before failure and sent 28 status
	responses. Its last pre-error report was at 09:09:22.925; the last status
	send was at 09:09:22.980. Five later ReportData records repeat counter
	`47688567`, first received at 09:09:33.668, after failure. The DUT records
	sending that counter. This establishes incomplete report progress followed
	by a late report, not the reason for the delay or a missing initial request.
- Several subscription report exchanges also time out around 09:09:33.614.
	Subsequent CASE traffic includes multiple overlapping Sigma1 exchanges.
- TH-3 started at 09:09:33.628 and failed at 09:09:34.246 with
	`0x000000DB` (Busy). There is no matched IM ReadRequest in its task window.
	The controller logs CASE protocol error 4. The DUT explicitly logs an
	existing CASE handshake and sends Busy on exchanges `12714`, `12715` and
	`12718`; matching secure-channel status counters are retained. This is
	CASE/session-establishment contention, not evidence of IM read-handler
	exhaustion. Exact TH-3/background-attempt association remains to be checked.
- TH-4 through TH-16 each have one matched read request and 47 distinct
	ReportData counters. Original `gather` raises on the two errors before the
	consistency comparison or any fresh written-value verification. Those
	response dictionaries and their decode/path status were not retained in the
	sealed logs; 13 returned tasks cannot retrospectively become 13 valid reads.

One separate serial, single-iteration read-shape diagnostic completed after
identity/runtime checks, retaining all 15 controllers, original source,
timeouts and native assertions: 1 executed, 0 PASS, 1 FAIL, 0 incomplete,
native exit 1. TH-2 timed out; TH-3 and TH-4 returned Busy. TH-5 through TH-16
returned mappings with five endpoints, 1,390 attribute paths, all 29 written
paths present and no malformed hierarchy. Each contained four decode failures
on endpoint 1, vendor test cluster `0xFFF1FC05`, attributes `0x31`, `0x32`,
`0x3001` and `0x402A`. These are new observations, not reconstruction of the
original 13 responses. The production comparator and verifier were skipped.

That diagnostic's separate fresh-verifier observations are invalid: it called
the original verifier without production's preceding cache update. The verifier
requires fresh presence/decode but compares cached attribute values. Its 12
reported verification failures cannot establish 12 written-value mismatches.
The original diagnostic and native FAIL remain preserved. Its service closed,
DUT process was absent, exact authorization was removed and private key deleted.

A corrected, separately counted serial diagnostic closed at 15:30 UTC with
1 executed, 0 PASS, 1 FAIL, 0 incomplete and native exit 1. It reproduced
TH-2 timeout and TH-3 Busy. Actual maximum read overlap was one. Its isolated
cache follows production's update-then-verify order; tests establish that the
original cache and assertion path remain unchanged.

All 13 returned mappings below have five endpoints, 1,390 attribute paths,
all 29 written paths present, no malformed hierarchy and the same four vendor
test-cluster decode failures identified above. The last column is diagnostic
fresh written-value verification, not the skipped production comparison.

| Controller | Fresh Values PASS | FAIL | Skipped |
| --- | ---: | ---: | ---: |
| TH-4 | 29 | 0 | 0 |
| TH-5 | 29 | 0 | 0 |
| TH-6 | 29 | 0 | 0 |
| TH-7 | 29 | 0 | 0 |
| TH-8 | 29 | 0 | 0 |
| TH-9 | 29 | 0 | 0 |
| TH-10 | 29 | 0 | 0 |
| TH-11 | 29 | 0 | 0 |
| TH-12 | 29 | 0 | 0 |
| TH-13 | 29 | 0 | 0 |
| TH-14 | 29 | 0 | 0 |
| TH-15 | 29 | 0 | 0 |
| TH-16 | 29 | 0 | 0 |

These 377 successful written-value observations do not establish validity of
every returned attribute, cross-controller consistency, or the contents of the
original unrecorded 13 dictionaries. Both probes use native controller/DUT logs,
not new packet captures. Both services closed; no owned DUT process remains,
and both exact temporary authorizations/private keys were removed. Their
driver hashes are `3e9be5568aa6584fa1f11e9399b97c66b731747e5020f9ea94db098f9bfdf9f6`
and `a0d6a3daf6bbffed17627ff18ddaf9e5cb443a78fb820e5a51f051b1f7e5d2eb`.
The four original variants plus these two diagnostics are six executed native
iterations, zero PASS, six FAIL and zero incomplete. Caps 2/4/8 have not been
launched: serial execution still has transport failures, and diagnostic validity
needed resolution first. No production scheduling fix or SDK change was made.

The DUT logged over 1,700 TLV `No memory` events in each concurrent variant.
The identified sources return that code for disabled buffer chaining or
insufficient remaining encoded space, not only allocator failure. Such report
chunk boundaries are not evidence of heap exhaustion. No speculative SDK
memory change was made. Controller RSS uses the Pi's actual 16-KiB page size.

## Evidence and Limitations

Private experiment root: `/home/feasel/qa-mar6/rt12-followup-20261017` locally;
`/home/feasel/matter-rt12-followup-20261017` on the controller Pi. Its manifest
hashes every Python source in each snapshot. The remote driver SHA-256 is
`ffa4e2d74b35e3f3ed0c7ab34c7f43b5b04dfe5d2e35aeedc27109fa4821fa14`.
The DUT binary SHA-256 is
`cbc6f50f2641ec5d93fdf074e2890ce8d5363fe3dce641e325bdfc1ad0ff947b`.
The controller native library remains the verified ARM64 runtime, not a new
SDK build. Both Pi machine identities were verified before launch.

The original separate DUT's normal-user Wi-Fi capture was bounded to a
16-by-16-MB ring. It started after baseline commissioning began, so baseline
capture coverage is partial. Eight stable segments, 127,514,604 bytes, were
sealed at the first observed closed-variant boundary; they can include the
following variant's prefix. Active files were excluded. Raw packets and logs
stay private. The installed decoder recognized 13,732 Matter packets but no IM
read/report/status fields in the sealed baseline segments. Authenticated
Matter decoding remains unverified; those packets cannot yet decide read
delivery or processing ownership.

Capture closure exited zero and reported 1,198,947 packets captured,
1,218,145 received by the filter and 19,156 kernel drops. Packet coverage is
therefore incomplete in addition to the partial baseline start and ring
boundaries. Absence from this capture is not proof of non-delivery.

The installed patched Pi btmon hash matches the separately verified live
discovery-capture receipt: eight HCI records decoded, growing capture, exit 0
and clean stop. This is not commissioning/ACL coverage and does not repair
historical capture loss. These on-network variants do not require BLE.

A durable event-driven closeout sealed stable capture segments at each variant
boundary. At 13:11 UTC the experiment service was inactive, no owned DUT process
remained, the exact capture was stopped, the temporary authorization was
removed and the campaign private key was deleted. Both closed evidence bundles
and every included object hash were verified locally:

- Controller archive SHA-256:
	`8ec3b4f1a46a52c0d4327391840e1b3bf9df30d902e3c8358c595c33c97a1e3b`.
- DUT capture archive SHA-256:
	`9498ca10157c2ced7f92500c71941ea0a809c5d6b07b17701e1843bcea053858`.

Collection excludes SSH private keys and controller storage. The disk reserve
guard blocked an expanded duplicate; collection resumed using streamed object
verification, preserving archives and originals. Only the newly created,
verified unpacked duplicate was removed. All four runs failed, so none is
eligible for successful-run detail pruning. Failed/shared evidence is retained.
The guarded success-only pruner subsequently removed 2,050 closed successful
detail files, retaining summaries/counts and reclaiming 827,408,384 allocated
bytes. All 15 historical failure references were revalidated afterward.
No active-run or failed-original detail was removed. Free disk was 9.03 GiB at
14:45 UTC and 8.76 GiB at 15:39 UTC, above the protected 8-GiB reserve. A regression
also exposed and repaired retention of exclusive archived successful details
after their originals were gone. Shared and catalog-referenced failure copies
remain protected; all 16 retention tests pass. The expanded guarded plan found
no further eligible deletions.

## Next Deciding Work

The concurrency control narrows, but does not resolve, full-load reliability.
Next compare exact read/report timelines and subscription traffic using an
authenticated decoder or equivalent correlated native traces. Do not increase
timeouts, reduce the controller cohort, or turn serialization into a passing
claim. Historical BLE/BlueZ/IPv6 and native-crash families remain open in the
living queue; this targeted set did not start another hardware matrix.