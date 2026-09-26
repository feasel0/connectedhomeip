# Issue #37075 stress-team recommendations

## 1. Executive summary

The retained #37075 failures do not represent one defect. At least two failure
mechanisms have been demonstrated independently:

**A. Thread topology/network-state failure.** The DUT can attach to unintended,
credential-compatible Thread infrastructure. That environment does not provide
the intended SRP and border-routing path, so the DUT's operational identity is
not discoverable. The controller then reports
`AddressResolve_DefaultImpl.cpp:124` / `CHIP_ERROR_TIMEOUT (0x32)`.

**B. Controller/session cleanup failure.** `AddNOC` succeeds, a later operation
fails, and cleanup/session expiration is incomplete. Because the second-fabric
peer identity is fixed across iterations, stale CASE/address state can be
reused. Encrypted commands are then sent toward an old DUT address until
`CommandSender` times out.

Other #37075 timeout subtypes exist. The retained January iteration 99, for
example, times out during CASE establishment. The evidence does not support
assigning every timeout to either mechanism above.

## 2. Evidence strength

### Proven from retained historical evidence

- October 2025 iterations 47-50 attached to Thread environments different from
  the immediately adjacent passing environment. They found no SRP server,
  obtained no usable intended OMR path, logged
  `Operational advertising failed: 3`, and ended in the exact
  `AddressResolve_DefaultImpl.cpp:124` timeout. Iterations 46 and 51 used the
  usable partition, found SRP, advertised successfully, and passed.
- The controller supplied the same complete dataset in iterations 46-51. Its
  safe SHA-256 prefix was `9d3f2cbfa7a50d90`; no raw dataset is reproduced
  here.
- February 2025 iteration 7 reused an existing CASE session for the fixed
  second-fabric peer identity. Controller and OTBR captures show encrypted
  retransmissions sent to old address
  `fd5c:ece7:589:1:8c0d:4946:fa5:eb26`, while the current DUT used
  `fd5c:ece7:589:1:b808:da10:9c1c:4ffe`. The command timed out in
  `CommandSender.cpp:343`.
- The historical harness cleanup path could stop before later controllers were
  cleaned, and an `UnpairDevice` exception could prevent local session
  expiration. This is the lifecycle gap addressed by matter-qa #527.

### Supported inference

- The October DUTs most likely selected RF-visible certification-style Thread
  parents whose networks were credential-compatible with the provisioned
  network. The changing final names, PAN IDs, channels, and partitions, together
  with the shared final Extended PAN ID, support this explanation.
- In February iteration 7, stale controller state most likely survived an
  earlier incomplete failure cleanup. The retained capture proves stale session
  and address reuse; it does not capture the exact earlier operation that left
  the state behind.

### Not proven / unavailable evidence

- The October evidence proves unintended attachment to credential-compatible
  Thread infrastructure. It does **not** prove a byte-for-byte mismatch between
  the historical controller dataset and the intended OTBR's contemporaneous
  complete Active Dataset, because that OTBR dataset was not retained.
- No October OTBR log or 802.15.4 capture identifies the exact parent/router
  selected by the failed DUTs or shows the dataset exchange over the air.
- A Thread partition ID is dynamic topology state. It is not Operational Dataset
  identity and must not be used as a substitute for complete-dataset equality.
- January iterations 78 and 99 establish command-delivery and CASE-handshake
  timeout stages, respectively, but the retained evidence does not prove their
  packet drop locations or root causes.

See [LOG_CATALOG.md](LOG_CATALOG.md) for the retained failure inventory and
[HARNESS_RESET_AUDIT.md](HARNESS_RESET_AUDIT.md) for the harness comparison.

## 3. Historical October failure sequence

The controller supplied one unchanged dataset in iterations 46-51: Network Name
`OpenThreadGRL`, PAN ID `0x1234`, Extended PAN ID `1111111122222222`, channel
15, and SHA-256 prefix `9d3f2cbfa7a50d90`. The raw dataset and credential fields
are intentionally omitted.

| Iteration | Result | DUT final network | PAN ID | Channel | Extended PAN ID | Partition | SRP / OMR / advertising |
| --------: | :----: | ----------------- | ------ | ------: | --------------- | --------- | ----------------------- |
| 46 | PASS | `Thread Cert 9.2` | `0xFACE` | 23 | `000DB80000000000` | `0x7D35C043` | SRP found; OMR present; advertising succeeded |
| 47 | FAIL | `GRL` | `0xAFCE` | 22 | `000DB80000000000` | `0x08472484` | No SRP or OMR; advertising error 3 |
| 48 | FAIL | `GRL` | `0xFACE` | 21 | `000DB80000000000` | `0x7738DBB4` | No SRP or OMR; advertising error 3 |
| 49 | FAIL | `GRL` | `0xABCD` | 22 | `000DB80000000000` | `0x2DF6DD12` | No SRP or OMR; advertising error 3 |
| 50 | FAIL | `GRL` | `0xABCD` | 22 | `000DB80000000000` | `0x2DF6DD12` | No SRP or OMR; advertising error 3 |
| 51 | PASS | `Thread Cert 9.2` | `0xFACE` | 23 | `000DB80000000000` | `0x7D35C043` | SRP found; OMR present; advertising succeeded |

The passing neighbors discovered SRP server
`fd00:0db9:0:0:4ce7:be90:26e0:f6ce`. The failed DUTs attached as children to
other RF-visible Thread configurations, never produced a reachable operational
advertisement, never received CASE Sigma1 or `CommissioningComplete`, and timed
out after approximately 45 seconds of operational discovery. Iterations 49 and
50 returning to the same failed partition across a factory-reset boundary is
additional evidence of persistent external infrastructure rather than a random
controller dataset change.

## 4. Current reproduction result

The local reproduction used one stable OTBR/RCP network, `Matter37075`. Before
the campaign, the complete live output of `ot-ctl dataset active -x` was read
from that OTBR and those exact bytes were supplied to matter-qa. The raw dataset
was not logged in this handoff. Its safe SHA-256 fingerprint is
`ed2e96c79a37c1f8af308d0867c3adaa3ebf186b5b6d65dc3777617debc04d39`.

The network remained stable at channel 20, PAN ID `0x6213`, Extended PAN ID
`9612ac5946f05eaf`, and partition `0x28CA9D9E`, with a working SRP server and
operational advertisement:

- `TC_Darwin_Pair`: 100 requested, 100 executed, 100 passed, 0 failed.
- `TC_Android_Pair` smoke: 1 requested, 1 executed, 1 passed, 0 failed.
- The first larger Darwin campaign completed 500/500. Later larger-campaign
  failures or interruptions were classified as cleanup or USB/J-Link
  infrastructure events, not the October wrong-network signature.

This is a **negative reproduction in an isolated topology**. It shows that the
historical signature did not recur while the intended complete dataset and
network remained stable; it does not prove that the historical issue no longer
exists in a shared RF environment.

## 5. What the stress team should change immediately

1. Give every concurrently RF-visible test cell unique Thread credentials.
2. Form one intended OTBR network for the cell.
3. Read the actual complete dataset with `ot-ctl dataset active -x`.
4. Pass those exact bytes to matter-qa.
5. Keep that OTBR and network unchanged for the entire stress campaign.
6. Do not independently reconstruct a dataset from only channel, PAN ID,
   Extended PAN ID, Network Name, and Network Key.
7. Do not reuse controller storage after OTBR recreation unless the exact
   corresponding complete Active Dataset is restored.
8. Before commissioning, require byte-for-byte equality between the controller
   dataset and the live intended OTBR dataset. Record only a cryptographic
   fingerprint and non-secret identity fields in ordinary logs.
9. After `ConnectNetwork`, where DUT diagnostics permit it, compare the DUT's
   Extended PAN ID with the intended network and classify a mismatch immediately.
10. On failure, capture the intended OTBR complete-dataset fingerprint; Network
    Name, channel, PAN ID, and Extended PAN ID; partition ID; Thread role; SRP
    state; OMR/border-routing state; DUT Thread identity when obtainable; and
    802.15.4 evidence when unintended attachment is suspected.
11. Use fresh controller state or a correctly persisted controller/dataset
    bundle according to the campaign lifecycle.
12. Record exact connectedhomeip, matter-qa, certification-tool-backend,
    OTBR/OpenThread, NCS/DUT, and RCP revisions for every campaign.

## 6. Recommended causal experiment

Run matched campaigns with the same DUT, harness, reset cadence, software, and
capture settings:

**A. Existing/shared/default lab Thread setup.** Preserve the current shared or
default credential behavior.

**B. Isolated canonical setup.** Assign unique credentials, form one intended
OTBR network, make its complete Active Operational Dataset canonical, and pass
the exact live dataset to matter-qa.

For both arms, capture 802.15.4 traffic, parent/router identity, LeaderData and
partition, complete-dataset identity by safe fingerprint and decoded non-secret
fields, SRP state, OMR/border-routing state, and operational discovery.

The topology hypothesis is strengthened if arm A reproduces attachment to a
different parent/network followed by missing SRP/OMR, failed publication, and an
operational-discovery timeout while arm B remains on the canonical network. It
is weakened or refuted if the timeout reproduces while controller, live OTBR,
and DUT dataset identity agree, the DUT remains attached to the intended parent,
and SRP, OMR routing, and operational publication are all healthy. Classify any
such result at its actual failing stage rather than forcing it into the topology
category.

## 7. Remediation PRs

### [matter-qa #527: Failure-safe cleanup](https://github.com/CHIP-Specifications/matter-qa/pull/527)

Registers cleanup ownership immediately after `AddNOC`, rather than waiting for
`CommissioningComplete`; cleans both controllers independently; expires local
sessions even when `UnpairDevice` fails; and makes subscription and BLE cleanup
failure-safe. It preserves the fixed second-fabric identity and fixes its
lifecycle instead of avoiding reuse.

### [matter-qa #528: Thread validation and diagnostics](https://github.com/CHIP-Specifications/matter-qa/pull/528)

Compares the controller dataset byte-for-byte with the intended OTBR's complete
live Active Dataset before commissioning; records only safe dataset
fingerprint/identity and topology diagnostics; and, after `ConnectNetwork`,
compares the DUT Extended PAN ID where available. A detected mismatch is
classified immediately instead of waiting for operational discovery. If DUT
Thread diagnostics are unavailable, OTBR preflight cannot prove which parent or
partition the DUT selected, so platform diagnostics or 802.15.4 capture remain
necessary.

### [certification-tool-backend #385: Complete Active Dataset persistence](https://github.com/project-chip/certification-tool-backend/pull/385)

Treats reusable controller state and Thread network state as one bundle. It
persists and restores the exact complete Active Dataset when OTBR is recreated,
preventing old `admin_storage.json` from being silently paired with a fresh
random dataset. The live destroy/recreate/reuse test remains outstanding because
the only available RCP is occupied by the Matter37075 environment; see
[PR385_INTEGRATION_VALIDATION_20260926.md](PR385_INTEGRATION_VALIDATION_20260926.md).

### [certification-tool-backend #386: Unique new-Project defaults](https://github.com/project-chip/certification-tool-backend/pull/386)

Stops newly created Projects from inheriting one shared Thread identity by
generating a random Network Key, Extended PAN ID, PAN ID, and Network Name when
the backend supplies defaults. Explicit, imported, and existing Project
configurations remain unchanged. This is per-Project isolation, not enforcement
of one Project per physical fixture.

All four PRs are Drafts and address separate parts of the investigation. None
alone fixes every timeout reported under #37075.

## 8. Remaining limitations / follow-up

- On upstream main, standalone `otbr_start.sh` still creates a new dataset on
  each invocation and uses its own fixed credential model.
- PR #385 overlaps that path and already improves secret handling and complete
  dataset capture. Further standalone-script persistence work should wait for
  that PR's disposition.
- Per-Project uniqueness does not stop users from explicitly copying or sharing
  configurations across physical fixtures.
- No historical 802.15.4 packet capture proves the exact parent/router identity
  selected during the October failures.
- PR #385's live destroy/recreate/reuse validation remains pending because the
  sole RCP is occupied by the Matter37075 environment.
- The October intended OTBR's contemporaneous complete Active Dataset was not
  retained, so historical byte-for-byte controller/OTBR comparison is
  impossible.

## 9. Bottom line

**Thread topology defect:** compatible neighboring networks plus insufficient
dataset/network authority allow the DUT to land on unintended Thread
infrastructure, leading to failed operational publication and an operational
discovery timeout.

**Cleanup defect:** a failure after commissioning plus incomplete session
cleanup allows stale controller session/address reuse, leading to a later
command timeout.

Both can surface under the same broad stress-test failure reporting. Classify
failures by protocol stage and retained evidence, not solely by timeout text.