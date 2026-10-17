# All PRs that address 37075 or were created while investigating that issue

## Current Fix Index: 2026-10-17

**ADDRESSED** means work in a PR fixes the named defect, not that the PR has
merged, all hardware gates pass, or every #37075 symptom is solved. Use the
[original failure dispositions](LOG_CATALOG.md#current-dispositions-2026-10-16),
[QA follow-up dispositions](PR539_FAILURE_ANALYSIS_20261011.md#current-failure-dispositions)
and [SDK matrix dispositions](SDK74676_HARDWARE_MATRIX_20261013.md#current-failure-dispositions-2026-10-16)
as the current backlog; historical FAIL outcomes remain unchanged.

The later fixes supplement the original PR inventory below:

| PR | Identified Defect | Current Disposition |
| --- | --- | --- |
| [QA539](https://github.com/CHIP-Specifications/matter-qa/pull/539) | IP prerequisite before unprovisioned BLE; secondary-window discriminator | **ADDRESSED**, published head `b99759a`; 36 tests and 22 passing BLE-Wi-Fi outcomes. |
| [QA544](https://github.com/CHIP-Specifications/matter-qa/pull/544) | Arithmetic XML bounds fail during payload generation | **ADDRESSED**; nine focused tests, full hardware matrix not rerun. |
| [QA545](https://github.com/CHIP-Specifications/matter-qa/pull/545) | Nordic reset/reboot reports success without fresh UART evidence | **ADDRESSED** in the adapter; successful corrected-firmware validation pending. |
| [QA547](https://github.com/CHIP-Specifications/matter-qa/pull/547) | Valve DefaultOpenLevel ignores live LevelStep | **ADDRESSED**; eight tests and 11 passing bulk outcomes. |
| [QA548](https://github.com/CHIP-Specifications/matter-qa/pull/548) | Invalid read equality, cached write verification and shared controller maps | **ADDRESSED**, published head `e8fcf30`; fresh 107-test PASS. Active endurance still uses `a550450`. Full-load native failures remain open. |
| [QA549](https://github.com/CHIP-Specifications/matter-qa/pull/549) | Registered ctypes callback ownership and failure cleanup | **ADDRESSED**; six tests and combined 11/11 with QA550. Historical SIGSEGV causality remains open. |
| [QA550](https://github.com/CHIP-Specifications/matter-qa/pull/550) | Unreachable SecurePairing reset callbacks and unpropagated reset errors | **ADDRESSED**, head `2b0feed`; nine tests and combined 11/11 with QA549. |
| [SDK74676](https://github.com/project-chip/connectedhomeip/pull/74676) | BLE scanner local lifecycle and native-error propagation | **ADDRESSED**, head `6ebed18`; 59 ordinary and nine isolated native tests. No BlueZ recovery guarantee. |

QA527 addresses the demonstrated stale-session/cleanup defect; QA528 adds
topology detection, not a guarantee of healthy Thread routing/publication.
QA527 `bd92c96` has a fresh 64-test cleanup PASS, including actual RT_1_2
primary-error preservation after diagnostic and cleanup failures. It is not in
the active five-PR snapshot. QA545 `a6ff4c1` is also absent from that snapshot.
Iteration 75 failed before QA549/550's selected-stage paths; the demonstrated
condition is wrong-peer PASE caused by shared short-discriminator discovery,
not evidence that those callback fixes failed. See the
[current continuation](../reports/2026-10-17_18-26-24.md). Historical attribution
remains 80 addressed/78 open, with original FAIL outcomes retained.
Backend385/386 are **PARTIALLY ADDRESSED** goals: their unchanged heads retain
the [fresh review's five OPEN findings](PR385_PR386_FRESH_REVIEW_20261007.md).
Native read/subscription/PASE failures, the original missing CASE response
after AddNOC, historical crash attribution and capture deployment/coverage
remain open as specified in the linked disposition tables.

**matter-qa** | PR | Purpose | |---|---| |
[#527: Failure-safe Darwin, Android, and RT pairing cleanup](https://github.com/CHIP-Specifications/matter-qa/pull/527) | Prevent failed iterations from leaving stale controller sessions, subscriptions, BLE state, or unhandled fabrics. | |
[#528: Validate Thread topology before commissioning](https://github.com/CHIP-Specifications/matter-qa/pull/528) | Compare the complete controller dataset with the live OTBR and detect contradictory DUT network identity. | |

**certification-tool-backend** | PR | Purpose | |---|---| |
[#385: Persist Thread Active Dataset with reusable commissioning state](https://github.com/project-chip/certification-tool-backend/pull/385) | Restore the exact Thread network consistently with reused controller/DUT state. | |
[#386: Generate unique Thread defaults for new projects](https://github.com/project-chip/certification-tool-backend/pull/386) | Give new projects distinct network credentials and identities, reducing neighboring-fixture interference. |

**connectedhomeip** These SDK improvements resulted from the investigation; they
are not blanket fixes for every #37075 failure.

| PR                                                                                                                        | Purpose                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| [#74430: Skip premature baseline CASE lookup](https://github.com/project-chip/connectedhomeip/pull/74430)                 | Avoid querying an uncommissioned/default DUT before configured commissioning, eliminating misleading framework-generated timeouts. |
| [#74431: Log Thread state when operational advertising fails](https://github.com/project-chip/connectedhomeip/pull/74431) | Include provisioned/attached state in advertising-failure diagnostics without retrieving or logging dataset credentials.           |
| [#74432: Add peer and stage context to discovery failures](https://github.com/project-chip/connectedhomeip/pull/74432)    | Identify the fabric/node, elapsed lookup time, and absence of a usable operational address.                                        |

We also opened
**[SDK issue #74436](https://github.com/project-chip/connectedhomeip/issues/74436)**
for platform DNS-SD failure callbacks losing the requested `PeerId`. That is an
issue, not an implemented fix or PR.


# Preventing 37075 from happening again

**Not All Occurrences**
Even with your definition of “solving,” I would **not promise that merging #527 and #528 will eliminate every #37075 symptom**.

- **#527 fixes the demonstrated harness cleanup defects:** failed iterations should no longer leave stale controller sessions simply because an earlier cleanup operation failed.
- **#528 catches certain network mistakes earlier:** controller-versus-live-OTBR dataset mismatch before commissioning, and contradictory DUT Extended PAN ID after `ConnectNetwork`, when readable.
- **Neither guarantees a healthy Thread network.** Matching datasets do not prove working SRP, OMR routing, operational advertising, or controller reachability. Those failures can still produce the original discovery timeout.
- **#528 is opt-in.** Merging it changes nothing for existing configurations unless the team enables it and configures access to the correct OTBR. Without usable DUT diagnostics, it also cannot guarantee detection of unintended attachment.

Importantly, the October evidence demonstrated unintended attachment and missing SRP/routing. We **did not retain the intended OTBR’s contemporaneous complete dataset**, so we cannot honestly say #528 would have converted every one of those historical failures into a preflight error.

**What To Change**
The biggest practical improvement is to make each fixture’s Thread network **isolated, authoritative, and persistent**, instead of relying on operators to keep several independently configured pieces consistent.

1. **Unique credentials per RF-visible fixture.** Generate a complete network configuration for each test cell, particularly a unique Network Key and Extended PAN ID. Changing only the network name or channel is not sufficient. Audit existing fixtures, not just newly created ones.

2. **Use the intended OTBR as the dataset authority.** Read its complete live Active Dataset and supply those exact bytes to the controller. Do not reconstruct it from a handful of fields, use a remembered example, or copy another fixture’s YAML.

3. **Keep network state and commissioning state together.** When recreating an OTBR, restore the exact dataset associated with reusable controller/DUT state. Otherwise deliberately start a fresh campaign with fresh controller state and reset DUTs. Do not combine old controller storage with a newly generated network.

4. **Enable #528 and verify that validation actually ran.** Check for a successful dataset-preflight result, not merely a `True` YAML value. An unavailable adapter or optional DUT diagnostic is not equivalent to successful validation.

5. **Require a complete commissioning smoke before scaling.** Check SRP, OMR routing, operational discovery, and successful CASE interactions from the actual controller host. For Darwin Pair, require both fabrics to complete. Dataset equality alone is too weak a readiness gate.

6. **Verify resets and stop infrastructure cascades.** Confirm fresh DUT boot/BLE readiness, keep one UART owner, and watch USB continuity. After a confirmed disconnected DUT or failed reset, preserve evidence and repair the fixture instead of accumulating dozens of misleading protocol failures.

Use fresh controller storage **between campaigns**, not every iteration. Restarting controllers or randomizing the reused peer every iteration can conceal the cleanup defect instead of testing its correction.

**Beyond Those PRs**
I would recommend the two backend changes alongside #527/#528:

- [Backend #385](https://github.com/project-chip/certification-tool-backend/pull/385): persist and restore the complete dataset with reusable commissioning state.
- [Backend #386](https://github.com/project-chip/certification-tool-backend/pull/386): generate unique defaults for new projects. Existing or copied configurations still need an explicit audit; project uniqueness does not automatically mean fixture uniqueness.

I would also give the team a short, enforced startup checklist and failure-collection procedure, based on `STRESS_TEAM_RECOMMENDATIONS.md`.

I’d frame the handoff as **“the harness and fixture workflow allowed these failure modes,”** not “you were definitely doing something wrong.” We proved a harness defect and demonstrated problematic network attachment. The prevention work is to remove shared-default networks, inconsistent persistence, and weak readiness checks from their daily workflow.