# CSA Matter QA — 24–48-hour hardware reliability matrix

**Document type:** Approved investigation/test-design plan; **not** an execution record.  
**Intended tracked repository path:** `investigation/WEEKEND_MATRIX_PLAN_2026-10-24.md` on `feasel0/connectedhomeip`, branch `investigation/2026-10-17` (or its verified successor).  
**Scope:** Original commissioning investigations [#37075](https://github.com/project-chip/connectedhomeip/issues/37075), [#38750](https://github.com/project-chip/connectedhomeip/issues/38750), [#39503](https://github.com/project-chip/connectedhomeip/issues/39503), and failures found by the earlier associated hardware matrices.  
**Planning date:** 2026-10-24 UTC. The worktree, current upstream revisions, PR inventory, hardware availability, and case applicability must be verified by Copilot before execution.  
**Execution window:** 24-hour checkpoint; **48-hour maximum wall-clock campaign budget**, including mandatory safe closeout. The target number of cases may require more time than the budget permits. No shortfall is to be hidden.

> **Locked policy:** Use a clean, frozen upstream `CHIP-Specifications/matter-qa` `main` and `project-chip/connectedhomeip` `master` baseline. **Do not preemptively integrate any open PR.** Compare a relevant PR or minimal dependency-complete PR set only in an isolated, explicitly labeled A/B run after a matching baseline failure. Preserve historical investigation results independently of the new campaign. Do not run test hardware until the source/evidence consolidation and all preflight gates are complete.

## A. Fixed decisions and boundaries

1. **One authoritative research branch:** `feasel0/connectedhomeip` investigation branch. Consolidated, sanitized high-level historical catalog/status/evidence summaries are **tracked and committed** in the root of `investigation/`; detailed material lives in subdirectories. Do not erase evidence-bearing branch history or other agents' work.
2. **Two ledgers with no shared denominators:** the historical 158 FAIL / 80 mapped to addressed mechanisms / 78 OPEN remains immutable; this campaign starts with **0 executed, 0 PASS, 0 FAIL** and unique run/iteration IDs. A new occurrence of a historical signature gets a new campaign ID cross-linked to the old ID.
3. **Plan vs live summary:** this Markdown plan is intended to be **committed** into `investigation/`. The campaign's mutable `investigation/campaigns/2026-10-weekend/LIVE_SUMMARY.md` should remain deliberately **untracked/dirty in local `git status`**, never staged or committed while the batch runs. Machine-readable ledgers/receipts and raw traces are kept in an approved **external, private** campaign root, not in Git.
4. **Baseline:** freshly fetched and verified upstream `matter-qa/main` plus `connectedhomeip/master`, built reproducibly into immutable snapshots. Record checkout SHA **and** actual loaded Python, shared library, app, firmware and package hashes. No open PR in the default baseline.
5. **Fixture-only adaptations:** permitted only when unavoidable to launch and observe upstream tests; they must be narrowly scoped, independently validated, listed per run, and not silently modify test assertions/protocol behavior. If the only way to run the baseline changes tested behavior, label it an *adjusted baseline* and preserve the pristine upstream counterexample.
6. **PR differential:** after a matching baseline failure, test one relevant PR/validated dependency set against exactly the same frozen upstream base, hardware/case/transport and configuration. Do not silently replace the baseline or mix A/B results. No PR older than four calendar months at selection time; for the October 23 planning checkpoint this is **created on/after 2026-06-23**. Recalculate cutoff at actual launch. Draft/non-draft flag alone does not establish readiness.
7. **At least ten iterations per *applicable, admitted* cell.** Additional stress runs are assigned explicitly below. A non-applicable or capability-unqualified combination is `EXCLUDED` or `GATED`, never PASS or FAIL. Once admitted, an incomplete 10-iteration block remains **unexecuted/incomplete**, not silently reduced to satisfy a time cap.
8. **24–48 hours means bounded unattended operation:** record progress at 24 hours. At 48 hours, initiate safe stop/closeout, preserve running failure context, and honestly report unfinished planned cells. Do not override native Matter deadlines to make more tests pass. Do not presume the entire expanded 1,110-iteration plan fits in 48 hours without measured throughput.
9. **Avoid RF interference:** tests share commissioning discovery even across host/process locks. Use one global RF/commissioning-domain owner or genuinely demonstrated isolation. The historical Nordic/Pi short-discriminator collision is proof that separate host locks alone are insufficient.
10. **No PR administration during the batch:** no merges, undrafts, force-pushes, branch resets, production fixes, data-model work, or modification of other agents' worktrees. A candidate A/B uses isolated source/build/fixture ownership, never an in-place patch to the active campaign.

## B. Required cleanup/preflight gates

Before the batch, Copilot must read the installed Matter laboratory/hardware-operation skills and fixture procedures, then the separate investigation-consolidation task must provide the following, or document any blocker before launch:

| Gate | Required evidence |
| --- | --- |
| Historical catalog consolidated | `investigation/FAILURE_CATALOG.md`, exact IDs, original result/attribution preservation; totals 158 / 80 / 78 reconciled |
| Top-level investigation status | `investigation/INVESTIGATION_STATUS.md` with established vs suspected mechanisms and current blockers |
| Raw evidence locator | `investigation/EVIDENCE_INDEX.md` with original machine/path, run ID, hashes, coverage limitations and AVAILABLE/UNVERIFIED state; no raw secrets in Git |
| PR registry | `investigation/PR_INVENTORY.md`, live QA and SDK PR ages/HEADs/readiness/dependencies, four-month cutoff; blockers explicit |
| Workspace integrity | Other agents' worktrees and seven previously observed dirty shared files untouched; no stale `git status` changes silently reset |
| Upstream identity | Exact Git remote/ref HEADs for both upstream repositories, checked against fetched originals and immutable executed binaries |
| Campaign identity | New unique campaign ID, receipt/capture root, controller/DUT host IDs, source manifest and failed-evidence retention policy |
| Mutable-path isolation | Exact native embedded paths (including `chip_counters.ini`) redirected/verified **before native import**; original counters seals and corrected isolated mount proof retained |
| Time forecast | Measured wall-time estimates from applicable representative cases, cleanup/capture overhead, and likelihood of completing at least ten iterations per admitted cell within 48 hours |

The current historical investigation branch checkpoint previously reviewed was `f06b825b783391300d67275dad103e1462d7cf77`; **do not reset to this SHA** if consolidation has advanced it. Resolve and record the actual HEAD at the time the plan is installed.

## C. Matrix axes and applicability

| Axis | Dimension(s) | Notes |
| --- | --- | --- |
| Controller | Ubuntu Linux machine; controller Raspberry Pi | Both use their own pinned Python/native Matter stack |
| DUT class | Wi-Fi Raspberry Pi; Nordic nRF52840 DK; nRF USB dongle used as Matter DUT | A USB dongle running OTBR RCP firmware is **not** also a Matter DUT; DUT qualification needs firmware, reset and log/console control |
| Initial pairing transport | On-network; BLE-Wi-Fi; BLE-Thread | Must match the active DUT application and network role; later operational discovery/CASE is over IP |
| Thread Border Router placement | OTBR+controller on same host; OTBR on separate host | Explicit physical host and RCP device ID: Ubuntu, controller Pi or Wi-Fi Pi where not a conflicting DUT |
| USB Nordic DUT host | Ubuntu, controller Pi, Wi-Fi Pi | This is a nested hardware topology property, not an independently multiplied controller choice |
| Matter-QA case | All currently discovered applicable cases; eight previously exercised cases below | Reinventory the current QA snapshot; do not assume all known scripts still apply unchanged |
| Repetitions | 10 mandatory per admitted cell; selected 15/20/30 targets | Same-process vs process-per-iteration semantics must match the case's real stress design |
| Controlled provenance | QA/SDK binaries, DUT image, NRF serial/MAC, dataset, current BlueZ HCI identity, addressing, logger, storage, capture profiles | Do not vary these inside a matched comparison without recording a new cell/configuration |

### Previously verified eight cases (reconfirm in current upstream)

1. `TC_RT_1_1`
2. `TC_RT_1_2`
3. `TC_RT_2_1`
4. `TC_Send_Command_Read_Write_Attributes`
5. `TC_Darwin_Pair`
6. `TC_Android_Pair`
7. `TC_ON_OFF`
8. `TC_LEVEL_CONTROL` (verify the actual case-sensitive filename)

**Previously excluded, require fresh positive prerequisite check:** `TC_RT_2_2` (second isolated network/route or appropriate network-change fixture), `TC_BDX_OTA` (OTA provider/update image and compatible requestor), `TC_Bridge_Add_Remove` (dynamic bridge DUT). Inventory every other case in current Matter-QA; either admit with a verified supported topology and at least ten iterations, or give an explicit exclusion reason. Do not invent unavailable peripherals or assume user authorization to reflash hardware.

## D. Recommended topology set

The six **core** topologies are supported by previous hardware-matrix precedent but **must be requalified at current source/fixture revisions**. Five additional topologies are **conditional**, not guaranteed supported. Global fixture lock prevents cross-test wrong-peer discovery, even for two physically different DUTs.

| ID | Controller | DUT | Initial pairing | OTBR / Nordic RCP host | Tier | Gate / purpose |
| --- | --- | --- | --- | --- | --- | --- |
| W1 | Ubuntu | Wi-Fi Pi | On-network | None needed | CORE | Baseline Ubuntu-to-Pi operational workflow |
| W2 | Controller Pi | Wi-Fi Pi | On-network | None needed | CORE | Controller-OS/host differential; never controller and Wi-Fi DUT on same Pi |
| T1 | Ubuntu | Nordic DK | BLE-Thread | Ubuntu; cohosted | CORE | Linux controller with colocated OTBR and distinct DK |
| T2 | Ubuntu | Nordic DK | BLE-Thread | Controller Pi; remote | CORE | Remote-host OTBR vs T1; verify Pi RCP/OTBR readiness |
| T3 | Controller Pi | Nordic DK | BLE-Thread | Controller Pi; cohosted | CORE | Pi controller with colocated OTBR |
| T4 | Controller Pi | Nordic DK | BLE-Thread | Ubuntu; remote | CORE | Remote OTBR vs T3; Ubuntu RCP stable |
| B1 | Ubuntu | Wi-Fi Pi | BLE-Wi-Fi | None needed | GATED | Requires BLE-enabled Pi DUT firmware, verified advertising, correct controller adapter, safe DUT reset |
| B2 | Controller Pi | Wi-Fi Pi | BLE-Wi-Fi | None needed | GATED | Same as B1 with Pi controller; don't overwrite active Wi-Fi DUT image without approved snapshot/restore |
| D1 | Ubuntu | nRF USB dongle on controller Pi | BLE-Thread | Ubuntu; cohosted | GATED | Distinct DUT/RCP dongles; Matter-DUT firmware, remote console/reset and capture proven |
| D2 | Controller Pi | nRF USB dongle on Wi-Fi Pi | BLE-Thread | Ubuntu; remote | GATED | USB host is *not* also Wi-Fi Matter DUT; firmware/console/reset proven |
| D3 | Controller Pi | nRF USB dongle on Ubuntu | BLE-Thread | Wi-Fi Pi; remote | GATED | Distinct DUT/RCP dongles, Pi OTBR established; USB-host cross-check |

**Culled/unavailable combinations:**

- Nordic DK or nRF Thread-only dongle with BLE-Wi-Fi; Wi-Fi-Pi Matter application with BLE-Thread absent a distinct Thread-DUT image; same physical Pi as controller and Wi-Fi Matter DUT; same dongle as Thread RCP and Matter DUT simultaneously.
- On-network pairing to a factory-reset Nordic Thread DUT unless it retains or can deterministically re-establish a valid Thread dataset within the *same tested semantics*. Do not change/reset criteria merely to manufacture a cell.
- Extra Pi-hosted OTBR placements for the DK when the same **colocated-vs-remote** distinction is already covered by T1–T4. Reopen a culled placement only if platform-specific evidence suggests a real new mechanism.
- The other USB dongle/USB-host/OTBR permutations once D1–D3 establish each materially different class. Retain them in a proposed expansion catalog with explicit reason, not as silent missing cells.
- Unsupported QA scripts, mismatched app capabilities, unavailable second Thread network, absent OTA server/artifacts or bridge DUT.

If Copilot proves that a topology's capabilities were only assumed, mark it **GATED** and do not count it as part of the mandatory executable denominator until admission. If a CORE topology is unavailable, flag it as a coverage blocker, not as a failure or an unqualified PASS.

## E. Iteration targets and 24–48-hour admission policy

### Per-test repetition tiers

| Test case | W1/W2 (per topology) | T1/T3 (per topology) | T2/T4 and every gated topology (per topology) |
| --- | ---: | ---: | ---: |
| `TC_RT_1_1` | 15 | 20 | 10 |
| `TC_RT_1_2` | 10 | 20 | 10 |
| `TC_RT_2_1` | 20 | 30 | 10 |
| `TC_Darwin_Pair` | 20 | 30 | 10 |
| `TC_Android_Pair` | 20 | 30 | 10 |
| `TC_Send_Command_Read_Write_Attributes` | 10 | 10 | 10 |
| `TC_ON_OFF` | 10 | 10 | 10 |
| `TC_LEVEL_CONTROL` | 10 | 10 | 10 |
| **Total per topology** | **115** | **160** | **80** |

#### Targets, not executed counts

| Scope | Applicable cells with the eight known cases | Ten-per-cell minimum | Additional target iterations | Total target |
| --- | ---: | ---: | ---: | ---: |
| Four historical topology classes W1/W2/T1/T3 | 32 | 320 | 230 | 550 |
| Two additional DK/OTBR placement classes T2/T4 | 16 | 160 | 0 | 160 |
| **Six CORE topologies** | **48** | **480** | **230** | **710** |
| Conditional B1/B2 BLE-Wi-Fi | 16 | 160 | 0 | 160 |
| Conditional D1/D2/D3 USB Nordic DUT | 24 | 240 | 0 | 240 |
| **Eleven topologies if all admitted** | **88** | **880** | **230** | **1,110** |

**Admission/throughput control:** the campaign is budgeted to run **24–48 hours**, not necessarily to achieve all stretch targets. At launch calculate a bounded runtime estimate from known historical durations and fresh, separately counted preflight samples, especially `TC_RT_2_1`. Schedule whole ten-iteration cells before optional extra repetitions; interleave topologies to maximize coverage without compromising same-process semantics. Do not claim that the full 710 or 1,110 run target fits without the estimate. If the estimated minimum alone exceeds 48 hours, record an explicit `CAPACITY_GAP`, propose a resumable continuation and preserve the at-least-10 rule rather than quietly reducing repetitions or discarding cells.

**Recommended execution order:**

1. Preflight outside the campaign denominator: check all fixtures/cases, RCP roles, Thread dataset, BLE physical MAC/index and capture/provenance; run one non-counted operational smoke where necessary. Do not conflate smoke success with ten-case qualification.
2. Establish ten-iteration *minimum blocks* on W1, W2, T1 and T3, distributed by test family and host to avoid discovering late that a basic topology was never covered. These are the four previously exercised classes (320 minimum executions).
3. Establish ten-iteration blocks on T2 and T4 to cover colocated vs remote OTBR placement for both controllers (160 minimum additional executions).
4. Add stretch repetitions to W1/W2/T1/T3 toward 710 total, using the above tiers. If a test is consistently failing, still preserve each of its required ten outcomes; don't automatically increase it to 30 identical failures until the mandatory matrix is covered.
5. Admit B1/B2 and D1–D3 only if their firmware/fixture gates are satisfied **and** the remaining time/resource plan allows the complete ten-iteration block. They expand the campaign up to 1,110 executions; otherwise carry forward an explicit expansion queue. If newly discovered cases qualify, add their cells and update forecasts before admission.
6. At 24 hours publish a *checkpoint*, not false completion. At 48 hours stop admission, close the current safe test boundary, seal all artifacts and mark remaining cells `UNEXECUTED/TIME_LIMIT`. Do not start a long case too near the closeout deadline if it cannot be safely stopped and preserved.

All planned counts assume eight cases per topology. After current-source applicability checks, regenerate the final matrix and sums from machine-readable rows; never leave a hard-coded total that disagrees with admitted cases.

### Per-cell source of truth (88 candidate cells; **all counters initially zero**)

The rows below specify *target* only. Copilot should generate run receipts with `planned, admitted, launched, executed, PASS, FAIL, incomplete, unexecuted, skipped-with-reason`, and an immutable `cell_id = topology/case/source_manifest`. The live summary imports actual counters from completed receipts; no original historical outcome is copied into these counters.

| Topology | Test case | Target | Gate | Executed | PASS | FAIL | Incomplete | Evidence/notes |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | --- |
| W1 | `TC_RT_1_1` | 15 | CORE | 0 | 0 | 0 | 0 | — |
| W1 | `TC_RT_1_2` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| W1 | `TC_RT_2_1` | 20 | CORE | 0 | 0 | 0 | 0 | — |
| W1 | `TC_Darwin_Pair` | 20 | CORE | 0 | 0 | 0 | 0 | — |
| W1 | `TC_Android_Pair` | 20 | CORE | 0 | 0 | 0 | 0 | — |
| W1 | `TC_Send_Command_Read_Write_Attributes` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| W1 | `TC_ON_OFF` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| W1 | `TC_LEVEL_CONTROL` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| W2 | `TC_RT_1_1` | 15 | CORE | 0 | 0 | 0 | 0 | — |
| W2 | `TC_RT_1_2` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| W2 | `TC_RT_2_1` | 20 | CORE | 0 | 0 | 0 | 0 | — |
| W2 | `TC_Darwin_Pair` | 20 | CORE | 0 | 0 | 0 | 0 | — |
| W2 | `TC_Android_Pair` | 20 | CORE | 0 | 0 | 0 | 0 | — |
| W2 | `TC_Send_Command_Read_Write_Attributes` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| W2 | `TC_ON_OFF` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| W2 | `TC_LEVEL_CONTROL` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T1 | `TC_RT_1_1` | 20 | CORE | 0 | 0 | 0 | 0 | — |
| T1 | `TC_RT_1_2` | 20 | CORE | 0 | 0 | 0 | 0 | — |
| T1 | `TC_RT_2_1` | 30 | CORE | 0 | 0 | 0 | 0 | — |
| T1 | `TC_Darwin_Pair` | 30 | CORE | 0 | 0 | 0 | 0 | — |
| T1 | `TC_Android_Pair` | 30 | CORE | 0 | 0 | 0 | 0 | — |
| T1 | `TC_Send_Command_Read_Write_Attributes` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T1 | `TC_ON_OFF` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T1 | `TC_LEVEL_CONTROL` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T2 | `TC_RT_1_1` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T2 | `TC_RT_1_2` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T2 | `TC_RT_2_1` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T2 | `TC_Darwin_Pair` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T2 | `TC_Android_Pair` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T2 | `TC_Send_Command_Read_Write_Attributes` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T2 | `TC_ON_OFF` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T2 | `TC_LEVEL_CONTROL` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T3 | `TC_RT_1_1` | 20 | CORE | 0 | 0 | 0 | 0 | — |
| T3 | `TC_RT_1_2` | 20 | CORE | 0 | 0 | 0 | 0 | — |
| T3 | `TC_RT_2_1` | 30 | CORE | 0 | 0 | 0 | 0 | — |
| T3 | `TC_Darwin_Pair` | 30 | CORE | 0 | 0 | 0 | 0 | — |
| T3 | `TC_Android_Pair` | 30 | CORE | 0 | 0 | 0 | 0 | — |
| T3 | `TC_Send_Command_Read_Write_Attributes` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T3 | `TC_ON_OFF` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T3 | `TC_LEVEL_CONTROL` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T4 | `TC_RT_1_1` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T4 | `TC_RT_1_2` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T4 | `TC_RT_2_1` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T4 | `TC_Darwin_Pair` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T4 | `TC_Android_Pair` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T4 | `TC_Send_Command_Read_Write_Attributes` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T4 | `TC_ON_OFF` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| T4 | `TC_LEVEL_CONTROL` | 10 | CORE | 0 | 0 | 0 | 0 | — |
| B1 | `TC_RT_1_1` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B1 | `TC_RT_1_2` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B1 | `TC_RT_2_1` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B1 | `TC_Darwin_Pair` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B1 | `TC_Android_Pair` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B1 | `TC_Send_Command_Read_Write_Attributes` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B1 | `TC_ON_OFF` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B1 | `TC_LEVEL_CONTROL` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B2 | `TC_RT_1_1` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B2 | `TC_RT_1_2` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B2 | `TC_RT_2_1` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B2 | `TC_Darwin_Pair` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B2 | `TC_Android_Pair` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B2 | `TC_Send_Command_Read_Write_Attributes` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B2 | `TC_ON_OFF` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| B2 | `TC_LEVEL_CONTROL` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D1 | `TC_RT_1_1` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D1 | `TC_RT_1_2` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D1 | `TC_RT_2_1` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D1 | `TC_Darwin_Pair` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D1 | `TC_Android_Pair` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D1 | `TC_Send_Command_Read_Write_Attributes` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D1 | `TC_ON_OFF` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D1 | `TC_LEVEL_CONTROL` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D2 | `TC_RT_1_1` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D2 | `TC_RT_1_2` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D2 | `TC_RT_2_1` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D2 | `TC_Darwin_Pair` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D2 | `TC_Android_Pair` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D2 | `TC_Send_Command_Read_Write_Attributes` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D2 | `TC_ON_OFF` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D2 | `TC_LEVEL_CONTROL` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D3 | `TC_RT_1_1` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D3 | `TC_RT_1_2` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D3 | `TC_RT_2_1` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D3 | `TC_Darwin_Pair` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D3 | `TC_Android_Pair` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D3 | `TC_Send_Command_Read_Write_Attributes` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D3 | `TC_ON_OFF` | 10 | GATED | 0 | 0 | 0 | 0 | — |
| D3 | `TC_LEVEL_CONTROL` | 10 | GATED | 0 | 0 | 0 | 0 | — |

## F. Baseline build and PR-specific differential rules

### Immutable upstream baseline

- Resolve exact remote refs by authenticated `git fetch` in **both** SDK and QA repos. Record upstream repo URL, ref, SHA, relevant submodules, Python version, build flags, generated dependencies, OS/arch and `pip` provenance. Freeze source and binary artifacts in dedicated read-only execution snapshots. Current-source HEADs must be resolved at **launch**, not copied from this document.
- Produce both x86-64 Ubuntu and ARM64 Pi controller binaries where supported; bind each runtime to its specific native/shared-library hash and actual imported Python path. Record Nordic/USB Matter app firmware and OTBR RCP firmware identities, Thread dataset hash, MAC/HCI mapping, interface addresses and the actual host that runs OTBR.
- An experiment must not use a recently patched helper or alternate QR path and still be called pristine upstream. Workload wrappers may provide bounded capture/fixture ownership only; no changes to assertions, expected result decoding, native timeouts, retries, logs that materially change timing, transport eligibility, fault injection, or reset semantics without labeling it as a distinct diagnostic configuration.
- Baseline staging is **not** the authoritative historical investigation branch. Keep separate, immutable local checkouts for `baseline`, `candidate-PR-N`, and `combined-qualification`; preserve the upstream source manifest in every run receipt.

### PR eligibility and differential policy

- Maintain the complete live catalog in `investigation/PR_INVENTORY.md`. Historical known lists: QA #527/#528/#529/#539/#544/#545/#547/#548/#549/#550; SDK #74938/#74889/#74888/#74886/#74858/#74676/#74432/#74431/#74430/#72902/#72824/#72823. **These are discovery seeds, not a verified complete or currently eligible list.** Confirm actual open status, creation dates, HEADs, merged status and readiness through `gh`/upstream access. Exclude PRs older than four calendar months at candidate selection. Already-merged code belongs to current upstream automatically.
- Readiness to use as a candidate means: demonstrated defect and narrow correction, meaningful failing-before/passing-after regression, relevant platform checks, understood dependencies, no blocking technical defect, and explicit confidence that the PR is fit for human technical review. **Do not conflate GitHub non-draft with technical readiness.** Draft/unready PRs remain `EXCLUDE-UNREADY`, not silently pulled into baseline.
- Categorize each PR `ALREADY-UPSTREAM`, `DIFFERENTIAL-CANDIDATE`, `DIAGNOSTIC-ONLY`, `EXCLUDE-UNREADY`, `EXCLUDE-UNRELATED`, `EXCLUDE-AGE`, or `BASELINE-REQUIRED/EXCEPTION` (exception only with specific user approval). There are **zero** currently approved `BASELINE-REQUIRED` open PRs.
- On a baseline failure, first preserve it with full native/test evidence and assign a phase-based signature. Consult the catalog for **one** matching correction. Execute a separate frozen-base candidate build under the same physical topology/case/firmware and with equivalent source changes restricted to that PR plus proven dependencies. A/B order and DUT reset/state must be recorded; account for randomness or environmental recovery, not just one green retry. At least ten *paired or otherwise statistically justified* iterations for an intermittent mechanism unless the evidence supports a deterministic counterexample. Mark matched baseline and candidate runs separately, never rewrite a FAIL.
- A PR-only diagnostic that adds logs without changing behavior may aid a **separate** instrumented comparison but must not be used to relabel the main upstream result. No automatic multi-PR cherry-pick batch, no PR merges/undraft/reviews during the weekend batch.

## G. Failure classification and accountable results

Use exactly these top-level codes, followed by evidence/confidence:

| Code | Required classification |
| --- | --- |
| 1 | Likely introduced by the current unmerged code changes (applies only to a clearly identified candidate/adjusted build; pristine upstream isn't treated as containing those changes) |
| 2 | Likely a harness or SDK defect that one of our current/open or intended PRs *should* address, but the tested correction did not fix |
| 3 | Likely a flaw in how this batch/fixture was executed rather than a production QA/SDK code defect |
| 4 | Likely a pre-existing test-harness defect outside our existing PR scope |
| 5 | Likely a pre-existing SDK defect outside our existing PR scope |
| 6 | Uncertain; requires deeper investigation (default when evidence is inadequate) |

Keep the observed **native outcome** (`PASS`, `FAIL`, `NOT_EXECUTED`), **invocation/setup outcome** (`STARTED`, `INCOMPLETE`, `BLOCKED`), and **evidence integrity** (`COMPLETE`, `PARTIAL`, `INVALID`) as independent dimensions. A clean infrastructure closeout cannot convert a failed Matter assertion into PASS; a catch-all error is not automatically an SDK defect.

Record for every failure: campaign ID, topology/case/iteration, source/binary/DUT/RCP hashes, pairing transport and controller/OTBR host, test phase, exception/failure signature, reproducing counters/exchange IDs when known, native logs/capture pointers, last verified normal protocol event, completeness/drop counter limitations, classification code/confidence, related prior historical failure/PR, candidate A/B result (if any), and current disposition. Preserve original failure evidence unchanged; assign new campaign IDs even if the symptom matches the historical 158 outcomes.

## H. Evidence policy, disk, privacy and success pruning

- Raw logs, UART dumps, HCI/IP/Thread pcapng, private controller/DUT stores, binary traces, crash cores and credential-bearing receipts remain **outside** the Git checkout under a versioned, access-controlled campaign root. Never include secrets, passcodes, controller storage or exported commissioning material in Git. Use source URLs and relative pointers to original run IDs from the committed `EVIDENCE_INDEX.md`; do not fabricate accessible raw paths.
- Capture controller and DUT interfaces relevant to each cell: Ubuntu/Pi native controller logs, physical BLE/HCI monitor, network interfaces, Thread/OTBR state/SRP where applicable, and DUT serial/app/log channels. Declare unavailable coverage before running. Bounded segments must close and hash before ring wrap; track packet counts, any `dumpcap` drops, ISB absence and closure status separately. Never claim a zero packet-loss proof from zero dumpcap drops.
- Keep *all* failed, uncertain, interrupted, setup-failed, capture-incomplete and safety-recovery artifacts; keep at least the necessary preceding/following context. Keep a permanent compact per-iteration **success receipt**: run ID, test case/cell, source/binary/DUT identity, iteration number, outcome, start/end, test duration and source summary/checksum. After final validation and only if exclusive to successful iterations, remove bulky success-only raw artifacts and record deletion/hashes/size in retention receipts. Do not delete shared capture segments, evidence referenced by a failure, or original historical source artifacts.
- Preflight local disk reserve: at least **8 GiB free as a provisional minimum**, adjusted upward to match observed capture throughput, plus bounded capture ring and cleanup headroom. Record RAM/CPU/PSI/host OOM, worker PID/start identity, NTP/clock sync envelope, controller import paths, normal shutdown, capture process exits and fixture readiness. Enforce safe disk thresholds that stop new test admission without destroying failed evidence.
- No blanket `git clean`, `rm -rf`, remote branch deletion or rewriting historical integrity seals. When original fixed file paths require isolated native writes, install/verify bind mounts before importing/loading Matter libraries and test a workload-free proof. The previous `chip_counters.ini` mutation was disclosed and its original hash recovered; its old failure must remain recorded.

## I. Unattended lifecycle, checkpoint and stop policy

1. **Preflight:** verify each machine's identity; fixture/RCP/DK USB identity and firmware; exclusive RF ownership; clean source snapshots; commissioned-state reset and replay safety; case inventory and test applicability; bounded capture health; native counter path isolation; available storage; Thread partition/SRP and BLE MAC-to-HCI mapping. Stop admission if a gate is unproved.
2. **Launch:** coordinator outside the IDE with durable state and a single campaign ID. No source changes after launch. Log each requested, admitted, started, executed, PASS, FAIL, incomplete, skipped and unexecuted transition atomically and idempotently. Restart after coordinator crash must not silently rerun or replace an old iteration ID.
3. **Ordinary failures:** preserve evidence, classify initially code 6 unless demonstrated otherwise, perform bounded documented fixture recovery and continue the next admitted cell only after positive readiness validation. Reset collisions/other advertisers require exclusive test domain, not merely process locks.
4. **Global stop conditions:** fixture identity/ownership violation, key or sealed-evidence integrity failure, inability to preserve a failing capture, unsafe disk/memory pressure, uncontrolled RF/Thread topology interference, missing safe reset state, stale native storage isolation, or a failure in recovery guards. Quarantine affected resources and continue only truly independent, safe work.
5. **24-hour checkpoint:** publish exact coverage by cell/topology/test, failure signatures, A/B comparisons, remaining time projection, capture/storage health and whether any admitted ten-iteration cell is still unfinished. This checkpoint is not a completion marker.
6. **48-hour limit:** stop new admissions early enough for graceful completion/closeout; if a cell cannot finish safely before the deadline, stop at a defined safe test boundary and preserve all partial results. Finalize running child/broker cleanup, hashes, failure artifacts, campaign machine-readable ledger, local dirty `LIVE_SUMMARY.md`, and separate proposed follow-up coverage. Do not report skipped/unstarted slots as FAIL or PASS.
7. **Result:** full topology×test×pairing×OTBR matrix with requested/admitted/started/executed/PASS/FAIL/incomplete/unexecuted counts; known-versus-new signatures, six-way classifications, ranked new investigative targets, PR differential outcomes, evidence pointers/integrity status, and explicit undercoverage/capacity limits.

## J. Git placement and visibility contract

1. Place **this plan** in `investigation/WEEKEND_MATRIX_PLAN_2026-10-24.md` and **commit** the sanitized plan on the authoritative investigation branch (from a dedicated documentation worktree, preserving more recent commits). Do not add the downloadable source file as an extra duplicate.
2. The live operational summary is **different**: `investigation/campaigns/2026-10-weekend/LIVE_SUMMARY.md`. It must remain **untracked** and visibly `??` in `git status --short --untracked-files=all`; do **not** add it to `.gitignore`, `.git/info/exclude`, stage or commit it during execution.
3. Tool-generated JSON, logs, trace buffers and packet captures should reside in the external private campaign root. Source evidence indexes and final sanitized summaries can be committed **after review**, but not raw traces or mutable run counters.
4. Do not confuse the committed historical `FAILURE_CATALOG.md` with the untracked current-campaign results. Each has independent provenance, denominators and failure identities.

### Prelaunch sign-off checklist

- [ ] Historical consolidation committed; 158/80/78 reconciled and source evidence pointers validated.
- [ ] Complete live upstream QA/SDK PR inventory; age cutoff and technical readiness documented. No open PR silently integrated.
- [ ] Upstream QA and SDK SHAs and executed runtime hashes frozen.
- [ ] All eight known cases re-inventoried; newly applicable cases and justified exclusions recorded.
- [ ] Every CORE topology and every GATED candidate assessed against actual firmware/hardware, with a per-cell status and reset/capture readiness.
- [ ] Controller and DUT roles, RCP/OTBR hosts, current physical BLE adapter indices and OTBR/SRP state positively verified.
- [ ] The native counters and all other mutable fixed paths safely isolated **before** runtime import; original seals untouched.
- [ ] Evidence archival, segmented capture, failed-run preservation, success receipt/prune and disk/ram stop controls verified.
- [ ] 24-hour checkpoint and 48-hour hard-stop/closeout behavior validated, and 10-iteration coverage forecast explicitly reviewed.
- [ ] Committed plan exists at the root of `investigation/`; separate untracked live summary is visibly dirty only after local creation.
- [ ] Campaign launch explicitly authorized through the user's subsequent Copilot instruction; this document alone does not start hardware.

---

**Locked recommendation:** Clean frozen upstream is the discovery baseline; no open QA/SDK PRs pre-merged. Relevant, adequately qualified PRs are evaluated as isolated, same-cell candidate fixes only after an actual baseline failure. One authoritative historical investigation catalog remains intact. The 24–48-hour campaign records new failures separately and preserves every legitimate coverage gap.
