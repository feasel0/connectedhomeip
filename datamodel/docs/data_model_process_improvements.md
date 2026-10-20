# Matter Data Model Release Process — Improvement and Automation Backlog

**Living idea register, not the operating mandate.** Updated 2026-10-19.  
**Companion:** [Operational data-model manager playbook](data_model_manager_role_and_release_playbook.md) · [Initial SVE findings](2026-10-19_SVE_status_and_findings.md)

## Purpose and ground rules

This file collects process problems, proposals, experiments, and longer-term automation ideas. The **September 9 onboarding mandate** remains the authority for our job; the **separate engineering meeting** provides useful, less authoritative alternatives. Nothing here is considered deployed or release policy unless marked as such with verification.

For each idea, maintain **problem/evidence, proposed intervention, scope/owner, prerequisite, validation metric, state, and promotion decision**. Move an idea into the [release playbook](data_model_manager_role_and_release_playbook.md) only after its reliability and governance are established.

Goals:
- Reduce incompatible data-model changes discovered just before test events/SVE.
- Preserve the reference model's normative correctness and backward validation.
- Distribute domain-specific fixes to engineers who understand the affected cluster/device.
- Make each update reproducible and observable, with fewer manual checks and less knowledge concentrated in one person.
- Prevent confidentiality leaks from the private specification into public SDK CI/artifacts.

## Priority map

| ID | State | Priority | Proposal | Expected benefit |
|---|---|---|---|---|
| P01 | **Observed fix implemented; fork draft PR open** | Immediate | Support combined specification book and historical book layouts in XML generator | Restores actual current generation and avoids silent selection errors |
| P02 | **Proposed in second meeting** | High, future | Periodic future-model validation against SDK applications | Move incompatibility discovery weeks/months before release |
| P03 | **Proposed** | High | Track per-cluster ownership and compatibility debt with actionable evidence | Route fixes to experts instead of sole release integrator |
| P04 | **Proposed in second meeting** | High, future | Spec-side protected CI / nightly prototype | Test private spec changes without publishing private material |
| P05 | **Proposed** | Medium | Automated semantic delta and release-risk report | Replace reading hundreds of XML files with prioritized review |
| P06 | **Proposed** | Medium | Validate include flags, provenance, provisional transitions and version selection automatically | Reduce configuration and release-selection mistakes |
| P07 | **Exploratory** | Medium | Split quick PR checks from heavier periodic app builds | Timely feedback without impractical per-PR costs |
| P08 | **Exploratory** | Medium | Evaluate a forward-looking model CI mode without changing SDK default specification revision | Find next-release drift without destabilizing current release |
| P09 | **Proposed in separate meeting** | Low / external owner | Clarify release/SVE branching policy and roles | Reduce stale branches and cherry-pick confusion |
| P10 | **Proposed** | Medium | Durable reporting and release-cycle metrics | Make handoff and continuous improvement measurable |

## P01 — Generator compatibility and file-selection correctness

**Observed failure (2026-10-19):** SDK generator called `pdf-appclusters-book`, `pdf-devicelibrary-book`, and `pdf-standardnamespaces-book`; the pinned specification master had combined the material into `pdf` and no longer offered those targets. Generator exited 1 after an otherwise successful Alchemy scrape/main-book build.

**Implemented on dedicated data-model work branch:** Detect the complete combined-book include entrypoint set; use its printed recursive include records; fall back to legacy book targets when needed; use exact AsciiDoc include basename membership instead of fragile substring matching. Six focused tests pass. Full current generation exited 0; 280 model XML and manifest checks passed. See [detailed evidence](../reports/2026-10-19_17-02-05.md).

**PR status:** [Fork-local draft PR #1](https://github.com/feasel0/connectedhomeip/pull/1) is open against the fork's master, containing exactly the generator fix and tests. Upstream PR creation was attempted but blocked by GitHub integration permissions; **no upstream PR exists yet**.

**Remaining:** Transfer/recreate the narrow fix as an upstream-facing draft when authorized by GitHub permissions; run upstream CI/review; verify old-spec behavior against an actual historical checkout when feasible. Expanded include-flag combinations (`None`, `All`) merit real integration validation later. Do not claim the fix means the new reference model is SVE-approved.

**Promotion:** Once merged upstream, mark this as an established generator compatibility feature in the playbook, with commit/PR reference.

## P02/P04 — Periodic upcoming-model compatibility validation (long-term option)

**Evidence:** During 1.7 T2 integration, the data model was brought in close to the event deadline. Arya described a cascade of outdated ZAP XML, implementations missing current behavior, and tests not ready for the new requirements. A late model revision switch exposed multiple independent clusters simultaneously, forcing urgent one-off fixes.

**Ideas discussed in the second meeting:**
1. Periodically generate the developing, possibly incomplete, upcoming-version reference model from the private specification.
2. Run the applicable IDM checks against current SDK-built test applications. All-clusters/all-devices would cover many cases; media/camera might need specialized apps.
3. Report mismatches early to cluster/spec owners. Understand legitimate revision drift vs real errors.
4. Permit explicit, inspectable, temporary acknowledgment of accepted in-progress mismatches where appropriate; before release, resolve or formally review this debt.
5. Prefer running sensitive portions **on the private specification side** to avoid publishing unreleased specification content in public SDK CI.

Meeting participants considered this promising; **Robert Szewczyk proposed prototyping with Arya as a consultant**. This was not assigned to us as an immediate deliverable, and the transcript does not demonstrate an existing deployment.

**Prototype design questions (unresolved):**
- Which repo owns orchestration, credentials, artifacts and access controls? Can every artifact/log be confined to authorized audiences?
- Does the job work with a tagged baseline SDK or moving master? How are spec and SDK SHAs pinned, with stale-version warnings?
- Can model drift be tested against existing prebuilt binaries, or does it require new all-devices/all-clusters/camera/media builds?
- How do we distinguish expected spec-first changes from disallowed/inconsistent spec changes without making ordinary feature PRs unmergeable?
- Should the model run be exploratory/nonblocking until ownership and feedback loops are mature?
- What is the reconciliation/expiry policy for temporary mismatches? An empty temporary ledger is **not** the same as deleting legitimate permanent compatibility errata.
- Who owns operational failure and infrastructure maintenance if the prototype becomes shared infrastructure?

**Feasible first prototype:** A private, read-only, scheduled job that records generated model SHA and narrow semantic mismatch summaries, with no automated file publication, no silent errata modification, no default-SDK-version bump, and a small predictable test target. Gather false-positive/false-negative data before broadening coverage.

**Promotion criterion:** repeated runs identify actionable mismatches earlier without leaking specification material or destabilizing current release; owners can triage them and show a reduction in late integration blockers.

## P03 — Distributed cluster-domain ownership and mismatch lifecycle

The second meeting raised the possibility of individual cluster owners making their ZAP/implementation/test changes while the overall release manager orchestrates the model. **Do not require partial, incomplete version directories** as the immediate solution: Arya explained that each reference revision lives in its own directory and missing clusters/device types can cause widespread IDM failures.

**Alternative:** Preserve one complete reference snapshot, but record mismatches per cluster:
`model source SHA | affected element | observed change | spec evidence | release inclusion | expected/defect/unknown | ZAP status | implementation status | test status | responsible person | deadline | issue/PR | resolution`.

Start by tracking real 1.7 differences (Group Key Management, Closure Dimension, Device Energy Management, Thermostat Mode, others). Do not assign blame or declare defects before matching the source spec. Escalate genuine domain questions to cluster owners and retain single accountable release integration coordination.

**Metric:** time from mismatch discovery to named owner and to disposition; number of uncovered changes at SVE; number of temporary test disables avoided.

## P05 — Generate a first-class semantic change/review report

Existing `spec_revision_diff_summary.py` is a starting point. Consider a reproducible report with:
- Added/removed/renamed clusters, devices, IDs, features, attributes, commands, events, globals and namespaces.
- Old/new revision, data type, optionality, access privilege, conformance, provisional/obsolete state and constraints.
- Explicit suspicious reductions, invalid rev/no-change combinations, unknown parser output and PICS differences.
- Grouping by domain owner, severity and release impact, linked to public changes or private identifiers as access rules permit.
- Distinction between **reference-model changes** and **SDK/ZAP drift**; automated classification never replaces review.

**Metric:** report highlights known review issues without flooding the reviewer or falsely calling valid changes defects.

## P06 — Provenance/include and release acceptance automation

Candidate checks:
- Verify `Current` flags match the actual ballot-approved list; explain diff and hold release acceptance if the list isn't available.
- Confirm requested spec SHA/tag and Alchemy binary version are recorded and tied to XML generation; warn on untagged `master` without treating it as a fatal error in exploratory runs.
- Check generated XML shape, file counts, ID maps, `data_model_xmls.gni`, no duplicate IDs, and version-selection mapping.
- Verify provisional transitions against the selected milestone (test event, SVE, post-SVE) rather than a hardcoded global rule.
- Detect surprising category depletion, file deletions, named constraint loss and unexpected manual generated-file edits.
- Separate warnings into **expected context** and **needs human decision** with exact evidence.

**Metric:** reproducible pass/fail with few false positives, meaningful release-safe reports and no undocumented exceptions.

## P07/P08 — Right-sized CI and forward model testing

The second meeting discussed that a sufficiently short (5–10 minute) validation might be feasible for spec PRs, whereas app builds plus IDM checks might require about an hour. That is a **meeting estimate**, not a measured current performance benchmark.

Test tiers to evaluate:
1. **Fast PR checks:** model extraction/static parse/provenance and narrowly scoped changed-cluster lint, if no huge build is required.
2. **Periodic integration:** current SDK binaries built/tested against the in-progress model plus specialized apps.
3. **Release gate:** full supported model suites, conformance/IDM checks and human sign-off.

Explore whether CI can load the **next** reference model without changing `kSpecificationVersion` or misclassifying an older device. Keep a clear separation between version-specific certification validation and development-only forward checks; avoid overlaying new requirements on devices claiming an older spec.

**Metric:** early detection, signal/noise, wall-clock cost, access safety and reproducibility.

## P09 — Release branch simplification (context, not our mandate)

The supplemental meeting attributed the unsuccessful early Matter 1.7 branch to staleness, late cherry-picks and coordination overhead. It discussed later release branching, separate SVE/test-harness branches, a single combined branch, and the need for written policy. **No final alternative was adopted in that transcript.**

Our responsibility is to know which specification tag, SDK baseline and model go with each event, and to communicate handoff points—not to change organization-wide branching independently. Link any future adopted policy in the playbook only after confirmation from release ownership.

## P10 — Repeatable reporting, milestones and agent handoff

Maintain a single release dashboard or index with:
- G0–G6 gate status from the role guide, each with source SHAs, timestamp and link to evidence.
- The semantic diff ledger and owner decisions, not only total pass/fail.
- Outstanding ballot inclusion questions and warnings.
- What is safe to commit publicly vs must stay in private scratch storage.
- Named toolchain regressions and their upstream PRs.
- Cycle metrics: total integration time, new mismatches at SVE, repeated failure modes, time lost to environment/build drifts, and number of human review iterations.

Prioritize collecting these observations over building elaborate infrastructure before the baseline process is stable.

## Decisions and promotion log

| Date | Decision | Basis | Effect |
|---|---|---|---|
| 2026-09-09 | CSA-side data-model release stewardship is core role; spec-side CI improvement is longer-term | Authoritative onboarding | Defines scope and playbook |
| Engineering meeting (date not established here) | Nightly/spec-side validation, temporary reconciliation and domain-owner assignment discussed, not confirmed implemented | Supplemental transcript | Backlog P02–P04; **not** binding requirements |
| 2026-10-19 | Combined-book generator compatibility fix implemented and successful end-to-end run verified | Execution report; 280 XML, six regressions | P01 implemented locally; initial execution gate passes |
| 2026-10-19 | No semantic fixes or SVE model publication until release flags and differences reviewed | Incomplete review evidence | Preserve investigation status |

## Maintenance discipline

At the end of each milestone, close/advance each item with explicit evidence, unsuccessful experiments included. When a proposal is adopted, update the **role playbook** with the tested command, expected outputs, known limitations and new gate; mark the idea here as promoted rather than erasing the history. Keep the improvement plan distinct from daily execution to avoid turning attractive, unverified proposals into mandatory steps.

**Privacy:** These notes summarize meetings in public-safe terms; do not check in raw private meeting transcripts, specification contents, confidential ballot emails, credentials, restricted generated outputs or private CI logs.
