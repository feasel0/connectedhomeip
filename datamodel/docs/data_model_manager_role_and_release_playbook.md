# Matter Data Model Manager — Role Charter and Release Playbook

**Living document for humans and future agents.**  
**Status:** Updated 2026-10-20 with tested defect-resolution methods. Update after every material release-cycle lesson.
**Operational scope:** Matter SDK specification-derived reference data model, its release integration, and the validation/coordination needed to deliver it.  
**Companion documents:** [Current SVE execution findings](2026-10-19_SVE_status_and_findings.md) · [Improvement backlog](data_model_process_improvements.md) · [Official SDK data-model procedure](../../data_model/README.md).

> **Start here before acting on a future release.** This document specifies responsibilities, checkpoints, evidence, and decision boundaries. It is not a substitute for the applicable ballot email, release coordinator, current SDK README, or normative specification.

## 1. Mission and decision hierarchy

The **authoritative September 9 onboarding meeting** assigned stable CSA-side stewardship of the Matter data-model release process. Historically, individual member-company contributors maintained data-model snapshots and solved late-breaking integration problems. This became a release-critical dependency: the goal is to provide dependable continuity when volunteer/member-company staffing changes.

Our objective is **a complete, faithfully generated, reviewed, versioned model of the specification at the relevant Matter release milestone that the SDK testing infrastructure can consume**, while identifying and coordinating any SDK/specification mismatches. The role includes technical release engineering, review of unexpected data-model changes, integration triage, documentation, and growing participation in the data-model team.

**Priority of instructions and evidence:**
1. Current explicit request from the responsible human and current agreed release milestone/ballot include list.
2. Normative Matter specification and official tagged SHA applicable to that milestone, plus the official SDK README/process.
3. This playbook's established, tested methods and release reports.
4. Supplemental team discussion and the improvement backlog: valuable **proposals**, not automatic alterations to the mandate.
5. Agent inference: always labeled; never treated as permission to silently change normative content.

If instructions conflict, preserve evidence, identify the conflict, and obtain a responsible-person decision on specification/release policy rather than manufacturing a workaround.

## 2. What the data model is — and is not

- The written Matter specification (AsciiDoc) defines cluster and device-type requirements, attributes, commands, events, features, conformance, global types, and namespaces.
- **Alchemy** is the Go-based specification extraction/transformation tool; the SDK's `scripts/spec_xml/generate_spec_xml.py` drives it and the spec include-list filtering.
- **`data_model/<version>/` XML** is a versioned, machine-readable reference of the specification's intent, used by certification/testing and other data-model consumers. Keep it generated, provenance-controlled, and semantically accurate.
- **ZAP XML** and generated SDK APIs serve implementation/code generation. They may have historical compatibility accommodations; **ZAP XML is not interchangeable with the normative reference XML**. When they disagree, locate the spec change, establish intended behavior and SDK constraints, and choose a justified resolution.
- Test harness selection is versioned: `SpecificationVersion` reported by the device is mapped to the appropriate reference directory via `basic_composition.py` and `spec_parsing.py`, preserving backward validation.
- The SDK may have **multiple errata mechanisms** with different scope. In particular, spec-side Alchemy-to-SDK generation errata and SDK Python CI-only `data_model/errata_future.yaml` are not synonyms. Confirm where and why an override is applied. Do not silently enable development errata for strict certification tests.

Key paths: `data_model/README.md`; `data_model/<version>/`; `scripts/spec_xml/generate_spec_xml.py`; `scripts/spec_xml/spec_revision_diff_summary.py`; `src/python_testing/matter_testing_infrastructure/matter/testing/spec_parsing.py`; `src/python_testing/matter_testing_infrastructure/BUILD.gn`; `src/app/SpecificationDefinedRevisions.h`; `.github/workflows/check-data-model-directory-updates.yaml`; `docs/guides/data_model_errata.md`.

## 3. Ownership boundary

**We are accountable for driving**:
- The data-model snapshot and update PRs at agreed release checkpoints.
- Provenance and correct include/feature/provisional selection.
- Inspection of meaningful semantic diffs, anomalies, and unexpected removal/revision changes.
- Parsing, version selection, model-test and relevant SDK/IDM validation evidence.
- Triage and coordination of necessary ZAP, code generation, implementation and test changes.
- Handoff, reviewer communication, documentation, and continuity.

**We are not automatically the implementer or policy owner of**:
- Every cluster's normative design, detailed SDK implementation, or feature-specific testing.
- General SDK release branching policy or all release engineering.
- Every bug raised by broader Matter QA investigations.
- A nightly spec-side integration platform that was only discussed as a future prototype.

We can implement a clearly evidenced, bounded fix in related SDK tooling; for domain-specific behavior, involve the relevant cluster/spec expert, record ownership, and follow through. **Owning resolution is not identical to personally authoring every fix.**

## 4. Release rhythm and collaborators

The onboarding described **three main model-update opportunities per release cycle**:
1. Ahead of a test event.
2. Ahead of the SVE / validation event.
3. Post-SVE, when provisional checks are removed and before the finalized test-harness release.

The first working snapshots can be taken when ballot tags/include definitions are available (historically around a 0.7 ballot); the exact current schedule, tag and include set must come from release coordinators. The first meeting expected progressive onboarding: study Arya's 1.7 example, shadow an SVE update, then lead a post-SVE update with collaborative review.

Expect multi-person review with the data-model lead, specification/release leads, and cluster owners. The onboarding identified Arya Hassanli as the previous hands-on data-model integrator and referenced review with the relevant Rob/Renee leads; **verify current owners, availability, and responsibilities each cycle** rather than treating names as permanent routing rules.

The supplementary engineering meeting described a separate SDK branch strategy debate. Its branch proposals were **not** part of this role assignment. Follow the current accepted release branching procedure; coordinate on timing but do not independently redesign it.

## 5. Repeatable release procedure

### Phase A — Define and freeze inputs before changing files

1. Identify milestone: test event, SVE, post-SVE, or later maintenance update; identify target model directory (e.g., existing `1.7` versus a new version).
2. Obtain authorized specification repository access. Record exact **spec commit SHA/tag**, SDK baseline SHA, Alchemy release/binary version, include mode (`Current`, `None`, or `All`), the authoritative feature-include list/ballot email, and planned reference directory. Do not infer inclusion from a nearby milestone.
3. Distinguish updating an existing revision from adding a new revision—follow the corresponding `data_model/README.md` section. For new revisions the README describes copying the prior directory first and separating baseline/spec/scraper changes in reviewable commits.
4. Establish an isolated clean checkout/worktree and output/log directory; record pre-existing dirty state and avoid unrelated branches. Exclude the private specification checkout, credentials, raw logs, and generated unreviewed snapshots from public commits.
5. Prefer a tool version matching the existing model when changing only the spec input; if intentionally upgrading Alchemy, separate its impact for review.

### Phase B — Run the real generator and record observable results

From a configured SDK checkout:

```bash
python scripts/spec_xml/generate_spec_xml.py \
  --scraper "$ALCHEMY" \
  --spec-root "$SPEC_ROOT" \
  --include-in-progress Current \
  --output-dir data_model/<revision>
```

Adapt the mode, version, and environment to the **actual** release requirements; the example is not universal. Run the **entire** command for acceptance—not merely `--dry-run`, `--skip-scrape`, or Alchemy in isolation.

Record full input SHAs, timestamp, command, duration, exit code, nonfatal warnings, expected outputs, and first failure point. If it fails: determine whether the cause is access/environment, SDK script/spec build interface, Alchemy parsing, bad spec input, include-list filtering, XML postprocessing, or genuine model conformance. Reproduce, isolate, and fix the **observed** cause; protect older supported inputs and add targeted regressions. Do not edit generated XML to suppress symptoms.

**Known 2026-10-19 lesson:** Specification `master` transitioned to a combined book; the old generator called nonexistent separate Make targets. The compatible fix detects the combined-book include record set and otherwise uses legacy targets; exact include basename filtering replaces risky substring checks. See [execution report](../reports/2026-10-19_17-02-05.md). Never assume one successful combined-book run validates other feature-flag combinations or historical specs.

### Phase C — Verify structural completeness and provenance

At minimum:
- Confirm every expected XML file parses and has the correct top-level structure.
- Count files and parsed definitions separately for **clusters, device types, namespaces, globals**. Watch for category-wide deletion, unexpected new/missing files, duplicate IDs, and name/ID shifts.
- Check `spec_sha`, `spec_tag`, `scraper_version`, both generated ID maps, and `data_model_xmls.gni` against the selected source and generated filesystem. Untagged `master` may legitimately lack `spec_tag`; do not mislabel it as a release tag.
- Compare generated XML against an independent equivalent-input Alchemy run when useful to isolate scraper output from postprocessing. This does not itself prove normative correctness.
- Check generated differences relative to the prior *complete* reference snapshot, never an earlier failed partial output.
- Check all provisional markings, include flags, changed revisions, and suspicious removals against the ballot/release instructions. Inspect actual *semantics*, not just file/ID counts.
- Keep spec SHA changes and Alchemy upgrades separately reviewable where possible.

### Phase D — Classify semantic changes and investigate mismatches

Produce a concise, itemized diff from `spec_revision_diff_summary.py`, supplemented by actual XML comparison and spec evidence. For **each material change**:
1. What changed: cluster/device/type, element, old/new conformance, feature, constraint, revision, provisional marking, and source inputs.
2. Is the source specification change intentional and included for this release milestone? Identify the exact source location/spec PR and owner.
3. Does the generated **reference XML** faithfully reflect normative intent, or is there a parser/tool/include defect?
4. Is **ZAP XML** up to date? Are generated APIs and code compatible? Are implementations and test expectations ready?
5. Who owns the required resolution? Track a factual classification: **expected**, **needs spec decision**, **generator issue**, **SDK/ZAP drift**, **implementation/test gap**, or **unknown**.
6. Change only what the evidence supports. If a generated API change is backward-incompatible, evaluate an explicitly documented and correctly scoped errata/compatibility approach with owners; don't silently rewrite the normative XML.
7. Validate the smallest relevant regression first, then rerun affected suites; record any remaining block and PR/issue link.

**Verified 2026-10-20 lesson:** use the actual prior/current directory pair when updating the same revision; a different-version summary is not a substitute. Count definitions separately from nested references: apparent GKM feature loss, DEM attribute additions and Push AV enum/field additions were references, not those API changes. Passing broad parser suites did not catch reproduced inheritance/constraint information loss; retain focused positive-control probes for newly changed constructs.

**Verified defect-resolution methods:** preserve absence separately from parser
fallbacks when merging overlays; test explicit Optional/Disallowed/feature/access
overrides in both command directions. Unsupported constraints must survive as
detectable object state through consumer boundaries; reject incomplete evaluation
instead of approximating a compound expression or calling it unconstrained.
Conditional extraction must distinguish AST occurrences from equal scalar values;
test cross-include suppression and enabled/disabled controls, including subslices.
Do not fix occurrence identity by silently breaking an exported AST struct.
See the [tested checkpoint](2026-10-20_SVE_defect_resolution.md).

Validate the exact public patch configuration, not a different private prototype.
Initialize an isolated Git root before applying patches inside a parent worktree;
exit zero can mean a patch was skipped. Assert patched source hashes and executed
test counts. Separate an extracted-body characterization, native fixture test and
real integration test; adapter-level passes cannot prove TLV, storage, composition
or domain policy. Keep owner decisions precise when invalid configuration crosses
delegate or persistence boundaries.

The onboarding specifically recommends reviewing Arya's [Matter 1.7 integration PR #73842](https://github.com/project-chip/connectedhomeip/pull/73842), especially its **Required manual modifications**, to learn the real failure modes, rather than reading hundreds of XMLs without a diff summary.

### Phase E — Validate integration into SDK testing

For a **new** model revision, follow the README's packaging and selection steps: `BUILD.gn`, generated `data_model_xmls.gni`, `PrebuiltDataModelDirectory`, `dm_from_spec_version()`, model version tests, `SpecificationDefinedRevisions.h`, and the directory-update workflow. For an **existing** revision, verify that these remain correct; change only what is needed.

Follow the official Python setup and run the documented `TestSpecParsingSupport.py`, `TestSpecParsingSelection.py`, `TestSpecParsingDeviceType.py` and additional appropriate `TestSpec*` suites. Run IDM and related SDK/test-harness regression tests relevant to the changed requirements. If a version default is updated, anticipate additional ZAP, implementation, and test failures beyond direct IDM model parsing.

**Verified 2026-10-20 execution method:** at SDK `24fafe816f7a5db9aeb514d6504ff6b57384b4f1`, these suites are under `src/python_testing/test_testing/`; DataType and Namespace are also relevant. When reusing an installed host controller, prove both the loaded `matter.testing.spec_parsing.__file__` and model-resource ZIP path/hash refer to the intended pinned sources/candidate. PYTHONPATH alone can lose to an installed regular package through namespace resolution. A private pinned-source overlay plus resource assertions passed all five suites (79 tests) without changing tests. Record reused native modules separately from freshly built binaries; resolve loader failures before attributing a failure to model content. Keep private storage/logs outside public commits.

**Do not claim integration pass merely because XML parses or the generator exits zero.** Do not disable failing tests solely to make the release appear green. A known, justified exception needs explicit ownership, documentation, and reviewer acceptance.

### Phase F — Review, PR and milestone handoff

Prepare a release PR with a **human-readable semantic comparison**, provisional changes, input provenance, separately identified tool changes, explicit manual adaptations, test evidence, known issues, and assigned decisions. For the **current initial 1.7 run**, the first requirement was only an error-free execution; generated model files have not yet been accepted as a release PR.

Get the necessary multi-person review. Coordinate the final spec tag, test event / SVE timeline, test-harness dependency, and post-SVE removal of provisional conditions as applicable. State clearly whether each gate is complete, blocked, or not run. Preserve previous snapshots for backwards-validation.

## 6. Acceptance gates (do not collapse them)

| Gate | Meaning |
|---|---|
| G0 Inputs ready | Correct milestone, source SHA/tag, scraper version, include set and clean work environment |
| G1 Generator executes | Entire script returns zero, expected stages executed; failures and warnings documented |
| G2 Structural/provenance validation | Valid XML, complete file/ID manifests, no unexplained wholesale change |
| G3 Semantic/spec review | All material changes, provisional conditions and removal anomalies tied to normative intent |
| G4 SDK/test readiness | Appropriate parsing, conformance, codegen, implementation and harness suites pass or are formally resolved |
| G5 Release acceptance | Reviewers approve the correct tagged snapshot and handoff / PR, including permitted exceptions |
| G6 Post-release lessons | Record what broke, owners, cycle time, validated tooling improvements, and playbook changes |

**Current state (2026-10-20):** G1 complete and substantial G2 evidence; G3 has a complete 20-file itemization with open dispositions. G4 now has 84 parsing/selection passes, six permanent consumer passes and targeted Alchemy/SDK-probe evidence, not full SDK sign-off. G0 still lacks ballot/tag authority; G5 is not complete. See the [defect resolution](2026-10-20_SVE_defect_resolution.md) and [ledger](SVE_mismatch_ledger.md). New scraper patches have not been released or used for an accepted regenerated model. Do not promote G1 to G5 by inference.

## 7. Per-release working artifacts

Maintain:
- One readable **status/findings summary** for humans, scoped to a milestone.
- A reproducible **execution report** with exact input/output versions, commands, outcomes, and file counts.
- A **change-review ledger** containing one record per material diff/mismatch, evidence, owner, severity, acceptance, and disposition.
- A **tooling-fix PR** distinct from the model release PR when a true shared bug is found.
- Updated **role playbook** (this file) when a method is validated and repeatable.
- Updated **improvement backlog** when discovering or advancing a hypothesis or prototype.

Recommended ledger columns: `cluster/device`, `source SHA and spec location`, `observed delta`, `expected/unknown`, `SDK/ZAP/test impact`, `owner`, `evidence`, `action/PR`, `status`.

## 8. Rules for autonomous agents

- Work from the current mandate, documented release gates, and observable evidence. Execute authorized local generation, comparison, testing, bounded fixes and reporting **without requesting permission at every step**.
- Keep **unreviewed generated models** isolated until the correct ballot/tag and semantics have been established. Opening a **draft tooling-fix PR** with a narrow, proven change is not the same as publishing a release model.
- Run independent mismatch investigations in parallel when there are no data dependencies; coordinate shared generator/integration changes to avoid conflicts. Advance multiple open threads per turn where feasible.
- No speculative fixes, fake passes, silently suppressed exceptions, or changes to spec semantics invented from CI failures.
- Prefer failures with reproducible logs, test fixtures, minimal diffs, and precise ownership. Flag uncertainties early rather than treating them as confirmed.
- Never leak private spec text, unpublished ballot material, credentials or raw private logs to a public PR. Record public-safe identifiers, checksums, results and links that reviewers with appropriate access can follow.
- Keep this thread's data-model work on a dedicated `datamodel/*` branch; do not blend with unrelated Matter QA investigations. Do not submit release PRs from a branch containing unrelated historical investigation changes. Check PR diffs against upstream first.
- Document milestones with the **current repository reporting convention**, link detailed evidence, and distinguish observed pass/fail/not-run. Be cautious with material changes to upstream or normative data: a correct reviewed release is the goal, not maximum changes.

## 9. Living-update protocol

### Verified Integration Methods (2026-10-20)

- Open one clean upstream draft early with independently reviewable code/tests when generated model disclosure is unverified. Label the missing payload explicitly; publication clearance and milestone selection remain separate gates. Keep reports and historical work-branch commits out of that integration branch.
- When upgrading the scraper, compare canonical XML against the same-spec old-tool candidate as well as the upstream reference. This separated 241 formatting-only changes from two intended repairs and caught an unintended inherited-response access artifact before publication.
- Keep each published tool fix and exact combined source in the provenance chain. A new helper worktree can preserve actual parent commits without overwriting an earlier dirty scratch tree. Assert custom version/source/hash before generation, not after writing outputs.
- Run a sanitizer when tests retain references through request/encoder wrappers. A temporary subject descriptor passed to a reference-retaining setter escaped ordinary GKM tests; a named descriptor covering encoding/decoding passes the fresh ASan fixture. Record platform-specific CI separately from local sanitizer results.

Update **this file** when a repeatable method is demonstrated, a release policy becomes official, a tool path changes, or a lesson alters the normal workflow. Mark what changed and retain applicability/version caveats.

Update [the separate improvement backlog](data_model_process_improvements.md) with hypotheses, costs, prototypes, owners and decisions; only migrate an idea here after it has been verified and accepted as an operating practice.

After each release, review G0–G6, reconcile open mismatch records, retire superseded advice and specify which cases remain unknown. The next agent should be able to read this document plus the current release's status/evidence and continue without reconstructing meeting discussions.

### Source provenance for this charter

- **Authoritative mandate:** user-provided September 9 onboarding meeting transcript, retained outside the public repository.
- **Supplemental, lower-authority discussion:** user-provided engineering meeting transcript on 1.7 T2 integration, early validation, errata and branch policy, retained outside the public repository; its ideas are clearly marked proposals.
- **Verified SDK implementation:** linked code and `data_model/README.md`.
- **Verified first-run evidence:** [2026-10-19 blocked and successful execution reports](../reports/2026-10-19_17-02-05.md).

## Verified Validation Practices

- Invoke a virtualenv Python through its virtualenv path; resolving its symlink can select the system interpreter and lose the installed Matter packages. Assert parser and model-resource paths before counting results.
- Compile new regressions in the normal registered target. Use independent metadata overlays for cross-version/dependency controls, verify both owner and test consume them, and distinguish repeat executions from distinct test cases.
- For targeted Alchemy ZAP updates, retain the established provisional policy and check generated metadata/file-sync as well as bounds. A shallow pinned spec may need bounded reachable-tag ancestry; never invent a release tag or hand-edit provenance to make CI pass.
- Invoke Alchemy with supported relative roots before proposing a provenance writer change. Compare absolute/relative replay XML semantically, retain truthful command metadata, and use existing SDK errata overlays for justified API/domain compatibility. Review generated project-index side effects separately; do not install collateral FeatureMap default changes.
- Keep strict dependency tests honest. Compile both owner and test against the actual dependency metadata in isolation, verify consumed headers, and report combined success separately from standalone failure. Never accept either privilege while claiming to enforce the stronger one.

## Canonical integration PR description — current-state reporting policy

The Matter 1.7 integration draft is [connectedhomeip #74862](https://github.com/project-chip/connectedhomeip/pull/74862). Its GitHub description is the canonical current technical summary. Edit it directly through the authenticated GitHub CLI and read it back after each meaningful update. Do not maintain a duplicate Markdown body in the repository.

**At any point, the PR description answers only: what changed, which changes look correct and intentional, which fixes are included, which fixes are in related PRs, what remains technically unresolved, and what validation supports that assessment.** It is a concise answer for the team, not an investigation report.

Enforce the following in every description rewrite:
- State meaningful model deltas (including all changed model areas), SDK changes and test evidence; distinguish verified correctness, plausible/intended changes, and unresolved technical mismatches.
- Link other PRs that supply implementation dependencies, without duplicating the implementations or narrating how they were discovered.
- Do **not** include provenance tables, commit SHAs, toolchain versions, private source locations, generated commands, investigative chronology, rejected approaches, future task sequences, or requests for acceptance/confirmation.
- Do **not** insert disclaimer-style qualifications or discussion of material not yet present in the PR, such as promises to add the XML later. Technical uncertainties and meaningful test-coverage gaps belong in a succinct **Open technical issues** section when they affect confidence.
- Update the body **in place** whenever the integrated model, SDK fixes, test results, or technical classifications change. Rewrite superseded entries; don't append chronological addenda. Ensure the description accurately reflects the current PR diff and the model comparison used for the update.
- Keep full provenance, generation evidence, documentation, open questions, process milestones and confidential disclosure considerations in internal work reports and this playbook rather than the PR description.
- Keep the regenerated `data_model/1.7/` XML and directly related SDK code/tests together in the existing integration PR rather than opening duplicates. Public publication of material originating in the private specification follows applicable disclosure controls; handle that operationally, not as boilerplate in the public PR body.

**Publication hygiene:** The upstream integration PR may be updated via a suitably authorized local `gh pr edit` when this connected GitHub integration lacks PR edit permissions. Read and verify its current contents before and after an edit; never claim remote success from only a local description file.
