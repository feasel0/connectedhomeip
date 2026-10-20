# Matter Data Model Manager — Role Charter and Release Playbook

**Living document for humans and future agents.**  
**Status:** Version 1, 2026-10-19. Update after every material release-cycle lesson.  
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

The onboarding specifically recommends reviewing Arya's [Matter 1.7 integration PR #73842](https://github.com/project-chip/connectedhomeip/pull/73842), especially its **Required manual modifications**, to learn the real failure modes, rather than reading hundreds of XMLs without a diff summary.

### Phase E — Validate integration into SDK testing

For a **new** model revision, follow the README's packaging and selection steps: `BUILD.gn`, generated `data_model_xmls.gni`, `PrebuiltDataModelDirectory`, `dm_from_spec_version()`, model version tests, `SpecificationDefinedRevisions.h`, and the directory-update workflow. For an **existing** revision, verify that these remain correct; change only what is needed.

Follow the official Python setup and run the documented `TestSpecParsingSupport.py`, `TestSpecParsingSelection.py`, `TestSpecParsingDeviceType.py` and additional appropriate `TestSpec*` suites. Run IDM and related SDK/test-harness regression tests relevant to the changed requirements. If a version default is updated, anticipate additional ZAP, implementation, and test failures beyond direct IDM model parsing.

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

**Current state (2026-10-19):** G1 complete and substantial G2 evidence; G0 include flags not fully verified, G3–G5 not complete. Do not promote G1 to G5 by inference.

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

Update **this file** when a repeatable method is demonstrated, a release policy becomes official, a tool path changes, or a lesson alters the normal workflow. Mark what changed and retain applicability/version caveats.

Update [the separate improvement backlog](data_model_process_improvements.md) with hypotheses, costs, prototypes, owners and decisions; only migrate an idea here after it has been verified and accepted as an operating practice.

After each release, review G0–G6, reconcile open mismatch records, retire superseded advice and specify which cases remain unknown. The next agent should be able to read this document plus the current release's status/evidence and continue without reconstructing meeting discussions.

### Source provenance for this charter

- **Authoritative mandate:** user-provided September 9 onboarding meeting transcript, retained outside the public repository.
- **Supplemental, lower-authority discussion:** user-provided engineering meeting transcript on 1.7 T2 integration, early validation, errata and branch policy, retained outside the public repository; its ideas are clearly marked proposals.
- **Verified SDK implementation:** linked code and `data_model/README.md`.
- **Verified first-run evidence:** [2026-10-19 blocked and successful execution reports](../reports/2026-10-19_17-02-05.md).
