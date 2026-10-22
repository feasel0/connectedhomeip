# PR #74862: Updated Human Review Reply Drafts

All responses below are DRAFTS ONLY. None has been posted, submitted as a review or used to resolve a thread. They describe the published PR head `7da3f2168292e73f3f296202f90abef454058598`, not merely an experimental proposal. Updated 2026-10-22 for opened parser/Linux drafts. Completed hosted check runs report no failure, but PullApprove is pending, CHANGES_REQUESTED remains active and the SME-reviewer workflow requires action; no final approval is claimed.

The 253-path diff contains only the approved reference model, provenance, four generated ZAP XML files and generated cluster index. Removed SDK implementations and tests remain reachable at original integration commit `fd4843c02fd2a20a64765abc6f2084cbedca12b4`, an ancestor of the published head. ModeBase [draft #74886](https://github.com/project-chip/connectedhomeip/pull/74886), parser [draft #74888](https://github.com/project-chip/connectedhomeip/pull/74888) and Linux [draft #74889](https://github.com/project-chip/connectedhomeip/pull/74889) are independently proposed and unmerged. The live model assessment includes all nineteen entries without making these independent SDK fixes model-update dependencies.

Reviewer text is reproduced with ASCII typography normalized. Counts from the earlier exact-canonical validation are not presented as a new full application/REPL run of this head. The private Spec dependency is published as [draft Spec PR #13695](https://github.com/CHIP-Specifications/connectedhomeip-spec/pull/13695), but is not merged.

## 1. Lint Workflow

[Comment 4337978832](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4337978832)

**Reviewer:**
> To keep the scope minimal, the addition of this test can be done in a follow-up PR.

**Draft Response:**
Agreed. This PR now retains the baseline lint workflow; the added ZAP test and its registration have been removed. Their implementation is preserved in the original integration commit for separate tooling review.

## 2. Python Workflow

[Comment 4337980842](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4337980842)

**Reviewer:**
> To keep the scope minimal, the addition of this test can be done in a follow-up PR.

**Draft Response:**
Agreed. The existing CI commands are restored, with no added unsupported-constraints suite registration. That suite remains preserved for the owning parser/harness follow-up, not this model update.

## 3. BaseDeviceType Rendering

[Comment 4338055085](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338055085)

**Reviewer:**
> This is an alchemy issue now tracked by https://github.com/project-chip/alchemy/issues/93

**Draft Response:**
Thanks; Alchemy #93 remains the rendering tracker. This PR retains the generated summaries without a hand-edited XML workaround or an unrelated eligibility change.

## 4. Errata Ownership

[Comment 4338082902](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338082902)

**Reviewer:**
> Errata lives in Spec repository. Please open a PR on Spec to add these changes to .github/alchemy/errata.yaml

**Draft Response:**
Moved to the Spec-owned configuration in private draft Spec PR #13695, published at `76fcb138fc42`. The SDK overlay is removed. Supported relative-root generation preserves all four intended XML trees; normal Spec review/merge is still pending. Independent project-index generator collateral is excluded.

## 5. Added ZAP Test

[Comment 4338283502](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338283502)

**Reviewer:**
> To keep the scope minimal, the addition of this test can be done in a follow-up PR.

**Draft Response:**
Agreed. The added test and its CI registration are no longer in this PR; the coverage is preserved for a tooling follow-up. The existing metadata/hand-edit check accepts all 157 files on the published tree.

## 6. Closure Coverage

[Comment 4338326570](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338326570)

**Reviewer:**
> While we update the DM files, we may occasionally need to modify incompatible tests. However, the scope of these modifications should be limited to "test fixes" necessary to keep the CI passing, rather than completing tests or increasing coverage. It appears that the current changes are intended to increase coverage; if that is the case, please propose them in a separate PR. Please keep the scope of this PR limited to updating the DM files and fixing whatever is necessary to maintain a healthy CI.
>
> Moreover, if a test fix is needed, the fix should be well documented and reported the owners of the test to fix-forward it.

**Draft Response:**
Agreed. Both the new configuration validation and expanded tests are removed from this PR and preserved for an owning follow-up, including the specified StepValue divisibility rule. No existing candidate failure established their necessity here; the 39 baseline Closure cases passed.

## 7. DEM Coverage

[Comment 4338337295](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338337295)

**Reviewer:**
> Same here. It appears that these are intended to increase the coverage, which is out of the scope of DM Update.

**Draft Response:**
Agreed. The expanded DEM coverage is removed and preserved separately. The existing test file is unchanged from the PR base; its 17 baseline cases passed on the canonical reduction.

## 8. EPA Coverage

[Comment 4338341235](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338341235)

**Reviewer:**
> Same here. It appears that these are intended to increase the coverage, which is out of the scope of DM Update.

**Draft Response:**
Agreed. The additional coverage is removed from this PR and preserved with the separate minima-enforcement proposal. The six baseline EPA cases passed without those additions.

## 9. EPA Implementation

[Comment 4338350156](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338350156)

**Reviewer:**
> if this is required to keep the CI passing, please add comments about why it's added and report the change to the Energy TT.

**Draft Response:**
No existing candidate failure established a CI need for the new validator, so it is removed from this PR. The implementation and essential regressions are preserved for separate review and Energy TT discussion; no owner contact or agreement is claimed.

## 10. GKM Coverage

[Comment 4338352997](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338352997)

**Reviewer:**
> Same here. It appears that these are intended to increase the coverage, which is out of the scope of DM Update.

**Draft Response:**
Agreed. The tests and dependencies now match the PR base. Reserved-path, wildcard and revision coverage remains preserved as one key-management follow-up, rather than separate PRs per test file; the 16 baseline cases passed.

## 11. Humidistat Coverage

[Comment 4338359173](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338359173)

**Reviewer:**
> Same here. It appears that these are intended to increase the coverage, which is out of the scope of DM Update.

**Draft Response:**
Agreed. The new tests and write-policy change are removed and preserved separately; the 35 baseline cases passed. Attribute writes, command omission and persisted/startup zero behavior remain distinct questions for the owning follow-up, not policies introduced by this model update.

## 12. ModeBase Coverage

[Comment 4338367629](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338367629)

**Reviewer:**
> Same here. It appears that these are intended to increase the coverage, which is out of the scope of DM Update.

**Draft Response:**
Agreed. The ModeBase implementation and tests are removed from the DM diff and proposed in independent [draft #74886](https://github.com/project-chip/connectedhomeip/pull/74886), open and unmerged. Its two-file fix has 33 focused passes versus 30 passes and three intended failures with the upstream owner. Thermostat Manage, ordinary Operate and COREMODES behavior are covered. The authorization inputs remain identical at latest checked upstream `54b92365e766`; this is not a fresh full-SDK build or a dependency of the DM update.

## 13. Push AV Coverage

[Comment 4338370399](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338370399)

**Reviewer:**
> Same here. It appears that these are intended to increase the coverage, which is out of the scope of DM Update.

**Draft Response:**
Agreed. The additional AmbientContext coverage is removed and preserved for a transport-testing follow-up. Production behavior is unchanged, and the nine baseline cases passed.

## 14. Linux BSS Coverage

[Comment 4338385273](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338385273)

**Reviewer:**
> Same here. It appears that these are intended to increase the coverage, which is out of the scope of DM Update.

**Draft Response:**
Agreed. The BSS testability, mapping and test-registration changes are removed from this DM update. Independent [draft #74889](https://github.com/project-chip/connectedhomeip/pull/74889) proposes the EAP translation at `d9316425a9de`, with essential decoder/TLV regressions in the existing connectivity test file and no new registration. Exact upstream passes two and fails five focused tests; the candidate passes all seven. The bug drops EAP membership when clearing the sentinel; it does not leak bit 7. The draft documents current 1.7 correctness separately from older advertised-version/backport compatibility. Offline proof does not establish live scan acquisition or universal backward compatibility.

## 15. Unsupported Parser Contract

[Comment 4339381020](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4339381020)

**Reviewer:**
> Before this PR, constraint expressions the parser couldn't represent were simply skipped, and existing tests/CI pass with that. `unsupported_expressions` / `UnsupportedConstraintError` / `require_supported()` (and the `parse_reference` / `minLength` / `maxLength` rewrites in `_parse_single_constraint`) add new behavior that every consumer now has to handle (IDM, Scenes, ...). Could we revert this part to the pre-PR parsing and do it in a follow-up together with an actual expression evaluator?
>
> That also removes the need for the `require_supported()` calls in `idm_support.py` and `TC_S_common.py`. The `TC_S_common.py` one currently raises with no handler, so the Scenes tests can error out when the chosen scenable attribute has an expression bound.

**Draft Response:**
Agreed. The parser and both IDM/Scenes consumers now match the PR base; the added unsupported-expression API and imports are absent. That contract and all consumer handling are preserved for separate review. This does not claim that expression evaluation is solved or make unsupported evaluation a DUT failure.

## 16. Strict IDM Gate

[Comment 4339381034](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4339381034)

**Reviewer:**
> The changes in step 1 (`except UnsupportedConstraintError`, `command_coverage_failures`, the strict `asserts.fail(...)`, the new `ChipStackError` / `other_error` entries, and moving `enforce_constraint_policy`) add a new strict-mode gate: harness coverage gaps, transport errors and non-CONSTRAINT_ERROR statuses now fail the DUT, where they were previously skipped. That's a policy change beyond the DM update, and with the 1.7 XML it would fail compliant DUTs for harness reasons (e.g. `<compute>`-bounded command fields in CameraAVSettingsUserLevelManagement, ElectricalAlarm, TemperatureAlarm, AudioControl). Could we restore the pre-PR step 1 as-is?

**Draft Response:**
Agreed. Step 1 is restored byte-for-byte to the PR base, without the added incomplete-coverage gate. A source-bound diagnostic confirms the skip/probe path while preserving failures for accepted violations and no exercised probe. That diagnostic itself is not a full REPL pass; completed hosted check runs now report no failure, but review/approval gates remain open. Any stricter coverage policy remains separate.

## 17. IDM/DEM Helpers

[Comment 4339381042](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4339381042)

**Reviewer:**
> The DEM-specific helpers (`_is_dem_power_range`, `_dem_max_of_supported`, `_dem_power_range_request`), `_numeric_bound_expression` and the `minOf`/`maxOf` handling in `_resolved_command_field_constraints`, `coverage_failure`, the new `return 0` in `_generate_valid_command_field_value`, and the `power-mw` range entry are new harness capability. Unless one of these is required to keep an existing test green with the 1.7 XML, could we drop them and keep `idm_support.py` at its pre-PR behavior? If a piece is required (e.g. the `power-mw` range for the new DEM bounds), please call out which existing test needs it and keep only that.

**Draft Response:**
Agreed. The helper module is restored to the PR base, without those additions or a broad expression evaluator. No existing reduced-candidate failure required retaining them. Capability/correctness work and stricter policy remain preserved for separate review; the 19 baseline helper cases passed.

## 18. Diagnostics And Expectations

[Comment 4339381051](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4339381051)

**Reviewer:**
> Before this PR, `add_cluster_data_from_xml` did `problems = problems + parser.get_problems()`, which only rebinds a local, so parser warnings never reached callers. Switching to `extend` is a correct fix, but it surfaces a set of warnings that were always there, which is why the zero-problem asserts for 1.2-1.7 in `test_build_xml_override` (and the `TestSpecParsingDataType.test_exhaustive_all_fields_in_1_5` check) were replaced with the pinned per-version table in `assert_historical_parser_diagnostics`. The same goes for the new/reworded warnings (derived-attribute fallback, bitmap bit range, unmatched derived command) and the `remove_problem` narrowing.
>
> For this PR, could we keep the pre-PR behavior and the existing zero-problem asserts, and do the "surface parser warnings" fix plus the diagnostics expectations as a separate change? If the 1.7 XML introduces a genuinely new warning that breaks the existing assert, I'd prefer the smallest targeted fix for that one case.

**Draft Response:**
Agreed. The pre-PR diagnostic behavior and original assertions are restored; the warning table and diagnostic changes are removed from this PR. All 79 baseline parser cases passed without weakening those assertions. The propagation fix and owning regressions remain preserved separately.

## 19. Derived Merge / Findall

[Comment 4339381058](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4339381058)

**Reviewer:**
> Are the derived-command merging changes (`conformance_is_explicit`, `combine_command`, parsing fields for unknown commands, skipping access warnings for base/generated commands) and the `_parse_data_type` `iter` -> `findall` change required to keep an existing test/CI job passing with the refreshed 1.7 XML (e.g. the Thermostat Mode command overlays)? If yes, could you point to the failing test so we keep just the minimal piece? If not, I'd prefer moving them to a follow-up with the other parser improvements.

**Draft Response:**
No existing reduced-candidate failure justified retaining these changes, so the pre-PR parser is restored. Independent [draft #74888](https://github.com/project-chip/connectedhomeip/pull/74888) at `704c456e0fbf` proposes command metadata inheritance only: upstream passes eight and fails three intended regressions; the candidate passes all eleven focused cases. Diagnostic propagation, historical expectations, broad iter/findall changes and expression policy are excluded. The sole generated-index inconsistency remains corrected by the existing generator's one-cell PICS update, without parser changes in this DM PR.

## 20. Added Python Coverage

[Comment 4339381068](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4339381068)

**Reviewer:**
> Same as the C++ test comments: these new test classes/methods (here, and in `TestSpecParsingSupport.py` / `TestSpecParsingSelection.py`, e.g. the derived-command, unsupported-constraint, diagnostics and `test_thermostat_mode_inherited_command_selection` tests) cover new behavior and increase coverage, which is out of the scope of the DM update. Please keep only test fixes needed for something this PR still changes.

**Draft Response:**
Agreed. Python tests and their executable modes now match the PR base; the added unsupported suite is absent. All 98 existing Python cases passed on the canonical reduction. The removed coverage remains preserved with the corresponding independent fixes, not silently discarded.
