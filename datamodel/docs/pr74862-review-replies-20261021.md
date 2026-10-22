# PR #74862: Updated Human Review Reply Drafts

These are drafts for approval. None has been posted or used to resolve a thread.

Reviewer comments are unchanged apart from normalized ASCII typography.

## 1. Lint Workflow

[Comment 4337978832](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4337978832)

**Reviewer:**
> To keep the scope minimal, the addition of this test can be done in a follow-up PR.

**Draft Response:**
Done. I've removed the added test and restored the lint workflow. The test can go in a separate PR.

## 2. Python Workflow

[Comment 4337980842](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4337980842)

**Reviewer:**
> To keep the scope minimal, the addition of this test can be done in a follow-up PR.

**Draft Response:**
Done. The original CI commands are restored; the new test suite is out of this PR.

## 3. BaseDeviceType Rendering

[Comment 4338055085](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338055085)

**Reviewer:**
> This is an alchemy issue now tracked by https://github.com/project-chip/alchemy/issues/93

**Draft Response:**
Thanks, I'll leave this to Alchemy #93. I haven't added a workaround to the generated XML.

## 4. Errata Ownership

[Comment 4338082902](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338082902)

**Reviewer:**
> Errata lives in Spec repository. Please open a PR on Spec to add these changes to .github/alchemy/errata.yaml

**Draft Response:**
I've opened [Spec PR #13695](https://github.com/CHIP-Specifications/connectedhomeip-spec/pull/13695) for the errata and removed the SDK overlay. The Spec PR is still awaiting approval and merge.

## 5. Added ZAP Test

[Comment 4338283502](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338283502)

**Reviewer:**
> To keep the scope minimal, the addition of this test can be done in a follow-up PR.

**Draft Response:**
Agreed. I've removed the test and its CI registration; they can be reviewed separately.

## 6. Closure Coverage

[Comment 4338326570](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338326570)

**Reviewer:**
> While we update the DM files, we may occasionally need to modify incompatible tests. However, the scope of these modifications should be limited to "test fixes" necessary to keep the CI passing, rather than completing tests or increasing coverage. It appears that the current changes are intended to increase coverage; if that is the case, please propose them in a separate PR. Please keep the scope of this PR limited to updating the DM files and fixing whatever is necessary to maintain a healthy CI.
>
> Moreover, if a test fix is needed, the fix should be well documented and reported the owners of the test to fix-forward it.

**Draft Response:**
Agreed. I've removed the new validation and extra tests. The existing Closure tests pass without them.

## 7. DEM Coverage

[Comment 4338337295](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338337295)

**Reviewer:**
> Same here. It appears that these are intended to increase the coverage, which is out of the scope of DM Update.

**Draft Response:**
Done. The extra DEM tests are removed, and the test file is back to its original version.

## 8. EPA Coverage

[Comment 4338341235](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338341235)

**Reviewer:**
> Same here. It appears that these are intended to increase the coverage, which is out of the scope of DM Update.

**Draft Response:**
Agreed. I've removed the extra EPA coverage and kept it with the separate implementation proposal.

## 9. EPA Implementation

[Comment 4338350156](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338350156)

**Reviewer:**
> if this is required to keep the CI passing, please add comments about why it's added and report the change to the Energy TT.

**Draft Response:**
I've removed the validator; we haven't found an existing CI failure that needs it here. It can be reviewed separately with the Energy TT.

## 10. GKM Coverage

[Comment 4338352997](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338352997)

**Reviewer:**
> Same here. It appears that these are intended to increase the coverage, which is out of the scope of DM Update.

**Draft Response:**
Done. The GKM tests and dependencies are restored to their original versions. The extra coverage can go in a follow-up.

## 11. Humidistat Coverage

[Comment 4338359173](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338359173)

**Reviewer:**
> Same here. It appears that these are intended to increase the coverage, which is out of the scope of DM Update.

**Draft Response:**
Agreed. I've removed the new tests and write-policy change. The zero-value behavior needs a separate discussion.

## 12. ModeBase Coverage

[Comment 4338367629](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338367629)

**Reviewer:**
> Same here. It appears that these are intended to increase the coverage, which is out of the scope of DM Update.

**Draft Response:**
Agreed. I've moved the ModeBase fix and its tests out of this PR into [#74886](https://github.com/project-chip/connectedhomeip/pull/74886).

## 13. Push AV Coverage

[Comment 4338370399](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338370399)

**Reviewer:**
> Same here. It appears that these are intended to increase the coverage, which is out of the scope of DM Update.

**Draft Response:**
Done. I've removed the extra AmbientContext tests and kept them for a follow-up.

## 14. Linux BSS Coverage

[Comment 4338385273](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4338385273)

**Reviewer:**
> Same here. It appears that these are intended to increase the coverage, which is out of the scope of DM Update.

**Draft Response:**
Agreed. I've removed the Linux BSS changes from this PR. The fix and tests are in [#74889](https://github.com/project-chip/connectedhomeip/pull/74889), with older-version compatibility called out for review.

## 15. Unsupported Parser Contract

[Comment 4339381020](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4339381020)

**Reviewer:**
> Before this PR, constraint expressions the parser couldn't represent were simply skipped, and existing tests/CI pass with that. `unsupported_expressions` / `UnsupportedConstraintError` / `require_supported()` (and the `parse_reference` / `minLength` / `maxLength` rewrites in `_parse_single_constraint`) add new behavior that every consumer now has to handle (IDM, Scenes, ...). Could we revert this part to the pre-PR parsing and do it in a follow-up together with an actual expression evaluator?
>
> That also removes the need for the `require_supported()` calls in `idm_support.py` and `TC_S_common.py`. The `TC_S_common.py` one currently raises with no handler, so the Scenes tests can error out when the chosen scenable attribute has an expression bound.

**Draft Response:**
Agreed. I've restored the original parser behavior and removed the new API and its IDM/Scenes calls. Expression handling can be reviewed separately.

## 16. Strict IDM Gate

[Comment 4339381034](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4339381034)

**Reviewer:**
> The changes in step 1 (`except UnsupportedConstraintError`, `command_coverage_failures`, the strict `asserts.fail(...)`, the new `ChipStackError` / `other_error` entries, and moving `enforce_constraint_policy`) add a new strict-mode gate: harness coverage gaps, transport errors and non-CONSTRAINT_ERROR statuses now fail the DUT, where they were previously skipped. That's a policy change beyond the DM update, and with the 1.7 XML it would fail compliant DUTs for harness reasons (e.g. `<compute>`-bounded command fields in CameraAVSettingsUserLevelManagement, ElectricalAlarm, TemperatureAlarm, AudioControl). Could we restore the pre-PR step 1 as-is?

**Draft Response:**
Done. Step 1 is restored exactly as it was before this PR, without the new strict-mode gate.

## 17. IDM/DEM Helpers

[Comment 4339381042](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4339381042)

**Reviewer:**
> The DEM-specific helpers (`_is_dem_power_range`, `_dem_max_of_supported`, `_dem_power_range_request`), `_numeric_bound_expression` and the `minOf`/`maxOf` handling in `_resolved_command_field_constraints`, `coverage_failure`, the new `return 0` in `_generate_valid_command_field_value`, and the `power-mw` range entry are new harness capability. Unless one of these is required to keep an existing test green with the 1.7 XML, could we drop them and keep `idm_support.py` at its pre-PR behavior? If a piece is required (e.g. the `power-mw` range for the new DEM bounds), please call out which existing test needs it and keep only that.

**Draft Response:**
Agreed. I've restored the original helper module. We haven't found an existing test failure that requires those additions here.

## 18. Diagnostics And Expectations

[Comment 4339381051](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4339381051)

**Reviewer:**
> Before this PR, `add_cluster_data_from_xml` did `problems = problems + parser.get_problems()`, which only rebinds a local, so parser warnings never reached callers. Switching to `extend` is a correct fix, but it surfaces a set of warnings that were always there, which is why the zero-problem asserts for 1.2-1.7 in `test_build_xml_override` (and the `TestSpecParsingDataType.test_exhaustive_all_fields_in_1_5` check) were replaced with the pinned per-version table in `assert_historical_parser_diagnostics`. The same goes for the new/reworded warnings (derived-attribute fallback, bitmap bit range, unmatched derived command) and the `remove_problem` narrowing.
>
> For this PR, could we keep the pre-PR behavior and the existing zero-problem asserts, and do the "surface parser warnings" fix plus the diagnostics expectations as a separate change? If the 1.7 XML introduces a genuinely new warning that breaks the existing assert, I'd prefer the smallest targeted fix for that one case.

**Draft Response:**
Agreed. The original diagnostic behavior and assertions are restored. The warning fix and updated expectations can go in a separate PR.

## 19. Derived Merge / Findall

[Comment 4339381058](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4339381058)

**Reviewer:**
> Are the derived-command merging changes (`conformance_is_explicit`, `combine_command`, parsing fields for unknown commands, skipping access warnings for base/generated commands) and the `_parse_data_type` `iter` -> `findall` change required to keep an existing test/CI job passing with the refreshed 1.7 XML (e.g. the Thermostat Mode command overlays)? If yes, could you point to the failing test so we keep just the minimal piece? If not, I'd prefer moving them to a follow-up with the other parser improvements.

**Draft Response:**
I've restored the original parser here. The command inheritance fix is in [#74888](https://github.com/project-chip/connectedhomeip/pull/74888); the broader parser changes are left out.

## 20. Added Python Coverage

[Comment 4339381068](https://github.com/project-chip/connectedhomeip/pull/74862#discussion_r4339381068)

**Reviewer:**
> Same as the C++ test comments: these new test classes/methods (here, and in `TestSpecParsingSupport.py` / `TestSpecParsingSelection.py`, e.g. the derived-command, unsupported-constraint, diagnostics and `test_thermostat_mode_inherited_command_selection` tests) cover new behavior and increase coverage, which is out of the scope of the DM update. Please keep only test fixes needed for something this PR still changes.

**Draft Response:**
Agreed. I've removed the added coverage and restored the original tests. The new tests are kept with their separate fixes.
