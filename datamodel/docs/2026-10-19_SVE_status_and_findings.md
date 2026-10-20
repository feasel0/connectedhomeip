# Matter 1.7 SVE Data Model Update — Work Summary and Findings

**Date:** 2026-10-19 (UTC)  
**Scope:** First CSA-side data-model stewardship exercise; update the existing Matter 1.7 reference XML directory from specification `master` and establish a reliable, error-free generator run.  
**Status:** **Initial generation/execution gate PASSED. Release readiness NOT established.**  
**Primary evidence:** [Initial blocked run](../reports/2026-10-19_16-39-38.md) · [successful rerun and detailed validation](../reports/2026-10-19_17-02-05.md) · [SDK procedure](../../data_model/README.md)

## Presentation summary

- **Assignment:** Run the existing-directory data-model update documented by the Matter SDK, using specification `master`. The **first requested deliverable** was an error-free execution of the update script—not a finalized SVE data-model release.
- **Blocker found:** Alchemy scraped successfully, but the SDK generator invoked obsolete specification Make targets (`pdf-appclusters-book`, `pdf-devicelibrary-book`, and `pdf-standardnamespaces-book`). Specification `master` now provides a **combined main book** containing the application clusters, device library, and namespaces. The old generator failed after building the main book.
- **Fix:** Detect complete combined-book inclusion from its actual printed AsciiDoc include records; otherwise retain the historical separate-book path. Use exact basename membership during generated-file filtering instead of substring checks. This is a generator/specification build-interface fix, **not** a change to Matter conformance rules or the reference XML content.
- **Result:** Complete non-dry-run generation exited **0** in **275.67 seconds**, with **zero error diagnostics, zero tracebacks, and two reported warnings**. Six targeted regression tests and Ruff passed. Existing historical-book behavior was checked with controlled test fixtures, not a complete old-spec generation.
- **Output quality:** **280/280 XML files** are nonempty and parse successfully: **139 cluster files, 105 device-type files, 31 namespaces, and 5 global files**. SDK parsers found **148 cluster definitions and 104 device types with zero parsing problems**. No XML files, cluster/device IDs, or ID names were added or removed; the regenerated build manifest matches the prior version. Independent Alchemy output canonically matches all resulting XML files.
- **What changed:** **20 XML files** differ from the checked-in 1.7 snapshot (14 cluster, 5 device-type, 1 global). The specification SHA changed; the previous tag was removed because the selected `master` commit is untagged. The generated XML and full logs remain in scratch, **not committed as an SVE release candidate**.
- **What remains:** Confirm the `Current` include flags against the applicable ballot email; review the 20-file semantic diff and provisional markings; investigate the specific reductions and conformance changes below; run the broader `TestSpec*` and appropriate SDK/test-harness checks before seeking a model-release PR.

## Reproducible input checkpoint

| Component | Selected input |
|---|---|
| Upstream SDK baseline | `24fafe816f7a5db9aeb514d6504ff6b57384b4f1` |
| Specification `master` | `eea0ffce8fe9e4951a4558a6e6c6362b307e0334` |
| Alchemy | `v1.7.10` (same version as existing 1.7 snapshot) |
| Output | `data_model/1.7` |
| Include mode | `--include-in-progress Current`, existing defines unchanged; **not yet ballot-verified** |
| Full successful execution | 2026-10-19 16:51:24–16:55:59 UTC; exit 0 |

Command shape (run only with legitimate specification access and an initialized Matter Python environment):

```bash
python scripts/spec_xml/generate_spec_xml.py \
  --scraper "$ALCHEMY" --spec-root "$SPEC_ROOT" \
  --include-in-progress Current --output-dir data_model/1.7
```

No specifications, tokens, private logs, or generated unapproved XML need to be published to communicate this outcome.

## Why this exercise matters to SDK developers

1. **The generation tooling—not the source specification or scraper—was the observed first blocker.** An upstream-facing, focused fix is justified by reproduction and a passing rerun.
2. **The refreshed model remains structurally coherent:** all known XML and identifiers remain represented; parsers and build manifest are consistent. This reduces risk of wholesale model loss during the current update.
3. **Successful generation does not imply implementation readiness.** The reference model represents specification intent; SDK ZAP XML, generated APIs, cluster implementations, and Python/IDM tests may still lag. Advancing the SDK's default specification revision can expose additional failures.
4. **The generated differences are not artifacts of the include-list repair:** an independent same-input Alchemy scrape yielded canonical XML identical to the finished generator output.
5. **Version provenance matters:** an untagged `master` input correctly records its SHA without claiming an official release tag. This is useful for the requested experimentation but does not substitute for an SVE tag/ballot checkpoint.

## Follow-up investigation queue (observations, not yet confirmed bugs)

| Priority | Observed difference or warning | Question to resolve / expected evidence |
|---|---|---|
| P1 | **Group Key Management:** loss of one feature, struct, field, entry, and related conformance/metadata | Find the responsible spec change, understand provisional/obsolete/inclusion rules, confirm whether deletion is intended, and identify any SDK/ZAP/test implications. **Do not re-add by assumption.** |
| P1 | **Closure Dimension:** one constraint removed | Determine the exact affected constraint and why it disappeared; confirm normative intent and test consequences. |
| P1 | **Device Energy Management:** four additional attribute elements, plus changed conformance-element counts | Classify each addition and changed condition against spec; establish whether SDK/ZAP/tests are current. |
| P1 | **Thermostat Mode:** three added command elements and changed conformance counts | Confirm command requirements, provisional state, implementation compatibility, and testing impact. |
| P2 | **Electrical Protection Alarm** and **Humidistat:** additional constraints | Check constraints against spec and parser semantics; look for genuine changed test expectations. |
| P2 | **Push AV Stream Transport:** enum/field addition | Confirm definition and whether generated APIs or implementations need coordinated changes. |
| P2 | Five device-type XML files and one global bitmap file differ | Produce itemized semantic comparisons and assess release/provisional effects. |
| P2 | Warning: inconsistent PICS codes for cluster ID **1875** across spec versions | Identify the involved versions and codes; distinguish intentional evolution from inconsistency needing upstream clarification. |
| Normal | Warning: no tag on specification `master` | Expected for an untagged input; obtain the official chosen release/tag later rather than inventing one. |
| Required gate | `Current` include defines not matched against ballot email | Retrieve authorized ballot include list, compare exact flags, and regenerate if necessary. |
| Required gate | Broader model `TestSpec*` tests, semantic/provisional review, SDK/test-harness integration | Execute and capture evidence after agreeing on selected spec snapshot and include flags. |

**Important classification:** changes in XML structure are **investigation leads**, not automatically defects. First confirm behavior against the intended specification and release include set; change code or spec only for a demonstrated discrepancy.

## Acceptance boundaries

**Completed:** execute generator end to end without errors; preserve historical Make-target layout; prove correct structural output and manifest; reproduce and regress the observed failure.

**Not claimed:** ballot-correct selection, official SVE model acceptance, provisional-marking approval, backward compatibility of all generated APIs, SDK implementation conformance, test-harness readiness, or verification that all 20 XML differences are desired.

## Near-term next actions

1. Communicate the successful first gate and the tool fix with its evidence; keep the generator repair as a **separate draft PR**, without bundling the unreviewed generated XML.
2. Confirm with release/spec contacts which official SHA/tag and include flags apply to this SVE milestone.
3. Generate an **itemized semantic diff** for 20 changed files, working independent mismatch threads in parallel (Group Key Management, Closure Dimension, Device Energy Management, Thermostat Mode, remaining changes).
4. For each mismatch, document spec reference, original/updated XML, ZAP/SDK/test impact, owner, decision, and specific required fix—or close as intended.
5. Run documented `TestSpec*` coverage and the appropriate integration/IDM suite against the accepted revision; publish a separate release-update PR only when its scope and evidence are ready.

## Source and interpretation hierarchy

The September 9 onboarding meeting is authoritative for our role; the separate engineering meeting proposes supplemental ways to improve early checking and distribute specialized fixes. The generator findings above are sourced from the linked checked-in execution reports and inspected SDK code; conclusions about potential semantic mismatches remain preliminary. The raw meeting transcripts and private specification checkout are intentionally not checked into this public fork.
