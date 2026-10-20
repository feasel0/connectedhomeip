# Matter 1.7 SVE Data Model Update — Work Summary and Findings

**Date:** 2026-10-19 (UTC)  
**Scope:** First CSA-side data-model stewardship exercise; update the existing Matter 1.7 reference XML directory from specification `master` and establish a reliable, error-free generator run.  
**Status:** **Initial generation/execution gate PASSED. Release readiness NOT established.**  
**Primary evidence:** [Initial blocked run](../reports/2026-10-19_16-39-38.md) · [successful rerun and detailed validation](../reports/2026-10-19_17-02-05.md) · [SDK procedure](../../data_model/README.md)

## Semantic-review checkpoint, 2026-10-20

**Subsequent defect-resolution checkpoint:** [tested fixes and owner decisions](2026-10-20_SVE_defect_resolution.md).
TMODE inheritance and explicit unsupported-constraint handling are implemented in
separate SDK commits; final five suites pass **84/84** and six consumer tests pass.
Public-safe Alchemy access and occurrence-based bitmap patch handoffs have
independent red/green evidence and **103** combined leaf passes. Six bounded SDK
probes clarify remaining policy/native coverage gaps. These are tooling advances,
not a released scraper or accepted model; ballot/tag and integration gates remain
open. The paragraphs below preserve the original review checkpoint.

All **20/20 XML differences** are now itemized against the exact previous/current specification commits in the [semantic review](2026-10-20_SVE_semantic_review.md), with proposed owners/actions in the [mismatch ledger](SVE_mismatch_ledger.md). Five candidate-bound TestSpec suites passed **79/79** tests: Support 15, Selection 2, DeviceType 29, DataType 26, Namespace 7; zero errors/failures/skips. Pinned Python source and generated-resource provenance were explicitly checked, using existing native controller modules rather than a fresh native build.

**Confirmed issues outside that coverage:** Thermostat Mode derived command inheritance becomes optional, DEM loses its `maxOf` lower constraint in the consumer parser, Thermostat Mode command access metadata is absent despite source Manage, and a PairingHint example operator is lost during extraction. SDK/ZAP bounds, ACL and behavioral drift have separate owner actions. No normative/generated XML or production parser was changed; the candidate remains scratch.

**Gates:** G1 remains passed; G2 has structural evidence; G3 itemization is complete but findings and milestone decisions remain open; G4 is partially exercised, not implementation-ready; G0/G5 remain blocked. The Current list is frozen at 40 entries / 39 unique flags, but no applicable ballot email/list, chosen release tag or coordinator approval was available. No ballot/SVE approval is claimed.

## Presentation summary

- **Assignment:** Run the existing-directory data-model update documented by the Matter SDK, using specification `master`. The **first requested deliverable** was an error-free execution of the update script—not a finalized SVE data-model release.
- **Blocker found:** Alchemy scraped successfully, but the SDK generator invoked obsolete specification Make targets (`pdf-appclusters-book`, `pdf-devicelibrary-book`, and `pdf-standardnamespaces-book`). Specification `master` now provides a **combined main book** containing the application clusters, device library, and namespaces. The old generator failed after building the main book.
- **Fix:** Detect complete combined-book inclusion from its actual printed AsciiDoc include records; otherwise retain the historical separate-book path. Use exact basename membership during generated-file filtering instead of substring checks. This is a generator/specification build-interface fix, **not** a change to Matter conformance rules or the reference XML content.
- **Result:** Complete non-dry-run generation exited **0** in **275.67 seconds**, with **zero error diagnostics, zero tracebacks, and two reported warnings**. Six targeted regression tests and Ruff passed. Existing historical-book behavior was checked with controlled test fixtures, not a complete old-spec generation.
- **Output quality:** **280/280 XML files** are nonempty and parse successfully: **139 cluster files, 105 device-type files, 31 namespaces, and 5 global files**. SDK parsers found **148 cluster definitions and 104 device types with zero parsing problems**. No XML files, cluster/device IDs, or ID names were added or removed; the regenerated build manifest matches the prior version. Independent Alchemy output canonically matches all resulting XML files.
- **What changed:** **20 XML files** differ from the checked-in 1.7 snapshot (14 cluster, 5 device-type, 1 global). The specification SHA changed; the previous tag was removed because the selected `master` commit is untagged. The generated XML and full logs remain in scratch, **not committed as an SVE release candidate**.
- **What remains:** Confirm `Current` and the official source/tag against ballot authority; resolve the itemized semantic/parser/extraction findings and owner decisions; run relevant native/ACL/IDM/test-harness checks before seeking a model-release PR. Five parsing/selection suites have now passed, not full SDK integration.

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

## Resolved Investigation Routing

The original aggregate XML counts were leads, not semantic facts. The following replaces that coarse queue; detailed evidence and open dispositions are in the linked review and ledger.

| Priority | Reviewed difference or warning | Outcome / remaining action |
|---|---|---|
| P2 | **Group Key Management** | No actual feature loss. Source retires adoption struct/attribute, reserves ID 0x0004; ZAP/runtime already align. Revision policy and independent adoption boundary tests remain open. |
| P2 | **Closure Dimension** | Encoded integer-hundredths correction; empty Speed constraint removed, conformance unchanged. ZAP default/minimum drift and boundary tests remain. |
| P1 | **Device Energy Management** | Four added nodes are constraint references, not attributes. Optional non-null power bounds/source contract mostly align with SDK; parser demonstrably loses MaxPower `maxOf` lower bound. |
| P1 | **Thermostat Mode** | Existing-command overlays/maturity changes; source Manage absent from XML, generated access Operate; parser replaces inherited command conformance with Optional. |
| P2 | **Electrical Protection Alarm** and **Humidistat** | Source minima/nullability changes; concrete ZAP/test/runtime gaps require owner decisions and targeted validation. |
| P2 | **Push AV Stream Transport** | No enum/field addition. Existing MaxPreRollLen condition adds AmbientContext; implementation aligns, focused test missing in inspected cases. |
| P2 | Five device-type files and global bitmap | Device-type eligibility unchanged; rendering question isolated. Bitmap example loses operator despite unchanged source: confirmed extraction discrepancy. |
| P3 | **Joint Fabric Administrator**, cluster 1875 | Historical JFPKI -> JFADMIN transition at 1.5.1 -> 1.6; same warning before/after candidate. Validate history, do not normalize old XML. |
| Normal | Warning: no tag on specification `master` | Expected for an untagged input; obtain the official chosen release/tag later rather than inventing one. |
| Required gate | `Current` not matched against ballot authority | Exact list/hash recorded; authoritative email/list and release SHA/tag unavailable. |
| Required gate | SDK/test-harness integration | 79 TestSpec passes complete; native cluster, ACL/IDM and certification checks not run. |

**Important classification:** changes in XML structure are **investigation leads**, not automatically defects. First confirm behavior against the intended specification and release include set; change code or spec only for a demonstrated discrepancy.

## Acceptance boundaries

**Completed:** execute generator end to end without errors; preserve historical Make-target layout; prove correct structural output and manifest; reproduce and regress the observed failure.

**Not claimed:** ballot-correct selection, official SVE model acceptance, provisional-marking approval, backward compatibility of all generated APIs, SDK implementation conformance, test-harness readiness, or approval of the 20 reviewed XML differences.

## Near-term next actions

1. Communicate the successful first gate and the tool fix with its evidence. **Draft tooling PR:** [feasel0/connectedhomeip #1](https://github.com/feasel0/connectedhomeip/pull/1), containing only the generator change and its six-test regression file. This is a **fork-local draft targeting the fork's master**, not an upstream PR; creation directly in project-chip/connectedhomeip was denied by the connected GitHub integration. The unreviewed generated XML is excluded.
2. Confirm with release/spec contacts which official SHA/tag and include flags apply to this SVE milestone.
3. Review the completed [20-file semantic comparison](2026-10-20_SVE_semantic_review.md) and resolve the [ledger](SVE_mismatch_ledger.md) with proposed cluster/parser/scraper owners.
4. Develop targeted reproducing regressions before bounded fixes; do not patch generated XML, invent normative requirements, or silently waive open findings.
5. Preserve the completed 79 TestSpec outcomes and execute appropriate native/ACL/IDM/test-harness validation after selection and fixes; publish a separate model-release PR only after approval.

## Source and interpretation hierarchy

The September 9 onboarding meeting is authoritative for our role; the separate engineering meeting proposes supplemental ways to improve early checking and distribute specialized fixes. The generator findings above are sourced from the linked checked-in execution reports and inspected SDK code; conclusions about potential semantic mismatches remain preliminary. The raw meeting transcripts and private specification checkout are intentionally not checked into this public fork.
