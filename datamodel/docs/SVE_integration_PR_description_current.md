## Matter 1.7 data-model changes

The refreshed Matter 1.7 model has **20 substantive/editorial XML deltas** across 14 cluster files, five device-type files and one global file. No cluster/device IDs or XML paths are added or removed. Declared revisions remain unchanged. Additional regenerated XML differences are formatting-only.

| Model | Change | Assessment |
| --- | --- | --- |
| Closure Control | Simplified positioning-feature summary. | Editorial; looks correct. |
| Closure Dimension | Percent-hundredths maximum 100 → 10000; Resolution/StepValue defaults and minima become 1. | Correct-looking unit correction. SDK invalid-configuration validation fixed; ZAP alignment needs attention. |
| Device Energy Management | PowerRangeAdjustRequest MinPower/MaxPower become optional, non-null, with at least one required; new absolute-power and compound maxOf bounds; Duration 1–86400. | Source-aligned. Compound expressions are explicitly detected/rejected by SDK consumers; full evaluation and null-valued examples need review. |
| Electrical Protection Alarm | Eight rating minima become 1; SurgeProtection bit-23 description corrected. | Source-aligned; constructor enforcement and native tests included. |
| General Commissioning | TC feature wording. | Editorial; looks correct. |
| Group Key Management | Retires GroupcastAdoptionStruct and reserves attribute 0x0004; uses Groups revision to infer adoption. CS/GCAST features remain. | Source-aligned; native revision/provider and metadata tests pass, with wire-level coverage still useful. |
| Humidistat | Step becomes 1–100; MistType non-null with 1–3 bounds; descriptive command-field constraint. | Plausible, but attribute/command/persistence zero-value handling differs. |
| Mode Base | Existing ChangeToModeByCoreTag explicitly requires Operate. | Source-aligned; Thermostat Mode has a derived-specific access requirement. |
| Mode Select | Revision-history wording. | Editorial. |
| Thermostat Mode | Three existing command overlays; provisional cluster/COREMODES conditions; derived incoming commands specify Manage. | Inheritance repaired. Alchemy extraction correction in #91. SDK generated ACL changes overlap #74803. |
| Network Commissioning | Security bitmap bit 5 renamed/reinterpreted as IEEE8021X, retaining value 0x20. | Source-aligned; Linux scan reporting fixed; version compatibility needs assessment. |
| Proximity Ranging | StartRangingRequest gains an association with its existing response. | Source-aligned; implementation agrees. |
| Push AV Stream Transport | Existing MaxPreRollLen requirement also applies to AmbientContext. | Production behavior already agrees; native coverage included. |
| Thermostat UI Configuration | Revision-history terminology. | Editorial. |
| Base Device Type | Summary references become explicit xrefs. | Eligibility unchanged; rendering presentation question only. |
| Generic Switch | Revision-history wording. | Editorial. |
| Network Infrastructure Manager | Revision-history wording. | Editorial. |
| Robotic Vacuum Cleaner | Revision-history wording. | Editorial. |
| Thread Border Router | Revision-history wording. | Editorial. |
| Global Bitmaps | PairingHint bit-21 example retains the intended AND operator after the Alchemy fix. | Text extraction fix in #92; wire bits unchanged. |

Nested XML conformance/constraint references do not represent new top-level features, commands, attributes or enums.

## SDK fixes included

- **Derived command parsing:** Inherit omitted conformance, access and fields while preserving explicitly overridden Optional, Disallowed, feature-conditional and privilege requirements. Thermostat Mode command conformance retains `M/M/P,COREMODES`.
- **DEM constraint consumers:** Retain unsupported expression state, including `maxOf`, and stop incomplete evaluation rather than silently dropping bounds or approximating them. Numeric and supported simple-reference constraints remain usable.
- **Closure Dimension:** Enforce valid Resolution/StepValue configuration before server use; invalid zero and non-divisible values are rejected while valid defaults and limits remain supported.
- **Electrical Protection Alarm:** Validate present rating minima before startup; preserve optional/null/disabled-feature behavior.
- **Linux Network Commissioning:** Translate internal EAP scan indication into wire bit 5, keeping existing public enum spelling and unrelated bits.
- **Group Key Management:** Regression coverage for adoption revisions, provider metadata and reserved IDs; repair test provider subject-descriptor lifetime.
- **Push AV Stream Transport:** Native regression tests for AmbientContext pre-roll and existing cases; unchanged production validation.

## Open technical issues

| Area | Remaining question |
| --- | --- |
| **Thermostat Mode access** | Derived Manage requirement versus existing SDK Operate privilege; align with [#74803](https://github.com/project-chip/connectedhomeip/pull/74803) and verify actual privilege enforcement and COREMODES selection. |
| **Humidistat** | Distinguish zero-valued attribute requirements, optional command values, persisted state and device capabilities. |
| **DEM** | Determine which consumers need full compound constraint evaluation, and reconcile source examples with non-null optional field definitions. |
| **Closure Dimension / Electrical Protection Alarm** | Reconcile remaining ZAP-generated defaults and minima with validated server behavior. |
| **Network Commissioning** | Assess older-version reported-security compatibility under the new bit meaning. |
| **GKM** | Complete wire-level reserved-ID and independently compiled revision-composition checks. |
| **Parser diagnostics** | Fix dropped loader notices without misclassifying historical diagnostics. |
| **Cross-reference rendering / PICS history** | Base-device summary xrefs and historical JFADMIN/JFPKI prefixes are low-priority presentation/versioning questions. |
| **Revision consistency** | Substantive contract changes coexist with unchanged declared cluster revisions; assess this consistently across the model. |

## Validation

- 280 generated XML files parse; no new/removed XML paths or cluster/device IDs.
- **84/84** data-model parser/selection tests and **28/28** IDM unit tests passed.
- **119/119** native C++ regression tests passed (Closure Dimension, Electrical Protection Alarm, Group Key Management, Push AV, Linux BSS).
- Group Key Management passed **21/21** tests under ASan.
- Corrected Alchemy tests passed **110/110** cases.
- Main confidence gaps: device-level ACL, Humidistat persistence, selected real-wire/version-compatibility behavior and full compound-expression evaluation.

## Related PRs

- [connectedhomeip #74858](https://github.com/project-chip/connectedhomeip/pull/74858) — Combined-book XML generator support.
- [Alchemy #91](https://github.com/project-chip/alchemy/pull/91) — Inherited-direction command access extraction.
- [Alchemy #92](https://github.com/project-chip/alchemy/pull/92) — Correct conditional-text special-character removal.
- [connectedhomeip #74803](https://github.com/project-chip/connectedhomeip/pull/74803) — Thermostat Mode ZAP/generated metadata alignment.

**Current assessment:** Most model changes appear intentional and source-consistent. Concrete SDK parser, configuration, scan-reporting and native-test issues have fixes; substantive uncertainties are concentrated in access control, Humidistat zero semantics, compound constraints and selected cross-version behavior.
