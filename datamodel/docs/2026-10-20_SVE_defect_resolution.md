# Matter 1.7 SVE Defect Resolution

**Current integration:** [SDK draft #74862](https://github.com/project-chip/connectedhomeip/pull/74862)
at `2ff4b57e3a2b1bf0fdc18c6726e4637bbcb5fe43` contains 18 source/build files,
not generated XML. Its comprehensive description and the [current ledger](SVE_mismatch_ledger.md)
supersede the historical local-only implementation statuses below.
Alchemy [#91](https://github.com/project-chip/alchemy/pull/91) and
[#92](https://github.com/project-chip/alchemy/pull/92), and generator
[#74858](https://github.com/project-chip/connectedhomeip/pull/74858) are open upstream drafts.

The interrupted combined-tool step is complete. Full private generation with
response-aware Alchemy exits zero in 321.53 s; 280 XML files parse, both ID maps
match the baseline and all GNI XML members match the filesystem. Canonical
same-spec comparison finds 241 formatting-only changes and exactly two intended
changes: Thermostat request access and PairingHint operator preservation.
Inherited RVC responses no longer gain invoke access. Current model/package
checks pass 84 parsing tests and 28 IDM units using actual integration sources.
Native suites total 119 passes. A Darwin CI-discovered GKM fixture reference to
a temporary descriptor is repaired; a separate fresh Linux ASan build passes
all 21 GKM tests with stack-use-after-return detection. Darwin CI rerun is pending.
No model XML is published: PUB-01/BALLOT-01 and the remaining normative/codegen/ACL
gates in the ledger are still open. No broad warning-suppression fix was adopted.

## Original Defect-Resolution Evidence

**Earlier checkpoint:** 2026-10-20 UTC, continuing `72052c90835`. The completed
[20-file review](2026-10-20_SVE_semantic_review.md) was not repeated.
**No SVE readiness or generated-model publication is claimed.**

## Inputs and Boundaries

SDK comparison input remains `24fafe816f7a5db9aeb514d6504ff6b57384b4f1`;
candidate specification is `eea0ffce8fe9e4951a4558a6e6c6362b307e0334`,
prior specification `214e40c9d51cfe89050eae68ca5b76238fcfa332`.
Alchemy is pinned to `v1.7.10`, source
`f672052c506b5aae5e2e23ffc58bfa1c5edb4c35`. Tests use cached Go 1.25.1,
not the release binary's Go 1.26.5 compiler. The scraper binary was not replaced.
Current remains 40 ordered entries / 39 unique; duplicate `pqc` is an
observation, not a demonstrated defect. No flag, normative XML, default SDK
specification revision, hardware fixture, or unrelated QA work was changed.

Independent investigation threads covered parser inheritance, expressions,
Alchemy extraction, three bounds domains, compatibility domains, and release
authority. Shared parser integration was serialized. Private sources, model
ZIPs, extracted probes and logs remain outside public commits.

## Priority A

### TMODE-02: Selective Derived-Command Inheritance

SDK commit `a4b7865e859` preserves whether command conformance was explicitly
present. Missing conformance and privilege inherit; explicit Optional,
Disallowed, feature conditions and privilege overrides remain authoritative.
The same merge handles directionless overlays and both explicit command
directions, retaining base fields and derived field overrides. Global
missing-conformance fallback behavior is unchanged. The appended defaulted
`XmlCommand` field preserves existing constructor calls.

The identical two regressions fail against the original parser and pass with
the fix, without setup errors. They cover incoming/generated commands,
missing/explicit conformance, omitted/Manage access and conditional inheritance.
Actual candidate conformance returns to `M`, `M`, `P, COREMODES`.
The TMODE-only five-suite checkpoint passed 81 tests.

### DEM-01: Detect Unsupported Expressions, Never Approximate

SDK commit `4cf579fbbe3` retains unsupported reference-bound XML/text expressions
in `Constraints.unsupported_expressions`; `has_constraints()` remains true and
`require_supported()` raises `SpecParsingException`. Existing representable
numeric/simple-reference bounds survive. Compound textual expressions are no
longer truncated to one identifier. Sibling constraint elements retain this
state. This is **explicit rejection, not a maxOf evaluator**.

IDM attribute checks/violation generation, command-field resolution/violation
generation/required-field synthesis, and scene-bound selection reject unsupported
constraints before I/O or incomplete value generation. These callers can now
stop visibly where they previously might validate only a surviving upper bound.
External consumers must also call `require_supported()` before evaluating bounds.

Actual DEM MaxPower retains the maxOf lower expression as unsupported and the
`AbsMaxPower` upper reference, without inventing a lower value/reference.
Final identical parser tests: original 2 FAIL / 1 PASS; fixed 3 PASS, no errors.
Six permanent consumer tests pass, including a supported numeric control.
Nested expressions, multiple references, attribute-field references, sibling
constraints and textual expressions have focused coverage. This is not a full
constraint vocabulary/struct-parser redesign.

A separate loader defect remains: `add_cluster_data_from_xml()` rebinds
`problems = problems + parser.get_problems()` rather than extending the caller's
list. An unadopted propagation prototype exposed legacy notices and failed
existing zero-problem expectations (39/41 in its two-suite run). It is not in
the production fix. Object-level unsupported state and consumer rejection do
not depend on that lost diagnostic list. Track this independently as PARSE-01.

### TMODE-01: Access Is Lost in Rendering

The command factory correctly retains Manage while inherited direction is
`InterfaceUnknown`; `dm/command.go` formerly emitted access only for explicitly
server-directed commands. The public-safe [Alchemy handoff](../patches/alchemy/README.md)
contains the minimal renderer fix and synthetic parsing/round-trip tests.
Missing direction remains missing, blank access remains absent, and explicitly
client-directed responses gain no invoke privilege. The patch does not resolve
the separate SDK Operate-versus-source-Manage policy/ACL question.

Identical tests: original 19 PASS / 2 FAIL; patched 21 PASS. Seven relevant
packages with **only** this patch pass 63 leaf tests. The release binary and
scratch generated model remain unchanged; upstream adoption is outstanding.

### BITMAP-01: Conditional Overlay Occurrences Collide

The original full-root pipeline proves that a suppressed special-character
value from an unrelated included document becomes an equal removal-map key for
the visible operator. Loss occurs between raw AST and overlay reading, before
table extraction/XML rendering. A single-removal bypass restores the original
expression with unchanged include flags. This is not XML entity escaping.

The handoff's production fix keys only special-character removals by parent and
raw child slot. It preserves exported AST layout, constructors, clone and value
comparison semantics, unlike the rejected private identity-field prototype.
Whole/tail slices, removed-only slices and copied occurrences have direct
controls. This fixes the demonstrated removal collision, not every conceivable
scalar-overlay operation.

Cross-include tests cover `&`, `|`, `<`, `>`, `&&`, `<=`, `>=`, `<<`, `>>`,
standalone/enabled/disabled-before/disabled-after inputs, suppression and intact
enabled content. Original: 20 PASS / 16 FAIL; fixed: 36 PASS. Eight non-pipe
operators fail in both disabled include orders; pipe controls pass. Seven
packages with only the final bitmap patch pass 82 leaves; both public patches
together pass 103. Original-root and XML replay with the final patch each pass,
preserving three operator occurrences instead of the candidate's two; the
external unkeyed-literal control also passes. No regenerated model was published.

## Priority B: Bounded Findings and Exact Decisions

These are extracted production-body probes with explicit adapters and real
generated-header controls where stated, **not native cluster suites, real TLV,
storage, ACL, D-Bus/radio or end-to-end application tests**. No production changes
were adopted for these six domains.

| Domain | Executable finding | Owner decision / next native check |
| --- | --- | --- |
| Closure Dimension | C++ defaults are 1/1; ordinary defaults do not crash. Explicit Resolution 0 triggers UBSan division by zero in target/range paths. StepValue 0 succeeds without movement. Targets 0/1/10000 succeed; 10001 is rejected. Invalid StepValue 65535 also exposes overflow, not a valid-configuration failure. | Spec owner confirms bounds/divisibility/revision policy. SDK owner chooses fail-fast construction versus fallible initialization, before delegate side effects. ZAP owner decides default migration from 0 to 1. Extend existing configuration/target/range/step tests; do not invent clamp/error policy. |
| Humidistat | Step 0/101 abort; 1/100 succeed. MistType 0 is accepted by setter/write/command and persists through the adapter. Unsupported bits reject; persisted invalid bits can filter to 0. Omitted fields preserve state; unsupported attributes' command fields are ignored. | Spec owner distinguishes present command zero from nonzero attribute bounds and confirms HUM's WARM/COLD choice. SDK owner chooses initialization/reload/repair policy, including zero or filtered-to-zero storage and hardware-specific combinations. Add native setter/write/command/persistence cases only after that decision. |
| Electrical Protection Alarm | All eight changed fields carry supplied 0/1 through constructor/read to the encoder adapter, without minima validation. Null/optional controls are retained. | Spec owner confirms minima and revision policy. SDK owner chooses provider invariant, constructor enforcement or fallible initialization and handling of invalid supplied values. Add existing-fixture TLV readback for present 0/1, upper/absent/null controls with valid companion fields. |
| Network Commissioning | Real scan lambdas with GLib dictionaries/arrays: baseline 7 PASS / 6 FAIL; private four-line translation proposal 13 PASS. WPA/RSN EAP variants map 0 to bit 5; mixed personal bits remain. Bit 7 is removed. Public enum spelling is preserved. | Domain/Linux owners approve milestone/version meaning of IEEE8021X versus prior PDC-only reporting, then add native fake-BSS coverage through the real function. No unsupported Enterprise commissioning requirement or API rename is inferred. |
| Group Key Management | Independent compiled Groups revisions 4/5/6 pass 12 checks each; a boundary mutation fails four assertions. Rev4 retains map/write/capacity; rev5/6 GCAST clears map, rejects write with 0xcb, capacity 0. Advertised IDs exclude reserved 4. | Owners resolve absent-Groups/provider composition and compiled-versus-custom-runtime revision invariants. Add native provider/composition and wire ID-4 rejection tests. Empty provider is not general composition proof; do not remove a public generated declaration speculatively. |
| Push AV | Exact pinned/main validator passes 13 cases each. Removing AmbientContext from the pre-roll condition causes four intended failures. Missing pre-roll rejects with 0x85; present 0/1000/65535 succeeds. | Test owner ports present/missing cases to the existing native fixture. Existing production behavior needs no fix on this evidence; real decode/delegate/allocation and analytics deployment remain untested. |

Bounds evidence: 308 isolated executions across main/pinned inputs, seven passing
characterization tests, real-generated-header preflight. Compatibility evidence:
nine small standalone executables, with intended baseline/mutation failures
distinguished from SDK suite failures. Main/pinned behavior agrees within these
scopes; initial adapter/header/verifier mistakes are retained privately and are
not classified as SDK failures.

## Regression and Consumer Checkpoint

Final candidate-bound suites: Support 20, Selection 2, DeviceType 29, DataType 26,
Namespace 7: **84/84**, zero errors/failures/skips. Permanent consumer tests:
**6/6**; private consumer/positive-control probe: seven checks pass. Ruff and
editor diagnostics pass for changed Python sources. The existing host native
controller and libevent were reused, not rebuilt. Loaded parser and candidate
resource paths were checked; the private overlay now contains the patched parser.
Candidate ZIP SHA-256:
`f05aee774bbe9e0fe2ac6bb2c3a0c400034cba0cba4dc792bd0fd33d3349a272`.

Private evidence remains below the pinned checkout's
`out/defect-resolution-20261020/`: `tmode/`, `dem-integrated/`, `bounds/`,
`compat/`, `alchemy/`, and final occurrence/root/public validation files.
The public Alchemy handoff needs no private inputs for its synthetic regressions.

## Release Authority and Remaining Gates

Authenticated metadata resolves `0.9-1.7-winter2027` to the prior model input
`214e40c9d51cfe89050eae68ca5b76238fcfa332`, and `0.7-recirc-1.7` to
`159cbaff8c5fb571676536d3c78b151177ef3cb2`. Neither establishes SVE selection.
Searches covered one full page each of 30 releases, 100 tags and 100 branches,
exact named endpoints, bounded local metadata and relevant meeting files; they
are not exhaustive. An interrupted/shared-terminal query is not absence proof.

Release/specification/data-model leads must provide the exact approved SVE tag
and resolved SHA (or explicitly approved untagged SHA), applicable ordered
Current list, and dated ballot/decision source. No external message was sent
and no approval was inferred. Domain owners above are proposed routing, not
confirmed assignments or decisions received.

G1/G2 evidence remains; G3 review is complete but dispositions remain open; G4
has stronger targeted evidence, not SDK/test-harness sign-off. G0/G5 remain
blocked. Tool fixes are separate from model acceptance. SDK commits are separate;
Alchemy fixes are independently reviewable patch handoffs pending current-tool
owner review/porting. No new PR, released scraper binary, full generator rerun
with the new scraper, or approved SVE model release is claimed.
