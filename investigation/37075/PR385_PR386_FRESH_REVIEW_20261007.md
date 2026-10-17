# Fresh Review: Backend PRs 385 and 386

Reviewed on 2026-10-07 without relying on previous review or hardware-validation conclusions.

## Current Dispositions: 2026-10-16

**All five findings remain OPEN.** Read-only PR metadata still reports exactly
the reviewed heads: PR385 `ab1e8bb282d1385874e9972760e96f852c027096` and PR386
`397b65562921bdd4e3caf883f8a0462e8cb2833f`. No later QA/scanner PR changes
these backend paths. Existing persistence/isolation work therefore does not
justify marking these reproduced gaps addressed. This is a head comparison,
not a claim that the original review tests were rerun today.

| Finding | Disposition / Remaining Action |
| --- | --- |
| 1: UI-created projects bypass unique defaults | **OPEN**: fix the normal UI/default-config creation contract while preserving explicit configuration. |
| 2: Cross-project or pairing-mode state reuse | **OPEN**: bind reusable state to project/DUT/pairing context and invalidate mismatched generations. |
| 3: Stale bundle after commissioning succeeds but capture fails | **OPEN**: revoke old-state reuse authorization when new commissioning changes the fixture. |
| 4: Ordinary Python test commands expose dataset credentials | **OPEN**: cover the ordinary command path; commissioning-only redaction is insufficient. |
| 5: Malformed persisted dataset accepted | **OPEN**: validate complete dataset structure before authorizing reuse. |

The historical recommendation, reproductions and test results below still
apply to those unchanged revisions.

## Recommendation

Hold both PRs pending the findings below. Their goals are justified, but the current implementations do not reliably deliver those goals across the normal UI and state-reuse workflows.

- PR 385: preserve the complete Thread network with reusable controller state. This is preferable to pinning only Mesh-Local Prefix or regenerating selected dataset fields, but ownership and invalidation are incomplete.
- PR 386: generate independent project identities with cryptographically secure randomness. The generator is appropriate, but normal frontend project creation bypasses it.

## Reviewed Revisions and Base Update

| Item | Revision |
| --- | --- |
| PR 385 head | `ab1e8bb282d1385874e9972760e96f852c027096` |
| PR 386 head | `397b65562921bdd4e3caf883f8a0462e8cb2833f` |
| Latest upstream `main` | `d7c2bb2e310ebcabea5eb6363c029bd52d648df0` |

Fetched upstream `main` and both fork branches. Executed `git merge --no-edit upstream/main` on each PR branch; both reported `Already up to date`. Both merge bases equal the current upstream tip. There are zero new base commits affecting either PR, no conflicts, and no update commit to push. PR production code and branch heads were left unchanged.

PR 386 was reviewed in a separate worktree at `/home/feasel/certification-tool-backend-pr386-review`. Both worktrees were clean after testing. Both PRs remain drafts.

## Findings

### 1. P1: PR 386 Does Not Isolate Normal UI-Created Projects

Source: [CRUD defaulting condition](https://github.com/project-chip/certification-tool-backend/blob/397b65562921bdd4e3caf883f8a0462e8cb2833f/app/crud/crud_project.py#L85) and [unchanged default-config endpoint](https://github.com/project-chip/certification-tool-backend/blob/397b65562921bdd4e3caf883f8a0462e8cb2833f/app/api/api_v1/endpoints/projects.py#L111).

The generator runs only when `config` is missing or empty. The frontend's normal create workflow does neither:

1. `ProjectsAPI.getEnvironmentConfig()` fetches `/projects/default_config`, which still returns the shared static Matter configuration.
2. `ProjectDetailsComponent` assigns that configuration to `projectDetails.config` in its constructor.
3. `ProjectSandbox.createNewProject()` posts that populated config alongside the name.
4. CRUD treats it as explicit configuration and preserves the common credentials.

Frontend sources inspected on its current `main`: [API client](https://github.com/project-chip/certification-tool-frontend/blob/main/src/app/shared/core_apis/project.ts), [project form initialization](https://github.com/project-chip/certification-tool-frontend/blob/main/src/app/components/project/project-details/project-details.component.ts#L43), and [create request](https://github.com/project-chip/certification-tool-frontend/blob/main/src/app/components/project/project.sandbox.ts#L35).

Reproduction: real API `GET default_config`, then two `POST projects` calls using the returned config. Both succeeded and persisted the same Network Key. The regression asserting distinct keys fails.

Fix: distinguish generated/default-origin config from deliberately explicit/imported config. Have the UI request fresh defaults per new project, or submit omitted config for untouched defaults and preserve customized fields through an explicit creation contract. Simply randomizing the existing default endpoint once is insufficient: the frontend caches its response and can reuse it for multiple project creations. Do not randomize every explicit config or regenerate keys on read/update.

### 2. P1: PR 385 Can Reuse State Belonging to Another Project or Pairing Mode

Source: [global state paths](https://github.com/project-chip/certification-tool-backend/blob/ab1e8bb282d1385874e9972760e96f852c027096/test_collections/matter/sdk_tests/support/utils.py#L29), [capture selection](https://github.com/project-chip/certification-tool-backend/blob/ab1e8bb282d1385874e9972760e96f852c027096/test_collections/matter/sdk_tests/support/python_testing/models/utils.py#L322), and [reuse validation](https://github.com/project-chip/certification-tool-backend/blob/ab1e8bb282d1385874e9972760e96f852c027096/test_collections/matter/sdk_tests/support/python_testing/models/utils.py#L385).

The new bundle consists of two global files, without project, DUT, pairing-mode, or generation metadata. Validation checks existence and, only if supplied, `operational_dataset_hex`. Normal project configs have no explicit complete dataset, so changes to Network Key, Extended PAN ID, PAN ID, Network Name, or channel do not prevent reuse. Setup then restores the previous dataset instead of honoring the current project's identity.

A second concrete mismatch occurs on managed Thread -> Wi-Fi/external Thread -> managed Thread transitions: the non-managed capture replaces controller storage but leaves the previous managed dataset file. The next managed-Thread validation accepts that mismatched pair as a complete bundle.

Reproductions: both a project-identity change and managed Thread -> Wi-Fi capture leave `_managed_thread_reuse_bundle_is_valid()` returning `True`. Both regression assertions fail.

Fix: scope reusable state to its actual project/DUT and pairing context, and store binding metadata with both artifacts. At minimum, compare the current configured identity and clear/invalidate managed dataset associations whenever controller storage is replaced by a non-managed capture. This is also essential to prevent PR 385 from silently undoing PR 386's project isolation.

### 3. P1: PR 385 Retains Reusable Old State After Successful Recommissioning Followed by Capture Failure

Source: [commission/capture/flag ordering](https://github.com/project-chip/certification-tool-backend/blob/ab1e8bb282d1385874e9972760e96f852c027096/test_collections/matter/sdk_tests/support/python_testing/models/test_suite.py#L211), [cleanup gate](https://github.com/project-chip/certification-tool-backend/blob/ab1e8bb282d1385874e9972760e96f852c027096/test_collections/matter/sdk_tests/support/python_testing/models/test_suite.py#L126), and [previous-state preservation](https://github.com/project-chip/certification-tool-backend/blob/ab1e8bb282d1385874e9972760e96f852c027096/test_collections/matter/sdk_tests/support/python_testing/models/utils.py#L556).

The old files are retained when new commissioning is selected. If `commission_device()` succeeds but `capture_reusable_commissioning_state()` fails, the established flag remains false. Cleanup skips capture and destroys the SDK container. On the next run, the old bundle still validates even though successful new commissioning may have changed the controller fabric/DUT/network association.

Reproduction: execute the real setup/cleanup methods with successful commissioning and an injected capture I/O error. Cleanup destroys the runtime, while the previous bundle remains reusable. The invalidation regression fails.

Fix: distinguish an archived previous snapshot from a snapshot still authorized for reuse. Once fresh commissioning changes the fixture, failure to persist the new state must disable reuse of the old state. Keeping old bytes for recovery or diagnostics is fine; offering them as current valid state is not. Apply the same conservative policy when the final counter refresh cannot be captured.

### 4. P2: PR 385's Credential Redaction Does Not Cover Ordinary Python Test Execution

Source: [normal test command](https://github.com/project-chip/certification-tool-backend/blob/ab1e8bb282d1385874e9972760e96f852c027096/test_collections/matter/sdk_tests/support/python_testing/models/test_case.py#L635), [dataset argument emission](https://github.com/project-chip/certification-tool-backend/blob/ab1e8bb282d1385874e9972760e96f852c027096/test_collections/matter/sdk_tests/support/python_testing/models/utils.py#L118), and [default logging behavior](https://github.com/project-chip/certification-tool-backend/blob/ab1e8bb282d1385874e9972760e96f852c027096/test_collections/matter/sdk_tests/support/sdk_container.py#L204).

Commissioning now passes `sensitive=True`; ordinary test execution does not. `omit_commissioning_method=True` still emits `--thread-dataset-hex`, so routine Python tests log the complete dataset, including Network Key and PSKc, at INFO level. Equivalent shell-command logging repeats it when enabled.

This is a pre-existing command path left unprotected by the PR's new redaction work, not a claim that the logging path was newly introduced. It matters especially when PR 386 makes credentials non-default and private.

Reproduction: the review's AST check finds the ordinary dataset-bearing command lacks `sensitive=True`; the argument-builder and logger source establish the resulting exposure. This check is structural, not a physical SDK log capture.

Fix: mark ordinary test commands sensitive too, or redact known credential-bearing arguments at the command logging boundary so every caller gets protection. Audit runner stdout and SDK trace output separately; a redacted command does not prove all output is credential-free.

### 5. P2: PR 385 Accepts Non-Dataset Hex as Valid Persisted State

Source: [normalization](https://github.com/project-chip/certification-tool-backend/blob/ab1e8bb282d1385874e9972760e96f852c027096/test_collections/matter/sdk_tests/support/python_testing/models/utils.py#L220) and [bundle validation](https://github.com/project-chip/certification-tool-backend/blob/ab1e8bb282d1385874e9972760e96f852c027096/test_collections/matter/sdk_tests/support/python_testing/models/utils.py#L405).

Normalization accepts any nonempty hex, without checking TLV framing or complete Active Dataset contents. A saved file containing just `aa` is considered valid, allowing the reuse prompt and controller copy before OTBR rejects it. Several existing positive tests use a truncated/incomplete dataset-shaped value, so they do not establish validation of a complete operational dataset.

Reproduction: controller file plus dataset file containing `aa` passes bundle validation. The regression asserting rejection fails.

Fix: validate dataset structure and required contents using an established parser, or require authoritative OpenThread validation before reuse is accepted. Treat bad persistence as a reason to require fresh commissioning, rather than repeatedly selecting a bundle that fails restoration. Validation must not print credential-bearing bytes.

## Better Design

Keep the two goals separate but give them a shared identity contract:

- Generate random credentials once for a genuinely new default project, through a creation workflow the UI actually invokes. The current `secrets.token_bytes` generator is sufficient; database-wide collision checking and physical-RCP ownership enforcement are unnecessary for the stated scope.
- Store a project/DUT-scoped bundle containing controller storage, full dataset, binding metadata, and a generation identifier. Replace one archive or one manifest pointer atomically instead of coordinating two global files through candidate/backup renames.
- Create credential-bearing staging files privately before writing. The current controller copy opens its candidate with normal process permissions and chmods only afterward, leaving a transient exposure under a permissive umask.
- Track whether a persisted generation is still valid independently from whether its files exist. Invalidate authorization on recommissioning or failed final refresh; preserve archived bytes only as archived bytes.
- Keep full-dataset restoration and live readback. Pinning only Mesh-Local Prefix, deriving network credentials from public hardware identity, or relying only on PAN ID/Network Name would not address the same failure modes.

An atomic single-file bundle removes meaningful rollback complexity. Fsync/durability and recovery policy should be explicit if surviving host crashes is a requirement; the present exception rollback is not a power-loss transaction.

## Verification

- PR 385 isolated OTBR/manual-redaction checks: **5 passed**.
- PR 385 original focused utility/lifecycle/YAML checks with the repository SDK mock installed before collection: **71 passed**.
- PR 386 generator, CRUD, and project API checks against disposable PostgreSQL: **38 passed**.
- Review-only PR 385 regressions: **5 expected failures**, exposing project mismatch, mode mismatch, malformed persistence, missing ordinary-command redaction, and stale reuse after successful commissioning/capture failure.
- Review-only PR 386 real API default-config round trip: **1 expected failure**, exposing shared keys in UI-style project creation. Request handling, validation, and persistence were exercised; this probe did not launch a browser or exercise application startup.
- PR 385 broad local suite: **521 passed, 3 failed, 78 setup errors**. Setup errors include SDK discovery JSON missing `info`; the three CLI failures include missing seeded `operator_id=1` records. This is not a clean full-suite result and is not attributed to these PR changes without baseline reproduction.
- Current GitHub CI: Backend Tests pass for both reviewed heads. PR 385 Mypy fails; PR 386 Mypy passes. The Mypy failure was not independently classified against the base in this review.
- Both PR diffs pass `git diff --check`; editor diagnostics for the review probe are clear.
- No new hardware campaign, RF-isolation test, or pinned ARM64 SDK-container integration test was run. Previous physical-test success was not used to dismiss the reproduced gaps.

Probe file: [37075/tools/test_backend_pr385_386_review.py](tools/test_backend_pr385_386_review.py). It extracts the actual PR 385 functions/methods through AST to isolate dependency-heavy modules, mocks runtime I/O and commissioning, and tests PR 386 through its real API and existing database test-session factory. These are review artifacts, not fixes committed to either PR.

Local broad-run log: `/tmp/backend-pr385-full-review-20261007.log`. The temporary PostgreSQL container and an auxiliary `th-sdk` container created during test setup were removed after validation. The SDK container's creation time, test-log provenance, and idle process list were verified before removal. The pre-existing OTBR and hardware fixtures were not changed.