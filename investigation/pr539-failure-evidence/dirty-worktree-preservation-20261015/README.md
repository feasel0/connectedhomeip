# Archived Alternatives: Final Disposition

## Decision

- Closed on 2026-10-15. The Valve implementation and tests are redundant with
  PR547. No further Valve implementation or tests were added.
- The write-only read alternative is rejected: removing cross-controller
  consistency checks silently accepts inconsistent unwritten attributes.
- Its useful per-controller verification behavior is incorporated into PR548
  commit `91c72691ef4bed6d9a20fc46f4f9a89268f3a9b3`, with explicit fresh-response
  presence checks rather than cache clearing as proof of successful readback.
- All three obsolete patch files are retired and removed. The six exact base
  and working source snapshots, original manifest, historical proofs, and current
  user-edited probe remain intact. No new PR or hardware testing was introduced.

## Patch Disposition

| Former Patch | Final Disposition |
| --- | --- |
| `matter-qa-527/changes.patch` | Removed. Useful read verification and three mocked-test behaviors are superseded by real-workflow regressions in PR548; weaker comparison is rejected. |
| `matter-qa-527-integration/changes.patch` | Removed. Valve portion is redundant with PR547; useful read behavior is incorporated in PR548, without removing its comparator. |
| `matter-qa-xml-constraints/changes.patch` | Removed. Valve implementation and six tests are covered by PR547's implementation and dedicated tests. |

[retirement-proof.json](retirement-proof.json) records original patch hashes,
behavior-to-test mappings, published PR heads, and hashes of retained artifacts.

## False Pass and Fix

Identical incomplete responses compare equal. The updater only overwrites
attributes present in a response, so a matching value from an earlier iteration
remains in `endpoint_map`; cache-based verification can then falsely pass.

PR548 retains its comparator unchanged. Each controller response now updates the
cache and is passed to the real write verifier. After existing failed-write
exclusions, every verified written attribute must be explicitly present and not
an SDK decode failure. Missing endpoints, clusters, and attributes fail; nullable
values remain valid. Existing value constraints and dynamic tolerances still run.

The optional response argument preserves existing cache-only callers outside
this scoped workflow. SDK DataVersion metadata and fabric-scoped comparison
rules are unchanged. No active campaign source or fixture was modified.

## Verification

- All 75 existing PR548 tests and 16 new CPU-only full-workflow regressions pass
  (91 total). Payload generation and controller transport are mocked; write
  distribution, read dispatch, cache updates, comparator, and verifier are real.
- Covers expected values, one/all omissions, stale prior-iteration cache,
  consistent wrong values, nullable/decode/missing-path cases, fabric differences,
  dynamic tolerances, known write-failure skips, and registered value constraints.
- Ruff, isort, autopep8, syntax, and diff checks pass. AST checks confirm the
  comparator and preexisting exclusion/tolerance methods are unchanged.
- [pr548-followup-validation.json](pr548-followup-validation.json) records the
  regression names and tested hashes; [pr548-followup-publication.json](pr548-followup-publication.json)
  confirms the existing PR/fork head and exact description update.
- [pr548-followup-ci.json](pr548-followup-ci.json) confirms Code Linters and
  Restyled passed on the published commit. Final GitKraken status checks found
  all 11 matter-qa worktrees clean, including the existing detached integration.

## Retained Evidence

[manifest.json](manifest.json), [reconstruction-proof.json](reconstruction-proof.json),
[cleanup-proof.json](cleanup-proof.json), [valve-equivalence-proof.json](valve-equivalence-proof.json),
and [read-alternative-proof.json](read-alternative-proof.json) are historical
records, not a live patch inventory. The prior 14-test Valve equivalence result
is accepted without new Valve tests. The historical
[read_alternative_probe.py](read_alternative_probe.py) is preserved byte-for-byte;
it assumes the pre-fix PR548 source and is not the current regression runner.
Saved `base/` and `working/` copies remain available for inspection and recovery;
obsolete patch-application and historical probe rerun instructions are retired.