# Separate IDM Strict-Verdict Follow-up

Status: proposed, independent and unimplemented. This is not part of PR75140.

## Demonstrated Defect

Strict-mode TC-IDM-9.1 can report PASS when every executed violating command
receives an unrelated error and none receives CONSTRAINT_ERROR. Zero accepted
commands alone is not evidence that the specified constraint was enforced.

The seven-case retained reproduction uses the captured TC and helper with a
mocked command transport. Strict InvalidCommand, ResourceExhausted and
InvalidCommand with diagnostic exclusions each PASS with one executed probe and
zero constraint rejections. ConstraintError passes and Success fails as expected.
Earlier-policy InvalidCommand fails and ConstraintError passes. The relevant
policy AST is identical between base 8cbf2b72ad46206078189d6cae3ed329456c580c
and PR75140 head 3d322af4ea0c2684d13586767dc3388fb77f8300: this defect predates
the diagnostic exclusion change.

## Proposed Scope

- Account separately for accepted violations, CONSTRAINT_ERROR, unrelated
  interaction-model errors, transport errors and unexecuted/unsupported paths.
- In strict mode, require positive rejection evidence for each qualified,
  executed safe probe. An unrelated error must not count as enforcement credit
  or be hidden by an empty accepted-path list.
- Preserve existing strict failure precedence. A qualified baseline receiving
  an unexpected status should fail the strict check; a baseline that cannot be
  qualified should be explicitly unsupported, not silently counted as PASS.
- Keep diagnostic-command exclusions discoverable and NOT DEMONSTRATED.
  Excluded paths and unsupported command baselines receive zero enforcement
  credit. Mixed runs report only the genuinely qualified scope.
- Preserve the existing all-excluded disposition and --fail-on-skipped behavior.
  Do not change the earlier-version policy without a separate justified decision.

## Regression Controls

Use the existing test fixtures and execute the real whole-TC verdict path, not
only per-probe helpers. Cover strict all-ConstraintError, all-InvalidCommand,
all-ResourceExhausted, mixed ConstraintError/unrelated errors, accepted violations
with unrelated errors, transport failures, and zero-qualified-probe cases.

Repeat relevant cases with diagnostic exclusions, ordinary safe commands,
writable attributes, mixed scope and --fail-on-skipped. Keep earlier-policy
controls to detect an unintended compatibility change. Verify exact send counts,
outcome counters, discovered-path reporting, skipped/excluded accounting and
final PASS/FAIL/SKIP behavior.

## Boundaries

The likely implementation surface is TC_IDM_9_1.py, idm_support.py and their
existing regression fixtures. Confirm the applicable normative strict-mode
contract before implementation and document the failure-versus-unsupported
boundary. Do not invent valid diagnostic baselines, add a baseline-generation
framework, change generated models, broaden PR75140, or create a separate PR
as part of this cleanup.

This proposal does not claim physical-DUT reproduction or full constraint
coverage. It records a separate review finding and recommended follow-up only.
