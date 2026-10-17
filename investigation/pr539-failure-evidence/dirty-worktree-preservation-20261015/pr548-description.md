#### Summary

##### Problem

`TC_RT_1_2` equates SDK metadata, fabric-specific data and changing diagnostics
across independent reads, causing false consistency failures. Identical incomplete
responses can also pass while write verification reuses cached values.

##### Solution

- Exclude SDK cache metadata, not cluster attributes.
- Use compressed fabric identity and validate fabric-filtered lists and
  `CurrentFabricIndex` without requiring cross-fabric equality; retain strict
  same-fabric and shared-value checks.
- Bound clocks, countdowns and uptime by the measured read window. Validate live
  diagnostics while retaining strict error-counter checks.
- Compare Thread-table membership and stable topology independently of entry
  order, preserving duplicate counts and rejecting malformed entries.
- Require explicit successful readback of each verified written attribute from
  every controller, then validate its value using existing constraints and
  tolerances. Preserve known expected write-failure exclusions.

#### Testing

- 91 CPU-only tests pass: 75 existing consistency tests and 16 full-workflow
  readback regressions covering omissions, stale cache, wrong values, nullable
  values, decode failures, fabric boundaries, dynamic tolerances and exclusions.
- Preserved-response replay and synthetic table-permutation controls. Physical
  multi-entry churn was not exercised.
- Ten passing combined Ubuntu/Nordic iterations do not cover the table-order
  correction or fresh-readback guard; those are CPU-tested, not hardware-tested.
- Ruff, autopep8 and isort checks pass.
