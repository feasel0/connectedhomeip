# Explicit Follow-up Design Decisions

No unacceptedmaterialdecisionwasimplementedaspolicy. C2 doesnotinvalidateC1 engineeringacceptance.

| Decision | Disposition | Exact Scope |
| --- | --- | --- |
| Push AV early-duplicate224-byte cost | PROVISIONALLY ACCEPTED | Narrow improvement only; not universal embedded qualification |
| Push AV contiguous-allocation/OOM | AUTHORIZED REDESIGN IMPLEMENTED | Checked scratch allocation falls back to prior node validator;modeled64-byte case passes;total-heap exhaustion retains prior contract |
| IDM selection/verdict | APPROACH A IMPLEMENTED | Actual safe-command test selection;explicit excluded NOT DEMONSTRATED accounting;all-excluded SKIP and --fail-on-skipped unchanged |
| Step C2 endpoint/transition | ACCEPTED SEPARATE CLARIFICATION;UNIMPLEMENTED | User accepted separate scope;no endpoint/grid-transition policy chosen orimplemented;not aC1gate |
