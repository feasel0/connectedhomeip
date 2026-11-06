# Follow-up Technical Qualification

Latest cleanup checkpoint 2026-11-06T01:04:13.237612+00:00: **BLOCKED** for the changed #74979/#75139 stack. The dated original qualification below is historical; see the [current source-movement and description report](../reoprts/2026-11-06_01-04-13.md).

Observed 2026-11-05T20:01:09.810534+00:00. Pending/missing/failed records are not passes;humanpoliciesremainseparate.

| PR | Exact Final HEAD | Local Tests / Negatives | Technical CI | External | Readiness | Remaining Gates |
| --- | --- | --- | --- | --- | --- | --- |
| [#75139](https://github.com/project-chip/connectedhomeip/pull/75139) | e0b26402bfb4642b63d7dc7040c8a7e7d60b15e5 | 19 native/19 sanitizer;868 sensitivity+560 ordering+1680 fault cases;stack/roundtrip negatives | 39/39;0 pending;0 failed | GREEN | READY FOR HUMAN REVIEW | No remaining technical/source/bot blocker |
| [#75140](https://github.com/project-chip/connectedhomeip/pull/75140) | 3d322af4ea0c2684d13586767dc3388fb77f8300 | 42 combined/5 PIXIT;four intended-failure negatives | 39/39;0 pending;0 failed | GREEN | READY FOR HUMAN REVIEW | No remaining technical/source/bot blocker |
| [#75138](https://github.com/project-chip/connectedhomeip/pull/75138) | 931f30b143faef3e23cd1d1ad48b59c9e1350f4b | 65/65;compat70/70,71/71,76/76;negative63+2 | 39/39;0 pending;0 failed | GREEN | READY FOR HUMAN REVIEW | No remaining technical/source/bot blocker |

## Cleanup Checkpoint: 2026-11-06T01:04:13.237612+00:00

Sensitivity validation and its complete 868-case regression now reside in #74979; #75139 integrates that parent without changing its original tree. Current parent/child HEADs are respectively `738e0bc7e8b9e925927ca6890a2a510699961e71` and `2f0dd204cb9f73e2973514edf66a66331088d4a0`.

Local parent 13/13 native and sanitized plus storage 22/22 each; child 19/19 each with 560 ordering, 1680 allocation-fault and 868 sensitivity cases. These are standalone source checks, not qualification of the newer hosted merge.

| PR | Exact Source HEAD | Technical CI: Success / Definitions | Failed / Pending |
| --- | --- | --- | --- |
| [#74888](https://github.com/project-chip/connectedhomeip/pull/74888) | `487f97e04c2ad3931fed573c4a936a47d5e3631e` | 40/40 | 0/0 |
| [#75139](https://github.com/project-chip/connectedhomeip/pull/75139) | `2f0dd204cb9f73e2973514edf66a66331088d4a0` | 18/39 | 0/21 |
| [#75140](https://github.com/project-chip/connectedhomeip/pull/75140) | `3d322af4ea0c2684d13586767dc3388fb77f8300` | 39/39 | 0/0 |
| [#75138](https://github.com/project-chip/connectedhomeip/pull/75138) | `931f30b143faef3e23cd1d1ad48b59c9e1350f4b` | 39/39 | 0/0 |
| [#74889](https://github.com/project-chip/connectedhomeip/pull/74889) | `f5b3e64018aa7d1e1697127ebd47ce686e8e5bab` | 39/39 | 0/0 |
| [#74979](https://github.com/project-chip/connectedhomeip/pull/74979) | `738e0bc7e8b9e925927ca6890a2a510699961e71` | 18/39 | 4/17 |

Parent hosted compilation fails at the old persistence fixture and zero-argument Init calls against the newer merged API. The fresh ESP32 parent fixture stopped before QEMU because its test archive was missing; child target runtime did not execute. Neither changed head is fully qualified. Remaining pending workflows are not passes. No retry, upstream integration, rewrite or compatibility layer was authorized or performed to bypass this blocker.

All six descriptions were read back, including the requested child title; parent/child testing sections explicitly remain unqualified. The unchanged parser/IDM/Step/EAP heads retain their complete technical workflow qualification. The separate preexisting strict IDM unrelated-status verdict finding is recorded in the [unimplemented follow-up proposal](idm-strict-response-follow-up-2026-11-06.md). Full evidence, limitations and the required owner decision are in the [cleanup report](../reoprts/2026-11-06_01-04-13.md).
