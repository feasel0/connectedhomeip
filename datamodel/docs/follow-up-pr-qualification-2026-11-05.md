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

## Recovery Checkpoint: 2026-11-06T03:03:31.226115+00:00

New authorization permits the minimum normal upstream API integration. The disposable conflict-free preview selects upstream Push AV migration `369fa749bac649cc64b82e8d7dba10fd104bd60e`; its raw imported history touches 766 paths, while the effective parent PR delta remains five Push AV files. Three test fixtures use the current persistence API, without production persistence changes or compatibility wrappers. The local parent recovery HEAD is `dfe6781b51c400edf67f675006d1faa53cb49404`; the local child is `a964dfcffe657187c29b646e533db5c3cfc156b3`, with its complete prior published tree preserved byte-for-byte. Neither recovery commit is pushed. Published parent/child heads and descriptions remain `738e0bc7` / `2f0dd204` and unchanged.

Fresh parent 17/17 native and sanitized, child 19/19 each, storage 22/22 each variant, URL 33 and TLS 16 all pass. Each cluster variant retains 868 sensitivity cases; child retains 560 ordering and 1,680 allocation-fault cases. The parent missing-sensitivity negative produces 16 passes and one intended failure. A current-upstream disposable parent merge also compiles and passes 17/17 locally.

Correction to mutation attribution: current unsorted-child execution produces 18 passes and only the ordering/precedence-method failure, not both ordering and allocation-failure methods. A narrower fallback duplicate-status mutation also fails only that ordering/precedence method. The harness expected the wrong failure set; an intervening broader mutation crashed and is not accepted as a clean negative pass. Artifacts remain preserved. The repair loop stopped at the retry limit without sealing child qualification, pushing source or starting later phases.

**Still NOT READY FOR HUMAN REVIEW.** Actual new-head hosted merge/technical/external checks, completed automated reviews and current ESP32/nRF target evidence remain outstanding. The earlier missing ESP32 archive is unresolved; historical target passes are not reused. Phase 2 IDM implementation and Phase 3 final audit have not started. No human routing, SME request, draft-state change, PR merge or hardware access occurred. See the [complete partial-recovery report](../reoprts/2026-11-06_03-03-31.md) for exact heads, observed controls, limits and the next decision.
