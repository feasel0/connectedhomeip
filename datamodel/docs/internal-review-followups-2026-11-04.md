# Internal Engineering Review Ledger

This ledger records engineering findings, independently of CI and bot qualification. The campaign is NOT COMPLETE. A published unmerged follow-up is not a fix in the original branch or merged production.

| Finding | PR Context | Disposition | Evidence / Remaining Action |
| --- | --- | --- | --- |
| XML combined books/CI registration | 74858 | FIXED IN ORIGINAL PR | 22e728 registers six regressions; failure propagation retained |
| ModeBase privileges/excess fixture | 74886 | FIXED IN ORIGINAL PR | 53a8 explicit metadata/ordinary defaults/aliases; singleton fixture removed; externally merged |
| Parser split/ordering objection | 74888 | DISPROVEN | Topological pure-base ordering required by demonstrated permutations |
| Parser cohesive metadata changes | 74888 | RETAINED BY DESIGN | 128 tests/eight suites;12 models/1371 records |
| Current EAP contract and Suite-B-192 | 74889 | FIXED IN ORIGINAL PR | Accepted current IEEE8021X contract; both decoders fixed;39/39 and239/239 recovery |
| Closure invalidity guards | 75000 | DISPROVEN; RETAINED BY DESIGN | Registry retains failed-Startup instances; pre-Startup setters;60/60+963;guard-removal55+5 |
| IDM invalid diagnostic baseline | 74959 ->75140 | FOLLOW-UP IMPLEMENTED BUT UNQUALIFIED | 26c333caf8c945e06e38cb897fb02448cea6a921; containment/exclusions implemented; coverage-policy decision and merge conflict |
| Push AV duplicate scratch allocation | 74979 ->75139 | FOLLOW-UP IMPLEMENTED BUT UNQUALIFIED | acec356d9df53fe57b0a2494bdd8c15dd1c29df8; measured allocation reduction; Darwin failure |
| Step/GroupedStep side-effect safety C1 | 75019 ->75138 | FOLLOW-UP IMPLEMENTED BUT UNQUALIFIED | 931f30b143faef3e23cd1d1ad48b59c9e1350f4b; zero effects on rejection; Darwin failure |
| Step endpoint interpretation C2 | 75019 context | DECISION REQUIRED | No policy selected or inferred; explicit separate endpoint-policy PR only after decision |
| Embedded resource budget | 75139 | DECISION REQUIRED | 93.75% unique-list scratch reduction versus early-duplicate224-byte increase; target constraints unmeasured |
