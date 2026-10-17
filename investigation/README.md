# Investigation Archive

Issue investigations, dossiers, reports, reproducibility tooling and temporary
test infrastructure configuration live here. The archival branch is
`investigation/2026-10-17` on `feasel0/connectedhomeip`, not the upstream SDK.

- `37075/`: issue #37075 investigation and related QA/SDK validation writeups.
- `pr539-failure-evidence/`: failure dossier, summary indexes and maintenance
  tooling, plus selected source/proof snapshots.
- `reports/`: detailed UTC-stamped reports for individual assistant turns.
- `tools/git_boundary.py`: relocation audit and publication-boundary checks.
- `tools/trace_lifecycle.py`: bounded, value-free extraction of retained PASE,
  MRP, CASE and attribute-status evidence; private derived output stays outside
  this tree.
- `tools/discovery_isolation.py`: future probe launcher that refuses overlap
  with the protected endurance process, plus discriminator collision regressions.

Raw logs, captures, controller private state, generated private indexes, firmware
builds, environments and bulk archives remain on disk but are ignored. They must
not be staged with `git add -f`. Historical documents may reference their original
absolute locations; those references are not rewritten as if evidence had been
collected at a different path.

On the original lab checkout, ignored root-level compatibility symlinks point
`37075` and `pr539-failure-evidence` into this directory. They preserve existing
jobs and historical absolute paths without duplicating evidence. They are local
compatibility aids, not additional folders to commit or guarantees that excluded
evidence is present in a new clone.

Checks from the repository root:

```sh
python3 -B investigation/tools/git_boundary.py self-test
python3 -B investigation/tools/git_boundary.py audit
python3 -B investigation/tools/git_boundary.py staged
python3 -B investigation/tools/trace_lifecycle.py self-test
python3 -B investigation/tools/discovery_isolation.py --self-test
python3 -B investigation/pr539-failure-evidence/update_dossier.py --self-test
python3 -B investigation/pr539-failure-evidence/prune_successful_runs.py --self-test
```

The `move` action is a guarded one-time relocation, not a routine closeout step.
The `verify` action compares against the local ignored pre-move inventory and is
intended immediately after relocation, before intentional document edits.
Use `staged` for subsequent publication checks.