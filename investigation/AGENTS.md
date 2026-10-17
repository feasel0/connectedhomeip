# Investigation Closeout

The user's standing authorization for this conversation is to finish every
turn by committing and pushing changed or new non-ignored investigation files
to `investigation/2026-10-17` on `feasel0/connectedhomeip` only. Never push this
branch to the upstream repository and never force-push it.

Before each commit:

1. Write a detailed report at `reports/YYYY-MM-DD_HH-MM-SS.md`, using UTC. Include
   the request, work performed, checks, results, discoveries, assessment and any
   outstanding limitations. Do not claim that running tests have completed.
2. Include dossiers, summaries, evidence writeups, tooling and temporary test
   infrastructure configuration. Respect this directory's ignore rules.
3. Exclude raw logs, captures, bulk archives, generated indexes, private keys,
   controller stores and other secret-bearing runtime data. Reports may refer
   to the real on-disk locations of excluded evidence.
4. Inspect the exact staged paths, sizes and diff. Preserve unrelated SDK and
   editor changes outside this directory. Initial relocation deletions at the
   old directory paths are intentional; subsequent commits stay within here.
5. Verify the push remote is the user's fork, commit the scoped files, push and
   verify that the remote branch points to the resulting commit.

The final chat response must contain only the number of files/changes committed
and confirmation that the report was written, committed and pushed. Report any
actual inability to commit or push honestly rather than claiming success.

The root-level `37075` and `pr539-failure-evidence` names may remain as ignored
local compatibility symlinks while existing jobs use historical absolute
paths. Do not remove those links or restart active campaigns to migrate paths.
Do not rewrite immutable historical evidence or its checksums just to change a
path. New writeups and tooling should use the `investigation/` layout.