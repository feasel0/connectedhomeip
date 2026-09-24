# Preserved evidence: second 500-run, iteration 37

This directory is a sanitized evidence copy for the failure recorded during
iteration 37 of the second native `TC_Darwin_Pair` 500-iteration campaign on
2026-09-22. It is intentionally outside the campaign log tree so successful
iteration logs can be removed later without deleting the failure evidence.

No root-cause investigation is asserted here. The recorded facts are:

- Iteration 37 ran from 2026-09-22 02:58:41 to 03:00:30 local time.
- The harness persisted iteration 37 as `FAIL` after `UnpairDevice()` timed out
  while `cleanup_and_unpair_sessions()` was removing a fabric.
- The error was `src/app/CommandSender.cpp:378: CHIP Error 0x00000032: Timeout`.
- Iterations 36 and 38 passed and are retained as adjacent comparison controls.
- The campaign continued through iteration 209. VS Code later exhausted its V8
  heap at 06:51:07 and interrupted iteration 210. Iteration 210 did not receive
  a harness result and is separate from the iteration 37 failure.

## Contents

- `iterations/37/`: controller and DUT logs for the failed iteration.
- `iterations/36/` and `iterations/38/`: adjacent successful controls.
- `campaign/*iterations-36-through-38.log`: exact contiguous slices from the
  campaign console and global INFO/DEBUG logs, beginning at iteration 36 and
  ending at the iteration 39 start marker.
- `campaign/summary-at-interruption.json`: latest persisted native-loop summary.
- `campaign/test-summary-at-interruption.yaml`: top-level Mobly summary left by
  the interrupted campaign.
- `campaign/matter-qa-nordic-500.yaml`: exact test configuration.
- `campaign/original-launch-command.txt`: exact launch pipeline and arguments.
- `campaign/provenance.txt`, repository status files, Python package inventory,
  executable checksum, and post-interruption test-bed state snapshots.
- `vscode-crash/`: journal window that records VS Code's V8 out-of-memory
  crash.
- `SHA256SUMS`: checksums for every evidence file except the checksum file.

## Intentionally excluded artifacts

- Controller storage was removed because it contains generated operational CA
  and fabric private keys. The removed file's SHA-256 was
  `2d003878475255e68018c2767d4564584e4963d7ff84cb26d1bc7167a74a8c5c`.
  Treat that controller state as compromised; it must not be reused.
- The raw VS Code Crashpad dump was removed because arbitrary process memory is
  not suitable for publication. Its SHA-256 was
  `e55b9b9d281074b0a6f2a1085165985c83749abf7a57386ded37b0cda2411481`.
  Its binary metadata file was also removed.
- Generated per-iteration `iteration.json` files are not included. The retained
  campaign summary and test summary provide the iteration results.

The sibling compressed archive is an additional immutable transport copy. Verify
it and the expanded evidence using the sibling archive checksum and `SHA256SUMS`
before analysis.
