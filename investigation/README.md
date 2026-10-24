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
- `tools/reporting_fairness.py`: isolated execution of pinned reporting methods
  with deterministic stubs and a deliberately starving negative control.
- `tools/historical_ble.py`: exact-ID, value-free original BLE phase accounting;
  neither configured adapter index nor a cleanup error assigns a root cause.
- `tools/ecred_order_probe.py` and `patches/ecred-request-index.patch`: pinned
  kernel-function before/after regression and PROPOSED requester CID correction.
  Host isolation only; not deployed or physically validated. See
  [correction assessment](reports/2026-10-20_03-02-58.md).
- `tools/ReportingTrace.h` and `tools/prepare_reporting_trace.py`: bounded Linux
  reporting diagnostic and guarded pinned-source overlay generator. Not deployed
  firmware or a production scheduling change.
- `tools/pi_nordic_campaign.py`: future capture errors retain owner-only private
  phase/message/traceback without changing validation or stop policy. The original
  endurance is closed and must not restart.
- `tools/consolidation_check.py`: offline historical failure identity and
  158/80/78 accounting checks.

## Approved Next Batch

The [approved 24-48-hour matrix plan](WEEKEND_MATRIX_PLAN_2026-10-24.md) is a
test-design document, not an execution record. The subsequent implementation
request authorized launch subject to its mandatory gates. Preparation and
synthetic standalone-service qualification ran; hardware admission is **BLOCKED**,
with zero hardware executions. See the [implementation report](reports/2026-10-24_14-17-00.md).
The local `campaigns/2026-10-weekend/LIVE_SUMMARY.md` exists and must remain visibly
untracked, never staged, committed or ignored.

Consolidated navigation: [historical failures](FAILURE_CATALOG.md),
[evidence availability](EVIDENCE_INDEX.md), [current status](INVESTIGATION_STATUS.md)
and [PR inventory](PR_INVENTORY.md). Historical results retain their own denominator.

New campaign tools provide the SQLite ledger (`campaign_state.py`), guarded
systemd coordinator/watchdog (`campaign_service.py`), native invocation boundary
(`campaign_native.py`), exact-source build (`campaign_build.py`), rootless import
proof (`campaign_isolation.py`), prelaunch assessment (`campaign_preflight.py`)
and synthetic-only remote ownership proof (`campaign_remote_worker.py` and
`qualify_remote_campaign.py`). These are **not** a qualified hardware fixture
adapter; native reset, capture and remote supervision gates remain unresolved.

The historical Nordic fixture adaptation is retained as
`patches/nordic-identify-extra-endpoints.patch`, not applied to SDK source.
It registers Identify instances for endpoints 2-4. Its presence is not approval
to include it in the plan's clean upstream baseline or rebuild/flash a DUT.

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
python3 -B investigation/tools/consolidation_check.py self-test
python3 -B investigation/tools/consolidation_check.py catalog
python3 -B investigation/tools/trace_lifecycle.py self-test
python3 -B investigation/tools/reporting_fairness.py self-test
python3 -B investigation/tools/discovery_isolation.py --self-test
python3 -B investigation/tools/historical_ble.py self-test
python3 -B investigation/tools/ecred_order_probe.py
python3 -B investigation/tools/prepare_reporting_trace.py self-test
python3 -B investigation/tools/prepare_reporting_trace.py runtime-test
python3 -B -m unittest investigation.tools.pi_nordic_campaign.CampaignTest
python3 -B investigation/pr539-failure-evidence/update_dossier.py --self-test
python3 -B investigation/pr539-failure-evidence/prune_successful_runs.py --self-test
```

The `move` action is a guarded one-time relocation, not a routine closeout step.
The `verify` action compares against the local ignored pre-move inventory and is
intended immediately after relocation, before intentional document edits.
Use `staged` for subsequent publication checks.
