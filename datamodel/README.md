# Data Model Work

Use branches named `datamodel/YYYY-MM-DD_data-model` for this work. The current
branch is `datamodel/2026-10-19_data-model`.

Keep summaries under `datamodel/` and UTC datetime-named reports under
`datamodel/reoprts/YYYY-MM-DD_HH-MM-SS.md`. Do not write or publish this work
under `investigation/` or on an investigation branch. Push only to the user's
`feasel0/connectedhomeip` fork.

## Per-Turn Closeout

Standing order: after every turn, including instruction-only turns, write a new
report describing the actions taken, results, verification, and remaining limits.
Use the exact `reoprts/` spelling requested by the user. Leave historical reports
under `reports/` in place.

At the end of each turn, commit and push all `datamodel/` changes and SDK changes
authored for this task to the dedicated data-model branch. Exclude investigation
changes, unrelated work, private sources, raw logs, and generated scratch outputs.

- [Standing per-turn reporting and publication order](reoprts/2026-10-20_03-30-32.md)
- [Documentation, fork draft PR, and current follow-up closeout](reoprts/2026-10-20_03-42-09.md)

## Transcription

The Ubuntu transcription kit is installed at `/home/feasel/transcription/`.
The recording and completed transcript remain together in
`/home/feasel/Documents/Data Model Work/`. The generated transcript is
`2026-09-09 14-02-48_transcript.md`.

- [Ubuntu kit conversion](reports/2026-10-19_13-05-26.md)
- [Completed MKV transcription](reports/2026-10-19_14-04-19.md)
- [Corrected reporting location and branch rollback](reports/2026-10-19_14-09-50.md)

The first two reports are preserved byte-for-byte. Their historical repository
closeout sections describe the superseded placement, not the current workflow.
The mistaken investigation-branch commit was removed from that branch's history
with the user's explicit authorization. Recordings, transcripts, response caches,
and API credentials are not included in this directory or its commits.

## Data Model Manager Working Documents

The reusable role and process guidance and the current presentation summary live in `datamodel/docs/`:

- [Matter 1.7 SVE — work summary and findings](docs/2026-10-19_SVE_status_and_findings.md) — shareable status, the generator fix, verified outputs, and the mismatch investigation queue.
- [Integration draft #74862](https://github.com/project-chip/connectedhomeip/pull/74862) contains the current technical summary; edit its description directly rather than maintaining a repository copy.
- [Data Model Manager role and release playbook](docs/data_model_manager_role_and_release_playbook.md) — **start here for future agents**; responsibilities, milestone workflow, validation gates, triage, and release handoff. Update after each meaningful tested process change.
- [Data model process improvements and automation backlog](docs/data_model_process_improvements.md) — lower-authority hypotheses, prototype proposals, and lessons to develop between releases. Promote successful improvements into the role playbook.

- [20-file SVE semantic review](docs/2026-10-20_SVE_semantic_review.md)
- [SVE mismatch ledger and proposed owners](docs/SVE_mismatch_ledger.md)
- [Semantic-review execution report](reoprts/2026-10-20_05-05-31.md)
- [Tested defect resolution and precise remaining owner decisions](docs/2026-10-20_SVE_defect_resolution.md)
- [Public-safe Alchemy access and bitmap patch handoffs](patches/alchemy/README.md)
- [Defect-resolution execution and closeout report](reoprts/2026-10-20_14-23-47.md)

The generated reference model and related SDK changes are published in
[upstream draft #74862](https://github.com/project-chip/connectedhomeip/pull/74862).
Separate dependencies remain [generator #74858](https://github.com/project-chip/connectedhomeip/pull/74858),
[Alchemy #91](https://github.com/project-chip/alchemy/pull/91),
[Alchemy #92](https://github.com/project-chip/alchemy/pull/92), and
[Thermostat metadata #74803](https://github.com/project-chip/connectedhomeip/pull/74803).

## SVE Data Model Update

- [Mandate interpretation and initial generation attempt](reports/2026-10-19_16-39-38.md)
- [Combined-book compatibility fix and verified full generation](reports/2026-10-19_17-02-05.md)

The first gate is a complete, error-free run of the existing-directory update
script against specification `master`. The baseline attempt failed on obsolete
specification Make targets. With the compatibility fix, the complete pinned run
exited 0 with no error diagnostics, and all 280 generated XML files passed
structural and manifest checks. The corrected response-aware candidate is now
published without regeneration: 245 XML updates, including 19 canonical
substantive/editorial changes and 226 formatting-only changes. The earlier
semantic review was reused, not repeated. Current checks pass 92 parser tests,
67 IDM units, 222 native cases and three ZAP alignment regressions, with
additional sanitizer, compiled-revision and Thermostat dependency controls.
The PR description records remaining technical questions directly on GitHub;
the mismatch ledger retains detailed evidence and release-input questions.

Publish all work under `datamodel/` and SDK changes needed for this task on the
dedicated data-model branch. Do not include changes from `investigation/`, private
specification content, scratch outputs, or unrelated work owned by another task.
