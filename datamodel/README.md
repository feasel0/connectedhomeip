# Data Model Work

Use branches named `datamodel/YYYY-MM-DD_data-model` for this work. The current
branch is `datamodel/2026-10-19_data-model`.

Keep summaries under `datamodel/` and UTC datetime-named reports under
`datamodel/reports/YYYY-MM-DD_HH-MM-SS.md`. Do not write or publish this work
under `investigation/` or on an investigation branch. Push only to the user's
`feasel0/connectedhomeip` fork.

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

## SVE Data Model Update

- [Mandate interpretation and initial generation attempt](reports/2026-10-19_16-39-38.md)
- [Combined-book compatibility fix and verified full generation](reports/2026-10-19_17-02-05.md)

The first gate is a complete, error-free run of the existing-directory update
script against specification `master`. The baseline attempt failed on obsolete
specification Make targets. With the compatibility fix, the complete pinned run
exited 0 with no error diagnostics, and all 280 generated XML files passed
structural and manifest checks. Release acceptance still requires ballot-flag
verification and semantic/conformance review; generated models remain in scratch.

Publish all work under `datamodel/` and SDK changes needed for this task on the
dedicated data-model branch. Do not include changes from `investigation/`, private
specification content, scratch outputs, or unrelated work owned by another task.
