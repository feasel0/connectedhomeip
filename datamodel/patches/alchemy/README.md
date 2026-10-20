# Alchemy Public Handoff

These independently applicable patches target the public repository
https://github.com/project-chip/alchemy.git, tag `v1.7.10`, source commit
`f672052c506b5aae5e2e23ffc58bfa1c5edb4c35`.
They contain public implementation context and invented synthetic inputs only.
No specification checkout, source excerpts, real masks, generated models, or
private probes are needed to run them. No PR has been created.

## Artifacts

- `TMODE-01.patch`: minimal `dm/command.go` renderer fix plus synthetic command
  parsing and XML round-trip tests. Explicit Manage/Operate access is emitted
  when direction is inherited. Blank access stays absent, unknown direction
  stays absent, and explicitly directed responses gain no invoke privilege.
  Parsing controls cover missing/blank direction and both explicit directions.
  This is not a general inheritance or inherited-response-direction fix.
- `BITMAP-01.patch`: internal occurrence-keyed removal fix and regression.
  A visible synthetic bitmap table and a separate conditionally hidden
  sibling are included through a shared root. Standalone, enabled sibling, and
  disabled sibling before/after the visible include exercise real parsing,
  include loading, preprocessing, and raw/preprocessed table extraction.
  Assertions require visible operators to survive and disabled content to stay
  suppressed. Enabled content must survive intact. No exported AST layout,
  constructor, clone, or direct Go `==` semantics changes are made.

## Cause Versus Held Design

In the pinned implementation, suppressed special-character value nodes become
removal keys shared with equal visible occurrences. The overlay reader can
therefore remove an operator from an unrelated visible table. This is a loss
between the raw AST and overlay reader, not an XML-escaping defect.

The grammar constructs special-character nodes only for `&`, `<`, and `>`.
The public regression covers these, `|`, and `&&`, plus composite expressions
`<=`, `>=`, `<<`, and `>>`. On the original release, the eight non-pipe
operators fail with disabled siblings in both include orders. In particular,
`<=` and `>=` lose the angle bracket but retain `=`. The pipe controls pass;
the table's existing escaped-pipe representation is deliberately preserved.

Separately, private read-only full-root probes reproduced the original loss:
the entire rendered summary matched the independently generated raw candidate.
Tracing identified one suppressed sibling occurrence colliding with the visible
operator. Bypassing only that removal restored the original expression with
unchanged include attributes. Production bitmap extraction, XML serialization,
and XML reparsing preserved the damaged baseline value and the restored control
value. These are private bounded production-stage probes, not these public
tests, a full CLI rebuild, or a regenerated model release. No private source
names, fragments, original expressions, or probe files are included here.

The private identity-field prototype remains **REJECTED FOR THIS HANDOFF** and is excluded.
Adding a field to the exported struct breaks existing external unkeyed
literals; keyed literals can bypass constructor identity. It also changes
layout, allocations, and direct comparison semantics. A compatibility-preserving
occurrence-aware overlay fix is now implemented and tested: special-character
removals are keyed by parent and raw child slot, instead of character value.
Readers carry this internal removal map; replacement arrays do not reuse the
original occurrence key. Exported `SpecialCharacter` source is byte-identical
to the release. This is a bounded repair for the demonstrated removal collision,
not an audit of every scalar node or every overlay operation. Owner review and
integration into a released Alchemy binary remain outstanding.

## Reproduce

Requirements: Git and Go 1.25 or newer. Validation used Go 1.25.1, not the
release binary's Go 1.26.5 compiler. Initial dependency downloads need network
access. Run the following in Bash from the SDK root containing this directory;
all application and test changes occur in disposable public Alchemy clones.
The function limits Go's writable caches and temporary files to that workspace.

```sh
patches="$PWD/datamodel/patches/alchemy"
pin=f672052c506b5aae5e2e23ffc58bfa1c5edb4c35
work="$(mktemp -d "${TMPDIR:-/tmp}/alchemy-handoff.XXXXXXXX")"
git clone --branch v1.7.10 --single-branch \
  https://github.com/project-chip/alchemy.git "$work/tmode"
test "$(git -C "$work/tmode" rev-parse HEAD)" = "$pin"
git clone --no-hardlinks "$work/tmode" "$work/bitmap"
test "$(git -C "$work/bitmap" rev-parse HEAD)" = "$pin"
mkdir -p "$work/tmp"
alchemy_go() {
  env GOTOOLCHAIN=local GOTELEMETRY=off GOMAXPROCS=2 \
    GOCACHE="$work/go-build" GOPATH="$work/go-path" \
    GOTMPDIR="$work/tmp" TMPDIR="$work/tmp" go "$@"
}
```

TMODE applicability, identical tests red on original code, then green with the
production change (the red command must execute tests and exit 1):

```sh
git -C "$work/tmode" apply --check "$patches/TMODE-01.patch"
git -C "$work/tmode" apply --exclude=dm/command.go "$patches/TMODE-01.patch"
status=0
alchemy_go -C "$work/tmode" test -p=1 ./dm ./matter/spec \
  -run '^TestCommandOverlay(InvokePrivilege|TableAccess)$' \
  -count=1 -timeout=180s -json || status=$?
test "$status" -eq 1
git -C "$work/tmode" apply --include=dm/command.go "$patches/TMODE-01.patch"
alchemy_go -C "$work/tmode" test -p=1 ./dm ./matter/spec \
  -run '^TestCommandOverlay(InvokePrivilege|TableAccess)$' \
  -count=1 -timeout=180s -json
git -C "$work/tmode" apply --reverse --check "$patches/TMODE-01.patch"
```

Bitmap applicability, identical tests red on original production code, then
green with the internal production fix:

```sh
git -C "$work/bitmap" apply --check "$patches/BITMAP-01.patch"
git -C "$work/bitmap" apply --exclude='asciidoc/overlay/*' "$patches/BITMAP-01.patch"
status=0
alchemy_go -C "$work/bitmap" test -p=1 ./matter/spec \
  -run '^TestBitmapIncludeOperatorPreservation$' \
  -count=1 -timeout=180s -json || status=$?
test "$status" -eq 1
git -C "$work/bitmap" apply --include='asciidoc/overlay/*' "$patches/BITMAP-01.patch"
alchemy_go -C "$work/bitmap" test -p=1 ./matter/spec \
  -run '^TestBitmapIncludeOperatorPreservation$' \
  -count=1 -timeout=180s -json
git -C "$work/bitmap" apply --reverse --check "$patches/BITMAP-01.patch"
```

An exit code alone is insufficient: require the executed leaf counts and
preservation assertions below, not build failures or zero-test runs. These
patches can also be applied together; their paths do not overlap. The bitmap
regression remains red with only TMODE because it exercises an independent defect.

Run the existing packages in each independently patched clone:

```sh
alchemy_go -C "$work/tmode" test -p=1 ./dm ./matter/spec ./asciidoc \
  ./asciidoc/parse ./asciidoc/render ./asciidoc/overlay ./tests \
  -count=1 -timeout=180s -json
alchemy_go -C "$work/bitmap" test -p=1 ./dm ./matter/spec ./asciidoc \
  ./asciidoc/parse ./asciidoc/render ./asciidoc/overlay ./tests \
  -count=1 -timeout=180s -json
```

## Verification

Fresh archives of the pinned public commit, each with its own initialized Git
root, were used locally. Existing private source and evidence were not modified.
Dependencies and the build cache came from disposable scratch with
`GOPROXY=off`; source trees and outputs were isolated. This Alchemy validation
did not change the SDK Python overlay. SDK parser fixes were validated separately.

| Check | Leaf PASS | Leaf FAIL | Skipped | Exit |
| --- | ---: | ---: | ---: | ---: |
| TMODE tests only, original production code | 19 | 2 | 0 | 1 |
| Identical TMODE tests, renderer fix applied | 21 | 0 | 0 | 0 |
| Bitmap regression, original production code | 20 | 16 | 0 | 1 |
| Identical bitmap regression, occurrence fix | 36 | 0 | 0 | 0 |
| Seven packages, access patch only | 63 | 0 | 0 | 0 |
| Seven packages, bitmap patch only | 82 | 0 | 0 | 0 |
| Seven packages, both public patches | 103 | 0 | 0 | 0 |
| Private original root, occurrence fix | 1 | 0 | 0 | 0 |
| Private original XML round trip, occurrence fix | 1 | 0 | 0 | 0 |
| External unkeyed struct literal, occurrence fix | 1 | 0 | 0 | 0 |

The two TMODE failures are `inherited/manage` and `inherited/operate` in
`TestCommandOverlayInvokePrivilege`. All 12 parsing controls pass before and
after the fix. Every bitmap failure is a `disabled-before` or `disabled-after`
preprocessed-summary assertion; every raw-reader check passes. All standalone,
enabled-sibling, and pipe controls pass. These are leaf counts, excluding parent
test events. Both patches have forward/reverse application and gofmt checks.
The private full-root and XML controls preserve all three operator occurrences;
the unchanged original candidate retains only two. No regenerated model is
published. The external literal control uses `-vet=off` to test compilation,
not Go vet's unrelated warning about external unkeyed literals.

The earlier private seven-package result of **80 leaf PASS** remains valid for
its original test set and private fixes. It included the held prototype and a
private probe. It is not a green result for this public bitmap regression or
evidence for these public configurations. Use the independent results above.
An initial access-only preparation lacked an initialized Git root and ran only
42 existing leaves because patch application was skipped; it is superseded by
the hash-verified 63-pass run, not counted as patched evidence. Two initial
suppression-control failures were test-rendering mistakes, repaired before
the final identical red/green runs.

Patch SHA-256 (from this directory, run
`sha256sum TMODE-01.patch BITMAP-01.patch`):

```text
7bfb82c98a7378b7c37730d426fe90dd6d740f57b5f97cdc7b8de53e378353b9  TMODE-01.patch
e9cecef28ccadc2cb1d87bbb436f3f1b5a0fff9d6d09db195b8591e2a8167f62  BITMAP-01.patch
```

Production-source SHA-256 proofs from the isolated validation copies:

```text
c07bf02fa7177949b7040370d9c5f8ea06fbe9a89e4c3d3f70eb416a20600353  original dm/command.go
8e1f562f68df57d94475c85dd76c87c8423135ef48d830252ec18e45f3b124a5  TMODE-patched dm/command.go
3b02726ee2080e3708a52eb56a45011478171227507917e222f31c595bee2329  original asciidoc/text.go
```

The bitmap validation copy matches both original production hashes. The TMODE
copy retains the original `asciidoc/text.go` hash. These prove that neither
public validation used the held identity-field prototype.
