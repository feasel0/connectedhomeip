# PR528 Ubuntu / Pi Controller and Nordic DUT Validation

## Current Failure Disposition: 2026-10-16

Ubuntu iteration 36's wildcard SubscribeRequest `INVALID_ACTION` remains
**OPEN**: no established matching fix or packet-loss root cause. QA528
addresses topology validation/diagnostics, and QA527 addresses cleanup; neither
establishes correction of this primary subscription failure. Matching datasets
do not close it. The 99/100 result and all evidence below remain unchanged.

Use the [current failure index](LOG_CATALOG.md#current-dispositions-2026-10-16)
for this and the distinct historical timeout families. PR status and source
pins below describe the validation snapshot, not a fresh campaign.

## Scope and Fixture

On 2026-10-07, both requested 50-iteration BLE-Thread `TC_Darwin_Pair`
(`stress_1_6`) campaigns completed with
`otbr_device_config.validate_thread_dataset: true`.

- PR: https://github.com/CHIP-Specifications/matter-qa/pull/528, open and ready
  for review.
- Exact QA revision: `e5fc0d6f786f7a754c94aa907425fd18e3de6cbb` on both
  controllers, without PR527 or PR539 QA overlays.
- DUT: Nordic nRF52840 DK, J-Link `001050208117`, 115200-baud UART.
- OTBR: existing Ubuntu Docker container `otbr-37075`, using the separate
  Nordic RCP dongle `8388F563A730D925`. Its network was preserved.
- Intended Thread identity: `Matter37075`, channel 20, PAN ID `0x6213`,
  Extended PAN ID `9612AC5946F05EAF`.
- Complete dataset SHA256:
  `ed2e96c79a37c1f8af308d0867c3adaa3ebf186b5b6d65dc3777617debc04d39`.
- Ubuntu used the shipped local Docker OTBR adapter. Pi used authenticated,
  loopback-only SSH forwarding to the Ubuntu-attached UART and a read-only
  OTBR relay. The run-local OTBR adapter inherited PR528's dataset parsing and
  topology logic unchanged.
- Each campaign had fresh controller storage, retained across its inner
  iterations. Both controller native libraries and the DUT were checked for
  fixed-key security-test-mode compatibility before the passing smokes.

## Results

Both preceding single-iteration commissioning smokes passed. All 25 focused
PR528 unit tests passed on Ubuntu and on the native ARM64 Pi controller.

| Controller | Requested | Executed | Passed | Failed | UTC Start | UTC End |
| ---------- | --------- | -------- | ------ | ------ | --------- | ------- |
| Ubuntu | 50 | 50 | 49 | 1 | 17:58:26 | 19:06:46 |
| Raspberry Pi | 50 | 50 | 50 | 0 | 19:12:23 | 20:18:08 |

The combined campaign result is **99/100**, not an all-pass validation.
Ubuntu exited 1 because its configured success threshold was 100%; Pi and
both smoke processes exited 0. Pi's detached sequence also exited 0.

For each campaign:

- Complete controller and live intended-OTBR datasets matched at preflight.
- All 50 post-ConnectNetwork PASE topology observations reported a matching
  DUT Extended PAN ID.
- All iteration numbers 1-50 and individual outcomes reconciled with the
  structured summary.
- All 50 iterations retained substantive DUT UART logs. Minimum log sizes
  were 88,965 bytes on Ubuntu and 182,485 bytes on Pi.

The live complete OTBR dataset remained byte-for-byte unchanged at closure.

## Ubuntu Iteration 36

The primary failure was the first-fabric wildcard SubscribeRequest:
`IM Error 0x00000580: General error: 0x80 (INVALID_ACTION)`.
The exception originated at `TC_Darwin_Pair.py:200`, through
`send_subscriberequest` and `ReadAttribute(..., attributes=[()])`.

PR528 preserved that primary exception and saved failure-time diagnostics:
the controller/OTBR complete datasets matched, DUT Extended PAN ID matched,
and intended OTBR SRP and border routing were running. The observed partition
was `0x2BD1A270`. No dataset mismatch or operational-discovery exception was
reported as the primary failure.

The DUT UART shows report/status-response retransmission and timeout activity
before the late INVALID_ACTION response. Without packet capture, the packet
loss location and root cause remain undetermined. This is not evidence that
PR528 caused the subscription failure, nor proof that it could prevent it.
Iterations 35 and 37 passed; iteration 36 and its neighbors were sealed before
the Pi phase reset the DUT.

## Evidence and Limitations

Private originals are retained under
`/home/feasel/qa-mar6/pr528-enabled-20261007`, including controller consoles,
native JSON traces, per-iteration UART logs, structured summaries, source and
binary provenance, UTC bounds, exit codes, controller storage and OTBR logs.
Pi originals were retrieved into `pi-retrieved` and every listed SHA256
verified locally. Whole-root checksums are in `SHA256SUMS.local`.

The first-failure archive is `ubuntu-first-failure-36.tar.gz`, SHA256:
`e9c504ebc930461d86eb00a5e3061fa92aa56f5dc3f6790f8657845f89cbcbe8`.

Pi kernel/Bluetooth journal queries completed but returned no entries for the
requested window. The initial incompatible journal timestamp error was
preserved separately before recollecting with normalized UTC bounds.
No IP, Thread-radio or BLE HCI packet capture was established. Raw traces,
storage and datasets remain private; this directory is not a redacted public
bundle.

This validates PR528's enabled matching-network path and failure diagnostics.
No deliberate wrong-network hardware fault was injected; negative mismatch
paths remain unit-tested. Matching identity does not prove the DUT's actual
parent, full dataset, routing health or SRP registration, and does not imply
all issue37075 failure classes are fixed.

The temporary UART bridge and authenticated SSH tunnel were stopped. Their
listening ports closed and the DK UART had no remaining owner. No OTBR
reconfiguration, firmware flash or production QA code edit occurred during
these campaigns.

## Reproduction

The private launcher refuses to overwrite existing run evidence and invokes
`TC_Darwin_Pair.py` with `--commissioning-method ble-thread`, a complete live
`--thread-dataset-hex`, native JSON tracing, fresh `--storage-path`, and the
enabled reliability YAML via `--string-arg reliability_tests_arg:...`.
The campaign YAML selects 50 iterations of `stress_1_6`.
For a new run, generate a fresh run directory and verified fixture config;
do not reuse these sealed controller stores or publish their datasets.