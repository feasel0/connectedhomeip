# Third 500-run: J-Link USB disruption evidence

This package preserves evidence needed to distinguish Matter failures from
host-to-DUT connection failures in the third native `TC_Darwin_Pair` campaign.
The contaminated campaign was intentionally stopped after 116 completed
iterations: 36 passed and 80 failed. `campaign/summary-before-stop.json` and
`campaign/final-status-before-stop.txt` record its final pre-stop state.

## Classification

### Infrastructure-correlated failure cascade

Iterations 37 and later in this campaign are contaminated by a confirmed USB
transport disruption and should not be counted as independent Matter protocol
failures without additional evidence.

- Iterations 1-36 passed.
- At 08:40:31.363, during iteration 37, the Linux kernel reported
  `usb 3-2.2-port2: disabled by hub (EMI?), re-enabling...` and disconnected the
  SEGGER J-Link with serial number `001050208117`.
- The iteration 37 DUT UART log ends abruptly at DUT uptime 28132 ms, which maps
  to the same wall-clock second as the kernel event.
- Iteration 37 later failed with a `ReadClient.cpp:756` timeout.
- From iteration 38 onward, DUT logs contain only their generated headers. The
  harness reports that it sends both factory-reset commands, but receives no DUT
  UART response; BLE discovery finds no matching Matter device and PASE then
  reports `Incorrect state`.
- A further disconnect/re-enumeration occurred during iteration 81.

The repeated PASE failures are therefore one continuing test-bed failure state,
not dozens of independent Matter failures.

### Earlier second-campaign failure remains distinct

The second campaign's iteration 37 cleanup/unpair timeout occurred around 03:00.
There were no J-Link USB disconnect or hub-disable events during that campaign's
02:10-06:51 execution window. That archived failure remains eligible for Matter
or harness investigation and must not be conflated with this physical-link
cascade.

### Comparison with clean campaign

The first 500/500 campaign had no J-Link USB disconnect or hub-disable events in
its execution window. The current campaign had three such disconnects by the
capture point: during iterations 15, 37, and 81. Iteration 15 still passed, so a
USB event is not automatically a Matter failure; event timing and subsequent
DUT/UART behavior determine whether an iteration is contaminated.

## Likely meaning of the observed popup

The J-Link exposes a USB mass-storage volume. At each disconnect/re-enumeration,
Ubuntu removed and remounted `/media/feasel/JLINK`; that mount/notification is a
plausible source of the popup. No J-Link commander, OpenOCD, nrfjprog, GDB server,
or similar active debug process was found. Two VS Code nRF extension
`nrfutil-device --json list --hotplug` monitor processes were present, but the
captured evidence does not show them initiating the kernel-level disconnect.

## Contents

- `iterations/14-16`: the first USB event and adjacent controls.
- `iterations/36-39`: last clean iteration, critical disconnect iteration, and
  first two cascade failures.
- `iterations/80-82`: later reconnect event and adjacent failed iterations.
- `system/kernel-since-run-start.log`: complete kernel window.
- `system/jlink-usb-and-mount-events.log`: filtered USB/J-Link/automount events.
- `system/critical-event-full-journal.log`: complete 08:40:25-08:40:40 journal.
- `system/event-to-iteration-map.txt`: event-to-iteration correlation.
- `system/usb-topology.txt`: topology showing the J-Link behind nested hubs.
- `system/debug-and-device-processes.txt`: process snapshot.
- `harness-source/`: exact serial and Nordic DUT helper source used by the run.
- `campaign/`: configuration, launch command, summary snapshot, and revisions.
- `SHA256SUMS`: integrity checksums.

Generated per-iteration `iteration.json` files are intentionally excluded from
the transport archive. Controller and DUT logs remain available for every
listed iteration, and no controller-storage snapshot or process-memory dump is
included.

## Practical classification rule

For reporting issue #37075 results:

1. Treat an iteration as infrastructure-contaminated if a J-Link USB disconnect,
   hub-disable, serial error, abrupt DUT-log truncation, or missing DUT response
   overlaps the iteration.
2. Treat subsequent iterations as part of the same infrastructure incident until
   a verified reset response and normal DUT boot/advertising output return.
3. Investigate as a Matter candidate only failures with intact USB/UART evidence
   through the entire operation and no overlapping host/device disruption.
