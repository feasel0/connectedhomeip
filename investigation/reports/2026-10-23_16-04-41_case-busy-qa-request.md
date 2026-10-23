# Draft QA evidence request: #33830

Status: draft only; not posted.

Please provide one existing, correlated CASE Busy failure with the following
evidence. A new campaign is not requested.

1. Continuous DUT native SC/CASE, exchange-manager and session logs from boot/reset
   or the accepted owner's Sigma1 through the Busy response and the owner's
   completion, timeout, abort or release. Identify the occupied exchange separately
   from the rejected request: roles, state, exchange/session/context IDs, peer
   endpoints and scoped peer/fabric where available. Include actual timer,
   watchdog and release events rather than inferring ownership from Busy alone.
2. UTC/monotonic clock alignment, DUT boot identity and the matching controller
   iteration trace, so both sides' events can be correlated.
3. DUT SDK/vendor/platform revisions and local diff, board/application, flashed
   image hash, matching ELF/build ID/symbols, build arguments and the consumed
   retry, resumption, MRP, watchdog and fault-injection configuration.
4. Controller QA/SDK revisions and local diff, exact command/options, actual loaded
   Python package and native-library paths/hashes, wheel/executable identity and
   relevant configuration. A checkout revision alone does not identify the
   executable code used by the failed iteration.

If normal logging does not expose the responder's occupied owner, please state
that limitation and include an already-available read-only state snapshot if one
exists. Do not reset or disturb an active fixture merely to obtain it.

The retained July archive contains controller native logs, iteration JSON,
bluetoothd and wpasupplicant logs, but no DUT owner lifecycle or matching build
manifest. The older late Sigma2Resume on a retired exchange does not by itself
prove overlapping live local CASE handshakes.

Exclude passcodes, network credentials, private keys, and session/resumption key
material. Metadata and value-free lifecycle events are sufficient for this
request; use the approved private evidence channel for any raw artifacts.
