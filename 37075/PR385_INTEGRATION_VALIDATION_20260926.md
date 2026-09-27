# PR #385 integration validation

## Result

**PASSED: the physical destroy/recreate/controller-reuse lifecycle completed.**

The owned Matter37075 OTBR was taken offline after its named volume, container
configuration, and 107-byte Active Dataset were preserved. PR #385 then created
a fresh managed Thread network, commissioned the physical DUT, captured the
controller storage and Active Dataset, destroyed the managed SDK/OTBR runtimes,
recreated the OTBR with the persisted dataset, and accessed the DUT without
commissioning it again.

Backend under test:

- Branch: `fix/persist-thread-active-dataset`
- Commit: `ab1e8bb282d1385874e9972760e96f852c027096`
- Configured Matter SDK image:
  `connectedhomeip/chip-cert-bins:e91ea83caae4adb1871aa4bbe93c4be2dd9e1abf`
- OTBR image: `nrfconnect/otbr:9185bda`

Physical hardware:

- Thread RCP: Nordic Thread Co-Processor `8388F563A730D925`
- DUT: nRF52840 DK/J-Link `001050208117`

## Lifecycle proof

Phase A used PR #385's `commission_device` and
`capture_reusable_commissioning_state` paths:

- Fresh BLE-Thread commissioning completed.
- A Basic Information `VendorID` read completed over an operational CASE
  session.
- `admin_storage.json` and `thread_active_dataset.hex` were created with mode
  `0600`.
- The decoded Active Dataset was 100 bytes with SHA-256
  `cae698016a188861dcb225b7753ca6843a910f1e1ffa86987c2d4a0a7799b2b2`.

Between phases, both managed runtime abstractions were destroyed. Phase B then
used PR #385's `should_perform_new_commissioning` and
`load_persisted_thread_active_dataset` paths:

- The reuse decision returned false for new commissioning.
- The managed OTBR was recreated and restored from the persisted dataset.
- The restored decoded dataset had the same SHA-256 as Phase A.
- A second Basic Information `VendorID` read completed through operational
  discovery and CASE using the restored controller state.
- Total commissioning invocations: **1**.

The resulting summary was `status=passed`, `stage=complete`, with both
operational-read proof markers present. Credential-bearing artifacts and full
logs are retained outside Git under the private validation state directory with
mode `0600`.

## Runtime note

The configured SDK image is ARM64-only. QEMU emulation could complete PASE but
was unreliable for the physical BLE/Interaction Model path, so the successful
controller run used native x86_64 Matter Python bindings from connectedhomeip
commit `c51f41f5a2419e15ee537756c5716b92efedef07`. The exact backend commit and
pinned OTBR image were used. Attempts to build native bindings from the exact
configured SDK commit were blocked by host build-toolchain dependency errors;
no product or backend source was changed to bypass them.

## Restoration

After validation, `otbr-37075` was recreated from the untouched
`37075_otbr-thread-data` volume. It returned to the `leader` role with a
107-byte Active Dataset whose SHA-256 is
`ed2e96c79a37c1f8af308d0867c3adaa3ebf186b5b6d65dc3777617debc04d39`,
matching the pre-test recovery record.

The raw Active Datasets, Network Keys, PSKc values, setup credentials, and
controller storage are intentionally omitted.
