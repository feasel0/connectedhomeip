# Issue 37075 reproduction build proof

## Result

Both peers were built successfully with `CHIP_CONFIG_SECURITY_TEST_MODE=1`:

- Ubuntu Python controller: PASS
- nRF52840 DK all-clusters-app: PASS

Security test mode is intentionally insecure. It fixes the session keys and uses
Node ID 0 in the nonce. These artifacts must only communicate with peers built
with the same option.

## Configuration provenance

- Python project config: `config/python/CHIPProjectConfig.h:53`
    - `#define CHIP_CONFIG_SECURITY_TEST_MODE 1`
- nRF Connect application project config:
  `examples/all-clusters-app/nrfconnect/main/include/CHIPProjectConfig.h:29`
    - `#define CHIP_CONFIG_SECURITY_TEST_MODE 1`
- nRF Connect GN warning policy: `config/nrfconnect/chip-gn/args.gni:21`
    - `treat_warnings_as_errors = false`
- Generated DUT GN arguments:
  `examples/all-clusters-app/nrfconnect/build/nrfconnect/modules/connectedhomeip/args.gn:34`
    - `chip_project_config_include = "</workspaces/connectedhomeip/examples/all-clusters-app/nrfconnect/main/include/CHIPProjectConfig.h>"`

## Compiler proof

The security-mode `#warning` from `src/transport/CryptoContext.cpp:140` was
emitted by both independent builds:

- Ubuntu-native Python controller: `37075/build-proof/python-host-build.log:397`
- Shell-enabled nRF52840 DK: `37075/build-proof/nrf52840dk-shell-build.log:943`

The DUT warning reads:

> Warning: CHIP_CONFIG_SECURITY_TEST_MODE=1 bypassing key negotiation... All
> sessions will use known, fixed test key, and NodeID=0 in NONCE. Node can only
> communicate with other nodes built with this flag set.

The successful DUT build continued through final link and generated `merged.hex`
at `37075/build-proof/nrf52840dk-shell-build.log:2170`.

## Translation-unit consumption proof

The macro reaches `CryptoContext.cpp` through this include/configuration chain:

1. `CryptoContext.cpp` includes `transport/CryptoContext.h`.
2. `CryptoContext.h` includes `lib/core/CHIPCore.h`.
3. `CHIPCore.h` includes `lib/core/CHIPConfig.h`.
4. `CHIPConfig.h` includes the header named by `CHIP_PROJECT_CONFIG_INCLUDE`
   before defining the fallback value of 0.
5. `CryptoContext.cpp` consumes the resulting value in
   `#if CHIP_CONFIG_SECURITY_TEST_MODE` around `InitTestMode()` and in
   `BuildNonce()`.

Ninja's recorded dependency graph for the exact `CryptoContext.cpp` object
confirms the selected project header was consumed by each translation unit:

- Python object:
  `out/python_lib/obj/src/transport/libTransportLayer.CryptoContext.cpp.o`
    - dependency: `config/python/CHIPProjectConfig.h`
- nRF52840 DK object:
  `examples/all-clusters-app/nrfconnect/build/nrfconnect/modules/connectedhomeip/obj/src/transport/libTransportLayer.CryptoContext.cpp.o`
    - dependency:
      `examples/all-clusters-app/nrfconnect/main/include/CHIPProjectConfig.h`

Replaying each object's recorded compiler command in preprocessor macro-dump
mode produced:

```text
python: #define CHIP_CONFIG_SECURITY_TEST_MODE 1
nrf52840dk: #define CHIP_CONFIG_SECURITY_TEST_MODE 1
```

The emitted compile-time warning is an additional independent check: the
`#warning` itself is inside the guarded `#if`, so it cannot appear unless that
same translation unit evaluated the macro as nonzero.

## Final-artifact proof

The full warning string is present in both final native binaries when inspected
with `strings`:

- `out/python_env_host_313/lib/python3.13/site-packages/matter/_ChipDeviceCtrl.so`
- `examples/all-clusters-app/nrfconnect/build/nrfconnect/zephyr/zephyr.elf`

The linked implementations of `CryptoContext::BuildNonce()` were also
disassembled:

- Python `_ChipDeviceCtrl.so` passes an immediate zero to the 64-bit nonce
  write; the incoming `nodeId` is not used.
- nRF52840 DK `zephyr.elf` executes an eight-iteration loop that writes byte
  value zero; the incoming `nodeId` is not used.

These are the machine-code forms of the test-mode-only `bbuf.Put64(0)` branch in
`CryptoContext.cpp`, so this proves that behavior survived preprocessing,
compilation, optimization, and final linking. The Python native library also
exports `CryptoContext::InitTestMode()`; the DUT's LTO build inlines that
function.

The Python smoke test successfully imported `matter`, `matter.ChipDeviceCtrl`,
and the current matter-qa base class from `out/python_env_host_313`. The Matter
native wheel uses CPython's stable ABI, so the controller built with the Ubuntu
22.04 host toolchain is usable from Python 3.13. Its newest required glibc
symbol version is `GLIBC_2.34`; a container-built candidate requiring
`GLIBC_2.38` was rejected because it cannot load on this host. The host build
requires `out/host-deps/libevent/usr/lib/x86_64-linux-gnu` in `LD_LIBRARY_PATH`.
Python 3.13 is required here because current matter-qa uses PEP 701 f-string
syntax that Python 3.11 cannot parse.

The physical BLE-Thread smoke run independently exercised the linked test-mode
path. Its controller log emitted
`Warning: CHIP_CONFIG_SECURITY_TEST_MODE=1 bypassing key negotiation... All sessions will use known, fixed test key, and NodeID=0 in NONCE.`
during PASE and CASE session establishment.

The nRF image also has `CONFIG_CHIP_LIB_SHELL=y`. Serial checks of
`matter config`, `matter device factoryreset`, and the subsequent reboot
succeeded, establishing that matter-qa can reset the physical DUT between
iterations.

Do not use `out/nrf-nrf52840dk-all-clusters/merged.hex`: that directory contains
an older May build made before the test-mode project-header change. The
validated September DUT image is
`examples/all-clusters-app/nrfconnect/build/merged.hex`, whose hash is recorded
below.

## DUT memory usage

From the final link:

- FLASH: 862,992 / 966,144 bytes (89.32%)
- RAM: 197,812 / 262,144 bytes (75.46%)

## Artifact manifest

| Artifact                                                                         |       Bytes | SHA-256                                                            |
| -------------------------------------------------------------------------------- | ----------: | ------------------------------------------------------------------ |
| `out/python_env_host_313/lib/python3.13/site-packages/matter/_ChipDeviceCtrl.so` | 157,292,880 | `6914d438c406d316813ab4ef9bbfd55c100c84a24bf1ebe801acbb6fa6205686` |
| `examples/all-clusters-app/nrfconnect/build/nrfconnect/zephyr/zephyr.elf`        |  73,047,784 | `99b0b7b117ceedc0291e9154ec960b879682e8fbf8f3730cc75601fdaea15e9c` |
| `examples/all-clusters-app/nrfconnect/build/nrfconnect/zephyr/zephyr.hex`        |   2,427,544 | `e27b0d55bbdd464b48e991e80a04b4a747e1595ac26adfe5c8c324267065f49c` |
| `examples/all-clusters-app/nrfconnect/build/nrfconnect/zephyr/zephyr.signed.hex` |   2,375,296 | `6bc65eb04c5f4a0140689783d8eb499ebd0fbf482fa2b674b98a92d6b71e1c84` |
| `examples/all-clusters-app/nrfconnect/build/merged.hex`                          |   2,442,796 | `5617e2df9939a2627ba6c10131cdaea2fe2c21311aceaff5fbf885f5990d6a1a` |
| `examples/all-clusters-app/nrfconnect/build/dfu_application.zip`                 |     864,412 | `e923475467c95a0a0da0ce207a3f8ba11a2f924689ca8b0ed27790fd1c7e9ece` |

For first-time programming of the DK, use `merged.hex`; it includes MCUboot and
the signed application image.
