# Issue 37075 BLE-Thread stress-test plan

## Verified hardware and firmware

The nRF52840 DK is connected through its short-edge SEGGER/interface-MCU USB
connector and is visible as J-Link probe `001050208117`, with VCOM ports
`/dev/ttyACM0` and `/dev/ttyACM1`. The `nRF` switch in `Default` is correct. No
GPIO jumpers are required. USB enumeration and working VCOM communication prove
that the selected power-source position is usable; LED5 activity is expected
from the interface MCU.

The DK is already flashed with the shell-enabled all-clusters application from:

- `examples/all-clusters-app/nrfconnect/build/merged.hex`

The application has `CHIP_CONFIG_SECURITY_TEST_MODE=1`,
`CONFIG_CHIP_LIB_SHELL=y`, and the serial factory-reset/reboot commands required
by matter-qa. Verified DUT identity:

- Discriminator: `3840`
- Passcode: `20202021`
- Manual setup code: `34970112332`
- QR payload: `MT:-24J042C00KA0648G00`
- Product ID: `32769` (`0x8001`)

Use the stable serial path
`/dev/serial/by-id/usb-SEGGER_J-Link_001050208117-if00`, rather than relying on
the potentially changing `/dev/ttyACM0` name.

## Controller environment

Use the Python 3.13 environment at `out/python_env_host_313`. Python 3.12 or
newer is required because current matter-qa uses PEP 701 multiline f-string
expressions. The environment contains:

- The ABI-stable Matter Python controller built with
  `CHIP_CONFIG_SECURITY_TEST_MODE=1`.
- The current editable matter-qa checkout.
- The Matter test infrastructure.

The host-built controller depends on the local libevent runtime. Set this for
every direct test invocation:

LD_LIBRARY_PATH=/home/feasel/matter-oct14/connectedhomeip/out/host-deps/libevent/usr/lib/x86_64-linux-gnu

The matter-qa checkout at `/home/feasel/qa-mar6/matter-qa` is on `main` at
upstream commit `9e878e38f8cfc75e77d928445a06ec0f5d068da9` from
`CHIP-Specifications/matter-qa`. The `origin` remote remains the older personal
fork, while `upstream` is the authoritative repository.

## Available stress tests

### Primary tests for this investigation

1. `TC_Darwin_Pair.py` (`stress_1_6`, operational scripts)
    - Despite the historical name, this script directly uses the Python Matter
      controller unless an external commissioner is explicitly configured.
    - Closest reproduction of issue 37075.
    - Manually performs PASE, attestation, CSR/AddNOC, CASE, first
      CommissioningComplete, ACL update, second-fabric AddNOC, second
      CommissioningComplete, subscriptions, reads/writes, and cleanup.

2. `TC_RT_1_1.py` (`stress_1_1`, reliability scripts)
    - Current generic commission/decommission stress test.
    - Uses the Python controller for repeated BLE-Thread commissioning and
      unpairing.
    - Captures commissioning-stage and CASE-handshake timing metrics.

3. `TC_RT_1_2.py` (`stress_1_2`, reliability scripts)
    - Current multi-admin stress test.
    - Performs initial commissioning, opens commissioning windows, adds
      controllers/fabrics, then runs subscription and bulk read/write
      operations.
    - Requires the configured Matter data-model XML tree.

### Other current tests

- `TC_RT_2_1.py` (`stress_2_1`): commissionable discovery.
- `TC_RT_2_2.py` (`stress_2_2`): operational discovery plus network switching.
  Its Thread-switch scenario requires a second Thread dataset/border-router
  arrangement and is not suitable for the initial single-RCP setup.
- `TC_ON_OFF.py` (`stress_1_3`): OnOff operations.
- `TC_Send_Command_Read_Write_Attributes.py` (`stress_1_4`): command plus bulk
  attribute operations.
- `TC_Level_Control.py` (`stress_1_5`): level-control operations.
- `TC_Android_Pair.py` (`stress_1_7`): Android/Appium controller; not applicable
  to the Ubuntu Python-controller setup.
- `TC_Bridge_Add_Remove.py` (`stress_1_8`): dynamic bridge endpoint operations.
- `TC_BDX_OTA.py` (`stress_bdx_3_1_fw`): OTA/BDX transfer and provider
  application; requires additional artifacts.

## matter-qa configuration

Use `37075/matter-qa-nordic.yaml`. It selects the Nordic serial adapter, enables
a factory reset for each iteration, contains the actual DUT setup values, and
initially disables optional packet captures and OTBR diagnostic collection.

The direct test scripts use the Matter test runner's supported generic argument
syntax:

- `--string-arg reliability_tests_arg:/home/feasel/matter-oct14/connectedhomeip/37075/matter-qa-nordic.yaml`

Do not use `--reliability-tests-arg` for direct script invocation with this
controller build. That spelling appears in matter-qa's higher-level runner
configuration but is not an option exposed by the installed Matter Python test
parser.

Start with `number_of_iterations: 1`. Increase it only after a complete smoke
test. For a stress run, change it to the desired value, such as `100`.

## Required Thread infrastructure

BLE commissioning uses the laptop's existing Bluetooth controller `hci0`. Thread
operational traffic requires a Border Router. The separate nRF52840 Dongle has
been connected, built, and flashed as the local RCP. It is distinct from the DUT
DK:

- Factory DFU identity: `E6D68B4EED6B`, USB `1915:521f`
- RCP application identity: `8388F563A730D925`, USB `1915:0000`
- Stable RCP path:
  `/dev/serial/by-id/usb-Nordic_Semiconductor_ASA_Thread_Co-Processor_8388F563A730D925-if00`
- Current kernel path: `/dev/ttyACM2`

The RCP firmware is the nRF Connect SDK OpenThread co-processor sample:

- SDK/sample provenance: clean NCS v3.4.0 container tree at
  `nrf/samples/openthread/coprocessor`
- Board target: `nrf52840dongle/nrf52840`
- Default architecture: RCP
- Host link: USB CDC ACM/Spinel, at the sample's default 1,000,000 baud
- Build output: `37075/nrf52840dongle-rcp-build-container`
- Secure DFU package: `37075/nrf52840dongle-rcp.zip`
- DFU package SHA-256:
  `ac69253b09637615b13c0dea4740b5d0d256f6c509d57fc809ddc75255fce291`
- Firmware size: 134,980 bytes flash and 33,592 bytes RAM

Configure OTBR on Ubuntu with this radio URL:

spinel+hdlc+uart:///dev/serial/by-id/usb-Nordic_Semiconductor_ASA_Thread_Co-Processor_8388F563A730D925-if00?uart-baudrate=1000000

Use `enx207bd2e29318` as the infrastructure interface and `wpan0` as the Thread
interface. Then form a Thread network and retrieve the full active operational
dataset using `ot-ctl dataset active -x` (with `sudo` for a native installation,
or inside the privileged host-network OTBR container).

The stress-test command requires that dataset as `--thread-dataset-hex`. The
dataset must come from the running local OTBR; the example dataset in matter-qa
is not a substitute.

The local OTBR image was built from `third_party/ot-br-posix/repo` as
`otbr-37075:local`. Its persistent host-network configuration is in
`37075/otbr-compose.yaml`. The container is running as `otbr-37075`, and the RCP
has formed the `Matter37075` network as leader. Current active dataset:

0e08000000000001000000030000144a0300001535060004001fffe002089612ac5946f05eaf0708fd973da1002981060510127d3c1fb807e695fb0e6afe4db333340102621304104c58fd9a797e1195061d9d934ee3494e0c0402a0f7f8030b4d61747465723337303735

Start or inspect it with:

    docker compose -f 37075/otbr-compose.yaml up -d
    docker exec otbr-37075 ot-ctl state
    docker exec otbr-37075 ot-ctl dataset active -x

## Smoke-test commands

### Exact issue reproducer

    LD_LIBRARY_PATH=/home/feasel/matter-oct14/connectedhomeip/out/host-deps/libevent/usr/lib/x86_64-linux-gnu \
      /home/feasel/matter-oct14/connectedhomeip/out/python_env_host_313/bin/python \
      /home/feasel/qa-mar6/matter-qa/src/matter_qa/scripts/operational_scripts/TC_Darwin_Pair.py \
      --discriminator 3840 \
      --passcode 20202021 \
      --storage-path /home/feasel/matter-oct14/connectedhomeip/37075/admin-darwin-pair.json \
      --timeout 1800 \
      --commissioning-method ble-thread \
      --logs-path /home/feasel/matter-oct14/connectedhomeip/37075/logs \
      --string-arg reliability_tests_arg:/home/feasel/matter-oct14/connectedhomeip/37075/matter-qa-nordic.yaml \
      --trace-to json:log \
      --ble-controller 0 \
      --thread-dataset-hex 0e08000000000001000000030000144a0300001535060004001fffe002089612ac5946f05eaf0708fd973da1002981060510127d3c1fb807e695fb0e6afe4db333340102621304104c58fd9a797e1195061d9d934ee3494e0c0402a0f7f8030b4d61747465723337303735 \
      --paa-trust-store-path /home/feasel/matter-oct14/connectedhomeip/credentials/development/paa-root-certs

### Generic pair/unpair test

Use the same arguments but replace the script with:

    /home/feasel/qa-mar6/matter-qa/src/matter_qa/scripts/reliability_scripts/TC_RT_1_1.py

### Multi-admin test

Use the same arguments but replace the script with:

    /home/feasel/qa-mar6/matter-qa/src/matter_qa/scripts/reliability_scripts/TC_RT_1_2.py

Use a separate storage JSON for each test to prevent stale fabrics from one run
affecting another. The configured per-iteration factory reset also ensures that
the DUT returns to BLE commissionable mode.

## Verified smoke-test result

The one-iteration `TC_Darwin_Pair.py` BLE-Thread smoke test passed on September
21, 2026:

- Result: 1 requested, 1 executed, 1 passed, 0 failed.
- Run artifacts:
  `37075/logs/smoke-darwin-pair/MatterTest/ble-thread/09-21-2026_08-12-59-788`
- Iteration duration: 84.384601 seconds.
- Pairing duration: 59.016965 seconds.
- Both first- and second-fabric `CommissioningComplete` commands returned `kOK`.
- Controller logs emitted the security-test-mode warning during PASE and both
  CASE paths, proving that the fixed session-key and zero-Node-ID nonce path
  executed during the physical test.
- The first operational discovery attempt logged the target issue signature,
  `AddressResolve_DefaultImpl.cpp:124: CHIP Error 0x00000032: Timeout`, before
  the subsequent CASE attempt and `CommissioningComplete` succeeded. A
  multi-iteration run is now ready to determine how often that transient timeout
  becomes the terminal issue #37075 failure.

An earlier infrastructure-valid run completed pairing and cleanup but was marked
failed only because an empty `analytics_parameters: {}` mapping triggers a
matter-qa `TestConfig` fallback bug. The configuration now uses valid
`current_heap_used` and `reboot_count` analytics entries.

## Packet capture and decryption

- Matter message decryption is enabled by the fixed test session keys in both
  the controller and DUT builds.
- Thread IEEE 802.15.4 decryption additionally requires the active Thread
  network key/dataset.
- Initially keep optional matter-qa captures disabled to avoid sudo/capture
  setup affecting the commissioning smoke test.
- After the smoke test, enable the desired controller capture flags and capture
  the OTBR/RCP-side Thread traffic. Preserve the active dataset alongside the
  captures.

## Next stress step

Increase `number_of_iterations` in `37075/matter-qa-nordic.yaml`, then rerun
`TC_Darwin_Pair.py`. Keep the passing smoke artifacts unchanged as the baseline
and use a new log directory and controller storage file for each stress
campaign.
