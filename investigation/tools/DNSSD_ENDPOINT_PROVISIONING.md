# Endpoint IP Capture Provisioning Request

Prepared 2026-10-21 UTC. **Administrator installation required; not executed.**
This extends the existing approved helper, not its caller privilege surface.
The two private bundles are already staged through identity-verified SSH at
`/home/feasel/lab-mdns-admin-20261021/` on their respective Pis. Their originals
and SHA256 manifests are under
`/home/feasel/qa-mar6/dnssd-provisioning-20261021/` on Ubuntu. Personal helper
source is private and is not copied into this repository.

## Exact Changes

The [policy document](dnssd-endpoint-profiles.json) has complete host-specific
configurations. Use only the configuration matching the machine ID:

| Host | Machine ID | New Profile | Interfaces |
| --- | --- | --- | --- |
| DUT | fa898f2a8e5c487489c516aaa233f86a | dut-mdns | wlan0 |
| Controller | ef72df43fba94793ab724dc3013cec17 | controller-mdns | eth0, wlan0 |

Fresh routes select DUT wlan0 for IPv4/IPv6 mDNS, controller eth0 for IPv4
and wlan0 for IPv6. Capturing both controller interfaces avoids guessing
which eligible interface receives the original response. Preserve pcapng
interface IDs; routing output alone is not proof of packet ingress.

- Both Pis: install distribution `wireshark-common` and `libcap2-bin`;
  grant only the existing helper's normal-user dumpcap execution mechanism.
- DUT: install the reviewed existing helper, unit, bounded sudoers rule and
  protected state directories, with only the dut-mdns profile.
- Controller: preserve installed helper, sudoers, state, existing runs and
  controller-hci policy. Add controller-mdns and a unit drop-in adding CAP_KILL
  to its existing capability set. The original Pi HCI-only unit omitted it;
  its root worker otherwise cannot reliably signal the normal-user dumpcap.
- No helper worker, command-line argument, capture framework, packet filter,
  Bluetooth restart, network configuration or recovery permission is added.
  IP profiles have hci_index=null and recovery_unit=null.

The current installer hardcodes thread-lab/controller-hci and refuses a
different existing policy. **Do not rerun it to overwrite these policies.**
These are explicit administrator-reviewed deployment steps using its existing
source, unit and sudoers conventions. No new NOPASSWD script is introduced.

## Administrator Steps

Perform directly on each verified Pi in an administrator terminal. Do not
route a password through chat, a script or `sudo -S`. Review the staged
manifest and source before copying; reject changed inputs. Keep all existing
capture units inactive and confirm no unrelated dumpcap/btmon/tcpdump owner.
The following commands are requests, not commands the agent has executed.

Both hosts, after verifying the matching machine ID and reviewing the bundle:
Record existing dumpcap ownership/mode/capabilities and operator membership
before any package/permission change; retain them with the administrator log.
Use the same administrator shell for these blocks; each stops on failure.

```sh
set -eu
BUNDLE=/home/feasel/lab-mdns-admin-20261021
python3 -I -c 'import json,hashlib,pathlib; p=pathlib.Path("/home/feasel/lab-mdns-admin-20261021"); m=json.loads((p/"manifest.private.json").read_text()); assert all(hashlib.sha256((p/n).read_bytes()).hexdigest()==v for n,v in m.items()); assert json.loads((p/"lab-resource-helper.json").read_text())["machine_id"]==pathlib.Path("/etc/machine-id").read_text().strip()'
sudo /usr/bin/apt-get install --no-install-recommends wireshark-common libcap2-bin
sudo /usr/sbin/groupadd -f wireshark
sudo /usr/sbin/usermod -a -G wireshark feasel
sudo /usr/bin/chown root:wireshark /usr/bin/dumpcap
sudo /usr/bin/chmod 0750 /usr/bin/dumpcap
sudo /usr/sbin/setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
```

DUT only, with the DUT identity above and no pre-existing helper installation:

```sh
set -eu
test "$(cat /etc/machine-id)" = fa898f2a8e5c487489c516aaa233f86a
for path in /usr/local/sbin/lab-resource-helper /etc/lab-resource-helper.json /etc/systemd/system/lab-resource-capture@.service /etc/sudoers.d/lab-resource-helper; do test ! -e "$path"; done
sudo /usr/sbin/visudo -cf "$BUNDLE/lab-resource-helper.sudoers"
sudo /usr/bin/install -d -o root -g feasel -m 0750 /var/lib/lab-resource-helper /var/lib/lab-resource-helper/runs
sudo /usr/bin/install -o root -g root -m 0755 "$BUNDLE/lab-resource-helper" /usr/local/sbin/lab-resource-helper
sudo /usr/bin/install -o root -g root -m 0644 "$BUNDLE/lab-resource-capture@.service" /etc/systemd/system/lab-resource-capture@.service
sudo /usr/bin/install -o root -g root -m 0644 "$BUNDLE/lab-resource-helper.json" /etc/lab-resource-helper.json
sudo /usr/bin/install -o root -g root -m 0440 "$BUNDLE/lab-resource-helper.sudoers" /etc/sudoers.d/lab-resource-helper
sudo /usr/sbin/visudo -c
```

Controller only: first retain an administrator-owned timestamped backup of
the current policy and any existing unit drop-ins; do not overwrite a backup.
The exact current controller-hci entry is preserved in the proposed JSON.

```sh
set -eu
test "$(cat /etc/machine-id)" = ef72df43fba94793ab724dc3013cec17
python3 -I -c 'import json,pathlib; c=json.loads(pathlib.Path("/etc/lab-resource-helper.json").read_text()); assert c["operator"]=="feasel" and c["profiles"]=={"controller-hci":{"interfaces":[],"hci_index":0,"recovery_unit":"bluetooth.service"}}'
BACKUP=/var/lib/lab-resource-helper/mdns-policy-backup-$(date -u +%Y%m%dT%H%M%SZ)
sudo /usr/bin/install -d -o root -g root -m 0700 "$BACKUP"
sudo /usr/bin/cp -a /etc/lab-resource-helper.json "$BACKUP/"
if test -d /etc/systemd/system/lab-resource-capture@.service.d; then sudo /usr/bin/cp -a /etc/systemd/system/lab-resource-capture@.service.d "$BACKUP/unit-dropins"; fi
sudo /usr/bin/install -d -o root -g root -m 0755 /etc/systemd/system/lab-resource-capture@.service.d
sudo /usr/bin/install -o root -g root -m 0644 "$BUNDLE/10-endpoint-ip.conf" /etc/systemd/system/lab-resource-capture@.service.d/10-endpoint-ip.conf
sudo /usr/bin/install -o root -g root -m 0644 "$BUNDLE/lab-resource-helper.json" /etc/lab-resource-helper.json
```

Both hosts: validate the unit and reload:

```sh
set -eu
sudo /usr/bin/systemd-analyze verify /etc/systemd/system/lab-resource-capture@.service
sudo /usr/bin/systemctl daemon-reload
```

Check every installed file/parent is root-owned and not operator-writable,
verify the effective unit includes CAP_KILL and confirm disk reserve >=2 GiB.
On the DUT run `sudo -n /usr/local/sbin/lab-resource-helper verify dut-mdns`;
on the controller substitute `controller-mdns`. The helper verifies dumpcap
interface discovery as the actual operator, with current supplementary groups.
A capability listing, package installation or verify result alone is not a
live capture/closure proof. Do not expand sudoers beyond the existing helper.

Rollback only after owned captures are stopped and evidence sealed: restore
the saved controller policy/drop-ins and previous dumpcap permissions/caps;
remove only the newly installed DUT helper policy/unit/sudoers if required.
Preserve state/run evidence and never restart Bluetooth as a rollback shortcut.

## Live Acceptance Gate

Use fresh lowercase run IDs, e.g. `20261021-mdns-coverage-01`; never reuse a run.
The helper permits one capture worker per host, so do not start controller-hci
alongside controller-mdns. This DNS-specific experiment requires no BLE arm.

1. Start each fixed profile with `capture-start PROFILE RUN_ID`, then obtain
   `capture-status PROFILE RUN_ID`. Require active/running unit, capture state
   running, private packet file growth and correct interfaces on both hosts.
2. Generate a bounded normal-user ICMP positive control between the verified
   endpoints using the intended DUT wlan0 route. Verify the same request/reply
   in both captures, including interface IDs and endpoint addresses. The
   unfiltered existing ring retains this control. Do not infer coverage from
   file size or a cached hostname lookup.
3. Stop only those runs with `capture-stop PROFILE RUN_ID`; require final
   stopped state, null error, normal child exit and inactive unit. SIGKILL,
   unexpected exit, restart or missing final statistics is not clean closure.
4. Preserve capture.json, dumpcap.log and every rotated pcapng segment.
   Record packet/interface statistics and capture drops from dumpcap's final
   output and pcapng interface statistics, using `capinfos -I`/tshark where
   supported. Missing counters mean UNKNOWN, never zero. Link counters are
   not capture drops. Reconcile file/packet counts; no rotated segment may
   disappear before sealing. Retain a timestamped relative SHA256 manifest.

If either endpoint fails this gate, do not start the deciding observation.
No profile is installed or live-tested as of this request; provisioning is
an administrator action, not an agent authorization question.

## One Original-Resolution Observation

After the live gate passes, recheck identities, clocks/bounds, interface
addresses and fixture ownership. Start fresh endpoint captures before the
unchanged retained original app/resolver configuration. Invoke the original
operational resolver entry point once, within the existing native timeout;
do not run the BLE-first pair_dut comparison, commission again, modify CASE,
change advertisement parameters or add retries/timeouts. If a prerequisite
cannot be retained, report the experiment blocked rather than improvise it.

Correlate the original operational instance name, address family/interface,
SRV owner/target/port, DNS flags and records, UDP payload fingerprint and
capture timestamps across DUT egress and controller ingress. mDNS IDs may be
zero, so they are not a unique packet match. Account for multicast copies,
cache behavior, duplicates, routing and clock uncertainty. Use actual packet
source and interface evidence to establish egress, not an advertisement log.
Retain the native resolver receive/callback/result at the same operational
identity; packet ingress alone does not establish native resolver delivery.

The causal chain is configuration -> eligible endpoint -> emitted Matter SRV
-> matching controller ingress -> resolver receive/result. Mark the first
unobserved boundary explicitly; a configured void AdvertiseRecords call does
not establish transmission. Stop and seal captures even on failure. Run only
this one bounded observation after coverage, not another EATT arm. Historical
accounting stays 158 FAIL / 80 mapped / 78 OPEN until evidence supports a
separate, explicit mapping decision.
