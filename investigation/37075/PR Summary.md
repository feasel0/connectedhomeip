## Current Dispositions: 2026-10-16

The four-PR narrative below is historical scope, not a declaration that all
remaining failures are fixed. **ADDRESSED** means a matching fix exists in a
PR, not necessarily merged or fully hardware-validated.

| Original Finding / Goal | Current Disposition |
| --- | --- |
| Stale sessions, partial fabric/subscription cleanup and masked primary errors | **ADDRESSED** by [QA527](https://github.com/CHIP-Specifications/matter-qa/pull/527); 52 regressions. Primary native timeouts remain open. |
| Inconsistent Thread topology / late generic discovery timeout | **PARTIALLY ADDRESSED** by [QA528](https://github.com/CHIP-Specifications/matter-qa/pull/528) opt-in detection. Healthy SRP/OMR/publication and the original missing CASE response are not guaranteed. |
| Dataset persistence and reuse across managed runtime recreation | **PARTIALLY ADDRESSED** by backend385; the [fresh review](PR385_PR386_FRESH_REVIEW_20261007.md) retains four open reuse/redaction/validation findings on the unchanged head. |
| Unique defaults for independent projects | **PARTIALLY ADDRESSED** by backend386; normal UI creation still bypasses generation, an **OPEN** finding on the unchanged head. |

See the [current PR index](All%20PRs%20for%2037075.md) for later readiness,
Valve, comparison, callback, reset-stage and scanner fixes. Use the
[log catalog](LOG_CATALOG.md#current-dispositions-2026-10-16) and
[follow-up failure dispositions](PR539_FAILURE_ANALYSIS_20261011.md#current-failure-dispositions)
as the remaining-work list. Historical failures and test counts are unchanged.

---

Fixing **four different ways our stress environment could produce misleading or
intermittent BLE-Thread commissioning failures**. Two are in `matter-qa` and
make the test itself safer and more diagnostic; two are in
`certification-tool-backend` and make the Thread network that the test runs
against stable and isolated.

## Summary version

| PR                                                                       | One-line explanation                                                                                                                                                                                                      |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **matter-qa #527 — failure-safe cleanup**                                | Fixes the stress test so that if an iteration fails halfway through, it still cleans up all Matter fabrics, CASE sessions, BLE state, and subscriptions instead of leaving stale state that can break the next iteration. |
| **matter-qa #528 — Thread topology validation**                          | Makes the test verify that the Thread dataset it is giving the DUT actually matches the intended OTBR, and adds diagnostics to detect when the DUT joins the wrong Thread network.                                        |
| **certification-tool-backend #385 — persist complete Thread dataset**    | Fixes backend restart/reuse behavior so that when we reuse an already-commissioned DUT/controller, we also recreate the **exact same Thread network**, instead of accidentally creating a slightly different one.         |
| **certification-tool-backend #386 — unique Thread defaults per project** | Stops every new test project from starting with the same default Thread credentials, reducing the chance that one DUT can accidentally join a neighboring fixture’s Thread network.                                       |

A slightly more concise version would be:

> We found that the stress failures were not all one bug. One PR fixes stale
> Matter session cleanup between iterations, one detects when the DUT attaches
> to the wrong Thread network, one makes Thread network state survive backend
> restarts consistently with reused commissioner state, and one gives separate
> test projects unique Thread credentials so neighboring fixtures are less
> likely to interfere with each other.

---

# The big picture: how BLE-Thread commissioning works here

The easiest mental model is that there are **two networks involved at different
times**.

First, the controller talks to the DUT over **BLE**. That is the temporary
commissioning connection. Over that BLE connection, the controller tells the DUT
what Thread network to join.

The controller gives the DUT a **Thread Operational Dataset**. That dataset is
essentially the Thread network's configuration and credentials.

The DUT then leaves the purely-BLE phase and joins the Thread network.

Once it is on Thread, it needs to advertise its new Matter identity onto the IP
network. The OTBR provides the connection between the Thread mesh and the rest
of the IP network. The DUT normally uses **SRP** to register its Matter service,
which eventually becomes discoverable through DNS-SD/mDNS.

The controller then says, effectively:

> “I commissioned Matter node X. Now find node X on the operational IP network.”

It discovers the DUT, establishes a **CASE** secure session over IP, and sends
operational Matter commands such as `CommissioningComplete`.

So the high-level path is:

```text
Controller
   |
   | BLE / PASE
   v
DUT receives Thread dataset
   |
   v
DUT joins Thread network
   |
   v
DUT gets usable IP connectivity
   |
   v
DUT publishes Matter operational service through SRP/DNS-SD
   |
   v
Controller discovers DUT
   |
   v
CASE secure session
   |
   v
CommissioningComplete / other Matter commands
```

Our historical failures occurred at several different points in that chain.

That is why simply saying "`CommissioningComplete` timed out" turned out to be
misleading.

---

# PR #527 — Failure-safe cleanup in `matter-qa`

## Summary

> If an iteration fails after partially commissioning the DUT, this PR makes
> sure we tear down **all of the state we already created** before the next
> iteration starts.

This fixes a real failure mode where a later iteration could accidentally reuse
a CASE session and IP address belonging to the **previous incarnation of the
DUT**.

## What was wrong

`TC_Darwin_Pair` performs commissioning with two controllers/fabrics.

A simplified version looks like:

```text
Controller 1:
    BLE/PASE
    AddNOC
    operational CASE
    CommissioningComplete

Controller 2:
    AddNOC
    operational CASE
    CommissioningComplete

cleanup
factory reset
next stress iteration
```

The important operation here is `AddNOC`.

`AddNOC` installs a Matter fabric on the DUT. Once that succeeds, the controller
and DUT now have persistent relationship/state that needs to be cleaned up if
anything later fails.

Historically, though, the test did not fully register that controller/DUT
relationship for cleanup until **after `CommissioningComplete` succeeded**.

That creates a dangerous window:

```text
AddNOC succeeds
      |
      v
Matter fabric now exists
      |
      v
CommissioningComplete fails
      |
      v
cleanup does not know everything it needs to clean
```

There were additional cleanup weaknesses.

If cleanup of controller 1 threw an exception, cleanup could stop before
controller 2 was handled.

And the code effectively did:

```text
UnpairDevice()
ExpireSessions()
```

rather than:

```text
try:
    UnpairDevice()
finally:
    ExpireSessions()
```

So if `UnpairDevice()` itself timed out, the local CASE session could survive.

## What we actually saw

The February failure gave us very strong packet-level evidence.

The second controller reused a fixed Matter node identity from iteration to
iteration.

Instead of doing a fresh DNS-SD lookup and fresh CASE handshake, it found an
**existing CASE session**.

That session still pointed at an old IPv6 address belonging to the previous DUT
incarnation.

So the controller did essentially this:

```text
"I already have a secure session for node 0x12344322."

        ↓

send CommissioningComplete over old CASE session

        ↓

old IPv6 address

        ↓

current DUT is somewhere else

        ↓

retransmit, retransmit, retransmit

        ↓

CommandSender timeout
```

The DUT had been factory-reset and recommissioned, but the controller had stale
local state.

## What #527 changes

The conceptual change is:

> As soon as a resource exists, cleanup owns it.

So once `AddNOC` succeeds, that fabric/controller is immediately registered for
cleanup.

Cleanup then attempts **everything**, even when one part fails.

Session expiration happens even if unpairing fails.

Subscriptions and BLE connections are also tracked in a way that lets the
failure path close them.

The goal is that iteration N cannot poison iteration N+1.

## Summary

> #527 makes the stress loop failure-safe: once a fabric or session exists, we
> guarantee it gets a cleanup attempt even if commissioning dies halfway
> through, preventing stale CASE sessions from leaking into later iterations.

---

# PR #528 — Validate the intended Thread topology in `matter-qa`

## Summary

> Before commissioning, verify that the Thread dataset passed to the test
> actually matches the live intended OTBR; after the DUT joins, collect enough
> diagnostics to detect when it attached to the wrong Thread environment.

This is mostly a **detection and classification PR**, rather than silently
trying to fix network topology.

## What was wrong

Historically, matter-qa could be told:

```text
Here is the Thread dataset to commission with.
```

But it had no strong check that:

```text
controller dataset
        ==
live dataset on intended OTBR
```

That matters because the Thread Operational Dataset is the actual
identity/configuration of the Thread network.

A human may look at:

```text
channel = 15
PAN ID = 0x1234
name = OpenThreadGRL
```

and think that describes the network.

But a complete Thread Operational Dataset contains more than that.

It includes things such as:

```text
Network Key
Extended PAN ID
Mesh-Local Prefix
PSKc
Security Policy
timestamps
channel
PAN ID
Network Name
...
```

Two things can look similar in a configuration file while not actually
representing the same complete Thread network.

## The historical failure this helps diagnose

In October, the controller supplied the same dataset over several iterations.

But the DUT did not stay on the same resulting Thread environment.

The immediate sequence was striking:

```text
iteration 46  PASS -> Thread Cert 9.2 -> partition 0x7D35C043
iteration 47  FAIL -> GRL             -> partition 0x08472484
iteration 48  FAIL -> GRL             -> partition 0x7738DBB4
iteration 49  FAIL -> GRL             -> partition 0x2DF6DD12
iteration 50  FAIL -> GRL             -> partition 0x2DF6DD12
iteration 51  PASS -> Thread Cert 9.2 -> partition 0x7D35C043
```

The passes found the expected SRP infrastructure and successfully published the
Matter operational service.

The failures attached to other Thread environments, found no usable SRP/OMR
path, and logged:

```text
Operational advertising failed: 3
```

Then the controller tried to discover the DUT operationally and eventually hit:

```text
AddressResolve_DefaultImpl.cpp:124
CHIP Error 0x32: Timeout
```

So the timeout itself was just the last visible symptom.

The real sequence was closer to:

```text
DUT joins wrong Thread environment
        ↓
no intended SRP/border-routing path
        ↓
Matter operational service isn't published where controller expects
        ↓
controller cannot resolve DUT
        ↓
AddressResolve timeout
```

## What #528 adds

Before commissioning, if matter-qa can reach the intended OTBR, it reads:

```text
ot-ctl dataset active -x
```

and compares those exact bytes with the dataset supplied to the controller.

If they differ, the test can fail immediately with an
**infrastructure/configuration problem**, instead of waiting 45 seconds and
reporting what looks like a mysterious Matter timeout.

It also records safe diagnostics such as dataset fingerprints rather than
dumping secret dataset contents.

After `ConnectNetwork`, it attempts to read the DUT's Thread Network Diagnostics
information.

One especially useful field is the DUT's **Extended PAN ID**.

So now we can compare:

```text
Expected Thread Extended PAN ID
vs.
DUT actual Extended PAN ID
```

If they differ, that is a much stronger signal that the DUT is not on the
intended network.

## What it deliberately does not do

It does not assume that the **partition ID** must remain constant.

Partition ID is dynamic Thread topology state, not the fundamental Operational
Dataset identity.

It also doesn't automatically rewrite or repair the network.

The goal is:

> fail early and tell us exactly what is wrong.

## Summary

> #528 makes matter-qa verify the Thread network before commissioning and adds
> DUT-side topology diagnostics afterward, so a wrong-network attachment becomes
> an explicit infrastructure failure instead of surfacing 45 seconds later as a
> generic AddressResolve timeout.

---

# PR #385 — Persist the complete Thread network with commissioner state

## Summary

> If we reuse an already-commissioned DUT/controller after restarting OTBR, we
> must also recreate the **exact same Thread network**. This PR couples those
> two pieces of state.

This is probably the most important architectural backend fix.

## The underlying concept

Suppose you commission a DUT onto Thread network **A**.

You now have two important kinds of state.

On the controller side:

```text
admin_storage.json
```

contains Matter controller/fabric/session-related persistent state.

Separately, the DUT lives on a particular Thread network defined by a complete
Operational Dataset:

```text
Dataset A
```

If later we say:

> “Reuse previous commissioning”

then logically that should mean:

```text
reuse controller state A
+
reuse Thread network A
```

Historically, the backend could do something more like:

```text
reuse controller state A
+
create new Thread network B
```

That is the core problem #385 addresses.

## Why network B could be different even when the config looked the same

The backend formed a Thread network using this general pattern:

```text
dataset init new
dataset channel ...
dataset panid ...
dataset extpanid ...
dataset networkkey ...
dataset networkname ...
dataset commit active
```

The important detail is:

```text
dataset init new
```

creates a **complete** random dataset first.

The backend then overwrote only some fields.

Other generated fields—such as the Mesh-Local Prefix—could remain different.

So two executions could have identical:

```text
channel
PAN ID
Extended PAN ID
Network Key
Network Name
```

while still having different complete Operational Datasets.

Conceptually:

```text
Run 1:
Visible fields = X
Hidden/generated fields = A
Complete dataset = X+A

Run 2:
Visible fields = X
Hidden/generated fields = B
Complete dataset = X+B
```

The backend already had a historical reproduction of this general problem:
recreate OTBR, reuse old commissioning state, and operational discovery fails.

## What #385 does

It treats these as one logical reusable bundle:

```text
admin_storage.json
+
complete Thread Active Dataset
```

For a brand-new network, it can still generate one normally.

But after formation it reads the real canonical value:

```text
ot-ctl dataset active -x
```

and persists those complete bytes.

Then, when reusing commissioning state, it restores that exact dataset rather
than saying:

```text
dataset init new
```

and hoping it becomes equivalent.

Conceptually:

```text
Initial run
───────────
generate network
     ↓
read complete Dataset A
     ↓
commission DUT
     ↓
persist:
    controller state A
    Dataset A


Reuse
─────
load controller state A
load Dataset A
     ↓
recreate OTBR using exact Dataset A
     ↓
verify live OTBR == Dataset A
     ↓
talk to already-commissioned DUT
```

## Why the persistence code became somewhat elaborate

Because we didn't want this:

```text
old good controller state
+
half-written new dataset
```

or:

```text
new controller state
+
old dataset
```

If one file updates and the other fails, the saved bundle becomes internally
inconsistent.

So #385 stages the new state and promotes the pair carefully.

It also tracks whether reusable state was actually successfully established.

A failed commissioning attempt must not turn into apparently valid reusable
state during cleanup.

## Summary

> #385 fixes a lifecycle mismatch in the backend: previously we could reuse old
> Matter commissioner state while generating a new Thread network. Now the
> controller state and exact complete Thread dataset are persisted and restored
> together.

---

# PR #386 — Unique Thread credentials for new projects

## Summary

> Stop creating every new test project with the same default Thread credentials,
> so neighboring test cells are not automatically compatible with each other's
> Thread networks.

This complements #385 but solves a different problem.

## What was wrong

The backend had a default project config containing values like:

```text
PAN ID:          0x1234
Extended PAN ID: 1111111122222222
Network Key:     00112233445566778899aabbccddeeff
Network Name:    DEMO
```

If you created Project A without specifying your own configuration, it got those
values.

If you created Project B without specifying config, it got the **same values**.

Likewise Project C, D, etc.

So separate labs or fixtures could end up using common Thread credentials.

That is bad in an RF-visible test environment.

You really want something more like:

```text
Fixture A -> credential set A
Fixture B -> credential set B
Fixture C -> credential set C
```

rather than:

```text
Fixture A ─┐
Fixture B ─┼─ same credential set
Fixture C ─┘
```

## Why that matters

Thread networking isn't simply:

> “join the network whose human-readable name matches.”

Cryptographic credentials matter.

If multiple nearby Thread environments are credential-compatible, a DUT can
potentially authenticate into infrastructure other than the one the test
operator thinks it is using.

That is very close to the class of environment we suspect from the October
evidence.

## What #386 does

When the user creates a new Project **without explicit configuration**, the
backend now generates fresh values.

It uses cryptographically secure randomness for:

```text
Network Key       128 bits
Extended PAN ID    64 bits
PAN ID             random valid value
Network Name       TH-<random suffix>
```

Those values are generated **once**, when the Project is created.

Then they live in:

```text
Project.config
```

They do not change on every test run.

That's important.

Randomizing them every run would create instability rather than isolation.

## What it does not change

If somebody explicitly supplies a Thread configuration, we preserve it.

If they import/export a Project, the config remains the same.

Existing Projects are not silently modified.

So #386 changes:

```text
"Give me a new project using defaults"
```

but not:

```text
"Use exactly this Thread configuration."
```

## Relationship to #385

They solve different dimensions.

Think of #386 as **horizontal isolation**:

```text
Test cell A != Test cell B
```

Think of #385 as **temporal stability**:

```text
Test cell A today == Test cell A after OTBR restart
```

That is probably the single best way to explain why we needed both PRs.

## Summary

> #386 gives each new default project its own random Thread identity, so
> independent RF-visible fixtures don't all start with the same credentials.
> #385 keeps one fixture stable over time; #386 keeps different fixtures
> distinct from each other.

---

# How all four fit together

This is the mental model I would keep.

```text
                         STRESS TEST RELIABILITY
                                  |
             ┌────────────────────┴────────────────────┐
             |                                         |
       Matter lifecycle                         Thread topology
             |                                         |
          #527                                      #528
   clean stale sessions                     detect wrong network
                                                       |
                                    ┌──────────────────┴──────────────────┐
                                    |                                     |
                                  #385                                  #386
                         same fixture stays same              different fixtures differ
                         across restart/reuse                 from one another
```

Or in plain English:

**#527:** Don't carry stale Matter state into the next iteration.

**#528:** Detect when the DUT isn't on the network we intended.

**#385:** If we restart the intended network, recreate the same network exactly.

**#386:** Don't give all the independent intended networks the same default
credentials.

---

# Terminology primer

| Term                          | Plain-English meaning                                                                                                                                           |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DUT**                       | Device Under Test. The Matter device we're commissioning.                                                                                                       |
| **Controller / Commissioner** | The software on the test machine that commissions and controls the DUT.                                                                                         |
| **BLE**                       | Bluetooth Low Energy. Used here as the temporary transport for initial commissioning.                                                                           |
| **PASE**                      | Passcode-Authenticated Session Establishment. The temporary secure session created using the Matter setup code during initial commissioning.                    |
| **Thread**                    | Low-power IPv6 mesh network used by many Matter devices.                                                                                                        |
| **OTBR**                      | OpenThread Border Router. Bridges the Thread mesh to the normal IP network.                                                                                     |
| **RCP**                       | Radio Co-Processor. In our setup, the nRF52840 dongle that provides the 802.15.4 radio used by OTBR.                                                            |
| **Operational Dataset**       | The complete configuration/credential package that defines a Thread network.                                                                                    |
| **Active Dataset**            | The Operational Dataset currently active on a Thread network. `ot-ctl dataset active -x` gives its encoded TLVs.                                                |
| **Network Key**               | Secret key used to authenticate/encrypt Thread network traffic.                                                                                                 |
| **Extended PAN ID**           | 64-bit Thread network identifier. More significant than the short 16-bit PAN ID, but still not equivalent to the whole dataset.                                 |
| **PAN ID**                    | 16-bit IEEE 802.15.4 network identifier. It can collide and is not sufficient to define a Thread network.                                                       |
| **Mesh-Local Prefix**         | IPv6 prefix used for Thread mesh-local addressing. One of the fields that `dataset init new` can generate.                                                      |
| **Partition**                 | A currently connected Thread topology sharing a leader. Partition ID is dynamic runtime state, not the permanent identity of the Operational Dataset.           |
| **SRP**                       | Service Registration Protocol. A Thread device uses it to register DNS-SD services through the Thread infrastructure.                                           |
| **DNS-SD**                    | DNS Service Discovery. How the controller discovers the Matter service advertised by the DUT.                                                                   |
| **Operational advertisement** | DUT publishing its Matter operational identity/service after commissioning.                                                                                     |
| **OMR**                       | Off-Mesh-Routable prefix. Gives Thread devices IPv6 addresses reachable through the Border Router from the infrastructure network.                              |
| **Fabric**                    | A Matter trust domain: controllers and devices sharing credentials/identity relationships. A device can belong to multiple fabrics.                             |
| **NOC**                       | Node Operational Certificate. Matter certificate identifying a node on a fabric.                                                                                |
| **AddNOC**                    | Command that installs the new Matter operational certificate/fabric on the DUT. This is an important persistence boundary.                                      |
| **CASE**                      | Certificate Authenticated Session Establishment. The normal secure Matter session used after commissioning, over IP.                                            |
| **CommissioningComplete**     | Matter command saying commissioning is finished. In Darwin Pair it is the first operational CASE command after first-fabric commissioning.                      |
| **AddressResolve timeout**    | Controller could not discover a usable operational network address for the Matter node before timeout. Usually a symptom, not necessarily the underlying cause. |
| **CommandSender timeout**     | Controller had enough information/session state to send a Matter command, but no usable response completed.                                                     |
| **`admin_storage.json`**      | Persistent state used by the Python Matter controller. It contains commissioner/fabric/session-related state needed when reusing commissioning.                 |
| **`dataset init new`**        | OpenThread CLI command that generates a new complete Operational Dataset. Important because fields you didn't explicitly overwrite can differ each time.        |
| **`dataset active -x`**       | OpenThread CLI command that returns the actual complete Active Operational Dataset as encoded hexadecimal TLVs.                                                 |

---

## The one-minute version I'd memorize

> We found that issue #37075 was grouping several different timeout failures
> together. One failure mode was stale Matter state leaking between stress
> iterations, so PR #527 makes cleanup failure-safe. Another was the DUT ending
> up on the wrong Thread infrastructure, so #528 validates the intended OTBR
> dataset and adds topology diagnostics. On the backend side, #385 makes reused
> commissioner state and the exact Thread network persist together across OTBR
> restarts, while #386 gives separate new projects unique Thread credentials so
> neighboring fixtures aren't all compatible by default. In short: clean up
> state, detect the right network, preserve one network across restarts, and
> isolate different networks from each other.
