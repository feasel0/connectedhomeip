i plugged the nRF52840 dev kit board into this ubuntu laptop. to one of the
laptop's usb ports. on the board itself i plugged into the small usb connector
that's along its short edge (not the similar usb connector that's located along
its long edge). the "power" switch is set to "VOD". the switch that says "nRF"
is set to "Default" instead of "Only". turned the board's power switch on. there
are no jumpers on any of the pins that i'm aware of. let me know if this is the
right state for things. it is powered on ansd i see a solid LED1 and a mostly
solid (tho occasionally flickering) LED5.

if that is the right state, you shoudl find how to communicate with this board
and then flash it with what is needed to use it as a DUT.

aadditionally i want you to figure out how to run a stress test using the test
harness in the matter-qa repository. there is a checkout of the matter-qa
repository in ~/qa-mar6/matter-qa which i want you to change to the main branch
and bring that main branch up to date with the lastest version from the remote
(the original latest version, not my out-of-date fork's latest version).

then i want you to figure out exactly what is needed to run a ble-thread stress
test using an ubuntu laptop as the controller and a nrf board as the DUT. they
have seveal test cases that we could run, so i'd like you to tell me what test
cases we have as options, and what things we need to set in which config files
in order to do this stress test.
