#
#    Copyright (c) 2024 Project CHIP Authors
#    All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#

# See https://github.com/project-chip/connectedhomeip/blob/master/docs/testing/python.md#defining-the-ci-test-arguments
# for details about the block below.
#
# === BEGIN CI TEST ARGUMENTS ===
# test-runner-runs:
#   run1:
#     app: examples/fabric-admin/scripts/fabric-sync-app.py
#     app-args: --app-admin=${FABRIC_ADMIN_APP} --app-bridge=${FABRIC_BRIDGE_APP} --discriminator=1234
#     app-ready-pattern: "Successfully opened pairing window on the device"
#     app-stdin-pipe: dut-fsa-stdin
#     script-args: >
#       --PICS src/app/tests/suites/certification/ci-pics-values
#       --storage-path admin_storage.json
#       --commissioning-method on-network
#       --discriminator 1234
#       --passcode 20202021
#       --endpoint 1
#       --string-arg th_server_app_path:${ALL_CLUSTERS_APP}
#       --trace-to json:${TRACE_TEST_JSON}.json
#       --trace-to perfetto:${TRACE_TEST_PERFETTO}.perfetto
#     factory-reset: true
#     quiet: true
#   run2:
#     app: ${FABRIC_SYNC_APP}
#     app-args: --discriminator=1234
#     app-stdin-pipe: dut-fsa-stdin
#     script-args: >
#       --PICS src/app/tests/suites/certification/ci-pics-values
#       --storage-path admin_storage.json
#       --commissioning-method on-network
#       --discriminator 1234
#       --passcode 20202021
#       --endpoint 1
#       --string-arg th_server_app_path:${ALL_CLUSTERS_APP}
#       --trace-to json:${TRACE_TEST_JSON}.json
#       --trace-to perfetto:${TRACE_TEST_PERFETTO}.perfetto
#     factory-reset: true
#     quiet: true
# === END CI TEST ARGUMENTS ===

# This test requires a TH_SERVER application. Please specify with --string-arg th_server_app_path:<path_to_app>

import logging
import os
import random
import tempfile
import time

import chip.clusters as Clusters
from chip import ChipDeviceCtrl
from chip.interaction_model import InteractionModelError, Status
from chip.testing.apps import AppServerSubprocess
from chip.testing.matter_testing import (MatterBaseTest, TestStep, async_test_body, default_matter_test_main, has_cluster,
                                         run_if_endpoint_matches)
from mobly import asserts


class TC_CCTRL_2_3(MatterBaseTest):

    @async_test_body
    async def setup_class(self):
        super().setup_class()

        self.th_server = None
        self.storage = None

        th_server_app = self.user_params.get("th_server_app_path", None)
        if not th_server_app:
            asserts.fail("This test requires a TH_SERVER app. Specify app path with --string-arg th_server_app_path:<path_to_app>")
        if not os.path.exists(th_server_app):
            asserts.fail(f"The path {th_server_app} does not exist")

        # Create a temporary storage directory for keeping KVS files.
        self.storage = tempfile.TemporaryDirectory(prefix=self.__class__.__name__)
        logging.info("Temporary storage directory: %s", self.storage.name)

        self.th_server_port = 5543
        self.th_server_discriminator = random.randint(0, 4095)
        self.th_server_passcode = 20202021

        # Start the TH_SERVER app.
        self.th_server = AppServerSubprocess(
            th_server_app,
            storage_dir=self.storage.name,
            port=self.th_server_port,
            discriminator=self.th_server_discriminator,
            passcode=self.th_server_passcode)
        self.th_server.start(
            expected_output="Server initialization complete",
            timeout=30)

        logging.info("Commissioning from separate fabric")

        # Create a second controller on a new fabric to communicate to the server
        new_certificate_authority = self.certificate_authority_manager.NewCertificateAuthority()
        new_fabric_admin = new_certificate_authority.NewFabricAdmin(vendorId=0xFFF1, fabricId=2)
        paa_path = str(self.matter_test_config.paa_trust_store_path)
        self.TH_server_controller = new_fabric_admin.NewController(nodeId=112233, paaTrustStorePath=paa_path)
        self.server_nodeid = 1111
        await self.TH_server_controller.CommissionOnNetwork(
            nodeId=self.server_nodeid,
            setupPinCode=self.th_server_passcode,
            filterType=ChipDeviceCtrl.DiscoveryFilterType.LONG_DISCRIMINATOR,
            filter=self.th_server_discriminator)
        logging.info("Commissioning TH_SERVER complete")

    def teardown_class(self):
        if self.th_server is not None:
            self.th_server.terminate()
        if self.storage is not None:
            self.storage.cleanup()
        super().teardown_class()

    def steps_TC_CCTRL_2_3(self) -> list[TestStep]:
        steps = [TestStep(1, "Get number of fabrics from TH_SERVER", is_commissioning=True),
                 TestStep(2, "Reading Attribute VendorId from TH_SERVER"),
                 TestStep(3, "Reading Attribute ProductId from TH_SERVER"),
                 TestStep(4, "Send RequestCommissioningApproval command to DUT with CASE session with correct VendorId and ProductId"),
                 TestStep(5, "(Manual Step) Approve Commissioning Approval Request on DUT using method indicated by the manufacturer"),
                 TestStep(6, "Reading Event CommissioningRequestResult from DUT, confirm one new event"),
                 TestStep(7, "Send another RequestCommissioningApproval command to DUT with CASE session with same RequestId as the previous one"),
                 TestStep(8, "Send CommissionNode command to DUT with CASE session, with valid parameters"),
                 TestStep(9, "Send another CommissionNode command to DUT with CASE session, with with same RequestId as the previous one"),
                 TestStep(10, "Send OpenCommissioningWindow command on Administrator Commissioning Cluster sent to TH_SERVER"),
                 TestStep(11, "Get number of fabrics from TH_SERVER, verify DUT successfully commissioned TH_SERVER (up to 30 seconds)")]

        return steps

    # This test has some manual steps and one sleep for up to 30 seconds. Test typically
    # runs under 1 mins, so 3 minutes is more than enough.
    @property
    def default_timeout(self) -> int:
        return 3*60

    @run_if_endpoint_matches(has_cluster(Clusters.CommissionerControl))
    async def test_TC_CCTRL_2_3(self):

        self.step(1)
        th_server_fabrics = await self.read_single_attribute_check_success(cluster=Clusters.OperationalCredentials, attribute=Clusters.OperationalCredentials.Attributes.Fabrics, dev_ctrl=self.TH_server_controller, node_id=self.server_nodeid, endpoint=0, fabric_filtered=False)

        self.step(2)
        th_server_vid = await self.read_single_attribute_check_success(cluster=Clusters.BasicInformation, attribute=Clusters.BasicInformation.Attributes.VendorID, dev_ctrl=self.TH_server_controller, node_id=self.server_nodeid, endpoint=0)

        self.step(3)
        th_server_pid = await self.read_single_attribute_check_success(cluster=Clusters.BasicInformation, attribute=Clusters.BasicInformation.Attributes.ProductID, dev_ctrl=self.TH_server_controller, node_id=self.server_nodeid, endpoint=0)

        self.step(4)
        good_request_id = 0x1234567812345678
        cmd = Clusters.CommissionerControl.Commands.RequestCommissioningApproval(
            requestID=good_request_id, vendorID=th_server_vid, productID=th_server_pid, label="Test Ecosystem")
        await self.send_single_cmd(cmd=cmd)

        self.step(5)
        if not self.is_pics_sdk_ci_only:
            self.wait_for_user_input("Approve Commissioning approval request using manufacturer specified mechanism")

        self.step(6)
        event_path = [(self.matter_test_config.endpoint, Clusters.CommissionerControl.Events.CommissioningRequestResult, 1)]
        events = await self.default_controller.ReadEvent(nodeid=self.dut_node_id, events=event_path)
        asserts.assert_equal(len(events), 1, "Unexpected event list len")
        asserts.assert_equal(events[0].Data.statusCode, 0, "Unexpected status code")
        asserts.assert_equal(events[0].Data.clientNodeID,
                             self.matter_test_config.controller_node_id, "Unexpected client node id")
        asserts.assert_equal(events[0].Data.requestID, good_request_id, "Unexpected request ID")

        self.step(7)
        cmd = Clusters.CommissionerControl.Commands.RequestCommissioningApproval(
            requestID=good_request_id, vendorID=th_server_vid, productID=th_server_pid)
        try:
            await self.send_single_cmd(cmd=cmd)
            asserts.fail("Unexpected success on CommissionNode")
        except InteractionModelError as e:
            asserts.assert_equal(e.status, Status.Failure, "Incorrect error returned")

        self.step(8)
        cmd = Clusters.CommissionerControl.Commands.CommissionNode(requestID=good_request_id, responseTimeoutSeconds=30)
        resp = await self.send_single_cmd(cmd)
        asserts.assert_equal(type(resp), Clusters.CommissionerControl.Commands.ReverseOpenCommissioningWindow,
                             "Incorrect response type")

        self.step(9)
        cmd = Clusters.CommissionerControl.Commands.CommissionNode(requestID=good_request_id, responseTimeoutSeconds=30)
        try:
            await self.send_single_cmd(cmd=cmd)
            asserts.fail("Unexpected success on CommissionNode")
        except InteractionModelError as e:
            asserts.assert_equal(e.status, Status.Failure, "Incorrect error returned")

        self.step(10)
        # min commissioning timeout is 3*60 seconds, so use that even though the command said 30.
        cmd = Clusters.AdministratorCommissioning.Commands.OpenCommissioningWindow(commissioningTimeout=3*60,
                                                                                   PAKEPasscodeVerifier=resp.PAKEPasscodeVerifier,
                                                                                   discriminator=resp.discriminator,
                                                                                   iterations=resp.iterations, salt=resp.salt)
        await self.send_single_cmd(cmd, dev_ctrl=self.TH_server_controller, node_id=self.server_nodeid, endpoint=0, timedRequestTimeoutMs=5000)

        self.step(11)
        max_wait_time_sec = 30
        start_time = time.time()
        elapsed = 0
        time_remaining = max_wait_time_sec
        previous_number_th_server_fabrics = len(th_server_fabrics)

        th_server_fabrics_new = None
        while time_remaining > 0:
            time.sleep(2)
            th_server_fabrics_new = await self.read_single_attribute_check_success(cluster=Clusters.OperationalCredentials, attribute=Clusters.OperationalCredentials.Attributes.Fabrics, dev_ctrl=self.TH_server_controller, node_id=self.server_nodeid, endpoint=0, fabric_filtered=False)
            if previous_number_th_server_fabrics != len(th_server_fabrics_new):
                break
            elapsed = time.time() - start_time
            time_remaining = max_wait_time_sec - elapsed

        asserts.assert_not_equal(th_server_fabrics_new, None, "Failed to read Fabrics attribute")
        asserts.assert_equal(previous_number_th_server_fabrics + 1, len(th_server_fabrics_new),
                             "Unexpected number of fabrics on TH_SERVER")


if __name__ == "__main__":
    default_matter_test_main()
