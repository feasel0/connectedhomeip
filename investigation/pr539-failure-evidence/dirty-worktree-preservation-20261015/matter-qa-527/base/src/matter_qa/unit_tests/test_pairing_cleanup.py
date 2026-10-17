#
# Copyright (c) 2026 Project CHIP Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import ctypes
import gc
import subprocess
import unittest
from types import MethodType, SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call, patch

from matter import ChipDeviceCtrl

from matter_qa.library.base_test_classes.chip_python_controller_node import ChipPythonControllerNode
from matter_qa.library.base_test_classes.matter_qa_base_test_class import MatterQABaseTestCaseClass
from matter_qa.library.base_test_classes.test_results_record import TestResultEnums
from matter_qa.library.helper_libs.augmented_matter_test_base import AugmentedMatterTestBase
from matter_qa.library.helper_libs.exceptions import IterationError, TestCaseExit
from matter_qa.library.helper_libs.pairing_flow_functions import PairingFlowFunctions
from matter_qa.scripts.operational_scripts.TC_Android_Pair import TC_Android_Pair
from matter_qa.scripts.operational_scripts.TC_BDX_OTA import TC_BDX_OTA
from matter_qa.scripts.operational_scripts.TC_Bridge_Add_Remove import TC_Bridge_Add_Remove
from matter_qa.scripts.operational_scripts.TC_Send_Command_Read_Write_Attributes import TC_Send_Command_Read_Write_Attributes
from matter_qa.scripts.reliability_scripts.TC_RT_1_1 import TC_RT_1_1
from matter_qa.scripts.reliability_scripts.TC_RT_1_2 import TC_RT_1_2
from matter_qa.scripts.reliability_scripts.TC_RT_2_1 import TC_RT_2_1
from matter_qa.scripts.reliability_scripts.TC_RT_2_2 import TC_RT_2_2


class PrimaryTestFailure(Exception):
    pass


class PairingCleanupTest(unittest.IsolatedAsyncioTestCase):
    async def test_bdx_process_start_failure_closes_opened_log_and_keeps_primary(self):
        pairing_flow = self.make_bdx_flow()
        pairing_flow._start_provider = MethodType(TC_BDX_OTA._start_provider, pairing_flow)
        log_file = MagicMock()
        primary_error = PrimaryTestFailure("provider process failed to start")
        with patch("matter_qa.scripts.operational_scripts.TC_BDX_OTA.os.path.isdir", return_value=False), \
                patch("matter_qa.scripts.operational_scripts.TC_BDX_OTA.os.path.exists", return_value=False), \
                patch("builtins.open", return_value=log_file), \
                patch("matter_qa.scripts.operational_scripts.TC_BDX_OTA.subprocess.Popen", side_effect=primary_error):
            await self.run_bdx_flow(pairing_flow)
        log_file.close.assert_called_once()
        self.assertIsNone(pairing_flow.provider_log_file)
        self.assertEqual(pairing_flow.default_controller.ExpireSessions.call_args_list, [call(2), call(2)])
        pairing_flow._commission_provider.assert_not_awaited()
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=primary_error)

    async def test_bdx_commission_cleanup_failure_keeps_primary_and_stops_retrying(self):
        pairing_flow = self.make_bdx_flow()
        primary_error = PrimaryTestFailure("provider commissioning failed")
        pairing_flow.default_controller.CommissionOnNetwork = AsyncMock(side_effect=primary_error)
        pairing_flow.default_controller.ExpireSessions.side_effect = RuntimeError("expire failed")
        with self.assertRaises(IterationError) as raised:
            await TC_BDX_OTA._commission_provider(pairing_flow)
        self.assertIs(raised.exception.args[0], primary_error)
        pairing_flow.default_controller.CommissionOnNetwork.assert_awaited_once()
        pairing_flow.default_controller.CloseBLEConnection.assert_called_once()

    async def test_bridge_callback_failure_still_registers_subscription_for_shutdown(self):
        pairing_flow = self.make_bridge_flow()
        controller = MagicMock()
        pairing_flow.list_of_controller_objects = [(controller, 2)]
        subscription = MagicMock()
        primary_error = PrimaryTestFailure("callback failed")
        subscription.SetAttributeUpdateCallback.side_effect = primary_error
        pairing_flow.perform_bulk_subscription = AsyncMock(return_value=subscription)
        subscriptions = []
        with patch("matter_qa.scripts.operational_scripts.TC_Bridge_Add_Remove.AttributeUpdateHandler"):
            with self.assertRaises(PrimaryTestFailure) as raised:
                await TC_Bridge_Add_Remove.subscribe_attributes(pairing_flow, subscriptions)
        self.assertIs(raised.exception, primary_error)
        self.assertEqual(subscriptions, [subscription])
        pairing_flow.shutdown_subscriptions(subscriptions)
        subscription.Shutdown.assert_called_once()

    async def test_discovery_metrics_cleanup_failure_does_not_skip_network_rollback(self):
        pairing_flow = self.make_discovery_flow()
        primary_error = PrimaryTestFailure("metrics cleanup failed")
        pairing_flow._clear_case_metrics_target.side_effect = primary_error
        await self.run_discovery_flow(pairing_flow)
        pairing_flow.revert_dut_network_changes.assert_awaited_once()
        pairing_flow.cleaning_up_the_paired_controller.assert_awaited_once()
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=primary_error)

    def make_command_flow(self):
        pairing_flow = MagicMock()
        pairing_flow.test_config.general_configs.number_of_iterations = 1
        pairing_flow.dut_node_id = 1
        for name in ("perform_initial_commission_with_dut", "_build_writable_attributes_list",
                     "_initialize_test_case_specific_methods", "verify_attributes_read_write",
                     "send_command_to_dut", "fetch_analytics_from_dut"):
            setattr(pairing_flow, name, AsyncMock())
        pairing_flow.device_inspector.inspect_device_implementation = AsyncMock()
        return pairing_flow

    async def run_command_flow(self, pairing_flow):
        with patch.object(MatterQABaseTestCaseClass, "iterate_tc", side_effect=lambda **kwargs: lambda body: body):
            await TC_Send_Command_Read_Write_Attributes.test_TC_Send_Command_Read_Write_Attributes.__wrapped__(pairing_flow)

    async def test_command_reboot_failure_expires_sessions_and_keeps_primary(self):
        pairing_flow = self.make_command_flow()
        primary_error = PrimaryTestFailure("reboot failed after stopping app")
        pairing_flow.dut.reboot_dut.side_effect = primary_error
        pairing_flow.default_controller_node.raw_controller.ExpireSessions.side_effect = RuntimeError("expire failed")
        await self.run_command_flow(pairing_flow)
        pairing_flow.default_controller_node.raw_controller.ExpireSessions.assert_called_once_with(1)
        pairing_flow.unpair_dut.assert_not_called()
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=primary_error)

    async def test_command_success_expires_sessions_and_retains_fabric(self):
        pairing_flow = self.make_command_flow()
        await self.run_command_flow(pairing_flow)
        pairing_flow.default_controller_node.raw_controller.ExpireSessions.assert_called_once_with(1)
        pairing_flow.unpair_dut.assert_not_called()
        self.assertEqual(pairing_flow.iteration_test_result, TestResultEnums.TEST_RESULT_PASS)

    async def test_command_failure_before_reboot_does_not_expire_sessions(self):
        pairing_flow = self.make_command_flow()
        primary_error = PrimaryTestFailure("command failed")
        pairing_flow.send_command_to_dut.side_effect = primary_error
        await self.run_command_flow(pairing_flow)
        pairing_flow.dut.reboot_dut.assert_not_called()
        pairing_flow.default_controller_node.raw_controller.ExpireSessions.assert_not_called()
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=primary_error)

    async def test_command_expiration_failure_is_not_a_pass(self):
        pairing_flow = self.make_command_flow()
        cleanup_error = RuntimeError("expire failed")
        pairing_flow.default_controller_node.raw_controller.ExpireSessions.side_effect = cleanup_error
        await self.run_command_flow(pairing_flow)
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=cleanup_error)

    async def test_wrong_pin_unexpected_failure_preserved_when_cleanup_fails(self):
        pairing_flow = self.make_commissionable_flow()
        pairing_flow.matter_test_config.setup_passcodes = [20202021]
        pairing_flow.matter_test_config.discriminators = [3840]
        pairing_flow.default_controller.FindOrEstablishPASESession = AsyncMock(side_effect=RuntimeError("PASE failed"))
        pairing_flow.default_controller.ExpireSessions.side_effect = RuntimeError("expire failed")
        with self.assertRaises(IterationError) as raised:
            await TC_RT_2_1.make_pase_wrong_setup_pin(pairing_flow)
        self.assertIn("PASE failed", str(raised.exception))
        pairing_flow.default_controller.CloseBLEConnection.assert_called_once()
        pairing_flow.unpair_dut.assert_not_awaited()

    def make_bdx_flow(self):
        pairing_flow = MagicMock()
        pairing_flow.provider_node_id = 2
        pairing_flow.provider_process = None
        pairing_flow.provider_log_file = None
        pairing_flow.test_config.general_configs.number_of_iterations = 1
        pairing_flow.analytics_dict = {}
        pairing_flow.do_factory_reset_every_iteration.return_value = False
        pairing_flow.dut_max_mbs = 1024
        pairing_flow._select_mbs_for_iteration.return_value = 1024
        for name in ("perform_initial_commission_with_dut", "_read_version", "_verify_image", "_start_provider",
                     "_commission_provider", "_setup_acl", "_set_default_provider", "_trigger_ota", "_perform_ota",
                     "fetch_analytics_from_dut"):
            setattr(pairing_flow, name, AsyncMock())
        pairing_flow._close_provider_sessions = MethodType(TC_BDX_OTA._close_provider_sessions, pairing_flow)
        pairing_flow._stop_provider = MethodType(TC_BDX_OTA._stop_provider, pairing_flow)
        return pairing_flow

    async def run_bdx_flow(self, pairing_flow):
        with patch.object(MatterQABaseTestCaseClass, "iterate_tc", side_effect=lambda **kwargs: lambda body: body):
            await TC_BDX_OTA.test_TC_BDX_OTA.__wrapped__(pairing_flow)

    async def test_bdx_stop_closes_log_when_provider_never_started(self):
        pairing_flow = self.make_bdx_flow()
        log_file = MagicMock()
        pairing_flow.provider_log_file = log_file
        await pairing_flow._stop_provider()
        log_file.close.assert_called_once()
        pairing_flow.default_controller.ExpireSessions.assert_called_once_with(2)
        self.assertIsNone(pairing_flow.provider_log_file)

    async def test_bdx_expiration_failure_still_stops_process_and_closes_log(self):
        pairing_flow = self.make_bdx_flow()
        process = MagicMock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("provider", 5), None]
        log_file = MagicMock()
        pairing_flow.provider_process = process
        pairing_flow.provider_log_file = log_file
        cleanup_error = RuntimeError("expire failed")
        pairing_flow.default_controller.ExpireSessions.side_effect = cleanup_error
        with self.assertRaises(RuntimeError) as raised:
            await pairing_flow._stop_provider()
        self.assertIs(raised.exception, cleanup_error)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        log_file.close.assert_called_once()
        pairing_flow.default_controller.CloseBLEConnection.assert_called_once()
        self.assertIsNone(pairing_flow.provider_process)

    async def test_bdx_commission_retry_expires_sessions_before_retry(self):
        pairing_flow = self.make_bdx_flow()
        pairing_flow.default_controller.CommissionOnNetwork = AsyncMock(side_effect=[RuntimeError("timeout"), None])
        pairing_flow.default_controller.ReadAttribute = AsyncMock()
        with patch("matter_qa.scripts.operational_scripts.TC_BDX_OTA.async_delay_between_stress_test_operations", new=AsyncMock()):
            await TC_BDX_OTA._commission_provider(pairing_flow)
        self.assertEqual(pairing_flow.default_controller.CommissionOnNetwork.await_count, 2)
        pairing_flow.default_controller.ExpireSessions.assert_called_once_with(2)
        pairing_flow.default_controller.CloseBLEConnection.assert_called_once()

    async def test_bdx_iteration_preserves_primary_when_shutdown_fails(self):
        pairing_flow = self.make_bdx_flow()
        primary_error = PrimaryTestFailure("transfer failed")
        pairing_flow._perform_ota.side_effect = primary_error
        pairing_flow.default_controller.ExpireSessions.side_effect = RuntimeError("expire failed")
        await self.run_bdx_flow(pairing_flow)
        pairing_flow.default_controller.CloseBLEConnection.assert_called_once()
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=primary_error)

    async def test_bdx_shutdown_failure_is_not_recorded_as_pass(self):
        pairing_flow = self.make_bdx_flow()
        cleanup_error = RuntimeError("expire failed")
        pairing_flow.default_controller.ExpireSessions.side_effect = cleanup_error
        await self.run_bdx_flow(pairing_flow)
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=cleanup_error)

    def make_bridge_flow(self):
        pairing_flow = MagicMock()
        pairing_flow.test_config.general_configs.number_of_iterations = 1
        pairing_flow.analytics_dict = {}
        pairing_flow.list_of_paired_controllers = []
        pairing_flow.list_of_controller_objects = []
        for name in ("perform_initial_commission_with_dut", "read_subscription_interval_duration",
                     "create_list_of_controller_object", "_build_writable_attributes_list",
                     "update_controller_endpoints_mapping", "subscribe_attributes", "perform_bulk_write_attributes",
                     "fetch_analytics_from_dut"):
            setattr(pairing_flow, name, AsyncMock())
        pairing_flow.create_list_of_controller_object.return_value = []
        pairing_flow.dut.remove_bridge_devices = AsyncMock()
        pairing_flow.dut.add_bridge_devices = AsyncMock()
        pairing_flow.device_inspector.inspect_device_implementation = AsyncMock()
        pairing_flow.shutdown_subscriptions = MethodType(AugmentedMatterTestBase.shutdown_subscriptions, pairing_flow)
        return pairing_flow

    async def run_bridge_flow(self, pairing_flow):
        with patch.object(MatterQABaseTestCaseClass, "iterate_tc", side_effect=lambda **kwargs: lambda body: body):
            await TC_Bridge_Add_Remove.test_TC_Bridge_Add_Remove.__wrapped__(pairing_flow)

    async def test_bridge_success_closes_subscriptions_without_unpairing(self):
        pairing_flow = self.make_bridge_flow()
        subscription = MagicMock()
        pairing_flow.subscribe_attributes.side_effect = lambda subscriptions: subscriptions.append(subscription)
        await self.run_bridge_flow(pairing_flow)
        subscription.Shutdown.assert_called_once()
        pairing_flow.unpair_dut.assert_not_called()
        pairing_flow.update_iteration_result.assert_called_once_with(iteration_result=TestResultEnums.TEST_RESULT_PASS)

    async def test_bridge_partial_subscription_failure_preserves_primary_and_attempts_all_shutdowns(self):
        pairing_flow = self.make_bridge_flow()
        first_subscription = MagicMock()
        second_subscription = MagicMock()
        first_subscription.Shutdown.side_effect = RuntimeError("shutdown failed")
        primary_error = PrimaryTestFailure("second callback registration failed")

        async def subscribe(subscriptions):
            subscriptions.extend([first_subscription, second_subscription])
            raise primary_error

        pairing_flow.subscribe_attributes.side_effect = subscribe
        await self.run_bridge_flow(pairing_flow)
        first_subscription.Shutdown.assert_called_once()
        second_subscription.Shutdown.assert_called_once()
        pairing_flow.unpair_dut.assert_not_called()
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=primary_error)

    def test_shared_subscription_shutdown_retries_only_failed_work(self):
        first_subscription = MagicMock()
        second_subscription = MagicMock()
        first_subscription.Shutdown.side_effect = [RuntimeError("shutdown failed"), None]
        subscriptions = [first_subscription, second_subscription]
        with self.assertRaises(IterationError):
            AugmentedMatterTestBase.shutdown_subscriptions(MagicMock(), subscriptions)
        self.assertEqual(subscriptions, [first_subscription])
        AugmentedMatterTestBase.shutdown_subscriptions(MagicMock(), subscriptions)
        self.assertEqual(subscriptions, [])
        self.assertEqual(first_subscription.Shutdown.call_count, 2)
        second_subscription.Shutdown.assert_called_once()

    def make_commissionable_flow(self):
        pairing_flow = MagicMock()
        pairing_flow.test_config.general_configs.number_of_iterations = 1
        pairing_flow.dut_node_id = 1
        pairing_flow.node_id = 1
        pairing_flow.close_session = MethodType(PairingFlowFunctions.close_session, pairing_flow)
        pairing_flow._cleanup_discovery_state = MethodType(TC_RT_2_1._cleanup_discovery_state, pairing_flow)
        for name in ("perform_commissionable_discovery", "pair_dut", "unpair_dut",
                     "commissioning_fail_during_pase_session", "make_pase_wrong_setup_pin",
                     "factory_rest_during_commissioning"):
            setattr(pairing_flow, name, AsyncMock(return_value=True))
        return pairing_flow

    async def run_commissionable_flow(self, pairing_flow):
        with patch.object(MatterQABaseTestCaseClass, "iterate_tc", side_effect=lambda **kwargs: lambda body: body):
            await TC_RT_2_1.test_TC_RT_2_1.__wrapped__(pairing_flow)

    def test_commissionable_cleanup_clears_native_callback_pointers(self):
        callback_pointers = {}

        def register_callback(name):
            def register(delegate, callback):
                callback_pointers[name] = ctypes.cast(callback, ctypes.c_void_p).value
            return register

        controller = SimpleNamespace(
            pairingDelegate=None,
            _dmLib=SimpleNamespace(
                pychip_ScriptDevicePairingDelegate_SetCommissioningStageStartCallback=register_callback("stage_start"),
                pychip_ScriptDevicePairingDelegate_SetCommissioningStatusUpdateCallback=register_callback("status_update")))
        for name in ("setCommissioningStageStartCallback", "setCommissioningStatusUpdateCallback"):
            setattr(controller, name, MethodType(getattr(ChipDeviceCtrl.ChipDeviceController, name), controller))
        pairing_flow = SimpleNamespace(
            default_controller=controller, node_id=1, close_session=lambda **kwargs: None)

        for cleanup_attempt in range(2):
            with self.subTest(cleanup_attempt=cleanup_attempt):
                TC_RT_2_1._cleanup_discovery_state(pairing_flow)
                gc.collect()
                self.assertEqual(callback_pointers, {"stage_start": None, "status_update": None})

    async def test_commissionable_discovery_failure_keeps_primary_and_resets_callbacks(self):
        pairing_flow = self.make_commissionable_flow()
        primary_error = PrimaryTestFailure("discovery failed")
        pairing_flow.perform_commissionable_discovery.side_effect = primary_error
        pairing_flow.default_controller.ExpireSessions.side_effect = RuntimeError("expire failed")
        await self.run_commissionable_flow(pairing_flow)
        pairing_flow.default_controller.CloseBLEConnection.assert_called_once()
        pairing_flow.default_controller.setCommissioningStageStartCallback.assert_called_once()
        pairing_flow.default_controller.setCommissioningStatusUpdateCallback.assert_called_once()
        pairing_flow.unpair_dut.assert_not_awaited()
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=primary_error)

    async def test_commissionable_cleanup_failure_is_not_a_pass(self):
        pairing_flow = self.make_commissionable_flow()
        cleanup_error = RuntimeError("callback reset failed")
        pairing_flow.default_controller.setCommissioningStageStartCallback.side_effect = cleanup_error
        await self.run_commissionable_flow(pairing_flow)
        pairing_flow.default_controller.setCommissioningStatusUpdateCallback.assert_called_once()
        pairing_flow.unpair_dut.assert_awaited_once()
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=cleanup_error)

    async def test_factory_reset_unexpected_failure_resets_callbacks_before_return(self):
        pairing_flow = self.make_commissionable_flow()
        primary_error = PrimaryTestFailure("commissioning failed before target")
        pairing_flow.pair_dut.side_effect = primary_error
        with patch("matter_qa.scripts.reliability_scripts.TC_RT_2_1.random.choice", side_effect=[0, MagicMock()]):
            with self.assertRaises(IterationError) as raised:
                await TC_RT_2_1.factory_rest_during_commissioning(pairing_flow)
        self.assertIs(raised.exception.args[0], primary_error)
        self.assertEqual(pairing_flow.default_controller.setCommissioningStageStartCallback.call_count, 2)
        pairing_flow.default_controller.setCommissioningStatusUpdateCallback.assert_called_once()
        pairing_flow.default_controller.CloseBLEConnection.assert_called_once()

    async def test_factory_reset_expected_failure_still_allows_recovery_pairing(self):
        pairing_flow = self.make_commissionable_flow()

        async def pair(**kwargs):
            pairing_flow.commissioning_target_stage_seen = True
            return False if pairing_flow.pair_dut.await_count == 1 else True

        pairing_flow.pair_dut.side_effect = pair
        with patch("matter_qa.scripts.reliability_scripts.TC_RT_2_1.random.choice", side_effect=[1, MagicMock()]):
            await TC_RT_2_1.factory_rest_during_commissioning(pairing_flow)
        self.assertEqual(pairing_flow.pair_dut.await_count, 2)
        self.assertEqual(pairing_flow.default_controller.setCommissioningStatusUpdateCallback.call_count, 2)
        pairing_flow.default_controller.CloseBLEConnection.assert_called_once()
        pairing_flow.unpair_dut.assert_not_awaited()

    def make_discovery_flow(self):
        pairing_flow = MagicMock()
        pairing_flow.test_config.general_configs.number_of_iterations = 1
        pairing_flow.matter_test_config.commissioning_method = "wifi"
        pairing_flow.connected_to_primary_network = True
        pairing_flow.list_of_paired_controllers = [(MagicMock(), 2)]
        pairing_flow.set_of_paired_dut_instances = set()
        for name in ("perform_initial_commission_with_dut", "create_list_of_controller_object",
                     "pair_controllers_with_dut", "expire_all_sessions_on_controller", "query_operational_mdns_service",
                     "reconfigure_network", "mdns_near_mtu_query_flood", "revoke_all_case_sessions_re_establish",
                     "fetch_analytics_from_dut", "revert_dut_network_changes", "cleaning_up_the_paired_controller",
                     "openCommissioningWindow", "pair_controller_with_dut", "close_commissioning_window",
                     "_await_case_metrics_capture"):
            setattr(pairing_flow, name, AsyncMock())
        return pairing_flow

    async def run_discovery_flow(self, pairing_flow):
        with patch.object(MatterQABaseTestCaseClass, "iterate_tc", side_effect=lambda **kwargs: lambda body: body), \
                patch("matter_qa.scripts.reliability_scripts.TC_RT_2_2.case_capture.AddCASEHandshakeListener"), \
                patch("matter_qa.scripts.reliability_scripts.TC_RT_2_2.case_capture.RemoveCASEHandshakeListener") as remove_listener:
            try:
                await TC_RT_2_2.test_TC_RT_2_2.__wrapped__(pairing_flow)
            finally:
                remove_listener.assert_called_once()

    async def test_discovery_registers_partial_pairing_and_preserves_failure(self):
        pairing_flow = self.make_discovery_flow()
        controller = MagicMock()
        pairing_flow.list_of_controller_objects = [(controller, 2)]
        primary_error = PrimaryTestFailure("partial pairing failed")
        pairing_flow.pair_controller_with_dut.side_effect = primary_error
        pairing_flow.close_commissioning_window.side_effect = RuntimeError("window close failed")
        with self.assertRaises(PrimaryTestFailure) as raised:
            await TC_RT_2_2.pair_controllers_with_dut(pairing_flow)
        self.assertIs(raised.exception, primary_error)
        self.assertEqual(pairing_flow.list_of_paired_controllers, [(controller, 2)])
        self.assertEqual(pairing_flow.set_of_paired_dut_instances, set())

    async def test_discovery_partial_pairing_cleans_without_paired_instance(self):
        pairing_flow = self.make_discovery_flow()
        cleanup_work = list(pairing_flow.list_of_paired_controllers)
        primary_error = PrimaryTestFailure("partial pairing failed")
        pairing_flow.pair_controllers_with_dut.side_effect = primary_error
        await self.run_discovery_flow(pairing_flow)
        pairing_flow.cleaning_up_the_paired_controller.assert_awaited_once_with(cleanup_work, [])
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=primary_error)

    async def test_discovery_network_failure_and_rollback_failure_still_clean_controllers(self):
        pairing_flow = self.make_discovery_flow()
        cleanup_work = list(pairing_flow.list_of_paired_controllers)
        primary_error = PrimaryTestFailure("network update failed halfway")
        pairing_flow.reconfigure_network.side_effect = primary_error
        pairing_flow.revert_dut_network_changes.side_effect = TestCaseExit("rollback failed")
        with self.assertRaises(TestCaseExit):
            await self.run_discovery_flow(pairing_flow)
        pairing_flow.revert_dut_network_changes.assert_awaited_once()
        pairing_flow.cleaning_up_the_paired_controller.assert_awaited_once_with(cleanup_work, [])
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=primary_error)
        pairing_flow.mark_iteration_failure_sync_mobly_and_summary_data.assert_not_called()
        self.assertEqual(pairing_flow.list_of_paired_controllers, [])

    async def test_discovery_cleanup_failure_is_not_recorded_as_pass(self):
        pairing_flow = self.make_discovery_flow()
        cleanup_error = TestCaseExit("cleanup failed")
        pairing_flow.cleaning_up_the_paired_controller.side_effect = cleanup_error
        with self.assertRaises(TestCaseExit):
            await self.run_discovery_flow(pairing_flow)
        pairing_flow.revert_dut_network_changes.assert_awaited_once()
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=cleanup_error)

    def make_multi_admin_flow(self):
        pairing_flow = MagicMock()
        pairing_flow.test_config.general_configs.number_of_iterations = 1
        pairing_flow.analytics_dict = {}
        pairing_flow.enable_diag_log_capture = True
        controller = MagicMock()
        pairing_flow.list_of_controller_objects = [(controller, 2)]
        for name in ("perform_initial_commission_with_dut", "read_subscription_interval_duration",
                     "create_list_of_controller_object", "update_controller_endpoints_mapping",
                     "_build_writable_attributes_list", "openCommissioningWindow", "pair_controller_with_dut",
                     "_await_case_metrics_capture", "perform_bulk_subscription", "perform_bulk_write_attributes",
                     "check_subscription_report", "perform_concurrent_operations", "retrieve_multiple_diagnostic_logs",
                     "cleaning_up_the_paired_controller", "fetch_analytics_from_dut"):
            setattr(pairing_flow, name, AsyncMock())
        pairing_flow.create_list_of_controller_object.return_value = [(controller, 2)]
        pairing_flow.device_inspector.inspect_device_implementation = AsyncMock()
        return pairing_flow, controller

    async def run_multi_admin_flow(self, pairing_flow):
        with patch.object(MatterQABaseTestCaseClass, "iterate_tc", side_effect=lambda **kwargs: lambda body: body), \
                patch("matter_qa.scripts.reliability_scripts.TC_RT_1_2.case_capture.AddCASEHandshakeListener"), \
                patch("matter_qa.scripts.reliability_scripts.TC_RT_1_2.case_capture.RemoveCASEHandshakeListener") as remove_listener:
            try:
                await TC_RT_1_2.test_TC_RT_1_2.__wrapped__(pairing_flow)
            finally:
                remove_listener.assert_called_once()

    async def test_multi_admin_partial_pairing_is_owned_before_pairing_returns(self):
        pairing_flow, controller = self.make_multi_admin_flow()
        primary_error = PrimaryTestFailure("partial commissioning failed")
        pairing_flow.pair_controller_with_dut.side_effect = primary_error
        await self.run_multi_admin_flow(pairing_flow)
        pairing_flow.cleaning_up_the_paired_controller.assert_awaited_once_with([(controller, 2)], [])
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=primary_error)

    async def test_multi_admin_diagnostics_and_cleanup_preserve_primary_failure(self):
        pairing_flow, controller = self.make_multi_admin_flow()
        primary_error = PrimaryTestFailure("metrics failed")
        pairing_flow._await_case_metrics_capture.side_effect = primary_error
        pairing_flow.retrieve_multiple_diagnostic_logs.side_effect = RuntimeError("diagnostics failed")
        pairing_flow.cleaning_up_the_paired_controller.side_effect = TestCaseExit("cleanup failed")
        with self.assertRaises(TestCaseExit):
            await self.run_multi_admin_flow(pairing_flow)
        pairing_flow.cleaning_up_the_paired_controller.assert_awaited_once_with([(controller, 2)], [])
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=primary_error)
        pairing_flow.mark_iteration_failure_sync_mobly_and_summary_data.assert_not_called()

    async def test_multi_admin_diagnostics_failure_still_cleans_subscription(self):
        pairing_flow, controller = self.make_multi_admin_flow()
        primary_error = PrimaryTestFailure("diagnostics failed")
        subscription = MagicMock()
        pairing_flow.perform_bulk_subscription.return_value = subscription
        pairing_flow.retrieve_multiple_diagnostic_logs.side_effect = primary_error
        with patch("matter_qa.scripts.reliability_scripts.TC_RT_1_2.AttributeUpdateHandler"):
            await self.run_multi_admin_flow(pairing_flow)
        pairing_flow.cleaning_up_the_paired_controller.assert_awaited_once_with([(controller, 2)], [subscription])
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=primary_error)

    async def test_multi_admin_cleanup_attempts_all_resources_after_failures(self):
        pairing_flow = MagicMock()
        pairing_flow.analytics_dict = {}
        pairing_flow.shutdown_subscriptions = MethodType(AugmentedMatterTestBase.shutdown_subscriptions, pairing_flow)
        pairing_flow.unpair_dut = AsyncMock(side_effect=[RuntimeError("unpair timed out"), True])
        first_controller = MagicMock()
        second_controller = MagicMock()
        first_controller.ExpireSessions.side_effect = RuntimeError("expiration failed")
        first_subscription = MagicMock()
        second_subscription = MagicMock()
        first_subscription.Shutdown.side_effect = RuntimeError("shutdown failed")
        subscriptions = [first_subscription, second_subscription]

        with self.assertRaises(TestCaseExit):
            await AugmentedMatterTestBase.cleaning_up_the_paired_controller(
                pairing_flow, [(first_controller, 1), (second_controller, 2)], subscriptions)

        self.assertEqual(pairing_flow.unpair_dut.await_args_list,
                         [call(controller=first_controller, node_id=1), call(controller=second_controller, node_id=2)])
        for controller, node_id in ((first_controller, 1), (second_controller, 2)):
            controller.ExpireSessions.assert_called_once_with(node_id)
            controller.CloseBLEConnection.assert_called_once_with()
        second_subscription.Shutdown.assert_called_once_with()
        self.assertEqual(subscriptions, [first_subscription])

    def make_pairing_flow(self):
        pairing_flow = object.__new__(PairingFlowFunctions)
        pairing_flow.list_of_commissioned_controller = []
        pairing_flow.list_of_active_subscriptions = []
        pairing_flow.use_test_event_trigger_factory_reset = False
        pairing_flow.unpair_dut = AsyncMock(return_value=True)
        pairing_flow.send_addnoc_command = AsyncMock(return_value=None)
        pairing_flow.send_commissioningcomplete_command = AsyncMock(return_value=None)
        return pairing_flow

    async def test_unpair_failure_still_expires_sessions(self):
        unpair_error = RuntimeError("unpair timed out")
        raw_controller = MagicMock()
        raw_controller.UnpairDevice = AsyncMock(side_effect=unpair_error)
        controller = ChipPythonControllerNode(raw_controller)

        with self.assertRaises(RuntimeError) as raised:
            await controller.unpair_device(node_id=1)

        self.assertIs(raised.exception, unpair_error)
        raw_controller.ExpireSessions.assert_called_once_with(1)

    def test_close_session_attempts_ble_when_session_expiration_fails(self):
        pairing_flow = MagicMock()
        controller = MagicMock()
        controller.ExpireSessions.side_effect = RuntimeError("session expiration failed")
        pairing_flow.th1 = controller
        pairing_flow.dut_node_id = 1

        with self.assertRaises(IterationError):
            PairingFlowFunctions.close_session(pairing_flow, admin=controller, node_id=1)

        controller.ExpireSessions.assert_called_once_with(1)
        controller.CloseBLEConnection.assert_called_once_with()

    async def test_first_cleanup_failure_does_not_skip_second_or_new_work(self):
        pairing_flow = self.make_pairing_flow()
        th1 = MagicMock()
        th2 = MagicMock()
        th3 = MagicMock()
        pairing_flow.list_of_commissioned_controller = [(th1, 1), (th2, 2)]

        async def unpair(controller, node_id):
            if controller is th1:
                pairing_flow.list_of_commissioned_controller.append((th3, 3))
                raise RuntimeError("TH1 cleanup failed")
            return True

        pairing_flow.unpair_dut = AsyncMock(side_effect=unpair)

        with self.assertRaises(TestCaseExit):
            await pairing_flow.cleanup_and_unpair_sessions()

        self.assertEqual(pairing_flow.unpair_dut.await_args_list,
                         [call(controller=th1, node_id=1), call(controller=th2, node_id=2)])
        th1.CloseBLEConnection.assert_called_once_with()
        th2.CloseBLEConnection.assert_called_once_with()
        self.assertEqual(pairing_flow.list_of_commissioned_controller, [(th1, 1), (th3, 3)])

    async def test_first_fabric_is_cleaned_when_commissioning_complete_fails(self):
        pairing_flow = self.make_pairing_flow()
        th1 = MagicMock()
        primary_error = PrimaryTestFailure("TH1 CommissioningComplete failed")
        pairing_flow.send_commissioningcomplete_command.side_effect = primary_error

        with self.assertRaises(IterationError) as raised:
            async with pairing_flow.CaseSession(pairing_flow, failure_handler=pairing_flow.cleanup_and_unpair_sessions):
                await pairing_flow.send_addnoc_and_register_cleanup(
                    controller=th1, node_id=1, chainForAddNOC=MagicMock(), admin_nodeId=11)
                await pairing_flow.send_commissioningcomplete_command()

        self.assertIs(raised.exception.args[0], primary_error)
        pairing_flow.unpair_dut.assert_awaited_once_with(controller=th1, node_id=1)
        th1.CloseBLEConnection.assert_called_once_with()

    async def test_second_fabric_is_cleaned_when_commissioning_complete_fails(self):
        pairing_flow = self.make_pairing_flow()
        th1 = MagicMock()
        th2 = MagicMock()
        pairing_flow.list_of_commissioned_controller.append((th1, 1))
        primary_error = PrimaryTestFailure("TH2 CommissioningComplete failed")
        pairing_flow.send_commissioningcomplete_command.side_effect = primary_error

        with self.assertRaises(IterationError) as raised:
            async with pairing_flow.CaseSession(pairing_flow, failure_handler=pairing_flow.cleanup_and_unpair_sessions):
                await pairing_flow.send_addnoc_and_register_cleanup(
                    controller=th2, node_id=2, chainForAddNOC=MagicMock(), admin_nodeId=22)
                await pairing_flow.send_commissioningcomplete_command()

        self.assertIs(raised.exception.args[0], primary_error)
        self.assertEqual(pairing_flow.unpair_dut.await_args_list,
                         [call(controller=th1, node_id=1), call(controller=th2, node_id=2)])
        th1.CloseBLEConnection.assert_called_once_with()
        th2.CloseBLEConnection.assert_called_once_with()

    async def test_failed_addnoc_is_not_registered_for_cleanup(self):
        pairing_flow = self.make_pairing_flow()
        controller = MagicMock()
        addnoc_error = IterationError("AddNOC failed")
        pairing_flow.send_addnoc_command.side_effect = addnoc_error

        with self.assertRaises(IterationError) as raised:
            await pairing_flow.send_addnoc_and_register_cleanup(
                controller=controller, node_id=1, chainForAddNOC=MagicMock(), admin_nodeId=11)

        self.assertIs(raised.exception, addnoc_error)
        self.assertEqual(pairing_flow.list_of_commissioned_controller, [])

    async def test_subscription_is_shut_down_on_failed_iteration(self):
        pairing_flow = self.make_pairing_flow()
        subscription = MagicMock()
        pairing_flow.register_subscription(subscription)

        with self.assertRaises(IterationError):
            async with pairing_flow.CaseSession(pairing_flow, failure_handler=pairing_flow.cleanup_and_unpair_sessions):
                raise PrimaryTestFailure("operation after subscribe failed")

        subscription.Shutdown.assert_called_once_with()
        self.assertEqual(pairing_flow.list_of_active_subscriptions, [])

    def test_failed_subscription_shutdown_remains_registered_for_retry(self):
        pairing_flow = self.make_pairing_flow()
        first_subscription = MagicMock()
        second_subscription = MagicMock()
        first_subscription.Shutdown.side_effect = [RuntimeError("shutdown failed"), None]
        pairing_flow.register_subscription(first_subscription)
        pairing_flow.register_subscription(second_subscription)

        with self.assertRaises(IterationError):
            pairing_flow.subscription_cleanup()

        first_subscription.Shutdown.assert_called_once_with()
        second_subscription.Shutdown.assert_called_once_with()
        self.assertEqual(len(pairing_flow.list_of_active_subscriptions), 1)
        self.assertIs(pairing_flow.list_of_active_subscriptions[0], first_subscription)

        pairing_flow.subscription_cleanup()

        self.assertEqual(first_subscription.Shutdown.call_count, 2)
        second_subscription.Shutdown.assert_called_once_with()
        self.assertEqual(pairing_flow.list_of_active_subscriptions, [])

    async def test_primary_failure_is_preserved_when_cleanup_also_fails(self):
        pairing_flow = self.make_pairing_flow()
        th1 = MagicMock()
        pairing_flow.list_of_commissioned_controller.append((th1, 1))
        pairing_flow.unpair_dut.side_effect = RuntimeError("cleanup failed")
        primary_error = PrimaryTestFailure("commissioning failed")

        with self.assertRaises(TestCaseExit) as raised:
            async with pairing_flow.CaseSession(pairing_flow, failure_handler=pairing_flow.cleanup_and_unpair_sessions):
                raise primary_error

        self.assertIs(raised.exception.args[0], primary_error)
        pairing_flow.unpair_dut.assert_awaited_once_with(controller=th1, node_id=1)
        th1.CloseBLEConnection.assert_called_once_with()

    async def test_pase_primary_failure_is_preserved_when_teardown_fails(self):
        pairing_flow = self.make_pairing_flow()
        pairing_flow.establish_pasesession = AsyncMock(return_value=True)
        pairing_flow.close_session = MagicMock(side_effect=RuntimeError("PASE cleanup failed"))
        failure_handler = AsyncMock(side_effect=RuntimeError("fabric cleanup failed"))
        primary_error = PrimaryTestFailure("PASE operation failed")

        with self.assertRaises(TestCaseExit) as raised:
            async with pairing_flow.PaseSession(pairing_flow, failure_handler=failure_handler):
                raise primary_error

        self.assertIs(raised.exception.args[0], primary_error)
        failure_handler.assert_awaited_once_with()

    def make_android_flow(self):
        pairing_flow = MagicMock()
        pairing_flow.th1 = MagicMock()
        pairing_flow.dut_node_id = 1
        pairing_flow.analytics_dict = {}
        pairing_flow.list_of_commissioned_controller = []
        pairing_flow.list_of_active_subscriptions = []
        pairing_flow.use_test_event_trigger_factory_reset = False
        pairing_flow.do_factory_reset_every_iteration.return_value = False
        pairing_flow.PaseSession = PairingFlowFunctions.PaseSession
        pairing_flow.CaseSession = PairingFlowFunctions.CaseSession
        for name in (
                "establish_pasesession", "generate_and_update_default_node_id", "read_serverlist_attribute",
                "read_network_commissiong_featuremap_attribute", "send_armfailsafe_command", "read_vendorid_attribute",
                "read_productid_attribute", "read_commissionedfabrics_attribute", "read_supportedFabrics_attribute",
                "read_fabric_attribute", "send_certificatechainrequest_command", "read_locationcapability_attribute",
                "send_setregulatoryconfig_command", "connect_network", "send_attestationrequest_command",
                "send_csrequest_command", "send_addtrustedrootcertificate_command", "send_addnoc_command",
                "read_windowstatus_attribute", "read_serialnumber_attribute", "wildcard_read",
                "send_commissioningcomplete_command", "send_subscriberequest", "send_settimezone_command",
                "send_setdefaultntp_command", "write_defaultotaproviders_attribute", "send_announceotaprovider_command",
                "send_setdstoffset_command", "fetch_analytics_from_dut", "unpair_dut"):
            setattr(pairing_flow, name, AsyncMock())
        for name in ("send_addnoc_and_register_cleanup", "cleanup_and_unpair_sessions", "register_subscription",
                     "subscription_cleanup"):
            setattr(pairing_flow, name, MethodType(getattr(PairingFlowFunctions, name), pairing_flow))
        return pairing_flow

    async def run_android_flow(self, pairing_flow):
        with patch.object(MatterQABaseTestCaseClass, "iterate_tc", side_effect=lambda **kwargs: lambda body: body):
            await TC_Android_Pair.test_TC_Android_Pair.__wrapped__(pairing_flow)

    async def test_android_failure_before_commissioning_complete_cleans_installed_fabric(self):
        pairing_flow = self.make_android_flow()
        primary_error = PrimaryTestFailure("read before CommissioningComplete failed")
        pairing_flow.read_windowstatus_attribute.side_effect = primary_error

        with self.assertRaises(IterationError) as raised:
            await self.run_android_flow(pairing_flow)

        self.assertIs(raised.exception.args[0], primary_error)
        pairing_flow.send_commissioningcomplete_command.assert_not_awaited()
        pairing_flow.unpair_dut.assert_awaited_once_with(controller=pairing_flow.th1, node_id=1)
        pairing_flow.th1.CloseBLEConnection.assert_called_once_with()
        self.assertEqual(pairing_flow.list_of_commissioned_controller, [])

    async def test_android_failure_after_subscription_shuts_it_down(self):
        pairing_flow = self.make_android_flow()
        subscription = MagicMock()
        pairing_flow.send_subscriberequest.return_value = subscription
        primary_error = PrimaryTestFailure("operation after subscribe failed")
        pairing_flow.send_settimezone_command.side_effect = primary_error

        with self.assertRaises(IterationError) as raised:
            await self.run_android_flow(pairing_flow)

        self.assertIs(raised.exception.args[0], primary_error)
        subscription.Shutdown.assert_called_once_with()
        pairing_flow.unpair_dut.assert_awaited_once_with(controller=pairing_flow.th1, node_id=1)
        self.assertEqual(pairing_flow.list_of_active_subscriptions, [])

    async def test_android_pase_teardown_failure_cleans_installed_fabric(self):
        pairing_flow = self.make_android_flow()
        primary_error = PrimaryTestFailure("PASE teardown failed")
        pairing_flow.close_session.side_effect = primary_error

        with self.assertRaises(TestCaseExit) as raised:
            await self.run_android_flow(pairing_flow)

        self.assertIs(raised.exception.args[0], primary_error)
        pairing_flow.read_windowstatus_attribute.assert_not_awaited()
        pairing_flow.unpair_dut.assert_awaited_once_with(controller=pairing_flow.th1, node_id=1)

    async def test_android_success_cleans_fabric_and_subscription_once(self):
        pairing_flow = self.make_android_flow()
        subscription = MagicMock()
        pairing_flow.send_subscriberequest.return_value = subscription

        await self.run_android_flow(pairing_flow)

        pairing_flow.send_addnoc_command.assert_awaited_once()
        pairing_flow.unpair_dut.assert_awaited_once_with(controller=pairing_flow.th1, node_id=1)
        subscription.Shutdown.assert_called_once_with()
        self.assertEqual(pairing_flow.list_of_commissioned_controller, [])
        self.assertEqual(pairing_flow.list_of_active_subscriptions, [])
        pairing_flow.update_iteration_result.assert_called_once_with(iteration_result=TestResultEnums.TEST_RESULT_PASS)

    async def test_android_primary_failure_survives_unpair_failure(self):
        pairing_flow = self.make_android_flow()
        primary_error = PrimaryTestFailure("read before CommissioningComplete failed")
        pairing_flow.read_windowstatus_attribute.side_effect = primary_error
        pairing_flow.unpair_dut.side_effect = RuntimeError("unpair timed out")

        with self.assertRaises(TestCaseExit) as raised:
            await self.run_android_flow(pairing_flow)

        self.assertIs(raised.exception.args[0], primary_error)
        pairing_flow.th1.CloseBLEConnection.assert_called_once_with()
        self.assertEqual(pairing_flow.list_of_commissioned_controller, [(pairing_flow.th1, 1)])

    def make_rt_flow(self, controller_type="chip-python"):
        pairing_flow = MagicMock()
        pairing_flow.test_config = SimpleNamespace(
            general_configs=SimpleNamespace(number_of_iterations=1, platform_execution="test"), current_iteration=1)
        pairing_flow.dut_node_id = 1
        pairing_flow.analytics_dict = {}
        pairing_flow.ecosystem_controller = None if controller_type == "chip-python" else MagicMock()
        pairing_flow.use_test_event_trigger_factory_reset = False
        pairing_flow.do_factory_reset_every_iteration.return_value = False
        pairing_flow.active_controller.controller_type = controller_type
        pairing_flow.pair_dut = AsyncMock(return_value=True)
        pairing_flow.fetch_analytics_from_dut = AsyncMock()
        pairing_flow.unpair_dut = AsyncMock(return_value=True)
        pairing_flow._cleanup_pairing_iteration = MethodType(TC_RT_1_1._cleanup_pairing_iteration, pairing_flow)
        return pairing_flow

    async def run_rt_flow(self, pairing_flow):
        with patch.object(MatterQABaseTestCaseClass, "iterate_tc", side_effect=lambda **kwargs: lambda body: body), \
                patch("matter_qa.scripts.reliability_scripts.TC_RT_1_1.case_capture.AddCASEHandshakeListener"), \
                patch("matter_qa.scripts.reliability_scripts.TC_RT_1_1.case_capture.RemoveCASEHandshakeListener") as remove_listener:
            try:
                await TC_RT_1_1.test_TC_RT_1_1.__wrapped__(pairing_flow)
            finally:
                remove_listener.assert_called_once()

    async def test_rt_partial_pairing_failure_still_unpairs_and_closes_sessions(self):
        pairing_flow = self.make_rt_flow()
        primary_error = PrimaryTestFailure("pairing failed after AddNOC")

        async def fail_pairing(**kwargs):
            pairing_flow.dut_node_id = 2
            raise primary_error

        pairing_flow.pair_dut.side_effect = fail_pairing
        await self.run_rt_flow(pairing_flow)

        pairing_flow.unpair_dut.assert_awaited_once_with(
            controller=pairing_flow.active_controller, accessory_name="Test_Matter_Accessory_test_1")
        pairing_flow.active_controller.raw_controller.ExpireSessions.assert_not_called()
        pairing_flow.active_controller.raw_controller.CloseBLEConnection.assert_called_once_with()
        pairing_flow.update_iteration_result.assert_called_once_with(
            iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=primary_error)

    async def test_rt_unsuccessful_pairing_result_still_cleans_partial_state(self):
        pairing_flow = self.make_rt_flow()
        primary_error = PrimaryTestFailure("commissioning returned failure")
        pairing_status = MagicMock()
        pairing_status.__bool__.return_value = False
        pairing_status.exception = primary_error
        pairing_flow.pair_dut.return_value = pairing_status

        await self.run_rt_flow(pairing_flow)

        pairing_flow.unpair_dut.assert_awaited_once()
        pairing_flow.active_controller.raw_controller.ExpireSessions.assert_not_called()
        pairing_flow.active_controller.raw_controller.CloseBLEConnection.assert_called_once_with()
        result_call = pairing_flow.update_iteration_result.call_args
        self.assertEqual(result_call.kwargs["iteration_result"], TestResultEnums.TEST_RESULT_FAIL)
        self.assertIs(result_call.kwargs["execption"].args[0], primary_error)

    async def test_rt_analytics_failure_keeps_primary_error_when_unpair_also_fails(self):
        pairing_flow = self.make_rt_flow()
        primary_error = PrimaryTestFailure("analytics failed after pairing")
        pairing_flow.fetch_analytics_from_dut.side_effect = primary_error
        pairing_flow.unpair_dut.side_effect = RuntimeError("unpair timed out")

        with self.assertRaises(TestCaseExit) as raised:
            await self.run_rt_flow(pairing_flow)

        pairing_flow.unpair_dut.assert_awaited_once()
        pairing_flow.active_controller.raw_controller.ExpireSessions.assert_not_called()
        pairing_flow.active_controller.raw_controller.CloseBLEConnection.assert_called_once_with()
        self.assertIs(raised.exception.args[0], primary_error)
        pairing_flow.update_iteration_result.assert_not_called()

    async def test_rt_unpair_failure_marks_otherwise_successful_iteration_failed(self):
        pairing_flow = self.make_rt_flow()
        unpair_error = RuntimeError("unpair timed out")
        pairing_flow.unpair_dut.side_effect = unpair_error

        with self.assertRaises(TestCaseExit) as raised:
            await self.run_rt_flow(pairing_flow)

        pairing_flow.active_controller.raw_controller.ExpireSessions.assert_not_called()
        pairing_flow.active_controller.raw_controller.CloseBLEConnection.assert_called_once_with()
        self.assertIs(raised.exception.args[0], unpair_error)
        pairing_flow.update_iteration_result.assert_not_called()

    async def test_rt_unsuccessful_unpair_result_is_not_a_pass(self):
        pairing_flow = self.make_rt_flow()
        pairing_flow.unpair_dut.return_value = False

        with self.assertRaisesRegex(TestCaseExit, "unsuccessful unpairing"):
            await self.run_rt_flow(pairing_flow)

        pairing_flow.active_controller.raw_controller.ExpireSessions.assert_not_called()
        pairing_flow.active_controller.raw_controller.CloseBLEConnection.assert_called_once_with()
        pairing_flow.update_iteration_result.assert_not_called()

    async def test_rt_session_expiration_failure_does_not_skip_ble_cleanup(self):
        pairing_flow = self.make_rt_flow()
        pairing_flow.use_test_event_trigger_factory_reset = True
        cleanup_error = RuntimeError("session expiration failed")
        pairing_flow.active_controller.raw_controller.ExpireSessions.side_effect = cleanup_error

        with self.assertRaises(TestCaseExit) as raised:
            await self.run_rt_flow(pairing_flow)

        pairing_flow.unpair_dut.assert_not_awaited()
        pairing_flow.active_controller.raw_controller.CloseBLEConnection.assert_called_once_with()
        self.assertIs(raised.exception.args[0], cleanup_error)
        pairing_flow.update_iteration_result.assert_not_called()

    async def test_rt_reset_mode_skips_remote_unpair_but_clears_local_state(self):
        pairing_flow = self.make_rt_flow()
        pairing_flow.use_test_event_trigger_factory_reset = True

        await self.run_rt_flow(pairing_flow)

        pairing_flow.unpair_dut.assert_not_awaited()
        pairing_flow.active_controller.raw_controller.ExpireSessions.assert_called_once_with(1)
        pairing_flow.active_controller.raw_controller.CloseBLEConnection.assert_called_once_with()
        pairing_flow.update_iteration_result.assert_called_once_with(iteration_result=TestResultEnums.TEST_RESULT_PASS)

    async def test_rt_ecosystem_cleanup_does_not_use_python_session_apis(self):
        for controller_type in ("ios", "android"):
            with self.subTest(controller_type=controller_type):
                pairing_flow = self.make_rt_flow(controller_type)

                await self.run_rt_flow(pairing_flow)

                pairing_flow.unpair_dut.assert_awaited_once_with(
                    controller=pairing_flow.active_controller, accessory_name="Test_Matter_Accessory_test_1")
                pairing_flow.active_controller.raw_controller.ExpireSessions.assert_not_called()
                pairing_flow.active_controller.raw_controller.CloseBLEConnection.assert_not_called()
                pairing_flow.fetch_analytics_from_dut.assert_not_awaited()
                pairing_flow.update_iteration_result.assert_called_once_with(iteration_result=TestResultEnums.TEST_RESULT_PASS)


class RealIterationCleanupTest(unittest.IsolatedAsyncioTestCase):
    def configure_iterator(self, flow):
        flow.TAG = "cleanup-regression"
        flow.get_existing_test_names.return_value = ["cleanup"]
        flow.results = SimpleNamespace(requested=[], executed=[], passed=[], failed=[])
        flow.test_config.general_configs.number_of_iterations = 2
        flow.test_config.general_configs.sleep_duration_between_iterations = 0
        for name in ("update_iteration_result", "update_mobly_results_record_and_summary_json_data"):
            setattr(flow, name, MethodType(getattr(MatterQABaseTestCaseClass, name), flow))
        flow.mark_iteration_failure_sync_mobly_and_summary_data = MagicMock(
            wraps=MethodType(MatterQABaseTestCaseClass.mark_iteration_failure_sync_mobly_and_summary_data, flow))
        flow.post_iteration = AsyncMock(side_effect=lambda *args, **kwargs: flow.update_mobly_results_record_and_summary_json_data())
        return flow

    def assert_terminal_recorded_once(self, flow, primary):
        flow.mark_iteration_failure_sync_mobly_and_summary_data.assert_called_once()
        self.assertEqual(len(flow.results.executed), 1)
        self.assertEqual(len(flow.results.failed), 1)
        self.assertEqual(flow.results.passed, [])
        flow.test_result_observable.notify.assert_called_once_with(flow.test_results_record)
        self.assertIn(primary, flow.iteration_exception)

    def make_rt11(self):
        flow = self.configure_iterator(MagicMock())
        raw = MagicMock()
        raw.UnpairDevice = AsyncMock(return_value=True)
        flow.active_controller = ChipPythonControllerNode(raw)
        flow.default_controller = raw
        flow.use_test_event_trigger_factory_reset = False
        flow.do_factory_reset_every_iteration.return_value = False
        flow.ecosystem_controller = None
        flow.dut_node_id = 1
        flow.analytics_dict = {}
        flow.pair_dut = AsyncMock(return_value=True)
        flow.fetch_analytics_from_dut = AsyncMock()
        flow._cleanup_pairing_iteration = MethodType(TC_RT_1_1._cleanup_pairing_iteration, flow)

        async def unpair(controller, **kwargs):
            return await controller.unpair_device(node_id=1)

        flow.unpair_dut = AsyncMock(side_effect=unpair)
        return flow, raw

    async def run_rt11(self, flow):
        with patch("matter_qa.scripts.reliability_scripts.TC_RT_1_1.case_capture.AddCASEHandshakeListener"), \
                patch("matter_qa.scripts.reliability_scripts.TC_RT_1_1.case_capture.RemoveCASEHandshakeListener") as remove:
            await TC_RT_1_1.test_TC_RT_1_1.__wrapped__(flow)
        remove.assert_called_once()

    async def test_rt11_uncertain_unpair_stops_real_iterator_and_expires_once(self):
        flow, raw = self.make_rt11()
        raw.UnpairDevice.side_effect = RuntimeError("unpair response lost")
        await self.run_rt11(flow)
        flow.pair_dut.assert_awaited_once()
        raw.UnpairDevice.assert_awaited_once_with(1)
        raw.ExpireSessions.assert_called_once_with(1)
        raw.CloseBLEConnection.assert_called_once()
        self.assert_terminal_recorded_once(flow, "unpair response lost")

    async def test_rt11_ordinary_failure_with_successful_cleanup_continues(self):
        flow, raw = self.make_rt11()
        flow.pair_dut.side_effect = [PrimaryTestFailure("ordinary pairing failure"), True]
        await self.run_rt11(flow)
        self.assertEqual(flow.pair_dut.await_count, 2)
        self.assertEqual(raw.ExpireSessions.call_count, 2)
        self.assertEqual(len(flow.results.executed), 2)
        self.assertEqual(len(flow.results.failed), 1)
        self.assertEqual(len(flow.results.passed), 1)

    async def test_failed_reset_prerequisite_stops_before_commissioning(self):
        flow, raw = self.make_rt11()
        flow.do_factory_reset_every_iteration.return_value = True
        flow.perform_factory_reset_dut = MethodType(MatterQABaseTestCaseClass.perform_factory_reset_dut, flow)
        flow.dut.factory_reset_dut.side_effect = RuntimeError("Nordic reset readiness not verified")
        await self.run_rt11(flow)
        flow.pair_dut.assert_not_awaited()
        raw.UnpairDevice.assert_not_awaited()
        self.assert_terminal_recorded_once(flow, "Nordic reset readiness not verified")

    async def test_reset_mode_still_expires_without_remote_unpair(self):
        flow, raw = self.make_rt11()
        flow.use_test_event_trigger_factory_reset = True
        await TC_RT_1_1._cleanup_pairing_iteration(flow, flow.active_controller, "accessory")
        raw.UnpairDevice.assert_not_awaited()
        raw.ExpireSessions.assert_called_once_with(1)
        raw.CloseBLEConnection.assert_called_once()

    async def test_multi_admin_terminal_cleanup_is_recorded_once_by_real_iterator(self):
        flow, _ = PairingCleanupTest.make_multi_admin_flow(self)
        self.configure_iterator(flow)
        flow.perform_bulk_subscription.return_value = MagicMock()
        flow.cleaning_up_the_paired_controller.side_effect = TestCaseExit("uncertain multi-admin cleanup")
        with patch("matter_qa.scripts.reliability_scripts.TC_RT_1_2.case_capture.AddCASEHandshakeListener"), \
                patch("matter_qa.scripts.reliability_scripts.TC_RT_1_2.case_capture.RemoveCASEHandshakeListener") as remove:
            await TC_RT_1_2.test_TC_RT_1_2.__wrapped__(flow)
        remove.assert_called_once()
        flow.cleaning_up_the_paired_controller.assert_awaited_once()
        self.assert_terminal_recorded_once(flow, "uncertain multi-admin cleanup")

    async def test_discovery_unpairs_before_rollback_and_records_terminal_once(self):
        flow = PairingCleanupTest.make_discovery_flow(self)
        self.configure_iterator(flow)
        order = []

        async def unpair(*args):
            order.append("unpair")
            raise TestCaseExit("uncertain discovery cleanup")

        async def rollback():
            order.append("rollback")

        flow.cleaning_up_the_paired_controller.side_effect = unpair
        flow.revert_dut_network_changes.side_effect = rollback
        with patch("matter_qa.scripts.reliability_scripts.TC_RT_2_2.case_capture.AddCASEHandshakeListener"), \
                patch("matter_qa.scripts.reliability_scripts.TC_RT_2_2.case_capture.RemoveCASEHandshakeListener"):
            await TC_RT_2_2.test_TC_RT_2_2.__wrapped__(flow)
        self.assertEqual(order, ["unpair", "rollback"])
        self.assertEqual(len(flow.list_of_paired_controllers), 1)
        self.assert_terminal_recorded_once(flow, "uncertain discovery cleanup")

    async def test_multi_admin_terminal_body_error_stops_after_successful_cleanup(self):
        flow, _ = PairingCleanupTest.make_multi_admin_flow(self)
        self.configure_iterator(flow)
        flow.perform_bulk_subscription.return_value = MagicMock()
        flow.perform_bulk_write_attributes.side_effect = TestCaseExit("uncertain fixture state")
        with patch("matter_qa.scripts.reliability_scripts.TC_RT_1_2.case_capture.AddCASEHandshakeListener"), \
                patch("matter_qa.scripts.reliability_scripts.TC_RT_1_2.case_capture.RemoveCASEHandshakeListener"):
            await TC_RT_1_2.test_TC_RT_1_2.__wrapped__(flow)
        flow.perform_bulk_write_attributes.assert_awaited_once()
        flow.cleaning_up_the_paired_controller.assert_awaited_once()
        self.assert_terminal_recorded_once(flow, "uncertain fixture state")

    async def test_successful_discovery_unpairs_before_network_rollback(self):
        flow = PairingCleanupTest.make_discovery_flow(self)
        self.configure_iterator(flow)
        order = []

        async def unpair(*args):
            order.append("unpair")

        async def rollback():
            order.append("rollback")

        flow.cleaning_up_the_paired_controller.side_effect = unpair
        flow.revert_dut_network_changes.side_effect = rollback
        with patch("matter_qa.scripts.reliability_scripts.TC_RT_2_2.case_capture.AddCASEHandshakeListener"), \
                patch("matter_qa.scripts.reliability_scripts.TC_RT_2_2.case_capture.RemoveCASEHandshakeListener"):
            await TC_RT_2_2.test_TC_RT_2_2.__wrapped__(flow)
        self.assertEqual(order, ["unpair", "rollback", "unpair", "rollback"])
        self.assertEqual(len(flow.results.passed), 2)
        self.assertEqual(flow.results.failed, [])

    async def test_case_failure_handler_contains_uncertain_cleanup_in_real_iterator(self):
        flow = self.configure_iterator(MagicMock())
        controller = MagicMock()
        flow.list_of_commissioned_controller = [(controller, 1)]
        flow.list_of_active_subscriptions = []
        flow.use_test_event_trigger_factory_reset = False
        flow.subscription_cleanup = MethodType(PairingFlowFunctions.subscription_cleanup, flow)
        flow.unpair_dut = AsyncMock(side_effect=RuntimeError("unpair failed"))
        flow.operation = MagicMock(side_effect=PrimaryTestFailure("original CASE failure"))
        handler = MethodType(PairingFlowFunctions.cleanup_and_unpair_sessions, flow)

        @MatterQABaseTestCaseClass.iterate_tc(iterations=2)
        async def body():
            async with PairingFlowFunctions.CaseSession(flow, failure_handler=handler):
                flow.operation()

        await body(flow)
        flow.operation.assert_called_once()
        self.assertEqual(flow.list_of_commissioned_controller, [(controller, 1)])
        self.assert_terminal_recorded_once(flow, "original CASE failure")


class SessionEntryCleanupTest(unittest.IsolatedAsyncioTestCase):
    async def test_failed_pase_entry_closes_session_and_invokes_failure_handler(self):
        flow = MagicMock()
        primary = PrimaryTestFailure("PASE commissioning failed")
        flow.establish_pasesession = AsyncMock(side_effect=primary)
        failure_handler = AsyncMock()
        with self.assertRaises(IterationError) as raised:
            async with PairingFlowFunctions.PaseSession(flow, failure_handler):
                self.fail("failed entry must not execute the body")
        self.assertIs(raised.exception.args[0], primary)
        flow.close_session.assert_called_once_with()
        failure_handler.assert_awaited_once_with()

    async def test_failed_pase_entry_with_uncertain_cleanup_preserves_primary_and_stops(self):
        flow = MagicMock()
        primary = PrimaryTestFailure("PASE commissioning failed")
        secondary = RuntimeError("session cleanup failed")
        flow.establish_pasesession = AsyncMock(side_effect=primary)
        flow.close_session.side_effect = secondary
        failure_handler = AsyncMock(side_effect=RuntimeError("fabric cleanup failed"))
        with self.assertRaises(TestCaseExit) as raised:
            async with PairingFlowFunctions.PaseSession(flow, failure_handler):
                self.fail("failed entry must not execute the body")
        self.assertIs(raised.exception.args[0], primary)
        self.assertIs(raised.exception.__cause__, secondary)
        flow.close_session.assert_called_once_with()
        failure_handler.assert_awaited_once_with()


if __name__ == "__main__":
    unittest.main()
