#
#
#  Copyright (c) 2023 Project CHIP Authors
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
import asyncio
import copy
import datetime
import logging
import threading
import time
import typing
from typing import Optional

import matter.case_capture as case_capture
import matter.clusters as Clusters
from matter import ChipDeviceCtrl
from matter.commissioning import CommissionFailure
from matter.testing.decorators import async_test_body
from matter.testing.runner import TestStep
from python_path import PythonPath

with PythonPath('../../..', relative_to=__file__):
    from matter_qa.library.base_test_classes.matter_qa_base_test_class import MatterQABaseTestCaseClass
    from matter_qa.library.base_test_classes.test_results_record import TestResultEnums
    from matter_qa.library.helper_libs.attribute_value_generator import AttributeValueGenerator
    from matter_qa.library.helper_libs.attribute_value_verifier import AttributeValueVerifier
    from matter_qa.library.helper_libs.augmented_matter_test_base import AttributeUpdateHandler, run_augmented_matter_tests
    from matter_qa.library.helper_libs.cluster_xml_parser import ClusterXMLParser
    from matter_qa.library.helper_libs.dut_topology_discovery import DUTTopologyDiscovery
    from matter_qa.library.helper_libs.exceptions import IterationError, TestCaseExit

log = logging.getLogger("base_tc")


class TC_RT_1_2(MatterQABaseTestCaseClass):

    # Test case metadata. Declared rather than assigned, so the most derived class
    # always wins and the position of super() below cannot affect it.

    @property
    def test_suite_name(self) -> str:
        return "StressTestSuite"

    @property
    def tc_name(self) -> str:
        return "Multi_Admin"

    @property
    def tc_id(self) -> str:
        return "stress_1_2"

    def __init__(self, *args):
        super().__init__(*args)
        # Reads and writes attributes, so it needs the cluster XMLs parsed. The rest of
        # the per-test-case state is set up by the base. open_commissioning_window_timeout
        # is a property on the base, resolved per test case from its own config section.
        self._initialize_parsers_and_generators()

    def pics_TC_RT_1_2(self) -> typing.List[str]:
        return ["STRESS.S"]

    def steps_TC_RT_1_2(self) -> typing.List[TestStep]:
        steps = [
            TestStep(1, "Device Factory Reset completed and Commission Ready", is_commissioning=True)
        ]
        return steps

    def desc_TC_RT_1_2(self) -> str:
        return "[TC-RT-1.2] Multi-Admin Commissioning and Attribute Subscription"

    async def _execute_write_task(self,
                                  controller: ChipDeviceCtrl.ChipDeviceController,
                                  node_id: int, write_payload: list) -> list:
        """
        Execute a write operation on the DUT using the specified controller.

        Args:
            controller: The controller to use for the write operation.
            node_id: The node ID of the target device.
            write_payload: List of attribute write requests.

        Returns:
            The result of the write operation.

        Raises:
            IterationError: If the write operation fails.
        """
        controller_name = self._get_controller_name(controller)
        try:
            log.info(
                f"Starting write operation for controller '{controller_name}' "
                f"with payload size: {len(write_payload)}")
            write_result = await controller.WriteAttribute(
                nodeId=node_id, attributes=write_payload)
            return write_result
        except Exception as e:
            log.error(
                f"Write operation failed for controller '{controller_name}': {e}",
                exc_info=True)
            raise IterationError(
                f"Concurrent write operation failed for controller '{controller_name}'.")

    async def _execute_read_task(self,
                                 controller: ChipDeviceCtrl.ChipDeviceController,
                                 node_id: int, read_request: list) -> dict:
        """
        Execute a read operation on the DUT using the specified controller.

        Args:
            controller: The controller to use for the read operation.
            node_id: The node ID of the target device.
            read_request: List of attribute read requests.

        Returns:
            The result of the read operation.

        Raises:
            IterationError: If the read operation fails.
        """
        controller_name = self._get_controller_name(controller)
        try:
            log.info(f"Starting read operation for controller '{controller_name}'")
            read_result = await controller.Read(
                nodeId=node_id, attributes=read_request)
            return read_result.attributes
        except Exception as e:
            log.error(
                f"Read operation failed for controller '{controller_name}': {e}",
                exc_info=True)
            raise IterationError(
                f"Concurrent read operation failed for controller '{controller_name}'.")

    def _distribute_payloads_across_controllers(self,
                                                payloads: list, number_of_controllers: int) -> list[list]:
        """
        Distribute payloads evenly across controllers.

        Uses round-robin distribution to ensure payloads are spread as evenly
        as possible, with earlier controllers receiving extra items when the
        total doesn't divide evenly.

        Args:
            payloads: List of payloads to distribute.
            number_of_controllers: Number of controllers to distribute across.

        Returns:
            List of payload lists, one per controller.
        """
        if not number_of_controllers:
            return []

        base_count = len(payloads) // number_of_controllers
        extra_count = len(payloads) % number_of_controllers

        distributed_payloads = []
        current_index = 0

        for controller_idx in range(number_of_controllers):
            # Earlier controllers get one extra payload if there's a remainder
            items_for_this_controller = base_count + (1 if controller_idx < extra_count else 0)

            if items_for_this_controller > 0:
                controller_payload = payloads[current_index:current_index + items_for_this_controller]
                current_index += items_for_this_controller
            else:
                controller_payload = []

            distributed_payloads.append(controller_payload)

        return distributed_payloads

    def _flatten_results(self, results: list) -> list:
        """Flatten a list of results, expanding any nested lists."""
        flat_results = []
        for result in results:
            if isinstance(result, list):
                flat_results.extend(result)
            else:
                flat_results.append(result)
        return flat_results

    async def perform_concurrent_write_operations(self,
                                                  list_of_paired_controllers: list[tuple[ChipDeviceCtrl.ChipDeviceController, int]]) -> None:
        """
        Perform concurrent write operations on DUT from multiple controllers.

        Distributes write payloads across all paired controllers and executes
        the write operations concurrently. Results are collected and flattened.

        Args:
            list_of_paired_controllers: List of (controller, node_id) tuples.

        Raises:
            IterationError: If any write operation fails.
        """
        log.info(
            f"Initiating concurrent write operations with "
            f"{len(list_of_paired_controllers)} controllers")

        try:
            # Prepare write payload
            self._write_timestamp = datetime.datetime.now()
            self._write_payload = await self._build_write_payload()

            # Distribute payloads across controllers
            number_of_controllers = len(list_of_paired_controllers)
            distributed_payloads = self._distribute_payloads_across_controllers(
                self._write_payload, number_of_controllers)

            # Build task list for controllers with non-empty payloads
            write_tasks = [self._execute_write_task(controller, node_id, payload)
                           for (controller, node_id), payload in zip(
                list_of_paired_controllers, distributed_payloads
            ) if payload]  # Only include controllers with payloads

            # Execute all write operations concurrently
            results = await asyncio.gather(*write_tasks, return_exceptions=True)

            # Check for any failures
            failed_operations = [r for r in results if isinstance(r, Exception)]
            if failed_operations:
                log.error(f"{len(failed_operations)} write operation(s) failed")
                raise IterationError("One or more concurrent write operations failed.")

            # Store flattened results
            self.write_result = self._flatten_results(results)
            log.info(
                f"Successfully completed {len(write_tasks)} concurrent write operations")

        except IterationError:
            raise
        except Exception as e:
            log.error(f"Unexpected error during concurrent write operations: {e}")
            raise IterationError("Concurrent write operations failed.")

    def _validate_read_results_consistency(self, results: list[dict],
                                           controllers: list[tuple[ChipDeviceCtrl.ChipDeviceController, int]]) -> None:
        """
        Validate that all read results are consistent across controllers.

        Args:
            results: List of read results from each controller.
            controllers: List of (controller, node_id) tuples.

        Raises:
            IterationError: If any results don't match the reference result.
        """

        reference_result = results[0]
        mismatched_controllers = []

        for idx, result in enumerate(results[1:], start=1):
            controller_name = self._get_controller_name(controllers[idx][0])

            if not self._compare_read_results(reference_result, result):
                mismatched_controllers.append(controller_name)
                log.error(f"Read result mismatch detected for '{controller_name}'")

        if mismatched_controllers:
            raise IterationError(
                f"Concurrent read results mismatch for controllers: "
                f"{', '.join(mismatched_controllers)}")

    async def perform_concurrent_read_attributes(self,
                                                 list_of_paired_controllers: list[tuple[ChipDeviceCtrl.ChipDeviceController, int]]) -> None:
        """
        Perform concurrent read operations on DUT from multiple controllers.

        Executes read operations from all controllers concurrently and validates
        that all controllers receive consistent attribute values.

        Args:
            list_of_paired_controllers: List of (controller, node_id) tuples.

        Raises:
            IterationError: If any read operation fails or results are inconsistent.
        """
        log.info(
            f"Starting concurrent read operations from "
            f"{len(list_of_paired_controllers)} controllers")

        # Prepare read request
        read_request = self._read_write_list if self._read_write_list else [()]

        # Build and execute read tasks concurrently
        read_tasks = [self._execute_read_task(controller, node_id, read_request)
                      for controller, node_id in list_of_paired_controllers]
        results = await asyncio.gather(*read_tasks, return_exceptions=True)

        # Check for any failures
        failed_operations = [r for r in results if isinstance(r, Exception)]
        if failed_operations:
            log.error(f"{len(failed_operations)} read operation(s) failed")
            raise IterationError(f"concurrent read operations failed with {failed_operations}.")
        # Validate consistency across all results
        self._validate_read_results_consistency(results, list_of_paired_controllers)

        # Update internal state with reference result
        reference_result = results[0]
        self._update_attribute_values_from_read_result(reference_result)

        log.info(
            f"Successfully completed concurrent read operations from "
            f"{len(list_of_paired_controllers)} controllers")

    def _compare_read_results(self, result1: dict, result2: dict) -> bool:
        """
        Compare two read results to verify they contain the same attribute values.

        Performs a deep comparison of the hierarchical structure:
        endpoint -> cluster -> attribute -> value

        Args:
            result1: First read result dictionary.
            result2: Second read result dictionary.

        Returns:
            True if results match exactly, False otherwise.
        """
        try:
            return self._compare_endpoints(result1, result2)
        except Exception as e:
            log.error(f"Error comparing read results: {e}", exc_info=True)
            return False

    def _compare_endpoints(self, result1: dict, result2: dict) -> bool:
        """Compare endpoint keys and their contents between two results."""
        endpoints1 = set(result1.keys())
        endpoints2 = set(result2.keys())

        if endpoints1 != endpoints2:
            log.warning(f"Endpoint mismatch: {endpoints1} vs {endpoints2}")
            return False

        for endpoint in result1:
            if not self._compare_clusters(result1[endpoint], result2[endpoint], endpoint):
                return False

        return True

    def _compare_clusters(self, clusters1: dict, clusters2: dict,
                          endpoint: int) -> bool:
        """Compare cluster keys and their contents within an endpoint."""
        cluster_keys1 = set(clusters1.keys())
        cluster_keys2 = set(clusters2.keys())

        if cluster_keys1 != cluster_keys2:
            log.warning(f"Cluster mismatch at endpoint {endpoint}")
            return False

        for cluster in clusters1:
            if not self._compare_attributes(clusters1[cluster],
                                            clusters2[cluster], endpoint, cluster):
                return False

        return True

    def _compare_attribute_values(self, value1, value2) -> bool:
        """
        Compare two attribute values, handling special cases like ValueDecodeFailure.

        ValueDecodeFailure objects don't implement __eq__ properly, so we need to
        compare their internal status (TLVValue and Reason)

        Args:
            value1: First attribute value.
            value2: Second attribute value.

        Returns:
            True if values are equivalent, False otherwise.
        """
        # Check if both values are ValueDecodeFailure instances
        value1_type = type(value1).__name__
        value2_type = type(value2).__name__

        if value1_type == 'ValueDecodeFailure' and value2_type == 'ValueDecodeFailure':
            # Compare the status of ValueDecodeFailure
            return (value1.TLVValue == value2.TLVValue and
                    str(value1.Reason) == str(value2.Reason))

        # For all other types, use standard equality comparison
        return value1 == value2

    def _compare_attributes(self, attrs1: dict, attrs2: dict,
                            endpoint: int, cluster: str) -> bool:
        """Compare attribute keys and values within a cluster."""
        attr_keys1 = set(attrs1.keys())
        attr_keys2 = set(attrs2.keys())

        if attr_keys1 != attr_keys2:
            log.warning(
                f"Attribute mismatch at endpoint {endpoint}, cluster {cluster}")
            return False

        for attr in attrs1:
            if not self._compare_attribute_values(attrs1[attr], attrs2[attr]):
                log.warning(f"Value mismatch at endpoint {endpoint}, "
                            f"cluster {cluster}, attribute {attr}: "
                            f"{attrs1[attr]} vs {attrs2[attr]}")
                return False

        return True

    async def perform_concurrent_operations(self,
                                            list_of_paired_controllers: list[tuple[ChipDeviceCtrl.ChipDeviceController, int]]) -> None:
        """
        Perform concurrent write and read operations on DUT from multiple controllers.

        This method orchestrates the full concurrent operation workflow:
        1. Execute concurrent write operations across all controllers
        2. Perform bulk read to retrieve current attribute values
        3. Verify that write operations completed successfully

        Args:
            list_of_paired_controllers: List of (controller, node_id) tuples
                representing all controllers that should participate in
                concurrent operations.

        Raises:
            IterationError: If any concurrent operation fails.
        """

        number_of_controllers = len(list_of_paired_controllers)
        log.info(
            f"Starting concurrent operations workflow with {number_of_controllers} controllers")

        # Step 1: Concurrent write operations
        await self.perform_concurrent_write_operations(list_of_paired_controllers)

        # Step 2: Read back and verify written values
        await self.perform_concurrent_read_attributes(list_of_paired_controllers)
        self.verify_bulk_attributes_write_results()

        log.info(
            f"Concurrent operations workflow completed successfully "
            f"with {number_of_controllers} controllers")

    @async_test_body
    async def test_TC_RT_1_2(self):

        self.dut.factory_reset_dut()  # performing factory reset on DUT
        self.step(1)
        await self.perform_initial_commission_with_dut()
        await self.read_subscription_interval_duration()
        self.read_bulk_subscription_test_config()
        self.endpoint_map = await self.device_inspector.inspect_device_implementation()
        self._read_write_list = self._build_read_write_list()
        self._writable_attributes = await self._build_writable_attributes_list()
        self.list_of_controller_objects = await self.create_list_of_controller_object()
        await self.update_controller_endpoints_mapping()

        # Registered once for the whole test; the listener is handed the timings for every CASE
        # handshake that completes, and attributes them using the target set by the pairing loop.
        case_metrics_collecting_observer = case_capture.AddCASEHandshakeListener(self._gather_case_handshake_metrics)

        @MatterQABaseTestCaseClass.iterate_tc(iterations=self.test_config.general_configs.number_of_iterations)
        async def tc_rt_1_2(*args, **kwargs):
            # List contains the controller object
            list_of_paired_controllers = []
            list_of_subscriptions = []
            pairing_duration_for_each_controller = {}
            # Handshakes are collected per iteration, so clear what the last one gathered.
            self._reset_case_metrics()
            iteration_error = None
            cleanup_error = None
            try:
                for controller, nodeId in self.list_of_controller_objects:
                    log.info(f"Started the commissioning process for the {controller.name}")
                    time_before_starting_pairing = datetime.datetime.now()
                    log.info(f"Opening the commissioning window for the {controller.name}")
                    open_commissioning_window_parameters = await self.openCommissioningWindow(dev_ctrl=self.default_controller, node_id=self.dut_node_id,
                                                                                              commissioning_window_timeout=self.open_commissioning_window_timeout_seconds)
                    # Set after the commissioning window is open, so the default controller's own
                    # traffic on that call is never mistaken for this controller's handshake.
                    self._set_case_metrics_target(controller.name, nodeId)
                    list_of_paired_controllers.append((controller, nodeId))
                    await self.pair_controller_with_dut(controller, nodeId, open_commissioning_window_parameters)
                    time_after_pairing_completed = datetime.datetime.now()
                    pairing_duration = (time_after_pairing_completed - time_before_starting_pairing).total_seconds()
                    # Only once pairing has been timed, so waiting on the capture library's
                    # delivery thread cannot be counted as part of the pairing duration.
                    await self._await_case_metrics_capture()
                    log.info(f"{controller.name} is commissioned")
                    pairing_duration_for_each_controller.update({controller.name: pairing_duration})
                    log.info(f"Paring duration of the {controller.name} is {pairing_duration}")
                    log.info(f"Subscribing to the attributes from the {controller.name}")
                    subscription = await self.perform_bulk_subscription(controller, nodeId)
                    list_of_subscriptions.append(subscription)
                    controller_endpoint_map = self.controller_endpoint_maps.get(controller.name)
                    self.subscription_callbacks[controller.name] = AttributeUpdateHandler(
                        controller_name=controller.name,
                        controller_endpoint_map=controller_endpoint_map,
                        expected_attributes=self._writable_attributes)
                    subscription.SetAttributeUpdateCallback(self.subscription_callbacks[controller.name])
                    # we are adding delay so that DUT is in a stable state before unpairing this can be controlled from configFile
                    self.delay_between_stress_test_operations()
                    log.info(
                        f"pairing duration for each controller in iteration-{self.test_config.current_iteration} is {pairing_duration_for_each_controller}")

                time_before_start_reading_subscription = datetime.datetime.now()
                # Every controller is commissioned, so handshakes from here on belong to the
                # subscription and attribute traffic rather than to a commissioning.
                self._clear_case_metrics_target()
                log.info(f"Starting to write attributes on DUT in iteration-{self.test_config.current_iteration}")
                await self.perform_bulk_write_attributes()
                self.delay_between_stress_test_operations()
                await self.check_subscription_report()
                time_after_reading_subscription = datetime.datetime.now()
                subscription_duration = (time_after_reading_subscription - time_before_start_reading_subscription).total_seconds()

                if self.enable_concurrent_operation:
                    log.info(f"Starting concurrent operations on controllers in iteration-{self.test_config.current_iteration}")
                    await self.perform_concurrent_operations(list_of_paired_controllers)

                self.analytics_dict.update({"subscription_duration": subscription_duration})
                log.info(f"subscription_duration for all controller in iteration-{self.test_config.current_iteration} "
                         f"is {subscription_duration}")
            except CommissionFailure as e:
                log.error(str(e), exc_info=True)
                iteration_error = e
                try:
                    await self.close_commissioning_window(self.open_commissioning_window_timeout_seconds)
                except Exception:
                    log.exception("Failed to close commissioning window after pairing failure")
            except Exception as e:
                log.error(str(e), exc_info=True)
                iteration_error = e

            finally:
                try:
                    self._clear_case_metrics_target()
                    self._record_case_metrics_in_analytics()
                    total_pairing_duration = sum(pairing_duration_for_each_controller.values())
                    average_pairing_duration = (total_pairing_duration / len(pairing_duration_for_each_controller)
                                                if pairing_duration_for_each_controller else 0)
                    self.analytics_dict.update({"total_pairing_duration": total_pairing_duration,
                                                "average_pairing_duration": average_pairing_duration})
                    if self.enable_diag_log_capture:
                        await self.retrieve_multiple_diagnostic_logs(list_of_paired_controllers)
                    await self.fetch_analytics_from_dut()
                except Exception as error:
                    log.exception("Failed to collect iteration diagnostics")
                    if iteration_error is None:
                        iteration_error = error
                finally:
                    try:
                        await self.cleaning_up_the_paired_controller(list_of_paired_controllers, list_of_subscriptions)
                    except Exception as error:
                        log.exception("Multi-admin cleanup failed")
                        cleanup_error = error
                        if iteration_error is None:
                            iteration_error = error

            if iteration_error is None:
                self.update_iteration_result(iteration_result=TestResultEnums.TEST_RESULT_PASS)
            else:
                self.update_iteration_result(iteration_result=TestResultEnums.TEST_RESULT_FAIL, execption=iteration_error)
            if cleanup_error is not None:
                self.mark_iteration_failure_sync_mobly_and_summary_data(iteration_error)
                raise TestCaseExit(str(iteration_error)) from cleanup_error

        try:
            await tc_rt_1_2(self)
        finally:
            case_capture.RemoveCASEHandshakeListener(case_metrics_collecting_observer)


if __name__ == "__main__":
    run_augmented_matter_tests(test_class=TC_RT_1_2)
