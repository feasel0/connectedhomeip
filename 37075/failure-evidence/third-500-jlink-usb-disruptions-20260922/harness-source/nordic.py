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
import datetime
import logging
import os
import subprocess
import time
from threading import Event, Thread

from matter_qa.library.base_test_classes.dut_base_class import BaseDutNodeClass
from matter_qa.library.base_test_classes.enums.matterqa_base_enums import NordicTimingEnums
from matter_qa.library.helper_libs.exceptions import DUTInteractionError
from matter_qa.library.helper_libs.serial import SerialConfig, SerialConnection

global log
log = logging.getLogger("nordic")
log.propagate = True

event_closer = Event()  # flag used to keep trace of start/stop of capturing the DUT log


class NordicDut(BaseDutNodeClass):
    """
    Represents a Nordic DUT (Device Under Test) with functionalities
    for serial communication, logging, and test management.

    """

    def __init__(self, test_config, matter_qa_base_class_object, *args, **kwargs) -> None:
        """
        Initialize the Nordic DUT instance with necessary configurations.

        Args:
            test_config: Configuration object containing DUT and test settings.
        """
        super().__init__()
        self.dut_config = test_config.dut_config.nordic
        self.matter_qa_base_class_object = matter_qa_base_class_object
        self.serial_config = SerialConfig(test_config.dut_config.nordic.serial_port,
                                          test_config.dut_config.nordic.serial_baudrate,
                                          test_config.dut_config.nordic.serial_timeout)
        self.serial_session = SerialConnection(self.serial_config)
        self.factoryreset_command = self.dut_config.factoryreset_command
        self.dut_reboot_command = self.dut_config.dut_reboot_command
        self.test_config = test_config
        self.last_log_lines = []

    def start_test(self, *args, **kwargs):
        """
        Starts the test by establishing a serial connection to the DUT.
        Exits the program if the connection fails.
        """
        try:
            self.serial_session.open_serial_connection()
        except Exception as e:
            raise DUTInteractionError(f"Could not establish Serial connection {e}", exc_info=True)

    def reboot_dut(self, *args, **kwargs):
        try:
            for iteration in range(1, 3):
                try:
                    log.info(f"Starting to Re-Boot Nordic as the DUT for {iteration}")
                    if self.serial_session.serial_object.is_open:  # directly send reboot command if port is opened
                        self.serial_session.send_command(self.dut_reboot_command.encode('utf-8'))
                        # we have to wait for a minimum of 4 seconds for the dut to be in stable mode after re-boot
                        time.sleep(NordicTimingEnums.DELAY_AFTER_FACTORY_RESET.value)
                    else:  # send re-boot command only after opening the port
                        self.serial_session.open_serial_connection()
                        self.serial_session.send_command(self.dut_reboot_command.encode('utf-8'))
                        # we have to wait for a minimum of 4 seconds for the dut to be in stable mode after re-boot
                        time.sleep(NordicTimingEnums.DELAY_AFTER_FACTORY_RESET.value)
                except Exception as e:
                    log.error(f"Failed to Re-Boot Nordic as the DUT {iteration}:{e}", exc_info=True)
            self.serial_session.close_serial_connection()
            log.info("DUT Re-Boot Completed")
        except Exception as e:
            log.error(f"Failed to Re-Boot the dut: {e}", exc_info=True)

    def start_matter_app(self, *args, **kwargs):
        """
        Start the Matter application on the DUT. To be implemented if necessary.
        """
        pass

    def factory_reset_dut(self, *args, **kwargs):
        """
        Performs a factory reset on the DUT by sending reset commands.
        Handles serial port operations and ensures the DUT is reset properly.
        """
        try:
            for iteration in range(1, 3):
                try:
                    log.info(f"Starting to Reset Nordic as the DUT {iteration}")
                    if self.serial_session.serial_object.is_open:  # directly send reset command if port is opened
                        self.serial_session.send_command(self.factoryreset_command.encode('utf-8'))
                        # we have to wait for a minimum of 4 seconds for the dut to be in advertising mode
                        time.sleep(NordicTimingEnums.DELAY_AFTER_FACTORY_RESET.value)
                    else:  # send reset command only after opening the port
                        self.serial_session.open_serial_connection()
                        self.serial_session.send_command(self.factoryreset_command.encode('utf-8'))
                        # we have to wait for a minimum of 4 seconds for the dut to be in advertising mode
                        time.sleep(NordicTimingEnums.DELAY_AFTER_FACTORY_RESET.value)
                except Exception as e:
                    log.error(f"Failed to Reset Nordic as the DUT {iteration}:{e}", exc_info=True)
            self.serial_session.close_serial_connection()
            log.info("Reset Completed")
        except Exception as e:
            log.error(f"Failed to Factory reset the dut: {e}", exc_info=True)

    def start_logging(self, file_name=None, *args, **kwargs):
        """
        Starts logging DUT output by initiating a separate thread.
        """
        try:
            event_closer.clear()  # setting the flag to bool 'False' value to start capturing the DUT logs
            self.thread = Thread(target=self._start_logging)
            self.thread.daemon = True
            self.thread.start()

        except Exception as e:
            log.error(f"Failed to capture the log:{e}", exc_info=True)

    # TODO need to check for usages, seems to be unused at the moment
    def start_ios_logging(self, udid, log_file="ios_device.log"):
        log_file = os.path.join(self.test_config.iter_log_path, "ios_log_{}_"
                                .format(str(self.test_config.current_iteration)) +
                                str(datetime.datetime.now().isoformat()).replace(':', "_")
                                .replace('.', "_") + ".log")  # build DUT log file name
        return subprocess.Popen(
            ["idevicesyslog", "-u", udid],
            stdout=open(log_file, "w"),
            stderr=subprocess.STDOUT
        )

    def _start_logging(self, file_name=None):
        """
        Internal method to read logs from the DUT and save them to a file.

        Args:
            file_name (str, optional): Name of the log file to save output.
        """
        log.info("Started log capturing on DUT")
        serial_session_read_logs = None
        try:
            # open serial connection when port is closed for reading dut logs via serial interface
            # Create a new serial object to avoid thread conflicts.
            serial_session_read_logs = SerialConnection(self.serial_config)
            if not serial_session_read_logs.serial_object.is_open:
                serial_session_read_logs.open_serial_connection()

            log.info("Started reading DUT logs")
            if serial_session_read_logs.serial_object.is_open:
                log_file = os.path.join(self.test_config.iter_log_path, "Dut_log_{}_"
                                        .format(str(self.test_config.current_iteration)) +
                                        str(datetime.datetime.now().isoformat()).replace(':', "_")
                                        .replace('.', "_") + ".log")  # build DUT log file name
                self.last_log_lines = []

                log.info("started to read buffer")

                with open(log_file, 'w') as fp:
                    log.info(f"Writing DUT log to file: {log_file}")
                    fp.write(f" \n\n  Dut log of {self.test_config.current_iteration} iteration \n")
                    fp.write(f" \n\n  Start time: {datetime.datetime.now().isoformat()} \n")
                    fp.flush()  # ensure the log is written to the file immediately
                    while not event_closer.is_set():
                        try:
                            # Set a timeout for serial read so the loop can regularly check for new lines every 2 seconds
                            serial_session_read_logs.serial_object.timeout = NordicTimingEnums.READ_LOG_TIMEOUT.value
                            line = serial_session_read_logs.serial_object.read_until(b'\n').decode('utf-8', errors='ignore')

                            if line:
                                fp.write(line)
                                fp.flush()  # ensure the log is written to the file immediately
                                self.last_log_lines.append(line.strip())

                                # Check if we received the stop_logging command
                                if 'stop_logging' in line:
                                    log.info("Received stop_logging signal from DUT, ending log capture")
                                    break
                        except Exception as read_error:
                            # Timeout or read error - check if we should stop
                            if event_closer.is_set():
                                log.info("Stop signal received, ending log capture")
                                break

                log.info(f"completed write to file for iteration {self.test_config.current_iteration}")
                log.info(f"DUT log saved to {log_file}")
                serial_session_read_logs.close_serial_connection()
                log.info("Closed serial connection after reading DUT logs")

        except Exception as e:
            log.error(f"Failed to capture the log:{e}", exc_info=True)
            raise DUTInteractionError(f"Failed to save the log: {e}")
        finally:
            if serial_session_read_logs and serial_session_read_logs.serial_object.is_open:
                serial_session_read_logs.close_serial_connection()
            log.info("Stopped reading DUT logs")

    def _stop_logging(self, *args, **kwargs):
        """
        Stops logging DUT output by signaling the DUT and closing the serial port.
        """
        log.info("Stopping DUT logging...")
        try:
            if not self.serial_session.serial_object.is_open:
                self.serial_session.open_serial_connection()
            self.serial_session.send_command(b'\n stop_logging \n')
            log.info("Stopping log capture on DUT")
            # TODO: Need to the check efficient duration for the STOP_LOGGING_WAIT_TIME.
            time.sleep(NordicTimingEnums.STOP_LOGGING_WAIT_TIME.value)
        except Exception as e:
            log.error(f"Failed to stop the log:{e}", exc_info=True)
        finally:
            event_closer.set()
            self.thread.join(timeout=NordicTimingEnums.LOG_THREAD_JOIN_TIMEOUT.value)
            if self.thread.is_alive():
                log.error("Logging thread failed to terminate properly waiting for thread join")
                self.thread.join()

    def stop_logging(self, *args, **kwargs):
        self._stop_logging(args, kwargs)

    def pre_iteration_loop(self, *args, **kwargs):
        """
        Prepares the DUT for each test iteration by starting the logging process.
        """
        self.start_logging()

    def post_iteration_loop(self, *args, **kwargs):
        """
        Cleans up after each test iteration by stopping the logging process.
        """
        self.stop_logging()

    def end_test(self, *args, **kwargs):
        """
        Ends the test and ensures the serial connection is closed properly.
        """
        try:
            if self.serial_session.serial_object.is_open:
                self.serial_session.close_serial_connection()
            # Set the Event_closer for the cleanup.
            event_closer.set()
        except Exception as e:
            log.error(f"Failed to end the test: {e}", exc_info=True)

    def set_advertising_mode(self, *args, **kwargs):
        log.info("Setting the DUT in advertising mode")
        self.reboot_dut()
