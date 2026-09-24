import logging

from mobly import signals
from serial import serial_for_url

from matter_qa.library.helper_libs.exceptions import SerialConnectionError

log = logging.getLogger(__name__)


class SerialConfig:
    """
    Configuration class for serial communication settings.

    Attributes:
        serial_port (str): The port used for serial communication.
        baudrate (int): The baud rate for the connection.
        timeout (float): Timeout value for serial communication.
    """

    def __init__(self, serial_port, baudrate, timeout) -> None:
        self.serial_port = serial_port
        self.baudrate = baudrate
        self.timeout = timeout


class SerialConnection:
    def __init__(self, serial_config):
        self.port = serial_config.serial_port
        self.baudrate = serial_config.baudrate
        self.timeout = serial_config.timeout

        try:
            self.serial_object = serial_for_url(self.port, do_not_open=True, baudrate=self.baudrate, timeout=self.timeout)
        except Exception as e:
            log.exception("Failed to create serial port from URL '%s'", self.port)
            raise signals.TestAbortAll(f"Failed to create serial from URL '{self.port}'") from e

    def __enter__(self):
        self.open_serial_connection()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_serial_connection()

    def send_command(self, command):
        try:
            self.serial_object.write(command)
            self.serial_object.flush()
        except Exception as e:
            log.exception("Failed to send command '%s'", command)
            raise SerialConnectionError(str(e)) from e

    def open_serial_connection(self):
        try:
            if not self.serial_object.is_open:
                log.info("Opening Serial Port")
                self.serial_object.open()
        except Exception as e:
            log.exception("Failed to open serial port '%s'", self.port)
            raise SerialConnectionError(str(e)) from e

    def close_serial_connection(self):
        try:
            if self.serial_object.is_open:
                log.info("Closing serial port")
                self.serial_object.close()
        except Exception as e:
            log.exception("Failed to close serial port '%s'", self.port)
            raise SerialConnectionError(str(e)) from e
