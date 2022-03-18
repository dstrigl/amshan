"""Util for reading from HAN port."""
from __future__ import annotations

import argparse
import datetime
import decimal
import json
import logging
import signal
import sys
import time
from asyncio import Queue, create_task, get_event_loop, run
from typing import Any

from influxdb import InfluxDBClient

from han import autodecoder
from han.dlms_tinetz import DlmsTinetzFrameReader
from han.meter_connection import (
    AsyncConnectionFactory,
    ConnectionManager,
    MeterTransportProtocol,
)
from han.serial_connection_factory import create_serial_message_payload_connection
from han.tcp_connection_factory import create_tcp_message_payload_connection

logging.basicConfig(
    level=logging.DEBUG, format="%(levelname)7s: %(message)s", stream=sys.stderr,
)
LOG = logging.getLogger("")


def _get_arg_parser() -> argparse.ArgumentParser:
    def valid_host_port(host_port: str) -> tuple[str, str]:
        host_and_port = host_port.split(":")
        if len(host_and_port) == 2:
            return host_and_port[0], host_and_port[1]
        else:
            msg = f"Not a valid host and port: '{host_port}'."
            raise argparse.ArgumentTypeError(msg)

    parser = argparse.ArgumentParser("read HAN port")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-host", dest="hostandport", type=valid_host_port, help="input host and port separated by :",
    )
    group.add_argument("-serial", dest="serialdevice", help="input serial port")

    parser.add_argument(
        "-sp",
        dest="ser_parity",
        default="N",
        required=False,
        choices=["N", "O", "E"],
        help="input serial port parity",
    )
    parser.add_argument(
        "-sb", dest="ser_baudrate", default=2400, type=int, required=False, help="input serial port baud rate",
    )
    parser.add_argument("-mh", dest="mqtthost", default="localhost", help="mqtt host")
    parser.add_argument("-mp", dest="mqttport", type=int, default=1883, help="mqtt port port")
    parser.add_argument("-t", dest="mqtttopic", default="han", help="mqtt publish topic")
    parser.add_argument("-dumpfile", dest="dumpfile", help="dump received bytes to file")
    parser.add_argument(
        "-r", dest="reconnect", type=bool, default=True, help="automatic retry/reconnect meter connection",
    )
    parser.add_argument(
        "-key", dest="hex_key", type=str, required=False, help="hexadecimal key of your network operator",
    )
    parser.add_argument(
        "-influxdb-host", dest="influxdb_host", type=str, required=False, help="InfluxDB host",
    )
    parser.add_argument(
        "-influxdb-user", dest="influxdb_user", type=str, required=False, help="InfluxDB username",
    )
    parser.add_argument(
        "-influxdb-pwd", dest="influxdb_pwd", type=str, required=False, help="InfluxDB password",
    )
    parser.add_argument(
        "-influxdb-db", dest="influxdb_db", type=str, required=False, help="InfluxDB database",
    )
    parser.add_argument("-v", dest="verbose", default=False)
    return parser


def _json_converter(source: Any) -> str | None:
    if isinstance(source, datetime.datetime):
        return source.isoformat()
    elif isinstance(source, decimal.Decimal):
        return float(source)
    return None


_decoder = autodecoder.AutoDecoder()

_influxdb_client: InfluxDBClient | None = None
_args: argparse.Namespace | None


def _measure_received(frame: bytes) -> None:
    decoded_frame = _decoder.decode_message_payload(frame)
    if decoded_frame:
        json_frame = json.dumps(decoded_frame, indent=4, default=_json_converter)
        print()
        LOG.debug("Decoded frame: %s", json_frame)

        if (
            _influxdb_client is None
            and _args.influxdb_host
            and _args.influxdb_user
            and _args.influxdb_pwd
            and _args.influxdb_db
        ):
            _influxdb_client = InfluxDBClient(
                host=_args.influxdb_host,
                username=_args.influxdb_user,
                password=_args.influxdb_pwd,
                database=_args.influxdb_db,
            )

        if _influxdb_client:
            influxdb_points = [
                {
                    "measurement": "kaifa_tinetz",
                    "tags": {
                        "meter_id": decoded_frame["meter_id"],
                        "meter_device_name": decoded_frame["meter_device_name"],
                    },
                    "fields": {
                        "voltage_l1": decoded_frame["voltage_l1"],
                        "voltage_l2": decoded_frame["voltage_l2"],
                        "voltage_l3": decoded_frame["voltage_l3"],
                        "current_l1": decoded_frame["current_l1"],
                        "current_l2": decoded_frame["current_l2"],
                        "current_l3": decoded_frame["current_l3"],
                        "active_power_import": decoded_frame["active_power_import"],
                        "active_power_export": decoded_frame["active_power_export"],
                        "active_power_import_total": decoded_frame["active_power_import_total"],
                        "active_power_export_total": decoded_frame["active_power_export_total"],
                        "reactive_power_import_total": decoded_frame["reactive_power_import_total"],
                        "reactive_power_export_total": decoded_frame["reactive_power_export_total"],
                    },
                }
            ]
            for _ in range(2):
                try:
                    _influxdb_client.write_points(influxdb_points)
                    break
                except Exception as ex1:
                    LOG.error(ex1)
                    time.sleep(1)
                    try:
                        _influxdb_client = InfluxDBClient(
                            host=_args.influxdb_host,
                            username=_args.influxdb_user,
                            password=_args.influxdb_pwd,
                            database=_args.influxdb_db,
                        )
                    except Exception as ex2:
                        LOG.error(ex2)
            else:
                _influxdb_client = None
    else:
        LOG.error("Could not decode frame content: %s", frame.hex())


async def _process_frames(queue: "Queue[bytes]") -> None:
    while True:
        frame = await queue.get()
        try:
            _measure_received(frame)
        except Exception as ex:
            LOG.error(ex)


async def main() -> None:
    """Start reading."""
    global _args
    args = _get_arg_parser().parse_args()
    _args = args
    loop = get_event_loop()

    queue: Queue[bytes] = Queue()

    create_task(_process_frames(queue))

    async def tcp_connection_factory() -> MeterTransportProtocol:
        host, port = args.hostandport
        return await create_tcp_message_payload_connection(queue, loop, None, host, port)

    async def serial_connection_factory() -> MeterTransportProtocol:
        return await create_serial_message_payload_connection(
            queue,
            None,
            [DlmsTinetzFrameReader(args.hex_key)],
            url=args.serialdevice,
            baudrate=args.ser_baudrate,
            parity=args.ser_parity,
        )

    connection_factory: AsyncConnectionFactory = (
        serial_connection_factory if args.serialdevice else tcp_connection_factory
    )

    if args.reconnect:
        # use high-level ConnectionManager
        connection_manager = ConnectionManager(connection_factory)
        loop.add_signal_handler(signal.SIGINT, connection_manager.close)
        await connection_manager.connect_loop()
    else:
        # use low-level transport and protocol
        transport, protocol = await connection_factory()
        loop.add_signal_handler(signal.SIGINT, transport.close)
        await protocol.done

    LOG.info("Done...")


if __name__ == "__main__":
    run(main())
