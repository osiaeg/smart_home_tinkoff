import sys

import requests

from .utils import (
    decode_uvarint,
    encode_base64,
    decode_base64,
    decode_packet,
    encode_uvarint,
    int2bytes,
    crc8,
    check_crc8,
    split_decoded_packets,
)
from .enums import CMD, DeviceType
from .packet.packet import Packet
from loguru import logger


def convert_base64_to_packet(res) -> list[Packet]:
    packets = []
    try:
        bytes_string = decode_base64(res)
        while bytes_string:
            length = bytes_string[0]
            if check_crc8(bytes_string[1 : length + 1], bytes_string[length + 1]):
                packets.append(
                    Packet(
                        length, bytes_string[length + 1], bytes_string[1 : length + 1]
                    )
                )
            bytes_string = bytes_string[length + 2 :]
    except Exception as e:
        logger.warning(e)
        return []

    return packets


class SmartHub:
    def __init__(self, url, address):
        self.url = url
        self.src = address
        self.dev_name = "HUB01"
        self.dev_name_length = len(self.dev_name)
        self.dev_type = DeviceType.SmartHub.value
        self.serial = 1
        self.network = {}
        self.timestamp = None

    def request(self, data=None) -> list[dict]:
        if data:
            response = requests.post(self.url, data)
        else:
            response = requests.post(self.url)
        self.serial += 1

        if response.status_code == 204:
            sys.exit(0)

        if decoded_packet := decode_packet(response.content):
            return [
                self.parse_packet(packet)
                for packet in split_decoded_packets(decoded_packet)
            ]

    def parse_packet(self, payload) -> dict:
        src, bytes_read = decode_uvarint(payload)
        payload = payload[bytes_read:]
        dst, bytes_read = decode_uvarint(payload)
        payload = payload[bytes_read:]
        serial, bytes_read = decode_uvarint(payload)
        payload = payload[bytes_read:]
        dev_type = DeviceType(payload[0])
        payload = payload[1:]
        cmd = CMD(payload[0])
        payload = payload[1:]
        message = {
            "payload": {
                "src": src,
                "dst": dst,
                "serial": serial,
                "dev_type": dev_type,
                "cmd": cmd,
            }
        }
        if cmd == CMD.TICK:
            timestamp, bytes_read = decode_uvarint(payload)
            payload = payload[bytes_read:]
            self.timestamp = int(timestamp)
            message["payload"]["cmd_body"] = {"timestamp": timestamp}
        elif cmd == CMD.IAMHERE:
            if dev_type == DeviceType.EnvSensor:
                cmd_body = {}
                dev_name_length = payload[0]
                dev_name = payload[1 : dev_name_length + 1].decode()
                payload = payload[dev_name_length + 1 :]
                cmd_body["dev_name"] = dev_name
                dev_props = {}
                sensors = payload[0]
                payload = payload[1:]
                dev_props["sensors"] = sensors
                triggers_size = payload[0]
                payload = payload[1:]
                triggers = []
                for _ in range(triggers_size):
                    op = payload[0]
                    payload = payload[1:]
                    value, bytes_read = decode_uvarint(payload)
                    payload = payload[bytes_read:]
                    name_length = payload[0]
                    name = payload[1 : name_length + 1].decode()
                    payload = payload[name_length + 1 :]

                    trigger = {
                        "op": op,
                        "value": value,
                        "name": name,
                    }
                    triggers.append(trigger)
                dev_props["triggers"] = triggers
                cmd_body["dev_props"] = dev_props
                message["payload"]["cmd_body"] = cmd_body

            elif dev_type == DeviceType.Switch:
                dev_name_length = payload[0]
                dev_name = payload[1 : dev_name_length + 1].decode()
                payload = payload[dev_name_length + 1 :]
                dev_drop_size = payload[0]
                payload = payload[1:]
                dev_drop_dev_name_arr = []

                for _ in range(dev_drop_size):
                    connect_dev_name_length = payload[0]
                    connect_dev_name = payload[1 : connect_dev_name_length + 1]
                    dev_drop_dev_name_arr.append(connect_dev_name.decode())
                    payload = payload[connect_dev_name_length + 1 :]

                dev_props = {
                    "dev_names": dev_drop_dev_name_arr,
                }
                cmd_body = {
                    "dev_name": dev_name,
                    "dev_props": dev_props,
                }
                message["payload"]["cmd_body"] = cmd_body
            elif dev_type in (DeviceType.Lamp, DeviceType.Socket, DeviceType.Clock):
                dev_name_length = payload[0]
                dev_name = payload[1 : dev_name_length + 1].decode()
                payload = payload[dev_name_length + 1 :]
                cmd_body = {
                    "dev_name": dev_name,
                }
                message["payload"]["cmd_body"] = cmd_body
        elif cmd == CMD.STATUS:
            if dev_type == DeviceType.EnvSensor:
                values_size = payload[0]
                payload = payload[1:]
                values_arr = []

                for _ in range(values_size):
                    value, bytes_read = decode_uvarint(payload)
                    payload = payload[bytes_read:]
                    values_arr.append(value)

                cmd_body = {
                    "values": values_arr,
                }
                message["payload"]["cmd_body"] = cmd_body
            elif dev_type in (DeviceType.Switch, DeviceType.Lamp, DeviceType.Socket):
                value = payload[0]
                payload = payload[1:]
                cmd_body = {
                    "value": value,
                }
                message["payload"]["cmd_body"] = cmd_body

        return message

    def get_cmd_base64(self, cmd, **kwargs):
        bytes_str = bytes()
        bytes_str += encode_uvarint(self.src)
        bytes_str += encode_uvarint(kwargs["dst"])
        bytes_str += encode_uvarint(self.serial)

        if cmd == CMD.WHOISHERE:
            bytes_str += int2bytes(self.dev_type)
            bytes_str += int2bytes(cmd.value)
            bytes_str += int2bytes(self.dev_name_length) + self.dev_name.encode()

        if cmd == CMD.SETSTATUS:
            bytes_str += int2bytes(kwargs["dev_type"])
            bytes_str += int2bytes(cmd.value)
            bytes_str += int2bytes(kwargs["value"])

        if cmd == CMD.GETSTATUS:
            bytes_str += int2bytes(kwargs["dev_type"])
            bytes_str += int2bytes(cmd.value)

        bytes_str_size = len(bytes_str)
        bytes_str = int2bytes(bytes_str_size) + bytes_str + crc8(bytes_str)
        return encode_base64(bytes_str)

    def send_WHOISHERE(self):
        pass

    def send_packet(self, packet_bytes):
        self.conn.request("POST", "", encode_base64(packet_bytes).encode())
        self.serial += 1
        response = self.conn.getresponse()
        self.update(response.read())
        return response.status

    def update(self, res):
        for packet in convert_base64_to_packet(res):
            payload = packet.get_payload()

            if payload["cmd"] == CMD.IAMHERE:
                if payload["dev_type"] == DeviceType.EnvSensor:
                    self.network[payload["src"]] = {
                        "src": payload["src"],
                        "dev_name": payload["dev_name"],
                        "dev_type": payload["dev_type"],
                        "sensors": payload["sensors"],
                        "triggers": payload["triggers"],
                    }
                elif payload["dev_type"] == DeviceType.Switch:
                    self.network[payload["src"]] = {
                        "src": payload["src"],
                        "dev_name": payload["dev_name"],
                        "dev_type": payload["dev_type"],
                        "dev_props": payload["dev_drop_dev_name_arr"],
                    }
                else:
                    self.network[payload["src"]] = {
                        "src": payload["src"],
                        "dev_name": payload["dev_name"],
                        "dev_type": payload["dev_type"],
                    }

            elif payload["cmd"] == CMD.TICK:
                self.timestamp = payload["timer_cmd_body"]

            elif payload["cmd"] == CMD.STATUS:
                if payload["dev_type"] == DeviceType.Switch:
                    switch = self.network[payload["src"]]
                    if "value" in switch:
                        switch_value = switch["value"]
                        if switch_value != payload["value"]:
                            cmd_SETSTATUS_all = b""
                            for dev_name in switch["dev_props"]:
                                for device in self.network.values():
                                    if device["dev_name"] == dev_name:
                                        cmd_SETSTATUS_all += self.get_cmd_bytes(
                                            CMD.SETSTATUS,
                                            value=payload["value"],
                                            dst=device["src"],
                                            dev_type=device["dev_type"].value,
                                        )
                            self.send_packet(cmd_SETSTATUS_all)

                        switch["value"] = payload["value"]
                    else:
                        switch["value"] = payload["value"]
                elif payload["dev_type"] == DeviceType.EnvSensor:
                    env = self.network[payload["src"]]
                    for op, value, name in env["triggers"]:
                        on_bin = bin(op)[2:]
                        if int(on_bin[0]):
                            if int(on_bin[1]):
                                if value < payload["value"][int(on_bin[2:4])]:
                                    for device in self.network.values():
                                        if device["dev_name"] == name:
                                            cmd_SETSTATUS_all += self.get_cmd_bytes(
                                                CMD.SETSTATUS,
                                                value=1,
                                                dst=device["src"],
                                                dev_type=device["dev_type"].value,
                                            )
                                    self.send_packet(cmd_SETSTATUS_all)
                            else:
                                if value > payload["value"][int(on_bin[2:4])]:
                                    for device in self.network.values():
                                        if device["dev_name"] == name:
                                            cmd_SETSTATUS_all += self.get_cmd_bytes(
                                                CMD.SETSTATUS,
                                                value=1,
                                                dst=device["src"],
                                                dev_type=device["dev_type"].value,
                                            )
                                    self.send_packet(cmd_SETSTATUS_all)
                        else:
                            if int(on_bin[1]):
                                if value < payload["value"][int(on_bin[2:4])]:
                                    for device in self.network.values():
                                        if device["dev_name"] == name:
                                            cmd_SETSTATUS_all += self.get_cmd_bytes(
                                                CMD.SETSTATUS,
                                                value=0,
                                                dst=device["src"],
                                                dev_type=device["dev_type"].value,
                                            )
                                    self.send_packet(cmd_SETSTATUS_all)
                            else:
                                if value > payload["value"][int(on_bin[2:4])]:
                                    for device in self.network.values():
                                        if device["dev_name"] == name:
                                            cmd_SETSTATUS_all += self.get_cmd_bytes(
                                                CMD.SETSTATUS,
                                                value=0,
                                                dst=device["src"],
                                                dev_type=device["dev_type"].value,
                                            )
                                    self.send_packet(cmd_SETSTATUS_all)
                        pass
                else:
                    for dev_name, device in self.network.items():
                        if device["src"] == payload["src"]:
                            device["value"] = payload["value"]
