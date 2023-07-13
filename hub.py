import os
import sys
from enum import Enum
from http.client import HTTPConnection
import base64
import requests
import binascii
import json
import time

CRC_TABLE = [0, 29, 58, 39, 116, 105, 78, 83, 232, 245, 210, 207, 156, 129, 166, 187,
             205, 208, 247, 234, 185, 164, 131, 158, 37, 56, 31, 2, 81, 76, 107, 118,
             135, 154, 189, 160, 243, 238, 201, 212, 111, 114, 85, 72, 27, 6, 33, 60,
             74, 87, 112, 109, 62, 35, 4, 25, 162, 191, 152, 133, 214, 203, 236, 241,
             19, 14, 41, 52, 103, 122, 93, 64, 251, 230, 193, 220, 143, 146, 181, 168,
             222, 195, 228, 249, 170, 183, 144, 141, 54, 43, 12, 17, 66, 95, 120, 101,
             148, 137, 174, 179, 224, 253, 218, 199, 124, 97, 70, 91, 8, 21, 50, 47,
             89, 68, 99, 126, 45, 48, 23, 10, 177, 172, 139, 150, 197, 216, 255, 226,
             38, 59, 28, 1, 82, 79, 104, 117, 206, 211, 244, 233, 186, 167, 128, 157,
             235, 246, 209, 204, 159, 130, 165, 184, 3, 30, 57, 36, 119, 106, 77, 80,
             161, 188, 155, 134, 213, 200, 239, 242, 73, 84, 115, 110, 61, 32, 7, 26,
             108, 113, 86, 75, 24, 5, 34, 63, 132, 153, 190, 163, 240, 237, 202, 215,
             53, 40, 15, 18, 65, 92, 123, 102, 221, 192, 231, 250, 169, 180, 147, 142,
             248, 229, 194, 223, 140, 145, 182, 171, 16, 13, 42, 55, 100, 121, 94, 67,
             178, 175, 136, 149, 198, 219, 252, 225, 90, 71, 96, 125, 46, 51, 20, 9,
             127, 98, 69, 88, 11, 22, 49, 44, 151, 138, 173, 176, 227, 254, 217, 196]


def decode_uvarint(data: bytes) -> tuple[int, int]:
    value = 0
    shift = 0
    for byte in data:
        value |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            break
    return value, len(data[:shift // 7])


def encode_uvarint(num):
    result = b""

    while True:
        b = num & 0x7F
        num >>= 7

        if num:
            result += bytes([b | 0x80])
        else:
            result += bytes([b])
            break

    return result


def encode_base64(input_bytes: bytes, urlsafe: bool = True) -> str:
    """Encode bytes as an unpadded base64 string."""

    if urlsafe:
        encode = base64.urlsafe_b64encode
    else:
        encode = base64.b64encode

    output_bytes = encode(input_bytes)
    output_string = output_bytes.decode("ascii")
    return output_string.rstrip("=")


def decode_base64(input_bytes) -> bytes:
    """Decode an unpadded standard or urlsafe base64 string to bytes."""

    input_len = len(input_bytes)
    padding = b"=" * (3 - ((input_len + 3) % 4))

    # Passing altchars here allows decoding both standard and urlsafe base64
    output_bytes = base64.b64decode(input_bytes + padding, altchars=b"-_")
    return output_bytes


def crc8(bytes_str):
    crc = 0

    for byte in bytes_str:
        data = byte ^ crc
        crc = CRC_TABLE[data]

    return crc.to_bytes(length=1, byteorder='big')


def check_crc8(payload, checksum):
    calculated_checksum = crc8(payload)
    return int.from_bytes(calculated_checksum, byteorder='big') == checksum


def int2bytes(num: int) -> bytes:
    return num.to_bytes(length=1, byteorder='big')


class CMD(Enum):
    WHOISHERE = 0x01
    IAMHERE = 0x02
    GETSTATUS = 0x03
    STATUS = 0x04
    SETSTATUS = 0x05
    TICK = 0x06


class DeviceType(Enum):
    SmartHub = 0x01
    EnvSensor = 0x02
    Switch = 0x03
    Lamp = 0x04
    Socket = 0x05
    Clock = 0x06


class Device:
    dev_name: str
    dev_props: bytes  # много байт


class TimerCmdBody:
    pass


class Payload:
    src: int
    dst: int
    serial: int
    dev_type: DeviceType
    cmd: CMD
    cmd_body = None
    time_cmd_body: int
    dev_name: str = None
    dev_drop_dev_name_arr: list[str] = None
    value: int

    def __init__(self, payload_bytes):
        self._parse(payload_bytes)

    def _parse(self, payload_bytes):
        common_field_arr = []

        for _ in range(3):
            field, bytes_read = decode_uvarint(payload_bytes)
            common_field_arr.append(field)
            payload_bytes = payload_bytes[bytes_read:]

        self.src, self.dst, self.serial = common_field_arr
        self.dev_type, self.cmd = DeviceType(payload_bytes[0]), CMD(payload_bytes[1])
        payload_bytes = payload_bytes[2:]

        if self.cmd == CMD.TICK:
            self.timer_cmd_body, _ = decode_uvarint(payload_bytes)

        elif self.cmd == CMD.IAMHERE:
            if self.dev_type == DeviceType.Switch:
                dev_name_length = payload_bytes[0]
                self.dev_name = payload_bytes[1: dev_name_length + 1].decode()
                payload_bytes = payload_bytes[dev_name_length + 1:]
                dev_drop_size = payload_bytes[0]
                payload_bytes = payload_bytes[1:]
                self.dev_drop_dev_name_arr = []

                for _ in range(dev_drop_size):
                    connect_dev_name_length = payload_bytes[0]
                    connect_dev_name = payload_bytes[1: connect_dev_name_length + 1]
                    self.dev_drop_dev_name_arr.append(connect_dev_name.decode())
                    payload_bytes = payload_bytes[connect_dev_name_length + 1:]

            elif self.dev_type in [DeviceType.Clock, DeviceType.Lamp]:
                dev_name_length = payload_bytes[0]
                self.dev_name = payload_bytes[1: dev_name_length + 1].decode()

        elif self.cmd == CMD.STATUS:
            if self.dev_type in [DeviceType.Switch, DeviceType.Lamp, DeviceType.Socket]:
                self.value = payload_bytes[0]
            else:  # обработка EnvSensor
                pass


class Packet:
    def __init__(self, length: int, crc8: int, payload_bytes: bytes):
        if not check_crc8(payload_bytes, crc8):
            print("crc8 failed.")

        self.length = length
        self.payload = Payload(payload_bytes)
        self.crc8 = crc8

    def get_payload(self):
        return self.payload.__dict__


def convert_base64_to_packet(res) -> list[Packet]:
    packets = []
    bytes_string = decode_base64(res)

    while bytes_string:
        length = bytes_string[0]
        packets.append(Packet(length, bytes_string[length + 1], bytes_string[1:length + 1]))
        bytes_string = bytes_string[length + 2:]

    return packets


class Clock:
    def __init__(self, src, cmd_body):
        self.src = src
        self.cmd_body = cmd_body


class Socket:
    dev_type = DeviceType.Switch

    def __init__(self, src, cmd_body, value):
        self.src = src
        self.cmd_body = cmd_body
        self.value = value


class Switch:
    dev_type = DeviceType.Switch

    def __init__(self, src, cmd_body):
        self.src = src
        self.cmd_body = cmd_body


class Lamp:
    dev_type = DeviceType.Switch

    def __init__(self, src, cmd_body, value):
        self.src = src
        self.cmd_body = cmd_body
        self.value = value


class EnvSensor:
    def __init__(self, src, cmd_body):
        self.src = src
        self.cmd_body = cmd_body


class EnvSensorProps:
    pass


class EnvSensorCmdBody:
    pass


class SmartHub:
    def __init__(self, url, address):
        # r = requests.post('http://' + url)
        # print(r.text)
        self.src = int(address, 16)
        self.dev_name = 'SmartHub'
        self.dev_name_length = len(self.dev_name)
        self.dev_type = DeviceType.SmartHub.value
        self.conn = HTTPConnection(url)
        self.serial = 1
        self.network = {}
        self.timestamp = None

    def send_test(self):
        self.conn.request('POST', '')
        self._update(self.conn.getresponse().read())
        self.serial += 1

    def send_packet(self, cmd, **kwargs):
        if cmd == CMD.WHOISHERE:
            bytes_str = bytes()
            bytes_str += encode_uvarint(self.src)
            bytes_str += encode_uvarint(kwargs['dst'])
            bytes_str += encode_uvarint(self.serial)
            bytes_str += int2bytes(self.dev_type)
            bytes_str += int2bytes(cmd.value)
            bytes_str += int2bytes(self.dev_name_length) + self.dev_name.encode()
            bytes_str_size = len(bytes_str)
            bytes_str = int2bytes(bytes_str_size) + bytes_str + crc8(bytes_str)

            self.conn.request('POST', '', encode_base64(bytes_str).encode())
            self._update(self.conn.getresponse().read())
            self.serial += 1

        if cmd == CMD.SETSTATUS:
            bytes_str = bytes()
            bytes_str += encode_uvarint(self.src)
            bytes_str += encode_uvarint(kwargs['dst'])
            bytes_str += encode_uvarint(self.serial)
            bytes_str += int2bytes(kwargs['dev_type'])
            bytes_str += int2bytes(cmd.value)
            bytes_str += int2bytes(kwargs['value'])
            bytes_str_size = len(bytes_str)
            bytes_str = int2bytes(bytes_str_size) + bytes_str + crc8(bytes_str)

            self.conn.request('POST', '', encode_base64(bytes_str).encode())
            self._update(self.conn.getresponse().read())
            self.serial += 1

        if cmd == CMD.GETSTATUS:
            bytes_str = bytes()
            bytes_str += encode_uvarint(self.src)
            bytes_str += encode_uvarint(kwargs['dst'])
            bytes_str += encode_uvarint(self.serial)
            bytes_str += int2bytes(kwargs['dev_type'])
            bytes_str += int2bytes(cmd.value)
            bytes_str_size = len(bytes_str)
            bytes_str = int2bytes(bytes_str_size) + bytes_str + crc8(bytes_str)

            self.conn.request('POST', '', encode_base64(bytes_str).encode())
            self._update(self.conn.getresponse().read())
            self.serial += 1

    def _update(self, res):
        for packet in convert_base64_to_packet(res):
            payload = packet.get_payload()

            if payload['cmd'] == CMD.IAMHERE:
                self.network[payload['dev_name']] = {
                    'src': payload['src'],
                    'dev_type': payload['dev_type']
                }

            elif payload['cmd'] == CMD.TICK:
                self.timestamp = payload['timer_cmd_body']

            elif payload['cmd'] == CMD.STATUS:
                for dev_name, device in self.network.items():
                    if device['src'] == payload['src']:
                        device['value'] = payload['value']
                print(self.network)


def main():
    if len(sys.argv) < 3:
        print("Invalid command line arguments")
        sys.exit(1)

    smart_hub = SmartHub(sys.argv[1], sys.argv[2])
    smart_hub.send_packet(CMD.WHOISHERE, dst=0x3FFF)
    smart_hub.send_test()
    smart_hub.send_test()
    smart_hub.send_test()
    smart_hub.send_test()
    smart_hub.send_packet(CMD.GETSTATUS,
                          dst=smart_hub.network['LAMP02']['src'],
                          dev_type=smart_hub.network['LAMP02']['dev_type'].value)
    smart_hub.send_test()
    smart_hub.send_test()
    smart_hub.send_test()
    smart_hub.send_test()
    smart_hub.send_packet(CMD.SETSTATUS,
                          value=1,
                          dst=smart_hub.network['LAMP02']['src'],
                          dev_type=smart_hub.network['LAMP02']['dev_type'].value)
    smart_hub.send_test()
    smart_hub.send_test()
    smart_hub.send_test()
    smart_hub.send_test()
    print(smart_hub.network)


if __name__ == "__main__":
    main()
