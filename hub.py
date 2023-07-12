import os
import sys
from enum import Enum
from http.client import HTTPConnection
import base64
import binascii
import json
import time
import uvarint


class CMD(Enum):
    WHOISHERE = 0x01
    IAMHERE = 0x02
    GETSTATUS = 0x03
    STATUS = 0x04
    SETSTATUS = 0x05
    TICK = 0x06


class Device:
    dev_name: str
    dev_props: bytes  # много байт


class DeviceType(Enum):
    SmartHub = 0x01
    EnvSensor = 0x02
    Switch = 0x03
    Lamp = 0x04
    Socket = 0x05
    Clock = 0x06


class TimerCmdBody:
    pass


def decode_uvarint(data: bytes) -> tuple[int, int]:
    value = 0
    shift = 0
    for byte in data:
        value |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            break
    return value, len(data[:shift // 7])


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


class Packet:
    def __init__(self, length: int, crc8: int, payload_bytes: bytes):
        self.length = length
        self.payload = Payload(payload_bytes)
        self.crc8 = crc8


class Clock:
    def __init__(self, src, cmd_body):
        self.src = src
        self.cmd_body = cmd_body

class Socket:
    def __init__(self, src, cmd_body):
        self.src = src
        self.cmd_body = cmd_body

class EnvSensorProps:
    pass


class EnvSensorCmdBody:
    pass


def encode_base64(input_bytes: bytes, urlsafe: bool = False) -> str:
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


def crc8(data):
    crc = 0

    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0xD5  # Возможно надо поменять кодировку
            else:
                crc <<= 1

    return crc


def check_crc8(payload, checksum):
    calculated_checksum = crc8(payload)
    return calculated_checksum == checksum


# Пример использования:
def check_date():
    payload = [0x01, 0x02, 0x03]
    crc_8 = 0xFA

    if check_crc8(payload, crc_8):
        print("Контрольная сумма корректна.")
    else:
        print("Контрольная сумма некорректна.")  # Надо отправить запрос на повторное отправление данных


def convert_base64_to_packet(res) -> list[Packet]:
    packets = []
    bytes_string = decode_base64(res)

    while bytes_string:
        length = bytes_string[0]
        packets.append(Packet(length, bytes_string[length + 1], bytes_string[1:length + 1]))
        bytes_string = bytes_string[length + 2:]

    return packets


def encode_uvarint(num):
    result = b""

    while True:
        # Младшие 7 битов числа
        b = num & 0x7F
        num >>= 7

        if num:
            # Если есть еще байты, устанавливаем младший бит в 1
            result += bytes([b | 0x80])
        else:
            # Если больше нет байтов, устанавливаем младший бит в 0
            result += bytes([b])
            break

    return result


def main():
    if len(sys.argv) < 3:
        print("Invalid command line arguments")
        sys.exit(1)
    url = sys.argv[1]
    hub_adress = sys.argv[2]

    conn = HTTPConnection(url)
    conn.request('POST', "", b'EPAd_38BAQEIU211cnRIdWIt')
    response = conn.getresponse().read()
    for packet in convert_base64_to_packet(response):
        print(packet.__dict__)
    base64_string = response.decode()
    print(base64_string)

    bytes_string = decode_base64(response)
    length = bytes_string[0]
    src = decode_uvarint(bytes_string[1:])[0]
    dst = uvarint.decode(bytes_string[3:5]).integer
    serial = uvarint.decode(bytes_string[5:7]).integer
    dev_type = bytes_string[6]
    cmd = bytes_string[7]
    timestamp = uvarint.decode(bytes_string[8:14]).integer
    crc_8 = bytes_string[-1]

    json_string = json.dumps([{
        'length': length,
        'payload': {
            'src': src,
            'dst': dst,
            'serial': serial,
            'dev_type': dev_type,
            'cmd': cmd,
            'cmd_body': {
                'timestamp': timestamp
            }
        },
        'crc8': crc_8
    }], indent=4)
    print(json_string)
    print('-' * 20)

    src = int(hub_adress, 16)
    dst = 16383
    serial = 1
    dev_type = DeviceType.SmartHub.value
    cmd = CMD.WHOISHERE.value
    who_is_here_json = json.dumps([{
        'payload': {
            'src': src,
            'dst': dst,
            'serial': serial,
            'dev_type': dev_type,
            'cmd': cmd,
            'cmd_body': {
                'dev_name': 'SmurtHub',
                'dev_drops': None,
            }
        }
    }])
    print(who_is_here_json)

    test_whoishere_base64 = "EPAd_38BAQEIU211cnRIdWIt"
    print(f"Base64 for WHOISHERE: {test_whoishere_base64}")

    conn.close()


if __name__ == "__main__":
    main()
