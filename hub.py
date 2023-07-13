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


class Switch:
    def __init__(self, src, cmd_body):
        self.src = src
        self.cmd_body = cmd_body


class Lamp:
    def __init__(self, src, cmd_body):
        self.src = src
        self.cmd_body = cmd_body


class EnvSensor:
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
    return output_string.rstrip("=").replace('/', '_')


def decode_base64(input_bytes) -> bytes:
    """Decode an unpadded standard or urlsafe base64 string to bytes."""

    input_len = len(input_bytes)
    padding = b"=" * (3 - ((input_len + 3) % 4))

    # Passing altchars here allows decoding both standard and urlsafe base64
    output_bytes = base64.b64decode(input_bytes + padding, altchars=b"-_")
    return output_bytes


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


def crc8(bytes_str):
    crc = 0

    for byte in bytes_str:
        data = byte ^ crc
        crc = CRC_TABLE[data]

    return crc.to_bytes(length=1, byteorder='big')


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


# def toBase(ayf):
#      ark = encode_uvarint(ayf[0][0])
#      # ark += encode_uvarint(ayf[dst])
#      # ark += encode_uvarint(ayf['serial'])
#      # ark += encode_uvarint(ayf['dev_type'])
#      # ark += encode_uvarint(ayf['cmd'])
#      # ark += encode_uvarint(ayf['cmd_body']['dev_name'])
#      # ark += encode_uvarint(ayf['cmd_body']['dev_drops'])
#      return ark

class SmartHub:
    def __init__(self, url, address):
        self.src = address
        self.dev_name = 'SmartHub'
        self.conn = HTTPConnection(url)
        self.serial = 1



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
    dev_name = "SmurtHub"
    who_is_here_dict = {
        'payload': {
            'src': src,
            'dst': dst,
            'serial': serial,
            'dev_type': dev_type,
            'cmd': cmd,
            'cmd_body': {
                'dev_name': dev_name,
                # 'dev_drops': None,
            }
        }
    }
    who_is_here_json = json.dumps([who_is_here_dict], indent=2)
    print(who_is_here_json)
    who_is_here_bytearray = bytes()
    who_is_here_bytearray += encode_uvarint(src)
    who_is_here_bytearray += encode_uvarint(dst)
    who_is_here_bytearray += encode_uvarint(serial)
    who_is_here_bytearray += dev_type.to_bytes(length=1, byteorder='big')
    who_is_here_bytearray += cmd.to_bytes(length=1, byteorder='big')
    dev_name_length = len(dev_name)
    who_is_here_bytearray += dev_name_length.to_bytes(length=1, byteorder='big') + dev_name.encode()
    who_is_here_size = len(who_is_here_bytearray)
    who_is_here_bytearray = who_is_here_size.to_bytes(length=1,
                                                      byteorder='big') + who_is_here_bytearray + crc8(who_is_here_bytearray)

    print(encode_base64(who_is_here_bytearray))
    test_whoishere_base64 = "EPAd_38BAQEIU211cnRIdWIt"
    print(f"Base64 for WHOISHERE: {test_whoishere_base64}")

    conn.close()


if __name__ == "__main__":
    main()
