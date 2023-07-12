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
    dev_props: bytes # много байт


class DeviceType(Enum):
    SmartHub = 0x01
    EnvSensor = 0x02
    Switch = 0x03
    Lamp = 0x04
    Socket = 0x05
    Clock = 0x06


class TimerCmdBody:
    pass


class Playload:
    src: uvarint.Number
    dst: uvarint.Number
    serial: uvarint.Number
    dev_type: bytes
    cmd: bytes = 0x01
    cmd_body = None
    if CMD(cmd) in [CMD.WHOISHERE, CMD.IAMHERE]:
        cmd_body: Device
    elif CMD(cmd) == CMD.TICK:
        cmd_body: TimerCmdBody


class Packet:
    length: bytes
    playload: Playload
    crc_8: bytes


class Clock():


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


def decode_uvarint(data):
    value = 0
    shift = 0
    for byte in data:
        value |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            break
    return value, len(data[:shift//7])


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
    conn.request('POST', "")
    response = conn.getresponse().read()
    base64_string = response.decode()
    print(base64_string)

    bytes_string = decode_base64(response)
    length = bytes_string[0]
    src = decode_uvarint(bytes_string[1:])[0]
    # src = uvarint.decode(bytes_string[1:3]).integer
    dst = uvarint.decode(bytes_string[3:5]).integer
    # serial = int.from_bytes(bytes_string[5:7], 'big')
    serial = uvarint.decode(bytes_string[5:7]).integer
    dev_type = bytes_string[6]
    cmd = bytes_string[7]
    # timestamp = int.from_bytes(bytes_string[8:14], 'big')
    timestamp = uvarint.decode(bytes_string[8:14]).integer
    crc_8 = bytes_string[-1]

    json_string = json.dumps([{
        'length': length,
        'playload': {
            'src': src,
            'dst': dst,
            'serial': serial,
            'dev_typ': dev_type,
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
        'playload': {
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
    }], indent=4)
    print(who_is_here_json)

    conn.close()


if __name__ == "__main__":
    main()
