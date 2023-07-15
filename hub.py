import os
import sys
from enum import Enum
from http.client import HTTPConnection
import base64
import requests

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
    sensors: int

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
            dev_name_length = payload_bytes[0]
            self.dev_name = payload_bytes[1: dev_name_length + 1].decode()

            if self.dev_type == DeviceType.Switch:
                payload_bytes = payload_bytes[dev_name_length + 1:]
                dev_drop_size = payload_bytes[0]
                payload_bytes = payload_bytes[1:]
                self.dev_drop_dev_name_arr = []

                for _ in range(dev_drop_size):
                    connect_dev_name_length = payload_bytes[0]
                    connect_dev_name = payload_bytes[1: connect_dev_name_length + 1]
                    self.dev_drop_dev_name_arr.append(connect_dev_name.decode())
                    payload_bytes = payload_bytes[connect_dev_name_length + 1:]

            elif self.dev_type == DeviceType.EnvSensor:
                payload_bytes = payload_bytes[dev_name_length + 1:]
                self.sensors = payload_bytes[0]
                payload_bytes = payload_bytes[1:]
                tiggers_length = payload_bytes[0]
                payload_bytes = payload_bytes[1:]
                self.triggers = []
                for _ in range(tiggers_length):
                    op = payload_bytes[0]
                    payload_bytes = payload_bytes[1:]
                    value, bytes_read = decode_uvarint(payload_bytes)
                    payload_bytes = payload_bytes[bytes_read:]
                    dev_name_length = payload_bytes[0]
                    tigger_name = payload_bytes[1: dev_name_length + 1].decode()
                    payload_bytes = payload_bytes[dev_name_length + 1:]
                    tigger = {'op': op, 'value': value, 'name': tigger_name}
                    self.triggers.append(tigger)

        elif self.cmd == CMD.STATUS:
            if self.dev_type in [DeviceType.Switch, DeviceType.Lamp, DeviceType.Socket]:
                self.value = payload_bytes[0]
            else:
                value_size = payload_bytes[0]
                payload_bytes = payload_bytes[1:]
                for _ in range(value_size):
                    value, bytes_read = decode_uvarint(payload_bytes)
                    payload_bytes = payload_bytes[bytes_read:]
                    self.value.append(value)
                pass


class Packet:
    def __init__(self, length: int, crc8: int, payload_bytes: bytes):
        self.length = length
        self.payload = Payload(payload_bytes)
        self.crc8 = crc8

    def get_payload(self):
        return self.payload.__dict__


def convert_base64_to_packet(res) -> list[Packet]:
    packets = []
    try:
        bytes_string = decode_base64(res)
        while bytes_string:
            length = bytes_string[0]
            if check_crc8(bytes_string[1:length + 1], bytes_string[length + 1]):
                packets.append(Packet(length, bytes_string[length + 1], bytes_string[1:length + 1]))
            bytes_string = bytes_string[length + 2:]
    except:
        return []

    return packets


class SmartHub:
    def __init__(self, url, address):
        self.src = int(address, 16)
        self.dev_name = 'HUB01'
        self.dev_name_length = len(self.dev_name)
        self.dev_type = DeviceType.SmartHub.value
        self.conn = HTTPConnection(url)
        self.serial = 1
        self.network = {}
        self.timestamp = None

    def get_cmd_bytes(self, cmd, **kwargs):
        bytes_str = bytes()
        bytes_str += encode_uvarint(self.src)
        bytes_str += encode_uvarint(kwargs['dst'])
        bytes_str += encode_uvarint(self.serial)

        if cmd == CMD.WHOISHERE:
            bytes_str += int2bytes(self.dev_type)
            bytes_str += int2bytes(cmd.value)
            bytes_str += int2bytes(self.dev_name_length) + self.dev_name.encode()

        if cmd == CMD.SETSTATUS:
            bytes_str += int2bytes(kwargs['dev_type'])
            bytes_str += int2bytes(cmd.value)
            bytes_str += int2bytes(kwargs['value'])

        if cmd == CMD.GETSTATUS:
            bytes_str += int2bytes(kwargs['dev_type'])
            bytes_str += int2bytes(cmd.value)

        bytes_str_size = len(bytes_str)
        bytes_str = int2bytes(bytes_str_size) + bytes_str + crc8(bytes_str)
        return bytes_str

    def send_test(self):
        self.conn.request('POST', '')
        self.serial += 1
        response = self.conn.getresponse()
        self.update(response.read())
        return response.status

    def send_packet(self, packet_bytes):
        self.conn.request('POST', '', encode_base64(packet_bytes).encode())
        self.serial += 1
        response = self.conn.getresponse()
        self.update(response.read())
        return response.status

    def update(self, res):
        for packet in convert_base64_to_packet(res):
            payload = packet.get_payload()

            if payload['cmd'] == CMD.IAMHERE:
                if payload['dev_type'] == DeviceType.EnvSensor:
                    self.network[payload['src']] = {
                        'src': payload['src'],
                        'dev_name': payload['dev_name'],
                        'dev_type': payload['dev_type'],
                        'sensors': payload['sensors'],
                        'triggers': payload['triggers']
                    }
                elif payload['dev_type'] == DeviceType.Switch:
                    self.network[payload['src']] = {
                        'src': payload['src'],
                        'dev_name': payload['dev_name'],
                        'dev_type': payload['dev_type'],
                        'dev_props': payload['dev_drop_dev_name_arr']
                    }
                else:
                    self.network[payload['src']] = {
                        'src': payload['src'],
                        'dev_name': payload['dev_name'],
                        'dev_type': payload['dev_type']
                    }

            elif payload['cmd'] == CMD.TICK:
                self.timestamp = payload['timer_cmd_body']

            elif payload['cmd'] == CMD.STATUS:
                if payload['dev_type'] == DeviceType.Switch:
                    switch = self.network[payload['src']]
                    if 'value' in switch:
                        switch_value = switch['value']
                        if switch_value != payload['value']:
                            cmd_SETSTATUS_all = b''
                            for dev_name in switch['dev_props']:
                                for device in self.network.values():
                                    if device['dev_name'] == dev_name:
                                        cmd_SETSTATUS_all += self.get_cmd_bytes(CMD.SETSTATUS,
                                                                                value=payload['value'],
                                                                                dst=device['src'],
                                                                                dev_type=device['dev_type'].value)
                            self.send_packet(cmd_SETSTATUS_all)

                        switch['value'] = payload['value']
                    else:
                        switch['value'] = payload['value']
                elif payload['dev_type'] == DeviceType.EnvSensor:
                    env = self.network[payload['src']]
                    for op, value, name in env['triggers']:
                        on_bin = bin(op)[2:]
                        if int(on_bin[0]):
                            if int(on_bin[1]):
                                if value < payload['value'][int(on_bin[2:4])]:
                                    for device in self.network.values():
                                        if device['dev_name'] == name:
                                            cmd_SETSTATUS_all += self.get_cmd_bytes(CMD.SETSTATUS,
                                                                                    value=1,
                                                                                    dst=device['src'],
                                                                                    dev_type=device['dev_type'].value)
                                    self.send_packet(cmd_SETSTATUS_all)
                            else:
                                if value > payload['value'][int(on_bin[2:4])]:
                                    for device in self.network.values():
                                        if device['dev_name'] == name:
                                            cmd_SETSTATUS_all += self.get_cmd_bytes(CMD.SETSTATUS,
                                                                                    value=1,
                                                                                    dst=device['src'],
                                                                                    dev_type=device['dev_type'].value)
                                    self.send_packet(cmd_SETSTATUS_all)
                        else:
                            if int(on_bin[1]):
                                if value < payload['value'][int(on_bin[2:4])]:
                                    for device in self.network.values():
                                        if device['dev_name'] == name:
                                            cmd_SETSTATUS_all += self.get_cmd_bytes(CMD.SETSTATUS,
                                                                                    value=0,
                                                                                    dst=device['src'],
                                                                                    dev_type=device['dev_type'].value)
                                    self.send_packet(cmd_SETSTATUS_all)
                            else:
                                if value > payload['value'][int(on_bin[2:4])]:
                                    for device in self.network.values():
                                        if device['dev_name'] == name:
                                            cmd_SETSTATUS_all += self.get_cmd_bytes(CMD.SETSTATUS,
                                                                                    value=0,
                                                                                    dst=device['src'],
                                                                                    dev_type=device['dev_type'].value)
                                    self.send_packet(cmd_SETSTATUS_all)
                        pass
                else:
                    for dev_name, device in self.network.items():
                        if device['src'] == payload['src']:
                            device['value'] = payload['value']


def main():
    if len(sys.argv) < 3:
        sys.exit(99)

    smart_hub = SmartHub(sys.argv[1], sys.argv[2])
    cmd_WHOISHERE = smart_hub.get_cmd_bytes(CMD.WHOISHERE, dst=0x3FFF)
    status = smart_hub.send_packet(cmd_WHOISHERE)

    command_timestamp = smart_hub.timestamp
    flag = True
    while status != 204:
        status = smart_hub.send_test()

        if (smart_hub.timestamp - command_timestamp >= 300) and flag:
            flag = False
            cmd_GETSTATUS_all = b''
            for device_name, device in smart_hub.network.items():
                cmd_GETSTATUS_all += smart_hub.get_cmd_bytes(CMD.GETSTATUS,
                                                             dst=device['src'],
                                                             dev_type=device['dev_type'].value)
            status = smart_hub.send_packet(cmd_GETSTATUS_all)


if __name__ == "__main__":
    try:
        main()
    except:
        sys.exit(99)
