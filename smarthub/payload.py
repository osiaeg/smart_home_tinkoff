from .enums import CMD, DeviceType
from .utils import decode_uvarint


class Payload:
    src: int
    dst: int
    serial: int
    dev_type: DeviceType
    cmd: CMD
    cmd_body = None
    time_cmd_body: int
    dev_name: str | None = None
    dev_drop_dev_name_arr: list[str] | None = None
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
            self.dev_name = payload_bytes[1 : dev_name_length + 1].decode()

            if self.dev_type == DeviceType.Switch:
                payload_bytes = payload_bytes[dev_name_length + 1 :]
                dev_drop_size = payload_bytes[0]
                payload_bytes = payload_bytes[1:]
                self.dev_drop_dev_name_arr = []

                for _ in range(dev_drop_size):
                    connect_dev_name_length = payload_bytes[0]
                    connect_dev_name = payload_bytes[1 : connect_dev_name_length + 1]
                    self.dev_drop_dev_name_arr.append(connect_dev_name.decode())
                    payload_bytes = payload_bytes[connect_dev_name_length + 1 :]

            elif self.dev_type == DeviceType.EnvSensor:
                payload_bytes = payload_bytes[dev_name_length + 1 :]
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
                    tigger_name = payload_bytes[1 : dev_name_length + 1].decode()
                    payload_bytes = payload_bytes[dev_name_length + 1 :]
                    tigger = {"op": op, "value": value, "name": tigger_name}
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
