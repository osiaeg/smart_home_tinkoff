from io import BytesIO

from .enums import CMD, DeviceType
from .uleb128 import u


class Payload:
    src: int
    dst: int
    serial: int
    dev_type: DeviceType
    cmd: CMD
    cmd_body: dict
    time_cmd_body: int
    dev_name: str | None = None
    dev_drop_dev_name_arr: list[str] | None = None
    value: int
    sensors: int

    def __init__(self, payload_bytes):
        self._parse(payload_bytes)

    def _parse(self, payload_bytes):
        fields = ["src", "dst", "serial", "dev_type", "cmd"]
        with BytesIO(payload_bytes) as bytes_stream:
            bytes_readed = 0
            for field in fields:
                value, byte = u.decode_reader(bytes_stream)
                bytes_readed += byte
                setattr(self, field, value)
            bytes_stream.seek(bytes_readed)
            self.cmd = CMD(self.cmd)
            self.dev_type = DeviceType(self.dev_type)
            self.__parse_cmd_body(bytes_stream.read())

    def __parse_one_byte(self, cmd_body: BytesIO) -> int:
        return int.from_bytes(cmd_body.read(1))

    def __parse_devname(self, cmd_body: BytesIO) -> None:
        dev_name_length = self.__parse_one_byte(cmd_body)
        dev_name = cmd_body.read(dev_name_length).decode()
        self.cmd_body = {"dev_name": dev_name}

    def __parse_env_sensor_props(self, cmd_body: BytesIO) -> None:
        sensors = self.__parse_one_byte(cmd_body)
        tiggers_length = self.__parse_one_byte(cmd_body)
        triggers = []

        for _ in range(tiggers_length):
            op = self.__parse_one_byte(cmd_body)
            value, _ = u.decode_reader(cmd_body)
            dev_name_length = self.__parse_one_byte(cmd_body)
            tigger_name = cmd_body.read(dev_name_length).decode()
            tigger = {"op": op, "value": value, "name": tigger_name}
            triggers.append(tigger)

        self.cmd_body["dev_props"] = {"sensors": sensors, "triggers": triggers}

    def __parse_switch_dev_names(self, cmd_body: BytesIO) -> None:
        dev_drop_size = self.__parse_one_byte(cmd_body)
        dev_drop_dev_name_arr = []

        for _ in range(dev_drop_size):
            connect_dev_name_length = self.__parse_one_byte(cmd_body)
            connect_dev_name = cmd_body.read(connect_dev_name_length).decode()
            dev_drop_dev_name_arr.append(connect_dev_name)

        self.cmd_body["dev_props"] = {"dev_names": dev_drop_dev_name_arr}

    def __parse_tick(self, cmd_body: BytesIO) -> None:
        timestamp, _ = u.decode_reader(cmd_body)
        self.cmd_body = {"timestamp": timestamp}

    def __parse_iamhere(self, cmd_body: BytesIO) -> None:
        self.__parse_devname(cmd_body)

        if self.dev_type == DeviceType.Switch:
            self.__parse_switch_dev_names(cmd_body)
        elif self.dev_type == DeviceType.EnvSensor:
            self.__parse_env_sensor_props(cmd_body)

    def __parse_whoishere(self, cmd_body: BytesIO) -> None:
        self.__parse_devname(cmd_body)

        if self.dev_type == DeviceType.EnvSensor:
            self.__parse_env_sensor_props(cmd_body)
        elif self.dev_type == DeviceType.Switch:
            self.__parse_switch_dev_names(cmd_body)

    def __parse_status(self, cmd_body: BytesIO) -> None:
        if self.dev_type in [
            DeviceType.Switch,
            DeviceType.Lamp,
            DeviceType.Socket,
        ]:
            self.cmd_body = {"value": self.__parse_one_byte(cmd_body)}
        else:
            value = []
            value_size = self.__parse_one_byte(cmd_body)
            for _ in range(value_size):
                v, _ = u.decode_reader(cmd_body)
                value.append(v)
            self.cmd_body = {"values": value}

    def __parse_getstatus(self, cmd_body: BytesIO) -> None:
        pass

    def __parse_setstatus(self, cmd_body: BytesIO) -> None:
        self.__parse_status(cmd_body)

    def __parse_cmd_body(self, cmd_body: bytes) -> None:
        PARSERS = {
            CMD.TICK: self.__parse_tick,
            CMD.IAMHERE: self.__parse_iamhere,
            CMD.STATUS: self.__parse_status,
            CMD.WHOISHERE: self.__parse_whoishere,
            CMD.GETSTATUS: self.__parse_getstatus,
            CMD.SETSTATUS: self.__parse_setstatus,
        }
        with BytesIO(cmd_body) as c:
            parser = PARSERS[self.cmd]
            parser(c)
