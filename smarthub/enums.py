from enum import Enum


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
