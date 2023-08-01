from smarthub.enums import DeviceType, CMD

IAMHERE = {
    "payload": {
        "src": 6,
        "dst": 16383,
        "serial": 21,
        "dev_type": DeviceType(6),
        "cmd": CMD(2),
        "cmd_body": {
            "dev_name": "CLOCK01"
        }
    }
}

TICK = {
    "payload": {
        "src": 6,
        "dst": 16383,
        "serial": 24,
        "dev_type": DeviceType(6),
        "cmd": CMD(6),
        "cmd_body": {
            "timestamp": 1801393098134
        }
    }
}
