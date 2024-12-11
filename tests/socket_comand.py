from smarthub.enums import DeviceType, CMD

IAMHERE = {
    "payload": {
        "src": 5,
        "dst": 16383,
        "serial": 17,
        "dev_type": DeviceType(5),
        "cmd": CMD(2),
        "cmd_body": {"dev_name": "SOCKET01"},
    }
}

STATUS = {
    "payload": {
        "src": 5,
        "dst": 1,
        "serial": 19,
        "dev_type": DeviceType(5),
        "cmd": CMD(4),
        "cmd_body": {"value": 1},
    }
}
