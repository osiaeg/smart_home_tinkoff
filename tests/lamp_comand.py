from smarthub.enums import DeviceType, CMD

IAMHERE = {
    "payload": {
        "src": 4,
        "dst": 16383,
        "serial": 12,
        "dev_type": DeviceType(4),
        "cmd": CMD(2),
        "cmd_body": {"dev_name": "LAMP01"},
    }
}

STATUS = {
    "payload": {
        "src": 4,
        "dst": 1,
        "serial": 14,
        "dev_type": DeviceType(4),
        "cmd": CMD(4),
        "cmd_body": {"value": 1},
    }
}
