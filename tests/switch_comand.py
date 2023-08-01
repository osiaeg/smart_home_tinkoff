from smarthub.enums import DeviceType, CMD

IAMHERE = {
    "payload": {
        "src": 3,
        "dst": 16383,
        "serial": 8,
        "dev_type": DeviceType(3),
        "cmd": CMD(2),
        "cmd_body": {
            "dev_name": "SWITCH01",
            "dev_props": {
                "dev_names": [
                    "DEV01",
                    "DEV02",
                    "DEV03"
                ]
            }
        }
    }
}

STATUS = {
    "payload": {
        "src": 3,
        "dst": 1,
        "serial": 10,
        "dev_type": DeviceType(3),
        "cmd": CMD(4),
        "cmd_body": {
            "value": 1
        }
    }
}
