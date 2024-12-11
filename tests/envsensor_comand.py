from smarthub.enums import DeviceType, CMD

IAMHERE = {
    "payload": {
        "src": 2,
        "dst": 16383,
        "serial": 4,
        "dev_type": DeviceType(2),
        "cmd": CMD(2),
        "cmd_body": {
            "dev_name": "SENSOR01",
            "dev_props": {
                "sensors": 15,
                "triggers": [
                    {"op": 12, "value": 100, "name": "OTHER1"},
                    {"op": 15, "value": 1200, "name": "OTHER2"},
                    {"op": 0, "value": 100012, "name": "OTHER3"},
                    {"op": 8, "value": 0, "name": "OTHER4"},
                ],
            },
        },
    }
}

STATUS = {
    "payload": {
        "src": 2,
        "dst": 1,
        "serial": 6,
        "dev_type": DeviceType(2),
        "cmd": CMD(4),
        "cmd_body": {"values": [165, 992, 100180, 24938124]},
    }
}
