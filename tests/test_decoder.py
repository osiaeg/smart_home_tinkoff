from smarthub.package.decoder import PackageDecoder
from smarthub.package.encoder import PackageJSONEncoder
import json

with open("tests/test_json.json") as f:
    cases = json.load(f)


def decode(msg):
    packages = PackageDecoder().decode(msg)
    return packages


def test_decoder():
    for case in cases:
        for name, data in case.items():
            packages = decode(data["msg"].encode())
            json_packets = json.dumps(packages, cls=PackageJSONEncoder)
            print(f"{name=}")
            assert json_packets == json.dumps(data["expect"])


def test_multipal_decoder():
    message = b"DYEg_38rBgbskaWyxDJbDoIg_38IBAIGTEFNUDAyZQ-BIP9_LAYCB1RJTUVSMDFq"
    expect = [
        {
            "length": 13,
            "payload": {
                "src": 4097,
                "dst": 16383,
                "serial": 43,
                "dev_type": 6,
                "cmd": 6,
                "cmd_body": {"timestamp": 1736345995500},
            },
            "crc8": 91,
        },
        {
            "length": 14,
            "payload": {
                "src": 4098,
                "dst": 16383,
                "serial": 8,
                "dev_type": 4,
                "cmd": 2,
                "cmd_body": {"dev_name": "LAMP02"},
            },
            "crc8": 101,
        },
        {
            "length": 15,
            "payload": {
                "src": 4097,
                "dst": 16383,
                "serial": 44,
                "dev_type": 6,
                "cmd": 2,
                "cmd_body": {"dev_name": "TIMER01"},
            },
            "crc8": 106,
        },
    ]

    packages = decode(message)
    json_packets = json.dumps(packages, cls=PackageJSONEncoder)
    assert json_packets == json.dumps(expect)
