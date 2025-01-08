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
