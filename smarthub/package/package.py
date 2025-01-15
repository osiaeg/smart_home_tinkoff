import json

from ..enums import CMD, DeviceType
from ..payload import Payload


class PackageJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Package):
            return {"length": o.length, "payload": o.get_payload(), "crc8": o.crc8}
        elif isinstance(o, DeviceType | CMD):
            return o.name
        return super().default(o)


class Package:
    def __init__(self, length: int, crc8: int, payload_bytes: bytes):
        self.length = length
        self.payload = Payload(payload_bytes)
        self.crc8 = crc8

    def get_payload(self):
        return self.payload.__dict__

    def __str__(self):
        return json.dumps(self, cls=PackageJSONEncoder, indent=4)
