import json

from ..enums import CMD, DeviceType
from .package import Package


class PackageJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Package):
            return {"length": o.length, "payload": o.get_payload(), "crc8": o.crc8}
        elif isinstance(o, DeviceType | CMD):
            return o.value
        return super().default(o)
