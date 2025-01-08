from ..payload import Payload


class Package:
    def __init__(self, length: int, crc8: int, payload_bytes: bytes):
        self.length = length
        self.payload = Payload(payload_bytes)
        self.crc8 = crc8

    def get_payload(self):
        return self.payload.__dict__
