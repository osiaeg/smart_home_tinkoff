import base64

from loguru import logger

from ..utils import check_crc8
from .package import Package


class PackageDecoder:
    def __decode_base64(self, input_bytes) -> bytes:
        """Decode an unpadded standard or urlsafe base64 string to bytes."""

        input_len = len(input_bytes)
        padding = b"=" * (3 - ((input_len + 3) % 4))

        # Passing altchars here allows decoding both standard and urlsafe base64
        output_bytes = base64.b64decode(input_bytes + padding, altchars=b"-_")
        return output_bytes

    def decode(self, res) -> list[Package]:
        """Decode bytes string to array of Package objects"""
        packets = []
        try:
            bytes_string = self.__decode_base64(res)
            while bytes_string:
                length = bytes_string[0]
                payload = bytes_string[1 : length + 1]
                crc8 = bytes_string[length + 1]
                bytes_string = bytes_string[length + 2 :]
                if check_crc8(payload, crc8):
                    package = Package(length, crc8, payload)
                    packets.append(package)
                else:
                    logger.warning("Message is broken. Check crc8 is failed.")
                    continue
        except Exception as e:
            logger.warning(e)
            return []

        return packets
