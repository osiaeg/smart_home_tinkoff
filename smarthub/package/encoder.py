import base64
from io import BytesIO

from ..enums import CMD
from ..uleb128 import u
from ..utils import crc8


class PackageEncoder:
    def __encode_base64(self, input_bytes: bytes, urlsafe: bool = True) -> str:
        """Encode bytes as an unpadded base64 string."""

        if urlsafe:
            encode = base64.urlsafe_b64encode
        else:
            encode = base64.b64encode

        output_bytes = encode(input_bytes)
        output_string = output_bytes.decode("ascii")
        return output_string.rstrip("=")

    def encode(self, package: dict) -> str:
        encoders = {CMD.WHOISHERE: self.__encode_whoishere}
        cmd = CMD(package["cmd"])
        encoder = encoders[cmd]
        value = encoder(package)

        package_lenght = self.__endcode_byte(len(value))
        package_crc8 = crc8(value)
        return self.__encode_base64(package_lenght + value + package_crc8)

    def __encode_whoishere(self, payload: dict) -> bytes:
        with BytesIO() as buffer:
            buffer.write(u.encode(payload["src"]))
            buffer.write(u.encode(payload["dst"]))
            buffer.write(u.encode(payload["serial"]))
            buffer.write(self.__endcode_byte(payload["dev_type"]))
            buffer.write(self.__endcode_byte(payload["cmd"]))
            buffer.write(self.__encode_string(payload["cmd_body"]["dev_name"]))
            value = buffer.getvalue()

        return value

    def __endcode_byte(self, num: int) -> bytes:
        return num.to_bytes(1, byteorder="big")

    def __encode_string(self, string: str) -> bytes:
        length = len(string)
        return self.__endcode_byte(length) + string.encode("utf-8")
