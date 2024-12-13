from io import BytesIO


class _U:
    @staticmethod
    def encode(i: int) -> bytearray:
        """Encode the int i using unsigned leb128 and return the encoded bytearray."""
        assert i >= 0
        r = []
        while True:
            byte = i & 0x7F
            i = i >> 7
            if i == 0:
                r.append(byte)
                return bytearray(r)
            r.append(0x80 | byte)

    @staticmethod
    def decode(b: bytearray) -> int:
        """Decode the unsigned leb128 encoded bytearray."""
        r = 0
        for i, e in enumerate(b):
            r = r + ((e & 0x7F) << (i * 7))
        return r

    @staticmethod
    def decode_reader(r: BytesIO) -> tuple[int, int]:
        """
        Decode the unsigned leb128 encoded from a reader, it will return two values, the actual number and the number
        of bytes read.
        """
        a = bytearray()
        while True:
            b = r.read(1)
            if len(b) != 1:
                raise EOFError
            b = ord(b)
            a.append(b)
            if (b & 0x80) == 0:
                break
        return _U.decode(a), len(a)


u = _U()
