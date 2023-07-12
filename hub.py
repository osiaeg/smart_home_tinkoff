import os
import sys
from http.client import HTTPConnection
import base64
import binascii
import json
import time
import uvarint


def encode_base64(input_bytes: bytes, urlsafe: bool = False) -> str:
    """Encode bytes as an unpadded base64 string."""

    if urlsafe:
        encode = base64.urlsafe_b64encode
    else:
        encode = base64.b64encode

    output_bytes = encode(input_bytes)
    output_string = output_bytes.decode("ascii")
    return output_string.rstrip("=")


def decode_base64(input_bytes) -> bytes:
    """Decode an unpadded standard or urlsafe base64 string to bytes."""

    input_len = len(input_bytes)
    padding = b"=" * (3 - ((input_len + 3) % 4))

    # Passing altchars here allows decoding both standard and urlsafe base64
    output_bytes = base64.b64decode(input_bytes + padding, altchars=b"-_")
    return output_bytes


def main():
    if len(sys.argv) < 3:
        print("Invalid command line arguments")
        sys.exit(1)
    url = sys.argv[1]
    hub_adress = sys.argv[2]

    conn = HTTPConnection(url)
    body = json.dumps([{
        'length':13,
        'playload':{
            # 'src': 0xef0,
            'src':819,
            'dst':16383,
            'serial':1,
            'dev_type':6,
            # 'cmd': 0x01,
            'cmd':6,
            'cmd_body': {
                # 'timestamp': time.time()
                'timestamp':1688984021000
            }
        },
        'crc8':138
    }]
    )
    print(body)
    conn.request('POST', "")
    response = conn.getresponse().read()
    # Входная строка в формате unappended base64
    encoded_string = "YWJjMTIzIT8kKiYoKSctPUB+"

    # Декодирование unappended base64
    decoded_bytes = base64.b64decode(encoded_string)

    # Конвертация декодированных байтов в строку
    decoded_string = decoded_bytes.decode('utf-8')

    # Конвертация строки в объект JSON
    json_object = json.loads(decoded_string)

    # Вывод результата
    print(json_object)
    # print(response)
    # padding = b"=" * (3 - ((len(response) + 3) % 4))
    # print(binascii.hexlify(base64.b64decode(response + padding), sep=' '))


if __name__ == "__main__":
    main()
