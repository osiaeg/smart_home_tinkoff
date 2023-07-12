import sys
from http.client import HTTPConnection
import base64
import os


def main():
    for param in sys.argv:
        print(param)

    conn = HTTPConnection('localhost:9998')
    conn.request('POST', "/")
    response = conn.getresponse()


if __name__ == "__main__":
    main()

def crc8(data):
    crc = 0

    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0xD5 # Возможно надо поменять кодировку
            else:
                crc <<= 1

    return crc

def check_crc8(payload, checksum):
    calculated_checksum = crc8(payload)
    return calculated_checksum == checksum

# Пример использования:
def check date():
    payload = [0x01, 0x02, 0x03]
    crc_8 = 0xFA

    if check_crc8(payload, crc_8):
        print("Контрольная сумма корректна.")
    else:
        print("Контрольная сумма некорректна.") # Надо отправить запрос на повторное отправление данных
