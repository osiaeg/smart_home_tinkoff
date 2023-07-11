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
