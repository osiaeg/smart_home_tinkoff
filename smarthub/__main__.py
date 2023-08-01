import sys
from .hub import SmartHub
from .enums import CMD, DeviceType
from .utils import *
from time import sleep

smart_hub = SmartHub(sys.argv[1], sys.argv[2])

request_base64 = smart_hub.get_cmd_base64(CMD.WHOISHERE, dst=0x3FFF)

for message in smart_hub.request(request_base64):
    print(message)

request_timestamp = smart_hub.timestamp
while True:
    isTimeout = smart_hub.timestamp - request_timestamp <= 300
    if not isTimeout:
        request_base64 = smart_hub.get_cmd_base64(CMD.WHOISHERE, dst=0x3FFF)

        for message in smart_hub.request(request_base64):
            print(message)

        request_timestamp = smart_hub.timestamp
    else:
        for message in smart_hub.request():
            print(message)
            if message['payload']['cmd'] == CMD.IAMHERE:
                src = message['payload']['src']
                smart_hub.network[src] = message['payload']
                print(smart_hub.network)
        sleep(0.5)
