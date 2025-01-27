from datetime import datetime
from time import sleep

import requests
from loguru import logger

from .device import Clock, Lamp, Switch
from .enums import CMD, DeviceType
from .hub import SmartHub
from .package.decoder import PackageDecoder
from .package.encoder import PackageEncoder
from .parser import parser

args = parser.parse_args()

smart_hub = SmartHub(args.url, args.address)

decoder = PackageDecoder()
encoder = PackageEncoder()

try:
    data = encoder.encode(
        {
            "src": smart_hub.src,
            "dst": 16383,
            "serial": smart_hub.serial,
            "dev_type": 1,
            "cmd": 1,
            "cmd_body": {"dev_name": smart_hub.dev_name},
        }
    )

    response = smart_hub.request(data=data)
    if response:
        packages = decoder.decode(response.content)
        for package in packages:
            cmd = package.payload.cmd
            dev_type = package.payload.dev_type
            if cmd == CMD.TICK:
                timestamp = package.payload.cmd_body["timestamp"]
                time = datetime.fromtimestamp(timestamp / 1e3)
                smart_hub.timestamp = time
                request_timestamp = time
            elif cmd == CMD.IAMHERE:
                payload = package.payload
                if dev_type == DeviceType.Lamp:
                    lamp = Lamp(payload.cmd_body["dev_name"], payload.src)
                    smart_hub.network[payload.src] = lamp
                elif dev_type == DeviceType.Clock:
                    clock = Clock(payload.cmd_body["dev_name"], payload.src, smart_hub.timestamp)
                    smart_hub.network[payload.src] = clock
                elif dev_type == DeviceType.Switch:
                    switch = Switch(payload.cmd_body["dev_name"], payload.src)
                    smart_hub.network[payload.src] = switch

    while (smart_hub.timestamp - request_timestamp).total_seconds() * 1e3 < 300:
        response = smart_hub.request()
        if response:
            packages = decoder.decode(response.content)
            for package in packages:
                cmd = package.payload.cmd
                dev_type = package.payload.dev_type
                if cmd == CMD.TICK:
                    timestamp = package.payload.cmd_body["timestamp"]
                    smart_hub.timestamp = datetime.fromtimestamp(timestamp / 1e3)
                elif cmd == CMD.IAMHERE:
                    payload = package.payload
                    if dev_type == DeviceType.Lamp:
                        lamp = Lamp(payload.cmd_body["dev_name"], payload.src)
                        smart_hub.network[payload.src] = lamp
                    elif dev_type == DeviceType.Clock:
                        clock = Clock(payload.cmd_body["dev_name"], payload.src, smart_hub.timestamp)
                        smart_hub.network[payload.src] = clock

                    elif dev_type == DeviceType.Switch:
                        switch = Switch(payload.cmd_body["dev_name"], payload.src)
                        switch.devices = payload.cmd_body["dev_props"]["dev_names"]
                        smart_hub.network[payload.src] = switch


except KeyboardInterrupt:
    pass
except requests.exceptions.ConnectionError:
    print("Server is not started.")
    print("Start server")

# request_base64 = smart_hub.get_cmd_base64(
#     CMD.WHOISHERE, dst=ReservedAddress.BROADCAST.value
# )
#
# for message in smart_hub.request(request_base64):
#     print(message)
#
# request_timestamp = smart_hub.timestamp
# while True:
#     isTimeout = smart_hub.timestamp - request_timestamp <= 300
#     if not isTimeout:
#         request_base64 = smart_hub.get_cmd_base64(
#             CMD.WHOISHERE, dst=ReservedAddress.BROADCAST.value
#         )
#
#         for message in smart_hub.request(request_base64):
#             print(message)
#
#         request_timestamp = smart_hub.timestamp
#     else:
#         for message in smart_hub.request():
#             logger.info(message)
#             if message["payload"]["cmd"] == CMD.IAMHERE:
#                 src = message["payload"]["src"]
#                 smart_hub.network[src] = message["payload"]
#                 logger.info(f"{smart_hub.network=}")
#         sleep(0.5)
