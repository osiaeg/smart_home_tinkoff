from .hub import SmartHub
from .enums import CMD, ReservedAddress
from time import sleep
from .parser import parser
from loguru import logger


args = parser.parse_args()

smart_hub = SmartHub(args.url, args.address)

request_base64 = smart_hub.get_cmd_base64(
    CMD.WHOISHERE, dst=ReservedAddress.BROADCAST.value
)

for message in smart_hub.request(request_base64):
    print(message)

request_timestamp = smart_hub.timestamp
while True:
    isTimeout = smart_hub.timestamp - request_timestamp <= 300
    if not isTimeout:
        request_base64 = smart_hub.get_cmd_base64(
            CMD.WHOISHERE, dst=ReservedAddress.BROADCAST.value
        )

        for message in smart_hub.request(request_base64):
            print(message)

        request_timestamp = smart_hub.timestamp
    else:
        for message in smart_hub.request():
            logger.info(message)
            if message["payload"]["cmd"] == CMD.IAMHERE:
                src = message["payload"]["src"]
                smart_hub.network[src] = message["payload"]
                logger.info(f"{smart_hub.network=}")
        sleep(0.5)
