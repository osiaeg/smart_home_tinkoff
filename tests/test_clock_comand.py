import unittest
from .clock_comand import TICK, IAMHERE
from smarthub.utils import decode_packet, split_decoded_packets
from smarthub.hub import SmartHub


class SocketCommandTestCase(unittest.TestCase):
    smart_hub = SmartHub("localhost:9998", "ef0")
    tests = {
        "IAMHERE": {
            "content": b"Dgb_fxUGAgdDTE9DSzAxsw",
            "expect": IAMHERE,
        },
        "TICK": {
            "content": b"DAb_fxgGBpabldu2NNM",
            "expect": TICK,
        },
    }

    def test_clock(self):
        for data in self.tests.values():
            decoded_packet = decode_packet(data["content"])

            if decoded_packet:
                for packet in split_decoded_packets(decoded_packet):
                    self.assertEqual(
                        self.smart_hub.parse_packet(packet), data["expect"]
                    )
