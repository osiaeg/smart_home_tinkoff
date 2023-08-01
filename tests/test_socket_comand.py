import unittest
from .socket_comand import *
from smarthub.utils import *
from smarthub.hub import SmartHub


class SocketCommandTestCase(unittest.TestCase):
    smart_hub = SmartHub('localhost:9998', 'ef0')

    def test_IAMHERE(self):
        content = b'DwX_fxEFAghTT0NLRVQwMc0'
        decoded_packet = decode_packet(content)

        if decoded_packet:
            for packet in split_decoded_packets(decoded_packet):
                self.assertEqual(self.smart_hub.parse_packet(packet), IAMHERE)

    def test_STATUS(self):
        content = b'BgUBEwUEAQ8'
        decoded_packet = decode_packet(content)

        if decoded_packet:
            for packet in split_decoded_packets(decoded_packet):
                self.assertEqual(self.smart_hub.parse_packet(packet), STATUS)
