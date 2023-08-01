import unittest
from .switch_comand import *
from smarthub.utils import *
from smarthub.hub import SmartHub


class SwitchCommandTestCase(unittest.TestCase):
    smart_hub = SmartHub('localhost:9998', 'ef0')

    def test_IAMHERE(self):
        content = b'IgP_fwgDAghTV0lUQ0gwMQMFREVWMDEFREVWMDIFREVWMDMo'
        decoded_packet = decode_packet(content)

        if decoded_packet:
            for packet in split_decoded_packets(decoded_packet):
                self.assertEqual(self.smart_hub.parse_packet(packet), IAMHERE)

    def test_STATUS(self):
        content = b'BgMBCgMEAac'
        decoded_packet = decode_packet(content)

        if decoded_packet:
            for packet in split_decoded_packets(decoded_packet):
                self.assertEqual(self.smart_hub.parse_packet(packet), STATUS)
