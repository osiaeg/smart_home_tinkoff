import unittest
from .envsensor_comand import *
from smarthub.utils import *
from smarthub.hub import SmartHub


class EnvSensorCommandTestCase(unittest.TestCase):
    smart_hub = SmartHub('localhost:9998', 'ef0')

    def test_IAMHERE(self):
        content = b'OAL_fwQCAghTRU5TT1IwMQ8EDGQGT1RIRVIxD7AJBk9USEVSMgCsjQYGT1RIRVIzCAAGT1RIRVI09w'
        decoded_packet = decode_packet(content)

        if decoded_packet:
            for packet in split_decoded_packets(decoded_packet):
                self.assertEqual(self.smart_hub.parse_packet(packet), IAMHERE)

    def test_STATUS(self):
        content = b'EQIBBgIEBKUB4AfUjgaMjfILrw'
        decoded_packet = decode_packet(content)

        if decoded_packet:
            for packet in split_decoded_packets(decoded_packet):
                self.assertEqual(self.smart_hub.parse_packet(packet), STATUS)
