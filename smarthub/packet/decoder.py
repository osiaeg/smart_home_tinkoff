class PacketDecoder:
    def decode(self, packet):
        pass

    def __split_decoded_packets(self, decoded_packet):
        packets = []
        while decoded_packet:
            length = decoded_packet[0]
            payload = decoded_packet[1 : length + 1]
            crc_8 = decoded_packet[length + 1]
            decoded_packet = decoded_packet[length + 2 :]
            if check_crc8(payload, crc_8):
                packets.append(payload)
            else:
                logger.warning("Message is broken. Check crc8 is failed.")
                continue
        return packets


if __name__ == "__main__":
    print("PacketDecoder")
