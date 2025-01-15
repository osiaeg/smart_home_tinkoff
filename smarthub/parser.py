from argparse import ArgumentParser, ArgumentTypeError


def __hex_address(addr: str):
    hex_addr = int(addr, 16)
    if hex_addr.bit_length() > 14:
        raise ArgumentTypeError("HEX address to long. It must be less then 14 bit.")
    else:
        return hex_addr


parser = ArgumentParser(
    prog="SmartHub",
    description="Emulate a SmartHub device which can connect to server",
)

# TODO: Add validation to url
parser.add_argument("url", help="URL address of server to connect (without http://)")
parser.add_argument("address", help="Address of SmartHub device", type=__hex_address)
