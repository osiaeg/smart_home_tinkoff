from datetime import datetime
import time

from rich.console import Console
from rich.live import Live
from rich.tree import Tree

from smarthub.device import Clock, Device, Lamp, Switch


class Cli:
    def __init__(self, network: dict):
        self.__console = Console()
        self.__network: dict[int, Device] = network

    def show(self):
        try:
            with Live(
                self.generate_tree(), refresh_per_second=4
            ):  # update 4 times a second to feel fluid
                while True:
                    time.sleep(0.3)
                    # update the renderable internally
        except KeyboardInterrupt:
            self.__console.print("Goodbye!!!")

    def generate_tree(self) -> Tree:
        root = Tree("Smarthub")
        for device in self.__network.values():
            root.add(device.pretty_print())

        return root


if __name__ == "__main__":
    network = {
        4097: Clock("TIMER01", 4097, datetime.now()),
        4098: Lamp("LAMP02", 4098),
        2: Switch("SWITCH03", 2)
    }
    network[4097].time = datetime.now()
    app = Cli(network)
    app.show()
