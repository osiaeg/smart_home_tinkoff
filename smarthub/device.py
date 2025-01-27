from datetime import datetime
from loguru import logger
from rich import inspect
from abc import ABC, abstractmethod


class Printable(ABC):
    @abstractmethod
    def pretty_print(self) -> str:
        pass


class Switchable:
    _status = 0

    @property
    def status(self) -> int:
        return self._status

    @status.setter
    def status(self, value) -> None:
        logger.info(f"{self.__class__.__name__}: Set atribute status={value}")
        if value not in (0, 1):
            raise ValueError("The status of the switched devices can only be 1 or 0")
        self._status = value

    def _check_status(self) -> str:
        return "[red]OFF" if self._status == 0 else "[green]ON"


class Device(Printable):
    def __init__(self, name, address) -> None:
        self.__name = name
        self.__address = address

    @property
    def name(self) -> str:
        logger.info(f"{self.__class__.__name__}: Get atribute name={self.__name}")
        return self.__name

    @name.setter
    def name(self, val) -> None:
        logger.info(f"{self.__class__.__name__}: Set atribute name={val}")
        self.__name = val

    @property
    def address(self) -> int:
        logger.info(f"{self.__class__.__name__}: Get atribute name={self.__address}")
        return self.__address

    @address.setter
    def address(self, val) -> None:
        logger.info(f"{self.__class__.__name__}: Set atribute address={val}")
        self.__name = val

    def __str__(self):
        inspect(self)
        return ""


class Clock(Device):
    def __init__(self, name, address, time):
        super().__init__(name, address)
        self.__time = time

    @property
    def time(self) -> str:
        return self.__time

    @time.setter
    def time(self, value: datetime) -> None:
        self.__time = str(value)[11:23]

    def pretty_print(self) -> str:
        return f"{self.name} -> {self.__time}"


class Lamp(Device, Switchable):
    def __init__(self, name, address):
        super().__init__(name, address)

    def pretty_print(self) -> str:
        return f":bulb: {self.name} -> {self._check_status()}"


class Switch(Device, Switchable):
    def __init__(self, name, address):
        super().__init__(name, address)
        self.__devices = []

    @property
    def devices(self):
        return self.__devices

    @devices.setter
    def devices(self, val):
        self.__devices = val

    def pretty_print(self) -> str:
        return f"{self.name} -> {self._check_status()}"
