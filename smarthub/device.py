from loguru import logger
from rich import inspect


class Device:
    def __init__(self, name, address):
        self.__name = name
        self.__address = address

    @property
    def name(self):
        logger.info(f"{self.__class__.__name__}: Get atribute name={self.__name}")
        return self.__name

    @name.setter
    def name(self, val):
        logger.info(f"{self.__class__.__name__}: Set atribute name={val}")
        self.__name = val

    @property
    def address(self):
        logger.info(f"{self.__class__.__name__}: Get atribute name={self.__address}")
        return self.__address

    @address.setter
    def address(self, val):
        logger.info(f"{self.__class__.__name__}: Set atribute address={val}")
        self.__name = val

    def __str__(self):
        inspect(self)
        return ""


class Lamp(Device):
    def __init__(self, name, address):
        super().__init__(name, address)


class Clock(Device):
    def __init__(self, name, address):
        super().__init__(name, address)


class Switch(Device):
    def __init__(self, name, address):
        super().__init__(name, address)
        self.__devices = []

    @property
    def devices(self):
        return self.__devices

    @devices.setter
    def devices(self, val):
        self.__devices = val
