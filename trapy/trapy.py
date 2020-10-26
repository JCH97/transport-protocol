from .utils import parse_address
from .package  import *

class Conn:
    def __init__(self, address: str):
        self.host, self.port = parse_address(address)
        

class ConnException(Exception):
    pass

connection_list: Conn = []

def listen(address: str) -> Conn:
    pass


def accept(conn) -> Conn:
    pass


def dial(address) -> Conn:
    pass


def send(conn: Conn, data: bytes) -> int:
    pass


def recv(conn: Conn, length: int) -> bytes:
    pass


def close(conn: Conn):
    pass
