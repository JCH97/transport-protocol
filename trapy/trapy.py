from utils import parse_address
from package import Packet
from random import randint
import socket
import logging
import subprocess


class Conn:
    def __init__(self, serverAddress: str, clientAddress: str = None, sock = None, isServer = True):
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        self.socket: socket = sock
        self.serverAddress: str = serverAddress
        self.clientAddress = clientAddress
        self.isServer: bool = isServer

        if self.isServer:
            self.clientConnections: list = []


class ConnException(Exception):
    pass


connections: dict = {}


def listen(address: str) -> Conn:
    conn: Conn = Conn(serverAddress=address)
    conn.socket.bind(parse_address(address))
    conn.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # El bool dice si la conexion ya paso por accept o no
    connections[address] = (conn, False)

    return conn


def accept(conn: Conn) -> Conn:
    try:
        conn, isAccepted = connections[conn.serverAddress]
        connections[conn.serverAddress] = (conn, True)

        return conn

    except KeyError as err:
        logging.error(f'Before call to listen with the address {conn.address}')


def dial(address: str) -> Conn:
    host, port = parse_address(address)
    ipClient: str = (subprocess.run(["ip", "route", "get", "to", host],
                                    universal_newlines=True, stdout=subprocess.PIPE).stdout.splitlines())[-2].split(' ')[-4]

    clientConn: Conn = Conn(address, ipClient, None, False)
    # clientConn.socket.sendto(b'Connection ok' + socket.inet_aton(ipClient), clientConn.serverAddress)

    # send syn for 3 meet connections
    seqNumber = randint(0, 1000000)
    p: Packet = Packet(ipClient, host, 0, 0, seqNumber, seqNumber, 1 << 3, 4, socket.inet_aton(ipClient))

    send(clientConn, p.build(), False) #enviar paquete de sincronizacion al server


def send(conn: Conn, data: bytes, splitData: bool = True) -> int:
    if not splitData:
        return conn.socket.sendto(data, parse_address(conn.clientAddress if conn.isServer else conn.serverAddress))


def recv(conn: Conn, length: int) -> bytes:
    while True:
        print('into')
        data = conn.socket.recvfrom(length)[0][20:]
        
        pack: list = Packet.unpack(data)
        # 0:token  1:sourceAddress 2:destAddress 3:sourcePort 4:destPort 5:seqNum 6:ACK 7:flags 8:winSize 9:CheckSum 10:data
        
        if validateCheckSum(pack[3:10], pack[10]): # el paquete que se recibio no tiene cambios en los datos
            if pack[0] == b'\x00\x0f\x00\x0f':  # token
                flags = pack[7]                

                if flags & (1 << 3):  # SYN flag active
                    print('SYN flag ok')
                elif flags & (1 << 6):  # ACK flag active
                    pass
                elif flags & (1 << 2):  # FIN flag active
                    pass
        else:  # volver a pedir el paquete
            pass

def close(conn: Conn):
    pass


# (source_port, dest_port, seqNum, ack, flags, WinSize, CheckSum)
def validateCheckSum(tcp_headers: tuple, data: bytes):
    # print(f'Validate checkSum: {tcp_headers[0]}, {tcp_headers[1] >> 1}, {tcp_headers[4]}, {len(data)}')
    return tcp_headers[6] == abs(~(tcp_headers[0] + tcp_headers[1] >> 1 + tcp_headers[4]) + len(data))


if __name__ == "__main__":
    server = listen('192.168.43.96:0')
    accept(server)
    recv(server, 512)

    # dial("192.168.43.96:0")
