from utils import parse_address
from package import Packet
from timer import Timer
from typing import Dict
from pathlib import Path
import socket
import subprocess
import random
import threading
import time

import sys

# Other data
PACKET_SIZE = 512
SLEEP_INTERVAL = 0.05
TIMEOUT_INTERVAL = 0.5
WINDOW_SIZE = 4

# Shared resources across threads
base = 0
send_timer = Timer(TIMEOUT_INTERVAL)
mutex = threading.Lock()
expected_num = 0


class Conn:
    def __init__(self, source: str, destination: str = None, sock=None, isServer=True):
        if sock is None:
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        self.socket: socket = sock
        self.isServer: bool = isServer
        self.source: str = source
        self.destination: str = destination


class ConnException(Exception):
    pass


connection_servers: dict = {}


def listen(address: str) -> Conn:
    conn: Conn = Conn(source=address)
    conn.socket.bind(parse_address(address))
    conn.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    connection_servers[address] = conn

    return conn


def accept(conn: Conn) -> Conn:
    if conn.destination is not None:
        raise ConnException()


def dial(address: str) -> Conn:
    host, port = parse_address(address)

    ipClient: str = (subprocess.run(["ip", "route", "get", "to", host],
                                    universal_newlines=True, stdout=subprocess.PIPE).stdout.splitlines())[-2].split(' ')[-4]

    clientConnection: Conn = Conn(f'{ipClient}:{0}', address, None, False)
    clientConnection.socket.bind((ipClient, 0))

    data = socket.inet_aton(ipClient) + b'\x00\x00'
    pck: Packet = Packet(ipClient, host, 0, port, random.randint(0, 1000) * 11 + 1, 0, 1 << 3, WINDOW_SIZE, data)

    send(clientConnection, pck.build(), False)  # paquete de SYN


def send(conn: Conn, data: bytes, splitData = True) -> int:
    global mutex
    global base
    global send_timer

    if not splitData:
        conn.socket.sendto(data, parse_address(conn.destination))

    packets = []
    seq_num = 0
    indx = 0

    sourceHost, sourcePort = parse_address(conn.source)
    destHost, destPort = parse_address(conn.destination)

    while indx <= len(data):
        d = data[indx:PACKET_SIZE - 32]
        pck: Packet = Packet(sourceHost, destHost, sourcePort, destPort, seq_num, 0, 0, WINDOW_SIZE, d)
        packets.append(pck.build())
        seq_num += 1
        indx += (PACKET_SIZE - 32)

    num_packets = len(packets)
    window_size = set_window_size(num_packets)
    next_to_send = 0
    base = 0

    threading.Thread(target=recv, args=(conn,)).start()

    while base < num_packets:
        mutex.acquire()
        while next_to_send < base + window_size:
            # print(f'Mandando el pqt {next_to_send}')
            send(conn, packets[next_to_send], False)
            # udt.send(packets[next_to_send], sock, RECEIVER_ADDR)
            next_to_send += 1

        if not send_timer.running():
            send_timer.start()
            while send_timer.running() and not send_timer.timeout():
                mutex.release()
                time.sleep(SLEEP_INTERVAL)
                mutex.acquire()

            if send_timer.timeout():
                next_to_send = base
                send_timer.stop()
            else:
                window_size = set_window_size(num_packets)

        mutex.release()

    # SEND FYN PACKET


def recv(conn: Conn, length: int = PACKET_SIZE + 20) -> bytes:
    global expected_num

    data = conn.socket.recvfrom(length)[0][20:]

    if data[:4] == b'\x00\x0f\x00\x0f':              # token
        # 0:token  1:sourceAddress 2:destAddress 3:sourcePort 4:destPort 5:seqNum 6:ACK 7:flags 8:winSize 9:CheckSum 10:data
        pack: list = Packet.unpack(data)
        print(pack)

        if validateCheckSum(pack[3:10], pack[10]):
            flags = pack[7]
            if flags & (1 << 3):                    # SYN flag active
                packetSYN(pack, conn)
            elif flags & (1 << 6):                  # ACK flag active
                packetACK(pack)
            elif flags & (1 << 2):                  # FIN flag active
                pass
            else:                                   # Recibi datos normales los datos a transmitir
                # print(f'Recive from reciver{pkt}')
                # print('Got packet', seq_num)

                # Send back an ACK
                if pack[5] == expected_num:
                    # print('Got expected packet')
                    # print('Sending ACK', expected_num)
                    pckACK: Packet = Packet(pack[1], pack[2], pack[3], pack[4], 0, expected_num, 1 << 6, WINDOW_SIZE, b'')
                    # udt.send(pkt, sock, addr)
                    expected_num += 1
                    # print(f'HERE {data}')
                else:
                    # print('Sending ACK', expected_num - 1)
                    # pkt = packet.make(expected_num - 1)
                    pckACK: Packet = Packet(pack[1], pack[2], pack[3], pack[4], 0, expected_num - 1, 1 << 6, WINDOW_SIZE, b'')
                    # udt.send(pkt, sock, addr)
                    
                send(conn, pckACK.build())


def close(conn: Conn):
    pass


def set_window_size(num_packets):
    global base
    return min(WINDOW_SIZE, num_packets - base)


# (source_port, dest_port, seqNum, ack, flags, WinSize, CheckSum)
def validateCheckSum(tcp_headers: tuple, data: bytes):
    return tcp_headers[6] == abs(~(tcp_headers[0] + tcp_headers[1] >> 1 + tcp_headers[4]) + len(data))


def packetSYN(pack: list, conn: Conn):
    # El objeto conn que llega es una conxion de server, hay que ponerle aqui el ip del cliente    
    key = f'{pack[2]}:{pack[4]}'
    conn: Conn = connection_servers.get(key, None)
    print(conn)
    
    if conn is None or conn.destination is None:
        raise ConnException(f'{conn.serverAddress} is alredy in use. First close connection')
    
    conn.destination = f'{socket.inet_ntoa(pack[10])}:0'

    connection_servers[key] = conn    

def packetACK(pack: list):
    global base
    global mutex
    if base <= pack[6]:  # pack[6] es el ACK
        with mutex:
            base = pack[6] + 1
            send_timer.stop()


if __name__ == "__main__":
    rol = sys.argv[1]

    if rol == 's':
        server = listen('192.168.43.96:0')
        accept(server)
        recv(server)

    if rol == 'c':
        filePath = Path.cwd() / 'tests' / 'tmp-data' / 'data.txt'
        conn: Conn = dial("192.168.43.96:0")
        print('SYN ok')
        hostS, portS = parse_address(conn.source)
        hostC, portC = parse_address(conn.destination)
        with open(filePath, 'r') as file:
            # p = Packet(hostS, hostC, portS, portC, 0, 0, 0, WINDOW_SIZE, )
            send(conn, bytes(file.read(), 'utf-8'))
