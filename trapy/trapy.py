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
    def __init__(self, source: str, destination: str = None, sock = None, isServer = True):
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
    # conn.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print(f'bind: {parse_address(address)}')

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
    
    data = socket.inet_aton(ipClient)
    pck: Packet = Packet(ipClient, host, 0, port, 0, random.randint(0, 1000) * 11 + 1, 1 << 3, WINDOW_SIZE, data)

    send(clientConnection, pck.build(), False)  # paquete de SYN
    print(f'Packet send: {Packet.unpack(pck.build())}')
    print('send packet SYN')

    return clientConnection


def send(conn: Conn, data: bytes, splitData=True) -> int:
    global mutex
    global base
    global send_timer

    if not splitData:
        return conn.socket.sendto(data, parse_address(conn.destination))

    packets = []
    seq_num = 0
    indx = 0

    sourceHost, sourcePort = parse_address(conn.source)
    destHost, destPort = parse_address(conn.destination)

    while indx <= len(data):
        # print(indx)
        # print(PACKET_SIZE - 32)
        d = data[indx:indx + PACKET_SIZE - 32]
        # print(d)
        # print(len(d))
        # print(len(data))
        # print('\n')
        pck: Packet = Packet(sourceHost, destHost, sourcePort, destPort, 0, seq_num, 0, WINDOW_SIZE, d)
        packets.append(pck.build())
        seq_num += 1
        indx += (PACKET_SIZE - 32)

    num_packets = len(packets)
    window_size = set_window_size(num_packets)
    next_to_send = 0
    base = 0

    print(f'Packets: {num_packets}')
    # print(packets)

    threading.Thread(target=recvForEver, args=(conn,)).start()

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
        # 0:token  1:source 2:destination 3:sourcePort 4:destPort 5:- 6:ACK/SeqNum 7:flags 8:winSize 9:CheckSum 10:data
        pack: list = Packet.unpack(data)
        # print(f'Packet recv: {pack}')

        if validateCheckSum(pack[3:10], pack[10]):
            flags = pack[7]
            # print(f'flags {flags}')
            if flags & (1 << 3):                    # SYN flag active
                packetSYN(pack, conn)
                return 1
            elif flags & (1 << 6):                  # ACK flag active
                packetACK(pack)
            elif flags & (1 << 2):                  # FIN flag active
                pass
            else:                                   # Recibi datos normales los datos a transmitir
                # print(f'Recive from reciver{pkt}')
                # print('Got packet', seq_num)

                hostS, portS = parse_address(conn.source)
                hostD, portD = parse_address(conn.destination)

                # Send back an ACK
                if pack[6] == expected_num:
                    # print(f'Recived pack: {expected_num}')
                    # print('Sending ACK', expected_num)
                    
                    pckACK: Packet = Packet(hostS,hostD, portS, portD, 0, expected_num, 1 << 6, WINDOW_SIZE, b'')
                    # udt.send(pkt, sock, addr)
                    expected_num += 1

                    # with open(Path.cwd() / 'tests' / 'tmp-data' / 'out.txt', mode="wb") as file:
                    #     file.write(pack[10])
                    print(pack[10].decode('utf-8'))
                    # print(conn.source)
                    # print(conn.destination)
                    # print(f'Sending pack to {conn.destination} -- {Packet.unpack(pckACK.build())}')
                    send(conn, pckACK.build(), False)

                    return len(pack[10])
                else:
                    # print('Sending ACK', expected_num - 1)
                    # pkt = packet.make(expected_num - 1)
                    pckACK: Packet = Packet(hostS, hostD, portS, portD, 0, expected_num - 1, 1 << 6, WINDOW_SIZE, b'')
                    # udt.send(pkt, sock, addr)
                    send(conn, pckACK.build(), False)

def close(conn: Conn):
    pass


def set_window_size(num_packets):
    global base
    return min(WINDOW_SIZE, num_packets - base)


# (source_port, dest_port, seqNum, ack, flags, WinSize, CheckSum)
def validateCheckSum(tcp_headers: tuple, data: bytes):
    # print(f'=====> {type(data)}')
    # print(f'=====> Data: {data}')
    # print(f'=====> {len}, {type(len)}')
    # print(f'=====> {len(data)}')
    # print(f'=====> Headers: {tcp_headers}')
    # print(f'=====> Check Sum Value: {abs(~(tcp_headers[0] + tcp_headers[1] >> 1 + tcp_headers[4]) + len(data))} --- Expected: {tcp_headers[6]}')
    return tcp_headers[6] == abs(~(tcp_headers[0] + tcp_headers[1] >> 1 + tcp_headers[4]) + len(data))


def packetSYN(pack: list, conn: Conn):
    # El objeto conn que llega es una conxion de server, hay que ponerle aqui el ip del cliente
    key = f'{pack[2]}:{pack[4]}'
    conn: Conn = connection_servers.get(key, None)

    if conn is None or conn.destination is not None:
        raise ConnException(
            f'{conn.destination} is alredy in use. First close connection')

    conn.destination = f'{socket.inet_ntoa(pack[10])}:0'

    connection_servers[key] = conn

    print(f'Connection ok between: {connection_servers[key].source} -- {connection_servers[key].destination}')


def packetACK(pack: list):
    # print(f'======> Recive pack ACK {pack[6]}')
    global base
    global mutex
    if base <= pack[6]:  # pack[6] es el ACK
        with mutex:
            base = pack[6] + 1
            send_timer.stop()


def recvForEver(conn: Conn):
    while True:
        recv(conn)

if __name__ == "__main__":
    rol = sys.argv[1]

    ip = '192.168.43.96:0'

    if rol == 's':
        server = listen(ip)
        accept(server)
        while True:
            length = recv(server)
            if length == 0:
                break

    if rol == 'c':
        filePath = Path.cwd() / 'tests' / 'tmp-data' / 'data.txt'
        conn: Conn = dial(ip)
        # print('SYN ok')
        with open(filePath, 'r') as file:
            b = bytes(file.read(), 'utf-8')
            # print(b)
            send(conn, b)
