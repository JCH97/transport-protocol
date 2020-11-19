from utils import parse_address, build_acks, build_packets
from package import Packet
from timer import Timer
from typing import Dict, List
from pathlib import Path
import socket
import subprocess
import random
import threading
import time
import sys

#Data
PACKET_SIZE = 512
SLEEP_INTERVAL = 0.0005
TIMEOUT_INTERVAL = 0.005
WINDOW_SIZE = 5

#Errors
SERVER_NOT_RUNNING = "Server isn't running"
FIRST_CALL_ACCEPT = "First call accept with %s"
CONNECTION_IN_USE = "Connection in use between %s and %s; wait for it to finish sending"
SERVER_FIRST = "Data recived, but plase first run server and after client"

logsServer = False
logsClient = False

connection_servers: dict = {}

class Conn:
    def __init__(self, source: str, destination: str = None, sock = None):
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        self.mutex = threading.Lock()
        self.socket: socket = sock
        self.source: str = source
        self.destination: str = destination
        self.base: int = 0
        self.sendTimer = Timer(TIMEOUT_INTERVAL)
        self.expectedNum: int = 0
        self.totalPackets: int = 0
        self.buffer: str = b""


class ConnException(Exception):
   pass

def listen(address: str, logs = False) -> Conn:
    global logsServer
    logsServer = logs

    conn: Conn = Conn(source = address)
    conn.socket.bind(parse_address(address))

    if logsServer: print(f'bind: {parse_address(address)}')

    connection_servers[address] = conn

    return conn


def accept(conn: Conn) -> Conn:
    if conn.destination is not None:
        raise ConnException(FIRST_CALL_ACCEPT % conn.source)

    return conn


def dial(address: str, logs = False) -> Conn:
    global logsClient
    logsClient = logs

    host, port = parse_address(address)

    ipClient: str = (subprocess.run(["ip", "route", "get", "to", host],
                                    universal_newlines=True, stdout=subprocess.PIPE).stdout.splitlines())[-2].split(' ')[-4]

    clientConnection: Conn = Conn(f'{ipClient}:{port}', address)

    send(clientConnection, socket.inet_aton(ipClient), flags = 1 << 3)  # paquete de SYN
    if logsClient: print('send packet SYN')

    return clientConnection

def send(conn: Conn, data: bytes, splitData = True, flags: int = 0) -> int:
    global logsServer
    global logsClient

    if not splitData:
        return conn.socket.sendto(data, parse_address(conn.destination))

    sourceHost, sourcePort = parse_address(conn.source)
    destHost, destPort = parse_address(conn.destination)

    packets: List[Packet] =  build_packets(data, PACKET_SIZE, WINDOW_SIZE, sourceHost, sourcePort, destHost, destPort, flags)
    numPackets: int = len(packets)
    conn.totalPackets = numPackets

    next_to_send = 0
    conn.base = 0
    window_size = set_window_size(conn, numPackets)

    send(conn, Packet(sourceHost, destHost, sourcePort, destPort, 0, 0, 1 << 4, WINDOW_SIZE, str(numPackets).encode('utf-8')).build(), False)    #new group packets to send

    if logsClient: print(f'Packets: {numPackets}')

    threading.Thread(target=recvForEver, args=(conn,), daemon = True).start()
    while conn.base < numPackets:
        conn.mutex.acquire()
        while next_to_send < conn.base + window_size:
            if logsClient: print(f'=======> Sending pck: {next_to_send}')
            send(conn, packets[next_to_send], False)
            next_to_send += 1

        if not conn.sendTimer.running():
            conn.sendTimer.start()
            while conn.sendTimer.running() and not conn.sendTimer.timeout():
                conn.mutex.release()
                time.sleep(SLEEP_INTERVAL)
                conn.mutex.acquire()

            if conn.sendTimer.timeout():
                next_to_send = conn.base
                conn.sendTimer.stop()
            else:
                window_size = set_window_size(conn, numPackets)

        conn.mutex.release()

    return len(data)


def recv(conn: Conn, length: int = 512) -> bytes:
    global logsServer
    global logsClient

    data = conn.socket.recvfrom(length + 52)[0][20:]
    if data[:4] == b'\x00\x0f\x00\x0f':
        # 0:token  1:source 2:destination 3:sourcePort 4:destPort 5:- 6:ACK/SeqNum 7:flags 8:winSize 9:CheckSum 10:data
        pack: list = Packet.unpack(data)

        if Packet.check_sum(data[:28] + data[32:]) == pack[9]:
            flags = pack[7]
            if flags & (1 << 3):                    # SYN flag active
                packetSYN(pack, conn)

                hostS, portS = parse_address(conn.source)
                hostD, portD = parse_address(conn.destination)

                send(conn, Packet(hostS, hostD, portS, portD, 0, 0, 1 << 6, WINDOW_SIZE, b'').build(), False)

                return recv(conn, length)
            elif flags & (1 << 6):                  # ACK flag active
                packetACK(pack, conn)
                return recv(conn, length)
            elif flags & (1 << 2):                  # FIN flag active
                pass
            elif flags & (1 << 4):                  # NEW [new connection]
                newSend(conn, int(pack[10].decode('utf-8')))
                return recv(conn, length)
            else:                                   # Normal data

                hostS, portS = parse_address(conn.source)
                hostD, portD = parse_address(conn.destination)

                if logsServer: print(f'Packet expected {conn.expectedNum}, packet recv {pack[6]}')
                # Send back an ACK
                if pack[6] == conn.expectedNum:

                    pckACK: Packet = Packet(hostS,hostD, portS, portD, 0, conn.expectedNum, 1 << 6, WINDOW_SIZE, b'')
                    conn.expectedNum += 1

                    send(conn, pckACK.build(), False)

                    conn.buffer += pack[10]

                    # if logsServer: print(f'Buffer ======> {conn.buffer}\n')

                    # print('here', conn.expectedNum, conn.totalPackets)
                    if len(conn.buffer) >= length or conn.expectedNum > conn.totalPackets:
                        ans = conn.buffer[:length]
                        conn.buffer = conn.buffer[length:]

                        return ans
                    else:
                        return recv(conn, length)

                else:
                    pckACK: Packet = Packet(hostS, hostD, portS, portD, 0, conn.expectedNum - 1, 1 << 6, WINDOW_SIZE, b'')
                    send(conn, pckACK.build(), False)
    else:
        return recv(conn, length)

def close(conn: Conn):
    conn.socket = conn.destination = conn.source = None
    if connection_servers.get(conn.source, None) is not None:
        del connection_servers[conn.source]

def set_window_size(conn: Conn, numPackets: int):
    return min(WINDOW_SIZE, numPackets - conn.base)


def packetSYN(pack: list, conn: Conn):
    global logsServer

    # El objeto conn que llega es una conxion de server, hay que ponerle aqui el ip del cliente
    key = f'{pack[2]}:{pack[4]}'
    conn: Conn = connection_servers.get(key, None)

    if conn is None or conn.destination is not None:
        raise ConnException(CONNECTION_IN_USE % (conn.source, conn.destination))

    conn.destination = f'{socket.inet_ntoa(pack[10])}:0'

    connection_servers[key] = conn

    if logsServer: print(f'Connection ok between: {connection_servers[key].source} -- {connection_servers[key].destination}')


def packetACK(pack: list, conn: Conn):
    global logsClient

    if logsClient: print(f'======> Recive pack ACK {pack[6]}, Base before ++ {conn.base}')
    if conn.base <= pack[6]:  # pack[6] is ACK
        with conn.mutex:
            conn.base = pack[6] + 1
            conn.sendTimer.stop()

def newSend(conn: Conn, total: int):
    conn.expectedNum = 0
    conn.totalPackets = total

def recvForEver(conn: Conn):
    while True:
        recv(conn)

        if conn.base == conn.totalPackets:
            break

if __name__ == "__main__":
    rol = sys.argv[1]

    ip = '10.0.0.1:0'

    if rol == 's':
        server = listen(ip, True)
        server = accept(server)
        # while True:
        #     data = recv(server)

        #     if data is not None and not data == b'\x00\x0f\x00\x0f':
        #         with open(Path.cwd() / 'tests' / 'data' / 'out.txt', mode="a") as file:
        #                 file.write(data.decode('utf-8'))

        filePath = Path.cwd() / 'tests' / 'data' / 'data.txt'

        with open(filePath, 'r') as file:
            b = bytes(file.read(), 'utf-8')
            send(server, b)

    if rol == 'c':
        conn: Conn = dial(ip, True)
        data = recv(conn, 2048)
        print(f'Recived {len(data)}')
        with open(Path.cwd() / 'tests' / 'data' / 'out.txt', mode="w") as file:
            file.write(data.decode('utf-8'))
        # send(conn, b'\nJose Carlos Hernandez')
        # send(conn, b'\nCiencias de la Computacion')

