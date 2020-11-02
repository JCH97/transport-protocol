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

#Data

PACKET_SIZE = 512
SLEEP_INTERVAL = 0.05
TIMEOUT_INTERVAL = 0.5
WINDOW_SIZE = 5
base = 0
send_timer = Timer(TIMEOUT_INTERVAL)
mutex = threading.Lock()
expected_num = 0
errors = ["Server isn't running", "First call accept with server connection"]
logsServer = False
logsClient = False
connection_servers: dict = {}


class Conn:
    def __init__(self, source: str, destination: str = None, sock = None):
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        self.socket: socket = sock
        self.source: str = source
        self.destination: str = destination


class ConnException(Exception):
    def __init__(self, status_code: int, errors_list: list = errors):
        self.status_code = status_code
        self.errors_list = errors_list

    @property
    def getError(self) -> str:
        return self.errors_list[self.status_code]

    
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
        raise ConnException(0)


def dial(address: str, logs = False) -> Conn:
    global logsClient
    logsClient = logs
    
    host, port = parse_address(address)

    ipClient: str = (subprocess.run(["ip", "route", "get", "to", host],
                                    universal_newlines=True, stdout=subprocess.PIPE).stdout.splitlines())[-2].split(' ')[-4]

    clientConnection: Conn = Conn(f'{ipClient}:{0}', address)
    
    data = socket.inet_aton(ipClient)
    pck: Packet = Packet(ipClient, host, 0, port, 0, random.randint(0, 1000) * 11 + 1, 1 << 3, WINDOW_SIZE, data)

    send(clientConnection, pck.build(), False)  # paquete de SYN
    if logsClient: print(f'Packet send: {Packet.unpack(pck.build())}')
    if logsClient: print('send packet SYN')

    return clientConnection

def send(conn: Conn, data: bytes, splitData = True) -> int:
    global mutex
    global base
    global send_timer
    global logsServer
    global logsClient
    amountSend = 0   
    
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

    numPackets = len(packets)
    window_size = set_window_size(numPackets)
    next_to_send = 0
    base = 0

    if logsClient: print(f'Packets: {numPackets}')
    # print(packets)

    threading.Thread(target=recvForEver, args=(conn,)).start()

    while base < numPackets:
        mutex.acquire()
        while next_to_send < base + window_size:
            if logsClient: print(f'Sending pck: {next_to_send}')
            amountSend += send(conn, packets[next_to_send], False)            
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
                window_size = set_window_size(numPackets)

        mutex.release()

    # fin = Packet(sourceHost, destHost, sourcePort, destPort, 0, 0, 1 << 2, WINDOW_SIZE)
    # send(conn, fin.build(), False)

    return amountSend


def recv(conn: Conn, length: int = PACKET_SIZE + 20) -> bytes:
    global expected_num
    global logsServer
    global logsClient

    data = conn.socket.recvfrom(length)[0][20:]
    print(data)
    if data[:4] == b'\x00\x0f\x00\x0f':              # token
        # 0:token  1:source 2:destination 3:sourcePort 4:destPort 5:- 6:ACK/SeqNum 7:flags 8:winSize 9:CheckSum 10:data
        pack: list = Packet.unpack(data)
        # print(f'Packet recv: {pack}')

        if validateCheckSum(pack[3:10], pack[10]):
            flags = pack[7]
            # print(f'flags {flags}')
            if flags & (1 << 3):                    # SYN flag active
                packetSYN(pack, conn)
                return b'\x00\x0f\x00\x0f'
            elif flags & (1 << 6):                  # ACK flag active
                packetACK(pack)
            elif flags & (1 << 2):                  # FIN flag active
                pass
            else:                                   # Recibi datos normales los datos a transmitir
                hostS, portS = parse_address(conn.source)
                hostD, portD = parse_address(conn.destination)

                if logsServer: print(f'Packet expected {expected_num}, packet recv {pack[6]}')
                # Send back an ACK
                if pack[6] == expected_num:
                    # print(f'Recived pack: {expected_num}')
                    # print('Sending ACK', expected_num)
                    
                    pckACK: Packet = Packet(hostS,hostD, portS, portD, 0, expected_num, 1 << 6, WINDOW_SIZE, b'')
                    expected_num += 1

                    # print(pack[10].decode('utf-8'))
                    # print(conn.source)
                    # print(conn.destination)
                    # print(f'Sending pack to {conn.destination} -- {Packet.unpack(pckACK.build())}')
                    send(conn, pckACK.build(), False)
                    # print(pack[10])

                    return pack[10]
                else:
                    # print('Sending ACK', expected_num - 1)
                    # pkt = packet.make(expected_num - 1)
                    pckACK: Packet = Packet(hostS, hostD, portS, portD, 0, expected_num - 1, 1 << 6, WINDOW_SIZE, b'')
                    # udt.send(pkt, sock, addr)
                    send(conn, pckACK.build(), False)

def close(conn: Conn):
    pass


def set_window_size(numPackets):
    global base
    return min(WINDOW_SIZE, numPackets - base)


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
    global logsClient

    # El objeto conn que llega es una conxion de server, hay que ponerle aqui el ip del cliente
    key = f'{pack[2]}:{pack[4]}'
    conn: Conn = connection_servers.get(key, None)

    if conn is None or conn.destination is not None:
        raise ConnException(f'{conn.destination} is alredy in use. First close connection')

    conn.destination = f'{socket.inet_ntoa(pack[10])}:0'

    connection_servers[key] = conn

    if logsClient: print(f'Connection ok between: {connection_servers[key].source} -- {connection_servers[key].destination}')


def packetACK(pack: list):
    global logsClient
    global base
    global mutex
    
    if logsClient: print(f'======> Recive pack ACK {pack[6]}')
    if base <= pack[6]:  # pack[6] is ACK
        with mutex:
            base = pack[6] + 1
            send_timer.stop()


def recvForEver(conn: Conn):
    while True:
        recv(conn)

if __name__ == "__main__":
    rol = sys.argv[1]

    ip = '10.0.0.1:0'

    if rol == 's':
        server = listen(ip, True)
        accept(server)
        while True:
            data = recv(server)

            if data is not None and not data == b'\x00\x0f\x00\x0f':
                with open(Path.cwd() / 'tests' / 'data' / 'out.txt', mode="a") as file:
                        file.write(data.decode('utf-8'))

    if rol == 'c':
        filePath = Path.cwd() / 'tests' / 'data' / 'data.txt'
        conn: Conn = dial(ip, True)        
        with open(filePath, 'r') as file:
            b = bytes(file.read(), 'utf-8')
            send(conn, b)
        # send(conn, b'Jose Carlos Hernandez', 0)
        # time.sleep(2)
        # send(conn, b'Ciencias de la Computacion', 0)
        
