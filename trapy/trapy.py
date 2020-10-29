from utils import parse_address
from package import Packet
from timer import Timer
from random import randint
from pathlib import Path
import socket
import logging
import subprocess
import sys
import threading
import time


PACKET_SIZE = 512
SLEEP_INTERVAL = 0.05
TIMEOUT_INTERVAL = 0.5
WINDOW_SIZE = 4

packetsToSend = []

base = 0
sendTimer = Timer(TIMEOUT_INTERVAL)
mutex = threading.Lock()
expectedPacket = 0

class Conn:
    def __init__(self, serverAddress: str, clientAddress: str = None, sock = None, isServer = True):
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        self.socket: socket = sock
        self.serverAddress: str = serverAddress
        self.clientAddress = clientAddress
        self.isServer: bool = isServer

        # if self.isServer:
        #     self.clientConnections: list = []


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
        conn, _ = connections[conn.serverAddress]
        connections[conn.serverAddress] = (conn, True)

        return conn

    except KeyError as err:
        logging.error(f'First call to listen with the address {conn.address}')


def dial(address: str) -> Conn:
    # if connections.get(address, None) is None:
    #     raise ConnException(f'{address} no match with any server. Plase make listen wiht {address}')
    
    host, port = parse_address(address)
    
    # if connections[address][0].clientAddress is not None:
    #     raise ConnException('Sock alredy in use; not support multiple connection')
    
    ipClient: str = (subprocess.run(["ip", "route", "get", "to", host],
                                    universal_newlines=True, stdout=subprocess.PIPE).stdout.splitlines())[-2].split(' ')[-4]

    clientConn: Conn = Conn(address, f'{ipClient}:0', None, False)
    
    seqNumber = randint(0, 1000)  # end syn for 3 meet connections
    p: Packet = Packet(ipClient, host, 0, 0, 11 * seqNumber + 1, 0, 1 << 3, 4, socket.inet_aton(ipClient))
    send(clientConn, p.build(), False) #enviar paquete de sincronizacion al server

    return clientConn

def send(conn: Conn, data: bytes, splitData: bool = True) -> int:
    if not splitData:
        return conn.socket.sendto(data, parse_address(conn.clientAddress if conn.isServer else conn.serverAddress))

    global base
    global mutex
    global sendTimer
    
    hostC, portC = parse_address(conn.clientAddress) #cliente
    hostS, portS = parse_address(conn.serverAddress) #server
    seqNumb = 0
    indx = 0
    while indx <= len(data):
        p = Packet(hostC, hostS, portC, portS, seqNumb, 0, 0, WINDOW_SIZE, data[indx:PACKET_SIZE])
        packetsToSend.append(p.build())
        indx += PACKET_SIZE

    numPackts = len(packetsToSend)
    windowSize = setWindowSize(numPackts)
    nextToSend = 0
    base = 0

    print(f'Packets: {numPackts}')

    threading.Thread(target=recv, args=(conn,512,True,)).start()

    while base < numPackts:
        mutex.acquire()
        while nextToSend < base + windowSize:
            send(conn, packetsToSend[nextToSend], False)
            nextToSend += 1

        if not sendTimer.running():
            sendTimer.start()
            while sendTimer.running() and not sendTimer.timeout():
                mutex.release()
                time.sleep(SLEEP_INTERVAL)
                mutex.acquire()
            
            if sendTimer.timeout():
                nextToSend = base
                sendTimer.stop()
            else:
                windowSize =  setWindowSize(numPackts)
        
        mutex.release()
            
    #enviar un pqt de finalizacion

def recv(conn: Conn, length: int, thread = False) -> bytes:
    global expectedPacket

    while True:
        data = conn.socket.recvfrom(length)[0][20:]
        if thread:
            print('From thread')
        
        if data[:4] == b'\x00\x0f\x00\x0f':              # token
            pack: list = Packet.unpack(data)
            # 0:token  1:sourceAddress 2:destAddress 3:sourcePort 4:destPort 5:seqNum 6:ACK 7:flags 8:winSize 9:CheckSum 10:data
            print(pack)
            if validateCheckSum(pack[3:10], pack[10]):  # el paquete que se recibio no tiene cambios en los datos
                flags = pack[7]
                if flags & (1 << 3):                    # SYN flag active
                    packetSYN(pack, conn)
                elif flags & (1 << 6):                  # ACK flag active
                    packetACK(pack)
                elif flags & (1 << 2):                  # FIN flag active
                    pass
                else:                                   # Recibi datos normales los datos a transmitir
                    # Send back an ACK
                    if pack[5] == expectedPacket:
                        print('Packet recived')
                        print('Sending ACK', expectedPacket)
                        
                        
                        hostS, portS = parse_address(conn.serverAddress)
                        hostC, portC = parse_address(conn.clientAddress)
                        
                        pkt = Packet(hostS, hostC, portS, portC, 0, expectedPacket, 1 << 6, WINDOW_SIZE)
                        # udt.send(pkt, sock, addr)
                        # print('DATA', conn.isServer, conn.clientAddress, conn.serverAddress)
                        print(pack[10].decode())
                        print('\n')
                        send(conn, pkt.build(), False)
                        expectedPacket += 1
                    else:
                        print('Sending ACK', expectedPacket - 1)
                        pkt = Packet(hostS, hostC, portS, portC, 0, expectedPacket - 1, 1 << 6, WINDOW_SIZE)
                        # pkt = packet.make(expected_num - 1)
                        # udt.send(pkt, sock, addr)
                        send(conn, pkt, False)
        else:                                       # volver a pedir el paquete
            pass

def close(conn: Conn):
    pass


def validateCheckSum(tcp_headers: tuple, data: bytes): #(source_port, dest_port, seqNum, ack, flags, WinSize, CheckSum)
    # print(f'Validate checkSum: {tcp_headers[0]}, {tcp_headers[1] >> 1}, {tcp_headers[4]}, {len(data)}')
    return tcp_headers[6] == abs(~(tcp_headers[0] + tcp_headers[1] >> 1 + tcp_headers[4]) + len(data))

def packetSYN(pack: list, conn: Conn):
    # El objeto conn que llega es una conxion de server, hay que ponerle aqui el ip del cliente

    if conn.clientAddress is not None:
        raise ConnException(f'{conn.serverAddress} is alredy in use. First close connection')
    
    address = f'{socket.inet_ntoa(pack[10])}:0'
    conn.clientAddress = address

    _conn, isAccept = connections[conn.serverAddress]
    _conn.clientAddress = address
    connections[conn.serverAddress] = _conn, isAccept

def packetACK(pack: list):
    global base
    global mutex
    if base <= pack[6]:  #pack[6] es el ACK
        with mutex:
            base = pack[6] + 1
            sendTimer.stop()

def setWindowSize(num_packets):
    global base
    return min(WINDOW_SIZE, num_packets - base)

if __name__ == "__main__":
    rol = sys.argv[1]

    if rol == 's':
        server = listen('192.168.43.96:0')
        accept(server)
        recv(server, 1024)

    if rol == 'c':
        filePath = Path.cwd() / 'tests' / 'tmp-data' / 'data.txt'
        conn: Conn = dial("192.168.43.96:0")
        print('SYN ok')
        hostS, portS = parse_address(conn.serverAddress)
        hostC, portC = parse_address(conn.clientAddress)
        with open(filePath, 'r') as file:
            p = Packet(hostS, hostC, portS, portC, 0, expectedPacket, 0, WINDOW_SIZE, bytes(file.read(), 'utf-8'))
            send(conn, p.build())
    
