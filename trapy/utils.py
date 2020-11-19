from package import Packet
from typing import List

def parse_address(address):
    host, port = address.split(':')
    if host == '':
        host = 'localhost'

    return host, int(port)

def build_packets(data, packet_size: int, winSize: int, sourceHost, sourcePort, destHost, destPort, flags = 0) -> List[Packet]:
    seq_num: int = 0
    indx: int = 0

    packets: List[Packet] = []

    while indx <= len(data):
        d = data[indx:indx + packet_size - 32]
        pck: Packet = Packet(sourceHost, destHost, sourcePort, destPort, 0, seq_num, flags, winSize, d)
        packets.append(pck.build())
        seq_num += 1
        indx += (packet_size - 32)

    return packets

def build_acks(hostS: str, hostD: str, portS: int, portD: int, winSize: int, expectedNum) -> bytes:
    return Packet(hostS, hostD, portS, portD, 0, expectedNum, 1 << 6, winSize, b'').build()