import struct
import socket
from typing import Tuple, Any

class Packet:
    def __init__(self, sourceAddress: str, destinationAddress: str, sourcePort: int, destinationPort: int, seqNumber: int, ack: int, flags: int, winSize: int, data=b''):
        self.sourceAddress = sourceAddress
        self.destinationAddress = destinationAddress
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.seqNumber = seqNumber
        self.ack = ack
        self.flags = flags
        self.winSize = winSize
        self.data = data
        self.checkSum = self.check_sum()

    def build(self) -> bytes:
        tcp_headers: bytes = struct.pack('!2h2i2hi', self.sourcePort, self.destinationPort,
                                         self.seqNumber, self.ack, self.flags, self.winSize, self.check_sum())

        ip_header = b'\x00\x0f\x00\x0f'                       #token
        ip_header += socket.inet_aton(self.sourceAddress)
        ip_header += socket.inet_aton(self.destinationAddress)
        
        return ip_header + tcp_headers + self.data

    def check_sum(self) -> int:
        return abs(~(self.sourcePort + self.destinationPort >> 1) + len(self.data))

    @staticmethod
    def unpack(packet: bytes) -> Tuple[Any]:

        try:
            return packet[0:4], packet[4:8], packet[8:12], struct.unpack('!2h2i2hi', packet[12:32]), packet[32:]
        except:
            pass

        return None


if __name__ == "__main__":
    p = Packet('127.0.0.1', '127.0.0.1', 80, 3000, 45221, 5421, 0, 512, b'Jose Carlos')

    pack = p.build()
    unpack = Packet.unpack(pack)

    print(pack)
    print(unpack)

    # a = 5
    # b = a.to_bytes(2, 'little')
    # c = 7
    # d = c.to_bytes(2, 'little')
    # e = b + d
    # print(e)

    # f = int.from_bytes(e[:2], 'little')
    # g = int.from_bytes(e[2:5], 'little')

    # print(f, g) => print(5, 7)
