import struct
import socket
import logging
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

    def build(self) -> bytes:
        ip_header = b'\x00\x0f\x00\x0f'  # token
        ip_header += socket.inet_aton(self.sourceAddress)
        ip_header += socket.inet_aton(self.destinationAddress)

        tcp_headers_out_checkSum: bytes = struct.pack('!2h2i2h', self.sourcePort, self.destinationPort,
                                         self.seqNumber, self.ack, self.flags, self.winSize)

        tcp_headers: bytes = struct.pack('!2h2i2hi', self.sourcePort, self.destinationPort,
                                         self.seqNumber, self.ack, self.flags, self.winSize, Packet.check_sum(ip_header + tcp_headers_out_checkSum + self.data))


        return ip_header + tcp_headers + self.data

    @staticmethod
    def check_sum(info: bytes) -> int:
        start: int = 0
        ans: int = 0

        while(start < len(info)):
            ans += int.from_bytes(info[start: start + 2], "little")
            start += 2

        return abs(ans)

    @staticmethod
    def unpack(packet: bytes) -> list:
        try:
            tcp_headers = struct.unpack('!2h2i2hi', packet[12:32])
            pack = [
                packet[0:4],
                socket.inet_ntoa(packet[4:8]),
                socket.inet_ntoa(packet[8:12]),
            ] + list(tcp_headers)
            pack.append(packet[32:])

            return pack

        except Exception as err:
            logging.error(err)

        return None


if __name__ == "__main__":
    p = Packet('127.0.0.1', '127.0.0.1', 80, 3000, 45221, 5421, 0, 512, b'Jose Carlos Hdez')

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
