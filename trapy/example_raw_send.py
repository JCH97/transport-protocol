import socket
import struct
from package import Packet

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# ip_header  = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
# ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
# ip_header += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum
# ip_header += b'\x0a\x00\x00\x01'  # Source Address
# ip_header += b'\x0a\x00\x00\x02'  # Destination Address

# tcp_header  = b'\x30\x39\x00\x50' # Source Port | Destination Port
# tcp_header += b'\x00\x00\x00\x00' # Sequence Number
# tcp_header += b'\x00\x00\x00\x00' # Acknowledgement Number
# tcp_header += b'\x50\x02\x71\x10' # Data Offset, Reserved, Flags | Window Size
# tcp_header += b'\xe6\x32\x00\x00' # Checksum | Urgent Pointer

# packet = ip_header + tcp_header + b'Jose Carlos Hernandez'

p = Packet('127.0.0.1', '192.168.43.105', 80, 3000, 45221, 5421, 0, 512, b'Jose Carlos Hernandez Pinnera, Ciencia de la Computacion')

a =  s.sendto(p.build(), ('192.168.43.105', 0))
print(a);
# h = struct.pack('!i', 121);
# y = struct.unpack('!i', h)
# print(h, y)

# a = s.sendto(b'Jose Carlos', ('127.0.0.1', 0))
# print(a)

# print(struct.pack('i', 121))