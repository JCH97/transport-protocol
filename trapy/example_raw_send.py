#CLIENT

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

a =  s.sendto(b'Jose Carlos', ('10.0.0.1', 0))

while True:
    data, _ = s.recvfrom(65565)
    print(data)
