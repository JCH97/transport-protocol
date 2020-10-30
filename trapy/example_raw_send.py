#CLIENT

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

a =  s.sendto(b'Jose Carlos', ('192.168.43.96', 0))

while True:
    data, _ = s.recvfrom(1024)
    print(data)