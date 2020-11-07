#SERVER

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
# s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.bind(('10.0.0.1', 0))

while True:
    data, addr = s.recvfrom(65565)
    print(f'Recibed data {data}, {addr}')
    
    s.sendto(b'Respuesta', addr)
