import socket
# from package import Packet
import struct

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

s.bind(('127.0.0.1', 0))

# print(type(a))
# print(len(a))

while True:    
    data = s.recvfrom(65565)[0][20:]

    ip_headers, tcp_headers, info = data[:12], data[12:32], data[32:]
    if ip_headers[:4] == b'\x00\x0f\x00\x0f': #token for validate my packets
        print(f"Token ok, recive data {info.decode('ascii')}")

    # print(struct.unpack('!i', data[0][4:8]))
    # print(data[0][20:])
    # print(len(data[0]))    
    # if len(data[0]) == 63:      
    #     print(struct.unpack('!2h2i2hi', data[0][32:52]))
    #     print(data[0][52:])

    # try:
    #     # print(struct.unpack('3i', data[0][:12]))
    #     b = struct.unpack('i', data[0][0:4])[0]
    #     a = socket.inet_ntoa(b)
    #     print(a)
    # except Exception as err:
    #     print(err)
    #     print(data)
    #     print('\n')

    # try:
    #     print(Packet.unpack(data[1]))
    # except Exception as e:
    #     print(e)
