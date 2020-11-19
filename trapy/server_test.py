import sys, getopt
from trapy import listen, accept, send, recv, close, Conn

host = "10.0.0.1"
port = 6

print("-------------SERVER---------------")
server = listen(host + f":{port}", True)
server_1: Conn = accept(server)
c = 0
while server_1 != None and c < 5:
    r = recv(server_1, 20)
    print("*******Data Recieved*******\n", r)
    send(server_1, b"Jose")
    print("*******Data Send***********\n", server_1.source ,server_1.destination, r)
    print("----------Success-----------")
    c += 1
    print(f'c value: {c}')
close(server)

