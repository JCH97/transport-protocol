import sys, getopt
from trapy import listen, accept, send, recv, close, Conn

host = "10.0.0.1"
port = 0

print("-------------SERVER---------------")
server = listen(host + f":{port}")
server_1: Conn = accept(server)
c = 0
# while server_1 != None and c < 5:
#     r = recv(server_1, 70)
#     print(f'Recived {r} {len(r)}')
#     send(server_1, r)
#     c += 1
# close(server)


r = recv(server_1, 70)
print(f'Recived {r} {len(r)}')
send(server_1, b"Jose Carlos Hdez")

r = recv(server_1, 70)
print(f'Recived {r} {len(r)}')
send(server_1, b"Jose Carlos Hdez")

r = recv(server_1, 70)
print(f'Recived {r} {len(r)}')
send(server_1, b"Jose Carlos Hdez")

r = recv(server_1, 70)
print(f'Recived {r} {len(r)}')
send(server_1, b"Jose Carlos Hdez")


