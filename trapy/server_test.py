import sys, getopt
from trapy import listen, accept, send, recv, close

host = "10.0.0.1"
port = 6

print("-------------SERVER---------------")
server = listen(host + f":{port}", True)
server_1 = accept(server)
c = 0
while server_1 != None and c < 5:
    r = recv(server_1, 20)
    print("*******Data Recieved*******\n", r)
    send(server_1, b"Jose")
    print("*******Data Send***********\n", r)
    print("----------Succeded-----------")
    c += 1
else:
    close(server_1)
close(server)

