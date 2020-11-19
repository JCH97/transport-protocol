from trapy import close, recv, dial, send

host = "10.0.0.1"
port = 0

print("-------------CLIENT--------------")
tests = ["a", "0123456789", "#0123456789ABCDEF","ReallyBigPackage000000001234567890A1234567890B01234567890C01234567890","Rodri i lov you"]
client = dial(f'{host}:{port}')
# if client:
#     for val in tests:
#         send(client, bytes(val,"utf8"))
#         r = recv(client, 20)
#         print(f'Recived {r}\n\n')
#     close(client)

send(client, b"ReallyBigPackage000000001234567890A1234567890B01234567890C01234567890")
r = recv(client, 20)
print(f'Recived {r} {len(r)}')

send(client, b"ReallyBigPackage000000001234567890A1234567890B01234567890C01234567890")
r = recv(client, 20)
print(f'Recived {r} {len(r)}')

send(client, b"ReallyBigPackage000000001234567890A1234567890B01234567890C01234567890")
r = recv(client, 20)
print(f'Recived {r} {len(r)}')


send(client, b"ReallyBigPackage000000001234567890A1234567890B01234567890C01234567890")
r = recv(client, 20)
print(f'Recived {r} {len(r)}')
