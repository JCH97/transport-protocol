from pathlib import Path, PosixPath

from trapy import listen, accept, send, recv, close, Conn

host: str = "10.0.0.1"
port: int = 0

def test1(server: Conn):
    toRecv: int = 15000

    r: bytes = recv(server, toRecv)
    rr: int = send(server, r)

    print(f'Recv {len(r)}')
    print(f'Send {rr}')

    assert len(r) == rr
    print('---------------------------------------Success------------------------------------------')

def test2(server: Conn):
    c: int = 0
    while server != None and c < 5:
        r = recv(server, 70)
        print(f'Recived {r} {len(r)}')
        send(server, r)
        c += 1

if __name__ == "__main__":
    print("-------------------------------------SERVER------------------------------------------")
    server: Conn = listen(f'{host}:{port}')
    server = accept(server)

    test1(server)
    test2(server)

    close(server)