from pathlib import Path, PosixPath

from trapy import close, recv, dial, send, Conn

host = "10.0.0.1"
port = 0

def test1(client: Conn):
    print('New Test \n')
    p = Path.cwd() / 'tests' / 'data'
    print(p)
    files = [obj.name for obj in Path(p).iterdir() if obj.is_file()]

    for i in files:
        newPath: PosixPath = Path.joinpath(p, i)
        if newPath.suffix == '.txt' and 'data' in newPath.stem:
            with open(newPath) as file:
                print(f'File: {i}')
                text: bytes = bytes(file.read(), 'utf-8')

                toSend: int= 15000
                lenSend: int = send(client, text[:toSend])
                print(f'Send {lenSend}\n')
                amount: int = 0

                while True:
                    ans: bytes = recv(client, 1024)
                    # print(ans)
                    # print(type(ans))
                    # print(len(ans))
                    print(f'Recv {len(ans)}')

                    amount += len(ans)

                    if amount == lenSend:
                        print(f'Recv all data ok len: {amount}')
                        break

                assert amount == lenSend
                print("------------------------------------Success-----------------------------------------------")

def test2(client: Conn):
    tests = ["a", "0123456789", "#0123456789ABCDEF","ReallyBigPackage000000001234567890A1234567890B01234567890C01234567890","Jose Carlos Hdez Pinnera"]

    for val in tests:
        send(client, bytes(val,"utf8"))
        r = recv(client, 70)
        print(f'Recived {r}\n')


if __name__ == "__main__":
    print("-------------------------------------CLIENT------------------------------------------")
    client: Conn = dial(f'{host}:{port}')

    test1(client)
    test2(client)
    close(client)


