from timer import Timer
import threading

# Other data
PACKET_SIZE = 512
SLEEP_INTERVAL = 0.05
TIMEOUT_INTERVAL = 0.5
WINDOW_SIZE = 5

# Shared resources across threads
base = 0
send_timer = Timer(TIMEOUT_INTERVAL)
mutex = threading.Lock()
expected_num = 0

errors = ["Server isn't running", "First call accept with server connection"]

showLogs = False

connection_servers: dict = {}

def parse_address(address):
    host, port = address.split(':')

    if host == '':
        host = 'localhost'

    return host, int(port)
