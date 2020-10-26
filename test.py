import threading
import time
import struct

# Esto ha estado funcionando con dos subprocesos el principal y el hilo creado

def thread_function(name):
    """
    docstring
    """
    print(f'Thread {name} starting')
    time.sleep(5)
    print(f'Thread {name} finished')

if __name__ == "__main__":

    a = struct.pack('!2h2l2hl', 80, 3000, 45123, 51212, 0, 512, 31424)
    b = struct.unpack('!2h2l2hl', a)
    print(a)
    print(b)
    
    exit()
    
    print('Main: before creating thread')
    x = threading.Thread(target = thread_function, args = (1,))
    print('Main: before running thread')
    x.start()
    x.join()
    print('Main: wait for thread finished')
    print('Main: all Done')
