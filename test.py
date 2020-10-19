import threading
import time

# Esto ha estado funcionando con dos subprocesos el principal y el hilo creado

def thread_function(name):
    """
    docstring
    """
    print(f'Thread {name} starting')
    time.sleep(5)
    print(f'Thread {name} finished')

if __name__ == "__main__":
    print('Main: before creating thread')
    x = threading.Thread(target = thread_function, args = (1,))
    print('Main: before running thread')
    x.start()
    x.join()
    print('Main: wait for thread finished')
    print('Main: all Done')
