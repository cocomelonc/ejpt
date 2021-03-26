#!/usr/bin/env python3
# tcp port scan example with multi-threading
import threading
import socket
import sys
from queue import Queue

print_lock = threading.Lock()
q = Queue()

host = "10.10.15.4"

# tcp scan current port
def tcp_scan(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        res = sock.connect_ex((host, port))
        if res == 0:
            print ('port {}: open'.format(port))
        sock.close()
    except socket.error:
        print ("failed connect to server :(")
        sys.exit()
    except KeyBoardInterrupt:
        print ("exit...")
        sys.exit()

# run scan
def run():
    while True:
        p = q.get()
        tcp_scan(p)
        q.task_done()

# main logic
def main():
    for p in range(1000):
        thread = threading.Thread(target = run)
        thread.daemon = True
        thread.start()

    for p in range(1000):
        q.put(p)

    q.join()

if __name__ == "__main__":
    main()
