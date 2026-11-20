import socket, sys, time

host = sys.argv[1]            # server IP, e.g. 10.0.0.1
count = int(sys.argv[2])      # how many connections to make
gap = float(sys.argv[3])      # seconds to wait between connections

for i in range(count):
    try:
        s = socket.create_connection((host, 5000), timeout=1)
        s.recv(10)
        s.close()
        print(i, "ok")
    except Exception:
        print(i, "FAILED (blocked?)")
    time.sleep(gap)
