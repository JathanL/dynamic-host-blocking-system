import socket

s = socket.socket()                                        # create a TCP socket
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)    # allow quick restart
s.bind(("0.0.0.0", 5000))                                  # listen on port 5000
s.listen(100)                                              # queue up to 100 waiting clients

while True:
    conn, addr = s.accept()                                # wait for a client
    print("connection from", addr[0])
    conn.send(b"hello\n")
    conn.close()
