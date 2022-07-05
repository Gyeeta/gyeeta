
# Run as 2 or more processes : python ./test_tcp_reuseport.py & python ./test_tcp_reuseport.py &

import socket
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s.bind(('0.0.0.0', 8888))
s.listen(1)
conn = s

while True:
	conn, addr = s.accept()
	print('Connected to {}'.format(os.getpid()))
	data = conn.recv(1024)
	conn.send(data)

