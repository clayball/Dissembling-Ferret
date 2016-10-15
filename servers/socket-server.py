#!/usr/bin/env python

import socket

s = socket.socket()

# Get local host name
host = socket.gethostname()

port = 37337
s.bind((host, port))

s.listen(1)
while True:
	conn, addr = s.accept()
	print '[*] Connection from ', addr
	conn.send('[*] data received')
	conn.close()