#!/usr/bin/env python

'''
The purpose of this is to view what different types of TCP traffic look like.

This is a basic example of a socket library based server. To connect to it

$ telnet x.x.x.x 37337

The connect is opened and closed without sending any data.

'''


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
	conn.send('[*] data received\n')
	conn.close()

print '[*] goodbye'