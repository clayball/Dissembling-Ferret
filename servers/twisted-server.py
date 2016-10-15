#!/usr/bin/env python

from twisted.internet import protocol, reactor

class Echo(protocol.Protocol):
	def dataReceived(self, data):
		# Echo back what was received
		# self.transport.write(data)
		# Print data received to STDOUT
		print '[*] received: '  + data

class EchoFactory(protocol.Factory):
	def buildProtocol(self, addr):
		return Echo()

reactor.listenTCP(8000, EchoFactory())
reactor.run()



