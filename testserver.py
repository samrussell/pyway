#!/usr/bin/python

import SocketServer
import lib.bgp.messages
import struct

class MyTCPHandler(SocketServer.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def setup(self):
        self.protocolbuffer = b''

    def handle(self):
        while True:
            # self.request is the TCP socket connected to the client
            self.data = self.request.recv(1024)
            if not self.data:
                break
            #self.data = self.data.strip()
            #print "{} wrote:".format(self.client_address[0])
            print "packet in length %d" % len(self.data)
            # append to protocolbuffer, then check if it fits our conditions
            self.protocolbuffer = self.protocolbuffer + self.data
            # do test
            if len(self.protocolbuffer) <= 19:
                # not enough data, loop
                continue
            # get length
            header = struct.unpack('!IIIIHB', self.protocolbuffer[:19])
            length = header[4]
            packet = self.protocolbuffer[:length]
            self.protocolbuffer = self.protocolbuffer[length:]
            # parse packet
            message = lib.bgp.messages.BGPMessage.decode(packet)
            print message


if __name__ == "__main__":
    HOST, PORT = "10.0.3.1", 179

    # Create the server, binding to localhost on port 9999
    server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()
