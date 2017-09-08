import socket
import random

port = random.randrange( 10000, 65536 )

server_sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
server_sock.bind( ('192.168.6.200', port) )
server_sock.listen(0)

print("listen on port: ", port )
while True:
  client_sock, addr = server_sock.accept()
  print("client:", addr[0] )

  client_sock.close()
