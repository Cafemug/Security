import socket
import sys

if len(sys.argv) < 2:
  print("Usage: python3 tcp_client.py ipaddr port")
  exit(0)

ipaddr = sys.argv[1]
port = int( sys.argv[2] )

sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
sock.connect( (ipaddr, port) )

sock.send('hello'.encode())

data  = sock.recv( 65535 )
print( data.decode() )
