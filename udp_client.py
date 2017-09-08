import socket

sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
sock.bind( ('', 0) )

# client
while True:
  data = input()
  sock.sendto( data.encode(), ('192.168.6.122', 20000))

  data, addr = sock.recvfrom( 1000 )
  print( data.decode() )
