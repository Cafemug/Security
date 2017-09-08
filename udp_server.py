import socket
sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )

# server
sock.bind( ('192.168.6.200', 10000) )

print("listen:", '192.168.6.200:'+str(10000) )
while True:
  data, addr = sock.recvfrom( 65535 )
  print("ip:", addr[0], "port:", addr[1] )
  print("echo data:", data.decode( errors='ignore' ) )
  sock.sendto( data, addr )
