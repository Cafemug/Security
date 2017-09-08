import struct
import socket
from header.eth import *
from header.ip import *
from header.icmp import *

def make_chksum( header ):

  size = len( header )
  if size % 2:
    header = header + b'\x00'
    size = len( header )

  size = size // 2
  header = struct.unpack('!' + str(size) + 'H', header )
  chksum = sum( header )

  carry = chksum & 0xFF0000
  carry = carry >> 16
  while carry != 0:
    chksum = chksum & 0xFFFF
    chksum = chksum + carry
    carry = chksum & 0xFF0000
    carry = carry >> 16

  chksum = chksum ^ 0xFFFF
  return chksum  

eth = Eth()
echo = Echo()

frag1 = Ip()
frag2 = Ip()
frag3 = Ip()

echo.type = 8
echo.code = 0
echo.chksum = 0
echo.id = 0xabcd
echo.seq = 1
echo.payload = '1234567891234567'
echo.chksum = make_chksum( echo.header )
echo.payload = ''

frag1.ver = 4
frag1.length = 20
frag1.service = 0
frag1.total = 20 + len( echo.header )
frag1.id = 0x1234
frag1.flag = 1
frag1.offset = 0
frag1.ttl = 64
frag1.type = 1
frag1.chksum = 0
frag1.src = '192.168.6.200'
frag1.dst = '192.168.6.122'
frag1.chksum = make_chksum( frag1.header )

payload2 = '12345678'.encode()
frag2.ver = 4
frag2.length = 20
frag2.service = 0
frag2.total = 20 + len( payload2 )
frag2.id = 0x1234
frag2.flag = 1
frag2.offset = 8
frag2.ttl = 64
frag2.type = 1
frag2.chksum = 0
frag2.src = '192.168.6.200'
frag2.dst = '192.168.6.122'
frag2.chksum = make_chksum( frag2.header )

payload3 = '91234567'.encode()
frag3.ver = 4
frag3.length = 20
frag3.service = 0
frag3.total = 20 + len( payload3 )
frag3.id = 0x1234
frag3.flag = 0
frag3.offset = 16
frag3.ttl = 64
frag3.type = 1
frag3.chksum = 0
frag3.src = '192.168.6.200'
frag3.dst = '192.168.6.122'
frag3.chksum = make_chksum( frag3.header )

# 00:50:56:2a:30:7c
eth.dst = '00:50:56:2a:30:7c'
eth.src = '00:50:56:31:A8:43'
eth.type = 0x0800

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW )
sock.bind( ('eth0', socket.SOCK_RAW) )

sock.send( eth.header + frag1.header + echo.header )
sock.send( eth.header + frag2.header + payload2 )
sock.send( eth.header + frag3.header + payload3 )













