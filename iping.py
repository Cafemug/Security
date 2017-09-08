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
ip = Ip()
echo = Echo()

echo.type = 8
echo.code = 0
echo.chksum = 0
echo.id = 0xabcd
echo.seq = 1
echo.payload = 'qazwsxedcrfvtgbyhnujmikopABCDCEFERTUACJI3456789'
echo.chksum = make_chksum( echo.header )

ip.ver = 4
ip.length = 20
ip.service = 0
ip.total = 20 + len( echo.header )
ip.id = 0x1234
ip.flag = 0
ip.offset = 0
ip.ttl = 64
ip.type = 1
ip.chksum = 0
ip.src = '192.168.6.200'
ip.dst = '168.126.63.1'
ip.chksum = make_chksum( ip.header )

# 00:50:56:2a:30:7c
eth.dst = '00:05:66:23:30:19'
eth.src = '00:50:56:31:A8:43'
eth.type = 0x0800

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW )
sock.bind( ('eth0', socket.SOCK_RAW) )

sock.send( eth.header + ip.header + echo.header )













