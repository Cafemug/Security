import struct
import socket
from header.eth import *
from header.ip import *
from header.udp import *

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
udp = Udp()

udp.data = ''
udp.src = 22333
udp.dst = 10
udp.chksum = 0
udp.length = 0
udp.length = len( udp.header )

ip.ver = 4
ip.length = 20
ip.service = 0
ip.total = 20 + len( udp.header )
ip.id = 0x1234
ip.flag = 0
ip.offset = 0
ip.ttl = 64
ip.type = 17
ip.chksum = 0
ip.src = '192.168.6.41'
ip.dst = '192.168.6.200'
ip.chksum = make_chksum( ip.header )

pseudo = ip._src + ip._dst + b'\x00' + ip._type + udp._length + udp.header
udp.chksum = make_chksum( pseudo )

# 00:50:56:2a:30:7c
eth.dst = '00:50:56:2a:30:7c'
eth.src = '00:50:56:31:A8:43'
eth.type = 0x0800

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW )
sock.bind( ('eth0', socket.SOCK_RAW) )

sock.send( eth.header + ip.header + udp.header )













