from header.eth import *
from header.ip import *
from header.tcp import *
from header.packet import *

import socket
import struct
import random
import time
import sys

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


port = random.randrange( 1, 65535 )
client_seq = random.randrange( 1, 4000000000 )
server_seq = 0

sock = socket.socket( socket.AF_PACKET, socket.SOCK_RAW )
sock.bind( ('eth0', socket.SOCK_RAW) )

eth = Eth()
ip = Ip()
tcp = Tcp()

tcp.src = port
tcp.dst = int(sys.argv[1])
tcp.seq = client_seq
tcp.ack = 0
tcp.flag = 2
tcp.length = 0
tcp.window = 65535
tcp.chksum = 0
tcp.dummy = 0
tcp.data = ''
tcp.length = len( tcp.header )

ip.ver = 4
ip.length = 20
ip.service = 0
ip.total = ip.length + tcp.length
ip.id = 0x1234
ip.flag = 0
ip.offset = 0
ip.ttl = 64
ip.type = 6
ip.chksum = 0
ip.src = '192.168.6.200'
ip.dst = '192.168.6.122'

ip.chksum = make_chksum( ip.header )
length = struct.pack( '!H', tcp.length )
pseudo_header = ip._src + ip._dst + b'\x00' + ip._type + length + tcp.header
tcp.chksum = make_chksum( pseudo_header )

eth.dst = '00:50:56:2a:30:7c'
eth.src = '00:50:56:31:A8:43'
eth.type = 0x0800

# SYN
sock.send( eth.header + ip.header + tcp.header )

packet = ''
while True:
  data, addr = sock.recvfrom( 65535 )
  packet = Packet( data )
  if packet.eth.type == 0x0800 and packet.ip.dst == '192.168.6.200' and packet.ip.type == 6 \
     and packet.tcp.dst == port and packet.tcp.ack == client_seq + 1:

    print( packet.ip.src + ':' + str(packet.tcp.src) + ' -> ' + \
           packet.ip.dst + ':' + str(packet.tcp.dst) )
    print( "seq: " + str( packet.tcp.seq ) + " | " + "ack: " + str( packet.tcp.ack) )
    print( "flag: " + str( packet.tcp.flag) )
    print()

    # SYN/ACK
    break

server_seq = packet.tcp.seq
client_seq = client_seq + 1
server_seq = server_seq + 1

tcp.seq = client_seq
tcp.ack = server_seq
tcp.chksum = 0
tcp.length = 0
tcp.flag = 16
tcp.length = len( tcp.header )

length = struct.pack( '!H', tcp.length )
pseudo_header = ip._src + ip._dst + b'\x00' + ip._type + length + tcp.header
tcp.chksum = make_chksum( pseudo_header )

#ACK
sock.send( eth.header + ip.header + tcp.header )

tcp.seq = client_seq
tcp.ack = server_seq
tcp.chksum = 0
tcp.length = 0
tcp.flag = 24
tcp.data = 'hello'
tcp.length = len( tcp.header ) - len(tcp.data)

ip.total = len( ip.header ) + len( tcp.header )
ip.chksum = 0
ip.chksum = make_chksum( ip.header )

length = tcp.length + len(tcp.data)
length = struct.pack( '!H', length )
pseudo_header = ip._src + ip._dst + b'\x00' + ip._type + length + tcp.header
tcp.chksum = make_chksum( pseudo_header )

#PSH/ACK
sock.send( eth.header + ip.header + tcp.header )

packet = ''
while True:
  data, addr = sock.recvfrom( 65535 )
  packet = Packet( data )
  if packet.eth.type == 0x0800 and packet.ip.dst == '192.168.6.200' and packet.ip.type == 6 \
     and packet.tcp.dst == port and packet.tcp.ack == client_seq + len(tcp.data):

    print( packet.ip.src + ':' + str(packet.tcp.src) + ' -> ' + \
           packet.ip.dst + ':' + str(packet.tcp.dst) )
    print( "seq: " + str( packet.tcp.seq ) + " | " + "ack: " + str( packet.tcp.ack) )
    print( "flag: " + str( packet.tcp.flag) )
    print()

    # ACK
    break

client_seq = client_seq + len( tcp.data )

packet = ''
while True:
  data, addr = sock.recvfrom( 65535 )
  packet = Packet( data )
  if packet.eth.type == 0x0800 and packet.ip.dst == '192.168.6.200' and packet.ip.type == 6 \
     and packet.tcp.dst == port and packet.tcp.ack == client_seq:

    print( packet.ip.src + ':' + str(packet.tcp.src) + ' -> ' + \
           packet.ip.dst + ':' + str(packet.tcp.dst) )
    print( "seq: " + str( packet.tcp.seq ) + " | " + "ack: " + str( packet.tcp.ack) )
    print( "flag: " + str( packet.tcp.flag) )
    print()

    # PSH/ACK
    break

server_seq = server_seq + len( packet.tcp.data )

tcp.seq = client_seq
tcp.ack = server_seq
tcp.chksum = 0
tcp.length = 0
tcp.flag = 16
tcp.data = ''
tcp.length = len( tcp.header ) - len(tcp.data)

ip.total = len( ip.header ) + len( tcp.header )
ip.chksum = 0
ip.chksum = make_chksum( ip.header )

length = tcp.length + len(tcp.data)
length = struct.pack( '!H', length )
pseudo_header = ip._src + ip._dst + b'\x00' + ip._type + length + tcp.header
tcp.chksum = make_chksum( pseudo_header )

# ACK
sock.send( eth.header + ip.header + tcp.header )


  













