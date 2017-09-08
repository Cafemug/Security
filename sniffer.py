import socket
import struct
import time
from header.packet import *

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

raw = socket.socket( socket.PF_PACKET, socket.SOCK_RAW )
raw.bind( ('eth0', socket.SOCK_RAW) )

filter_ip = '192.168.6.122'

while True:
  data, addr = raw.recvfrom( 65535 )
  packet = Packet( data )

  if (packet.eth.type == 0x0806 and packet.arp.sender_ip == filter_ip) or \
     (packet.eth.type == 0x0806 and packet.arp.target_ip == filter_ip) or \
     (packet.eth.type == 0x0800 and packet.ip.src == filter_ip) or \
     (packet.eth.type == 0x0800 and packet.ip.dst == filter_ip):

    '''
    if packet.eth.type == 0x0806:
      print(packet.eth.src + ' -> ' + packet.eth.dst)
      print("ethernet type: " + str(packet.eth.type) )
      print("sender: " + packet.arp.sender_ip + " target: " + packet.arp.target_ip )
      print()

    if packet.eth.type == 0x0800 and packet.ip.type == 1:
      print(packet.eth.src + ' -> ' + packet.eth.dst)
      print("ethernet type: " + str(packet.eth.type) )
      print( packet.ip.src + ' -> ' + packet.ip.dst )
      print("type: " + str(packet.icmp.type) + " code: " + str(packet.icmp.code) )
      print()

    elif packet.eth.type == 0x0800 and packet.ip.type == 17:
      print(packet.eth.src + ' -> ' + packet.eth.dst)
      print("ethernet type: " + str(packet.eth.type) )
      print( packet.ip.src + ':' + str(packet.udp.src) + ' -> ' + \
             packet.ip.dst + ':' + str(packet.udp.dst) )
      print( "id:", packet.ip.id, "flag:", packet.ip.flag, "offset:", packet.ip.offset )
      print( "data: " + packet.udp.data )
      print()
    '''
    if packet.eth.type == 0x0800 and packet.ip.type == 6:
      old_chksum = packet.tcp.chksum
      packet.tcp._chksum = b'\x00\x00'
      new_chksum = make_chksum( packet.ip._src + packet.ip._dst + b'\x00' + packet.ip._type + 
                                b'\x00\x14' + packet.tcp.header )

      print( packet.ip.src + ':' + str(packet.tcp.src) + ' -> ' + \
             packet.ip.dst + ':' + str(packet.tcp.dst) )
      print( "seq: " + str( packet.tcp.seq ) + " | " + "ack: " + str( packet.tcp.ack) )
      print( "flag: " + str( packet.tcp.flag) )
      if new_chksum != old_chksum:
        print( "chksum: " + str( old_chksum ) + "(invalid cheksum)" )
      else:
        print( "chksum: " + str( old_chksum ) )
        
      
      print()










