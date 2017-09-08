from header.eth import *
from header.ip import *
from header.udp import *
from header.tcp import *
from header.arp import *
from header.icmp import *

class Packet:

  def __init__( self, raw ):
    self._eth = Eth( raw[:14] )

    if self._eth.type == 0x0800:
      self.analyze_ip( raw[14:] )
    elif self._eth.type == 0x0806:
      self.analyze_arp( raw[14:] )

  def analyze_ip( self, raw ):
    self._ip = Ip( raw )
    if self._ip.type == 17:
      self.analyze_udp( raw[20:] )
    elif self._ip.type == 6:
      self.analyze_tcp( raw[20:] )
    elif self._ip.type == 1:
      if self._ip.offset == 0:
        self.analyze_icmp( raw[20:] )
      else:
        self._raw = raw[20:]

  def analyze_icmp( self, raw ):
    self._icmp = Icmp( raw )

  def analyze_arp( self, raw ):
    self._arp = Arp( raw )

  def analyze_udp( self, raw ):
    self._udp = Udp( raw )

  def analyze_tcp( self, raw ):
    self._tcp = Tcp( raw )

  @property
  def raw( self ):
    return self._raw

  @property
  def icmp( self ):
    return self._icmp

  @property
  def eth( self ):
    return self._eth

  @property
  def ip( self ):
    return self._ip

  @property
  def udp( self ):
    return self._udp

  @property
  def tcp( self ):
    return self._tcp

  @property
  def arp( self ):
    return self._arp
