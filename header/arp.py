import struct

class Arp:

  def __init__( self, raw=None ):
    if raw != None:
      self._hw_type = raw[:2]
      self._protocol_type = raw[2:4]
      self._hw_size = raw[4:5]
      self._protocol_size = raw[5:6]
      self._opcode = raw[6:8]
      self._sender_mac = raw[8:14]
      self._sender_ip = raw[14:18]
      self._target_mac = raw[18:24]
      self._target_ip = raw[24:28]

  @property
  def header( self ):
    return self._hw_type + self._protocol_type + self._hw_size + \
           self._protocol_size + self._opcode + self._sender_mac + \
           self._sender_ip + self._target_mac + self._target_ip

  @property 
  def hw_type( self ):
    (type,) = struct.unpack( '!H', self._hw_type )
    return type

  @hw_type.setter
  def hw_type( self, type ):
    type = struct.pack('!H', type )
    self._hw_type = type

  @property 
  def protocol_type( self ):
    (type,) = struct.unpack( '!H', self._protocol_type )
    return type

  @protocol_type.setter
  def protocol_type( self, type ):
    type = struct.pack('!H', type )
    self._protocol_type = type

  @property 
  def hw_size( self ):
    (size,) = struct.unpack( '!B', self._hw_size )
    return size

  @hw_size.setter
  def hw_size( self, size ):
    size = struct.pack('!B', size )
    self._hw_size = size

  @property 
  def protocol_size( self ):
    (size,) = struct.unpack( '!B', self._protocol_size )
    return size

  @protocol_size.setter
  def protocol_size( self, size ):
    size = struct.pack('!B', size )
    self._protocol_size = size

  @property 
  def opcode( self ):
    (opcode,) = struct.unpack( '!H', self._opcode )
    return opcode

  @opcode.setter
  def opcode( self, opcode ):
    opcode = struct.pack('!H', opcode )
    self._opcode = opcode

  @property 
  def sender_mac( self ):
    mac = struct.unpack( '!6B', self._sender_mac )
    mac = '%02x:%02x:%02x:%02x:%02x:%02x' % mac
    return mac

  @sender_mac.setter
  def sender_mac( self, mac ):
    mac = mac.split(':')
    for i in range( len(mac) ):
      mac[i] = int( mac[i], 16 )

    self._sender_mac = b''
    for i in range( len(mac) ):
      self._sender_mac += struct.pack('!B', mac[i] )
      
  @property 
  def target_mac( self ):
    mac = struct.unpack( '!6B', self._target_mac )
    mac = '%02x:%02x:%02x:%02x:%02x:%02x' % mac
    return mac

  @target_mac.setter
  def target_mac( self, mac ):
    mac = mac.split(':')
    for i in range( len(mac) ):
      mac[i] = int( mac[i], 16 )

    self._target_mac = b''
    for i in range( len(mac) ):
      self._target_mac += struct.pack('!B', mac[i] )
 
  @property 
  def sender_ip( self ):
    ip = struct.unpack( '!4B', self._sender_ip )
    ip = '%d.%d.%d.%d' % ip
    return ip

  @sender_ip.setter
  def sender_ip( self, ip ):
    ip = ip.split('.')
    for i in range( len(ip) ):
      ip[i] = int( ip[i] )

    self._sender_ip = b''
    for i in range( len(ip) ):
      self._sender_ip += struct.pack('!B', ip[i] )

  @property 
  def target_ip( self ):
    ip = struct.unpack( '!4B', self._target_ip )
    ip = '%d.%d.%d.%d' % ip
    return ip

  @target_ip.setter
  def target_ip( self, ip ):
    ip = ip.split('.')
    for i in range( len(ip) ):
      ip[i] = int( ip[i] )

    self._target_ip = b''
    for i in range( len(ip) ):
      self._target_ip += struct.pack('!B', ip[i] )









