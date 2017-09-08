import struct

class Ip:

  def __init__( self, raw=None ):
    if raw != None:
      self._ver_and_len = raw[:1]
      self._service = raw[1:2]
      self._total = raw[2:4]
      self._id = raw[4:6]
      self._flag_and_offset = raw[6:8]
      self._ttl = raw[8:9]
      self._type = raw[9:10]
      self._chksum = raw[10:12]
      self._src = raw[12:16]
      self._dst = raw[16:20]
    else:
      self._flag_and_offset = b'\x00\x00'
      self._ver_and_len = b'\x00'

  @property
  def header( self ):
    return self._ver_and_len + self._service + self._total + self._id + \
           self._flag_and_offset + self._ttl + self._type + self._chksum + \
           self._src + self._dst

  @property
  def ver( self ):
    (ver,) = struct.unpack('!B', self._ver_and_len )
    ver = ver >> 4
    return ver

  @ver.setter
  def ver( self, ver ):
    (len,) = struct.unpack('!B', self._ver_and_len ) 
    len = len & 0x0F
    ver = ver << 4
    tmp = ver + len 
    self._ver_and_len = struct.pack('!B', tmp )

  @property
  def length( self ):
    (len,) = struct.unpack('!B', self._ver_and_len )
    len = ( len & 0x0F ) << 2
    return len

  @length.setter
  def length( self, len ):
    (ver,) = struct.unpack('!B', self._ver_and_len )
    ver = ver & 0xF0
    len = len >> 2
    tmp = ver + len
    self._ver_and_len = struct.pack('!B', tmp )

  @property
  def service( self ):
    (service,) = struct.unpack('!B', self._service )
    return service 

  @service.setter
  def service( self, service ):
    self._service = struct.pack('!B', service )

  @property
  def total( self ):
    (total,) = struct.unpack('!H', self._total )
    return total

  @total.setter
  def total( self, total ):
    self._total = struct.pack('!H', total )

  @property
  def id( self ):
    (id,) = struct.unpack('!H', self._id )
    return id

  @id.setter
  def id( self, id ):
    self._id = struct.pack('!H', id )

  @property
  def flag( self ):
    (flag,) = struct.unpack('!H', self._flag_and_offset )
    flag = flag >> 13
    return flag

  @flag.setter
  def flag( self, flag ):
    (offset,) = struct.unpack('!H', self._flag_and_offset)
    offset = offset & 0x1FFF
    flag = flag << 13
    tmp = flag + offset

    self._flag_and_offset = struct.pack('!H', tmp )

  @property
  def offset( self ):
    (offset,) = struct.unpack('!H', self._flag_and_offset )
    offset = (offset & 0x1FFF) << 3
    return offset

  @offset.setter
  def offset( self, offset ):
    (flag,) = struct.unpack('!H', self._flag_and_offset )
    flag = flag & 0xE000
    offset = offset >> 3
    tmp = flag + offset
    self._flag_and_offset = struct.pack('!H', tmp)

  @property
  def ttl( self ):
    (ttl,) = struct.unpack('!B', self._ttl )
    return ttl

  @ttl.setter
  def ttl( self, ttl ):
    self._ttl = struct.pack('!B', ttl )

  @property
  def type( self ):
    (type,) = struct.unpack('!B', self._type )
    return type

  @type.setter
  def type( self, type ):
    self._type = struct.pack('!B', type )

  @property
  def chksum( self ):
    (chksum,) = struct.unpack('!H', self._chksum )
    return chksum

  @chksum.setter
  def chksum( self, chksum ):
    self._chksum = struct.pack('!H', chksum )

  @property
  def src( self ):
    src = struct.unpack('!4B', self._src ) 
    src = '%d.%d.%d.%d' % src
    return src

  @src.setter
  def src( self, ip ):
    ip = ip.split('.')
    for i in range( len(ip) ):
      ip[i] = int( ip[i] )

    self._src = b''
    for i in range( len(ip) ):
      self._src += struct.pack('!B', ip[i] )

  @property
  def dst( self ):
    dst = struct.unpack('!4B', self._dst ) 
    dst = '%d.%d.%d.%d' % dst
    return dst

  @dst.setter
  def dst( self, ip ):
    ip = ip.split('.')
    for i in range( len(ip) ):
      ip[i] = int( ip[i] )

    self._dst = b''
    for i in range( len(ip) ):
      self._dst += struct.pack('!B', ip[i] )


