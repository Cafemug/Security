import struct

class Eth:

  def __init__( self, raw=None ):
    if raw != None:
      self._dst = raw[:6]
      self._src = raw[6:12]
      self._type = raw[12:14]

  @property
  def header( self ):
    return self._dst + self._src + self._type

  @property
  def dst( self ):
    dst = struct.unpack('!6B', self._dst )
    dst = '%02x:%02x:%02x:%02x:%02x:%02x' % dst
    return dst

  @dst.setter
  def dst( self, dst ):
    dst = dst.split(':')
    for i in range( len(dst) ):
      dst[i] = int( dst[i], 16 )

    self._dst = b''
    for i in range( len(dst) ):
      self._dst += struct.pack('!B', dst[i] ) 

  @property
  def src( self ):
    src = struct.unpack('!6B', self._src )
    src = '%02x:%02x:%02x:%02x:%02x:%02x' % src
    return src

  @src.setter
  def src( self, src ):
    src = src.split(':')
    for i in range( len(src) ):
      src[i] = int( src[i], 16 )

    self._src = b''
    for i in range( len(src) ):
      self._src += struct.pack('!B', src[i] ) 

  @property
  def type( self ):
    (type,) = struct.unpack('!H', self._type )
    return type

  @type.setter
  def type( self, type ):
    type = struct.pack('!H', type )
    self._type = type






 


