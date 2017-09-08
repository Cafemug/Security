import struct 

class Udp:

  def __init__( self, raw=None ):
    if raw != None:
      self._src = raw[:2]
      self._dst = raw[2:4]
      self._length = raw[4:6]
      self._chksum = raw[6:8]
      self._data = raw[8:]

  @property
  def header( self ):
    return self._src + self._dst + self._length + self._chksum + self._data

  @property
  def src( self ):
    (src,) = struct.unpack('!H', self._src )
    return src
  @src.setter
  def src( self, src ):
    self._src = struct.pack('!H', src )

  @property
  def dst( self ):
    (dst,) = struct.unpack('!H', self._dst )
    return dst
  @dst.setter
  def dst( self, dst ):
    self._dst = struct.pack('!H', dst )

  @property
  def length( self ):
    (length,) = struct.unpack('!H', self._length )
    return length
  @length.setter
  def length( self, len ):
    self._length = struct.pack('!H', len )

  @property
  def chksum( self ):
    (chk,) = struct.unpack('!H', self._chksum )
    return chk
  @chksum.setter
  def chksum( self, chksum ):
    self._chksum = struct.pack('!H', chksum )

  @property
  def data( self ):
    return self._data.decode( errors='ignore' )
  @data.setter
  def data( self, data ):
    self._data = data.encode()
