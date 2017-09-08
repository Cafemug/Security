import struct 

class Tcp:

  def __init__( self, raw=None ):
    if raw != None:
      self._src = raw[:2]
      self._dst = raw[2:4]
      self._seq = raw[4:8]
      self._ack = raw[8:12]
      self._length = raw[12:13]
      self._flag = raw[13:14]
      self._window = raw[14:16]
      self._chksum = raw[16:18]
      self._dummy = raw[18:20]
      self._data = raw[20:]

  @property
  def header( self ):
    return self._src + self._dst + self._seq + self._ack + self._length + self._flag + \
           self._window + self._chksum + self._dummy + self._data

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
  def seq( self ):
    (seq,) = struct.unpack('!L', self._seq )
    return seq
  @seq.setter
  def seq( self, seq ):
    self._seq = struct.pack('!L', seq )

  @property
  def ack( self ):
    (ack,) = struct.unpack('!L', self._ack )
    return ack
  @ack.setter
  def ack( self, ack ):
    self._ack = struct.pack('!L', ack )

  @property
  def length( self ):
    (length,) = struct.unpack('!B', self._length )
    return length >> 2
  @length.setter
  def length( self, length ):
    self._length = struct.pack('!B', length << 2)

  @property
  def flag( self ):
    (flag,) = struct.unpack('!B', self._flag )
    return flag
  @flag.setter
  def flag( self, flag ):
    self._flag = struct.pack('!B', flag )

  @property
  def window( self ):
    (window,) = struct.unpack('!H', self._window )
    return window
  @window.setter
  def window( self, window ):
    self._window = struct.pack('!H', window )

  @property
  def chksum( self ):
    (chk,) = struct.unpack('!H', self._chksum )
    return chk
  @chksum.setter
  def chksum( self, chksum ):
    self._chksum = struct.pack('!H', chksum )

  @property
  def dummy( self ):
    (dummy,) = struct.unpack('!H', self._dummy )
    return dummy
  @dummy.setter
  def dummy( self, dummy ):
    self._dummy = struct.pack('!H', dummy )

  @property
  def data( self ):
    return self._data.decode( errors='ignore' )
  @data.setter
  def data( self, data ):
    self._data = data.encode()
