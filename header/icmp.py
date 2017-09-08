import struct

class Icmp:
  
  def __init__( self, raw=None ):
    if raw != None:
      self._type = raw[:1]
      self._code = raw[1:2]
      self._chksum = raw[2:4]

  @property
  def header( self ):
    return self._type + self._code + self._chksum

  @property
  def type( self ):
    (type,) = struct.unpack('!B', self._type )
    return type
  @type.setter
  def type( self, type ):
    self._type = struct.pack('!B', type )

  @property
  def code( self ):
    (code,) = struct.unpack('!B', self._code )
    return code
  @code.setter
  def code( self, code ):
    self._code = struct.pack('!B', code )

  @property
  def chksum( self ):
    (chksum,) = struct.unpack('!H', self._chksum )
    return chksum

  @chksum.setter
  def chksum( self, chksum ):
    self._chksum = struct.pack('!H', chksum )


class Echo( Icmp ):

  def __init__( self, raw=None ):
    if raw != None:
      self._id = raw[:2]
      self._seq = raw[2:4]
      self._payload = raw[4:]

  @property
  def header( self ):
    return self._type + self._code + self._chksum + self._id + self._seq + self._payload

  @property
  def id( self ):
    (id,) = struct.unpack('!H', self._id )
    return id

  @id.setter
  def id( self, id ):
    self._id = struct.pack('!H', id )

  @property
  def seq( self ):
    (seq,) = struct.unpack('!H', self._seq )
    return seq

  @seq.setter
  def seq( self, seq ):
    self._seq = struct.pack('!H', seq )

  @property
  def payload( self ):
    return self._payload.decode( errors=ignore )

  @payload.setter
  def payload( self, payload ):
    self._payload = payload.encode()
  

