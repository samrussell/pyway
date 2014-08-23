#!/usr/bin/python

import struct

class BGPMessage(object):
  factory = {}

  def __init__(self):
    self.length=19
    self.messagetype=-1

  @staticmethod
  def decode(rawdata):
    # parse out raw data
    header=struct.unpack('!IIIIHB', rawdata[:19])
    marker = 0xFFFFFFFF
    # test for marker
    for x in header[:4]:
      if x != marker:
        raise Exception('Message received with bad marker %s != %s' % (x, marker))
    length = header[4]
    # confirm length
    if length != len(rawdata):
      raise Exception('Message length incorrect %d %d' % (length, len(rawdata)))
    messagetype = header[5]
    # try to create a subclass
    #try:
    subclass = BGPMessage.factory[messagetype].decode(rawdata[19:], length - 19)
    #except Exception as e:
    #  raise Exception('Couldn\'t create subclass: %s' % str(e))
    return subclass

  def encode(self):
    return struct.pack('!IIIIHB', 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, self.length, self.messagetype)

class BGPMessageOpen(BGPMessage):
  def __init__(self):
    super(BGPMessageOpen, self).__init__()
    self.length=29
    self.messagetype=1
    self.bgpversion=0
    self.asnum=0
    self.holdtime=0
    self.routerid=0
    self.optionalparamterslength=0
    self.optionalparameters=struct.pack('')

  def encode(self):
    header = super(BGPMessageOpen, self).encode()
    return header + struct.pack('!BHHIB', self.bgpversion, self.asnum, self.holdtime, self.routerid, self.optionalparameterslength) + self.optionalparameters

  @staticmethod
  def decode(payload, length):
    message = BGPMessageOpen()
    message.length = length+19
    (message.bgpversion, message.asnum, message.holdtime, message.routerid, message.optionalparameterslength) = struct.unpack('!BHHIB', payload[:10])
    # make sure optionalparameterslength makes sense
    if message.optionalparameterslength + 10 != length:
      raise Exception('Optional parameters length incorrect')
    message.optionalparameters = payload[10:]
    return message

  def __str__(self):
    return "BGP Open message, version %d AS%d holdtime %d routerid %X optionalparameters length %d" % (self.bgpversion, self.asnum, self.holdtime, self.routerid, self.optionalparameterslength)

BGPMessage.factory[1] = BGPMessageOpen

class BGPMessageUpdate(BGPMessage):
  def __init__(self):
    super(BGPMessageUpdate, self).__init__()
    self.length=23
    self.messagetype=2
    self.withdrawnroutes=struct.pack('')
    self.widthdrawnrouteslength=0
    self.totalpathattributeslength=0
    self.pathattributes=struct.pack('')
    self.nlri=struct.pack('')

  def encode(self):
    header = super(BGPMessageUpdate, self).encode()
    return header + struct.pack('!H', self.widthdrawnrouteslength) + self.withdrawnroutes + struct.pack('!H', self.totalpathattributeslength) + self.pathattributes + self.nlri

  @staticmethod
  def decode(payload, length):
    message = BGPMessageUpdate()
    message.length = length+19
    (message.withdrawnrouteslength,) = struct.unpack('!H', payload[:2])
    # sanity check withdrawn routes
    if message.withdrawnrouteslength > length-2:
      raise Exception('Withdrawnrouteslength is too damn high')
    pathattributeoffset = message.widthdrawnrouteslength+2
    message.widthdrawnroutes = payload[2:pathattributeoffset]
    (message.totalpathattributeslength,) = struct.unpack('!H', payload[pathattributeoffset:pathattributeoffset+2])
    # sanity check attributes field
    if message.totalpathattributeslength > length-4-message.withdrawnrouteslength:
      raise Exception('Totalpathattributeslength is too damn high')
    nlrioffset = message.totalpathattributeslength+2+pathattributeoffset
    message.pathattributes = payload[pathattributeoffset+2:nlrioffset]
    message.nlri=payload[nlrioffset:]
    return message

  def __str__(self):
    return "BGP Update message, length %d, withdrawnrouteslength %d, pathattributeslength %d" % (self.length, self.withdrawnrouteslength, self.totalpathattributeslength)

BGPMessage.factory[2] = BGPMessageUpdate

class BGPMessageKeepalive(BGPMessage):
  def __init__(self):
    super(BGPMessageKeepalive, self).__init__()
    self.length=19
    self.messagetype=3

  def encode(self):
    header = super(BGPMessageKeepalive, self).encode()
    return header

BGPMessage.factory[3] = BGPMessageKeepalive

class BGPMessageNotification(BGPMessage):
  def __init__(self):
    super(BGPMessageNotification, self).__init__()
    self.length=21
    self.messagetype=4
    self.errorcode=0
    self.errorsubcode=0
    self.data=struct.pack('')

  def encode(self):
    header = super(BGPMessageNotification, self).encode()
    return header + struct.pack('!BB', self.errorcode, self.errorsubcode) + self.data

BGPMessage.factory[4] = BGPMessageNotification

