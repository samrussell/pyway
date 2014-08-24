#!/usr/bin/python

import struct

def printhexstring(hexstring):
  return ''.join(['%02X' % ord(x) for x in hexstring])

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

def nlritoprefix(nlrituple):
  # pad to 4 0s, assume IPv4
  nlriprefix = nlrituple[0] + ''.join([chr(0) for x in range(4 - len(nlrituple[0]))])
  nlrilen = nlrituple[1]
  prefix = '.'.join(['%d' % ord(x) for x in nlriprefix])
  return '%s/%d' % (prefix, nlrilen)

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
    self.nlrilist = []

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
    # decode nlri
    i = 0
    while i < len(message.nlri):
      (nlrilen, ) = struct.unpack('!B', message.nlri[i:i+1])
      nlribytelen = nlrilen/8 + (1 if (nlrilen%8 > 0) else 0)
      i = i+1
      if nlribytelen+i > len(message.nlri):
        raise Exception('Bad NLRI - length is too damn high %d %d %d', nlribytelen, i, len(message.nlri))
      nlriprefix = message.nlri[i:i+nlribytelen]
      message.nlrilist.append((nlriprefix, nlrilen))
      i = i + nlribytelen
    return message

  def __str__(self):
    return "BGP Update message, length %d, withdrawnrouteslength %d, pathattributeslength %d nlris: %s" % (self.length, self.withdrawnrouteslength, self.totalpathattributeslength, ','.join([nlritoprefix(x) for x in self.nlrilist]))

BGPMessage.factory[2] = BGPMessageUpdate

class BGPMessageNotification(BGPMessage):

  errordecode = {
                      1 : 'Message Header Error',
                      2 : 'OPEN Message Error',
                      3 : 'UPDATE Message Error',
                      4 : 'Hold Timer Expired',
                      5 : 'Finite State Machine Error',
                      6 : 'Cease',
      }
  suberrordecode = { 
                      1 : {
                        1 : 'Connection Not Synchronized.',
                        2 : 'Bad Message Length.',
                        3 : 'Bad Message Type.',
                        },
                      2 : {
                        1 : 'Unsupported Version Number.',
                        2 : 'Bad Peer AS.',
                        3 : 'Bad BGP Identifier.',
                        4 : 'Unsupported Optional Parameter.',
                        5 : '[Deprecated - see Appendix A]. (RFC 4271)',
                        6 : 'Unacceptable Hold Time.',
                        },
                      3 : {
                        1 : 'Malformed Attribute List.',
                        2 : 'Unrecognized Well-known Attribute.',
                        3 : 'Missing Well-known Attribute.',
                        4 : 'Attribute Flags Error.',
                        5 : 'Attribute Length Error.',
                        6 : 'Invalid ORIGIN Attribute.',
                        7 : '[Deprecated - see Appendix A]. (RFC 4271)',
                        8 : 'Invalid NEXT_HOP Attribute.',
                        9 : 'Optional Attribute Error.',
                        10 : 'Invalid Network Field.',
                        11 : 'Malformed AS_PATH.',
                        },
    }

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

  @staticmethod
  def decode(payload, length):
    message = BGPMessageNotification()
    message.length = length+19
    if message.length<21:
      raise Exception('BGP Notification message less than 21 bytes, only %d bytes' % message.length)
    (message.errorcode, message.errorsubcode) = struct.unpack('!BB', payload[:2])
    message.data = payload[2:]
    return message

  def __str__(self):
    errortext = 'code not found'
    suberrortext = 'code not found'
    try:
      errortext = BGPMessageNotification.errordecode[self.errorcode]
      suberrortext = BGPMessageNotification.suberrordecode[self.errorcode][self.errorsubcode]
    except:
      pass
    return 'BGP Notification message length %d error %d [%s] suberror %d [%s] data %s' % (self.length, self.errorcode, errortext, self.errorsubcode, suberrortext, printhexstring(self.data))

BGPMessage.factory[3] = BGPMessageNotification

class BGPMessageKeepalive(BGPMessage):
  def __init__(self):
    super(BGPMessageKeepalive, self).__init__()
    self.length=19
    self.messagetype=3

  def encode(self):
    header = super(BGPMessageKeepalive, self).encode()
    return header

  @staticmethod
  def decode(payload, length):
    message = BGPMessageKeepalive()
    message.length = length+19
    # basic sanity check
    if message.length!=19:
      raise Exception('Keepalive message with trash on the end, length: %d' % message.length)
    return message

  def __str__(self):
    return 'BGP Keepalive message length %d' % self.length

BGPMessage.factory[4] = BGPMessageKeepalive

