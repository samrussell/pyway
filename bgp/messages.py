#!/usr/bin/python

import struct

class BGPMessage:
  def __init__(self):
    self.length=19
    self.messagetype=-1

  def encode(self):
    return struct.pack('!LLLLHB', 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, self.length, self.messagetype)

class BGPMessageOpen(BGPMessage):
  def __init__(self):
    super(BGPMessageOpen, self).__init__()
    self.length=29
    self.messagetype=1
    self.localas=0
    self.holdtime=0
    self.routerid=0
    self.optionalparamterslength=0
    self.optionalparameters=struct.pack('')

  def encode(self):
    header = super(BGPMessageOpen, self).encode()
    return header + struct.pack('!BHHIB', self.bgpversion, self.localas, self.holdtime, self.routerid, self.optionalparameterslength) + self.optionalparameters

class BGPMessageUpdate(BGPMessage):
  def __init__(self):
    super(BGPMessageUpdate, self).__init__()
    self.length=23
    self.messagetype=2
    self.withdrawnroutes=struct.pack('')
    self.widthdrawnrouteslength=0
    self.totalpathattributeslength=0
    self.pathattributes=struct.pack('')
    self.nlri=self.pack('')

  def encode(self):
    header = super(BGPMessageUpdate, self).encode()
    return header + struct.pack('!H', self.widthdrawnrouteslength) + self.withdrawnroutes + struct.pack('!H', self.totalpathattributeslength) + self.pathattributes + self.nlri

class BGPMessageKeepalive(BGPMessage):
  def __init__(self):
    super(BGPMessageKeepalive, self).__init__()
    self.length=19
    self.messagetype=3

  def encode(self):
    header = super(BGPMessageKeepalive, self).encode()
    return header

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

