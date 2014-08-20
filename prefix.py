#!/usr/bin/python

class Prefix:
  def __init__(self, address=None, length=None, ip_version=None):
    self.address = address
    self.length = length
    self.ip_version = ip_version

  def __str__(self):
    return 'Prefix <%s/%d>, IP version %d' % (self.address, self.length, self.ip_version)

