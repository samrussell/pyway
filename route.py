#!/usr/bin/python

class Route:
  def __init__(self, protocol=None, prefix=None, nexthop=None):
    self.protocol = protocol
    self.prefix = prefix
    self.nexthop = nexthop

  def __str__(self):
    return 'Route protocol [%s] prefix [%s]' % (self.protocol, self.prefix)
