#!/usr/bin/python

class RouteDB:
  def __init__(self):
    self.db = {}
  def insertRoute(self, prefix, route):
    if prefix not in self.db:
      self.db[prefix] = set()
    self.db[prefix].add(route)
  def removeRoute(self, prefix, route):
    if prefix not in self.db:
      raise Exception("Prefix doesn't exist")
    # this will raise a KeyError if the route isn't in the DB
    self.db[prefix].remove(route)
  def getPrefixes(self):
    return self.db.keys()

