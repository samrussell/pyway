#!/usr/bin/env python

import unittest

from lib.bgp import messages
from tests import bgp_samples

class TestBGP(unittest.TestCase):
	def setUp(self):
		pass

	def test_decode_openmessage(self):
		self.assertEqual(str(messages.BGPMessage.decode(bgp_samples.openmessage_sample)), bgp_samples.openmessage_result)

	def test_decode_updatemessage(self):
		self.assertEqual(str(messages.BGPMessage.decode(bgp_samples.updatemessage_sample)), bgp_samples.updatemessage_result)

	def test_decode_updatemessage2(self):
		self.assertEqual(str(messages.BGPMessage.decode(bgp_samples.updatemessage2_sample)), bgp_samples.updatemessage2_result)

	def test_decode_updatemessage3(self):
		self.assertEqual(str(messages.BGPMessage.decode(bgp_samples.updatemessage3_sample)), bgp_samples.updatemessage3_result)

	def test_decode_notificationmessage(self):
		self.assertEqual(str(messages.BGPMessage.decode(bgp_samples.notificationmessage_sample)), bgp_samples.notificationmessage_result)

	def test_decode_keepalivemessage(self):
		self.assertEqual(str(messages.BGPMessage.decode(bgp_samples.keepalivemessage_sample)), bgp_samples.keepalivemessage_result)

if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(TestBGP)
	unittest.TextTestRunner(verbosity=2).run(suite)
