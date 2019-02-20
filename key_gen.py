#!/usr/bin/python

import hashlib

class KeyGen:
	def __init__(self, secret_key_base):
		self.secret_key_base = secret_key_base

	def getKey(self):
		return hashlib.pbkdf2_hmac("sha1", self.secret_key_base, 'authenticated encrypted cookie', 1000, 32)
