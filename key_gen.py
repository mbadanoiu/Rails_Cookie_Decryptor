#!/usr/bin/python

import hashlib
import sys

class KeyGen:
	def __init__(self, secret_key_base):
		self.secret_key_base = secret_key_base

	def getKey(self):
		return hashlib.pbkdf2_hmac("sha1", self.secret_key_base, 'authenticated encrypted cookie', 1000, 32)

def print_help():
        sys.stdout.write("\n\tUsage: " + sys.argv[0] + " <secret_key_base>\n\n")
        quit()

def init():
	if len(sys.argv) != 2:
		print_help()

	secret = sys.argv[1]

	return secret

if __name__ == "__main__":
	secret = init()
	key = KeyGen(secret).getKey()
	print(key.encode("hex"))
