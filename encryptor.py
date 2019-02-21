#!/usr/bin/python

import os
import base64
import sys
import urllib
import key_gen

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def print_help():
	sys.stdout.write("\n\tUsage: " + sys.argv[0] + " <secret_key_base> <payload>\n\n")
	quit()

def cookiefy(ciphertext, iv, tag):
	separator = b"--"
	ciphertext_b64 = base64.b64encode(ciphertext)
	iv_b64 = base64.b64encode(iv)
	tag_b64 = base64.b64encode(tag)
	res = ciphertext_b64 + separator + iv_b64 + separator + tag_b64
	res = urllib.quote_plus(res)
	return res.decode('utf-8')

def encrypt(key, plaintext):
	# Generate a random 96-bit IV.
	iv = os.urandom(12)

	# Construct an AES-GCM Cipher object with the given key and a
	# randomly generated IV.
	encryptor = Cipher(
	algorithms.AES(key),
	modes.GCM(iv),
	backend=default_backend()
	).encryptor()

	# Encrypt the plaintext and get the associated ciphertext.
	# GCM does not require padding.
	ciphertext = encryptor.update(plaintext) + encryptor.finalize()

	return (iv, ciphertext, encryptor.tag)

def init():
	if len(sys.argv) != 3:
		print_help()

	secret = sys.argv[1]
	payload = sys.argv[2]

	return (secret, payload)

if __name__ == "__main__":
	secret, payload = init()

	plaintext = payload
	key = key_gen.KeyGen(secret).getKey()

	iv, ciphertext, tag = encrypt(
	    key,
	    plaintext)

	print(cookiefy(ciphertext, iv, tag))

