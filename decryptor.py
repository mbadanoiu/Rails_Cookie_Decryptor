#!/usr/bin/python

import urllib
import sys
import key_gen
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def print_help():
        sys.stdout.write("\n\tUsage: " + sys.argv[0] + " <secret_key_base> <cookie>\n\n")
        quit()

def genKey(secret_key_base):
	return key_gen.KeyGen(secret_key_base).getKey()

def decodeCookie(cookie):
	return urllib.unquote(cookie).decode('utf8')

def uncookiefy(cookie):
	cookie = decodeCookie(cookie)
	separator = b"--"
	ciphertext_b64, iv_b64, tag_b64 = cookie.split(separator)
	ciphertext = base64.b64decode(ciphertext_b64)
	iv = base64.b64decode(iv_b64)
	tag = base64.b64decode(tag_b64)
	return (ciphertext, iv, tag)

def decrypt(key, iv, ciphertext, tag):
	# Construct a Cipher object, with the key, iv, and additionally the
	# GCM tag used for authenticating the message.
	decryptor = Cipher(
	algorithms.AES(key),
	modes.GCM(iv, tag),
	backend=default_backend()
	).decryptor()

	# Decryption gets us the authenticated plaintext.
	# If the tag does not match an InvalidTag exception will be raised.
	return decryptor.update(ciphertext) + decryptor.finalize()

def init():
	if len(sys.argv) != 3:
		print_help()

	secret = sys.argv[1]
	cookie = sys.argv[2]

	return (cookie, secret)

if __name__ == "__main__":
	cookie, secret = init()

	key = key_gen.KeyGen(secret).getKey()
	ciphertext, iv, tag = uncookiefy(cookie)

	dec = decrypt(
		key,
		iv,
		ciphertext,
		tag)

	print(dec)
