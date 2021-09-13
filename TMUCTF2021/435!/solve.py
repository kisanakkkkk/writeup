import binascii
import hashlib
import sys
from Crypto.Cipher import AES
import string

def pad(message):
    padding = bytes((key_len - len(message) % key_len) * chr(key_len - len(message) % key_len), encoding='utf-8')
    return message + padding


def encrypt(message, key, iv):
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(message)

def decrypt(message, key, iv):
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(message)

Go = True
for i in range(33, 127):
	if Go:
		for j in range(33, 127):
			if Go:
				for k in range(33, 127):
					key = (chr(i) + 'XhN2' + chr(j)+'8d%8Slp3'+chr(k)+'v').encode()
					key_len = len(key)
					h = hashlib.sha256(key).hexdigest()
					hidden = binascii.unhexlify(h)[:10]
					message = b'CBC (Cipher Blocker Chaining) is an advanced form of block cipher encryption' + hidden
					padded = pad(message)
					ori = binascii.hexlify(padded[80:])
					IV = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
					ciphertext = bytes.fromhex("1f3ef3fab2bbfc838b9ef71867c3bcbb")#C6 (only known ciphertext)
					decrypted = binascii.hexlify(decrypt(ciphertext, key, IV))
					res = hex(int(decrypted, 16)^int(ori, 16))[2:]
					if "9f43fd6634" in str(res):
						print(f"HOLLLLDDDD! key: {key} prevcipher:{res}")
						Go = False
						break

h = hashlib.sha256(key).hexdigest()
hidden = binascii.unhexlify(h)[:10]
message = b'CBC (Cipher Blocker Chaining) is an advanced form of block cipher encryption' + hidden
padded = pad(message)
for i in range(80, 0, -16):
	ori = binascii.hexlify(padded[i-16:i])
	IV = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	ciphertext = binascii.unhexlify(res)
	decrypted = binascii.hexlify(decrypt(ciphertext, key, IV))
	res = hex(int(decrypted, 16)^int(ori, 16))[2:]
	print(f"prevcipher:{str(res)}")

print('should be iv: ',bytes.fromhex(res).decode())
