import sys
import os
import random
import binascii
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from pwn import *

def decryptECB(key, msg):
	cipher = AES.new(key, AES.MODE_ECB)
	flag = cipher.decrypt(msg)
	return flag

def getIV(r):
	r.sendline('2')
	r.sendline('616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161')
	r.recvuntil('enc (in hex) = ')
	decsample = r.recvline().strip()

	c0 = decsample[0:32]
	c1 = decsample[32:64]
	c2 = decsample[64:96]
	c3 = decsample[96:128]
	payload = c0+c1+c0+c3
	
	r.sendline('3')
	r.sendline(payload)
	r.recvuntil('msg (in hex) = ')
	plain = r.recvline().strip()
	
	p0 = plain[0:32]
	p1 = plain[32:64]
	p2 = plain[64:96]
	p3 = plain[96:128]
	
	dkco = int(p2, 16)^int(c1, 16)
	iv = bytes.fromhex(hex(dkco ^ int(p0, 16))[2:])
	print('default iv = ', iv)
	return iv

def decrypting(r):
	r.sendline('1')
	r.recvuntil('flag (in hex) = ')
	flag = r.recvline().strip()
	r.sendline('3')
	r.sendline(flag[0:32])
	r.recvuntil("msg (in hex) = ")
	firstPlainPart = r.recvline().strip()#flag didecrypt
	print(decryptECB(iv, binascii.unhexlify(firstPlainPart)))
	newIV = hex(int(firstPlainPart, 16)^int(flag[0:32], 16))[2:]
	for i in range(32, len(flag), 32):
		r.sendline('3')
		r.sendline(flag[i:i+32])
		r.recvuntil("msg (in hex) = ")
		decryptedGiven = r.recvline().strip()#flag didecrypt
		PlainPart = hex(int(decryptedGiven, 16) ^ int(binascii.hexlify(iv), 16) ^ int(newIV, 16))[2:]#decrypt^IV^newIV
		print(decryptECB(iv, binascii.unhexlify(PlainPart)))
		newIV = hex(int(PlainPart, 16)^int(flag[i:i+32], 16))[2:]

if __name__ == "__main__":
	r = remote('103.152.242.242', 10016)
	iv = getIV(r)
	decrypting(r)

#COMPFEST13{y0u_aes_me_UpPpppPp_____t0_c0d3_on_st0rmy_Sea4aA5____e0212d1a34}