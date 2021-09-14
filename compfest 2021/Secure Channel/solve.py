import binascii
import base64
from pwn import *
from Crypto.Util.number import getPrime, bytes_to_long  as bl, long_to_bytes as lb
from Crypto.Cipher import AES

def getBobSecret():
	for i in range(2, 100):
		r = remote('103.152.242.56', 8232)
		mysecret = base64.b64encode(lb(i))
		opener = base64.b64encode(lb(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF+1))
		r.sendline(mysecret)
		r.sendline(opener)
		r.recvuntil("p: ")
		p = r.recvline().strip()
		r.recvuntil("Bob's public part: ")
		bobPub = r.recvline().strip()
		r.recvuntil("Your public part: ")
		myPub = r.recvline().strip()
		if bobPub == myPub:
			print("bobSecret is", i)
			return i
		else:
			r.close()

def unpad(msg):
    res = ""
    for i in msg:
        if chr(i) in string.printable:
            res+=chr(i)
    return res

def receive_message(key, enc_message):
	iv = enc_message[:16]
	enc = enc_message[16:]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	msg = cipher.decrypt(enc)
	return base64.a85decode(unpad(msg))

def createKey(secret, gx, p):
	key = lb(pow(gx, secret, p) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
	while (len(key) != 16):
		key += b'\x01'
	return key

if __name__ == "__main__":
	# bobSecret = getBobSecret()
	bobSecret = 73
	r = remote('103.152.242.56', 8231)
	opener = base64.b64encode(lb(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF+1))
	r.sendline(opener)
	r.recvuntil("p:")
	p = int(r.recvline().strip().decode())
	r.recvuntil("Alice\'s public part:")
	alicePub = bl(base64.b64decode(r.recvline().strip().decode()))
	key = createKey(bobSecret, alicePub, p)
	print('bobKey is', key)
	for i in range(15):
		r.recvuntil("Messages from Alice:\n")
		aliceMessage = r.recvline().strip()
		decrypted = receive_message(key, base64.b64decode(aliceMessage))
		print('a:', decrypted)
		r.recvuntil("Messages from Bob:\n")
		bobMessage = r.recvline().strip()
		decrypted = receive_message(key, base64.b64decode(bobMessage))
		print('b:', decrypted)

#COMPFEST13{4fd29464a28a1b39559f4fc500b41c4b17ec8ad74512394a830b51506AIUEOuh_f8facf99fe}