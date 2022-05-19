from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import hashlib
import random
import socketserver
import signal
from pwn import *
import binascii

def encrypt(plaintext, shared_secret):
    key = hashlib.md5(long_to_bytes(shared_secret)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    message = cipher.encrypt(plaintext)
    return message

r = remote('138.68.183.64', 31336)
r.recvuntil('Memory: ')
r.sendline('0')
r.recvuntil('Sequence: ')

r.sendline(binascii.hexlify(encrypt(b"Initialization Sequence - Code 0", 0)))
r.interactive()
print(binascii.hexlify(encrypt(b"Initialization Sequence - Code 0", 0)))