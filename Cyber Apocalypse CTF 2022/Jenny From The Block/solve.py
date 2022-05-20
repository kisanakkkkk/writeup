from pwn import *
from hashlib import sha256
from Crypto.Util.Padding import pad, unpad
import signal
import subprocess
import socketserver
import os

BLOCK_SIZE = 32

def decrypt_block(enc_block, secret):
    ori_block = b''
    for i in range(BLOCK_SIZE):
        val = enc_block[i]
        if val - secret[i] < 0:
            val = val + 256
        val = val - secret[i]
        ori_block += bytes([val])
    return ori_block

def decrypt(msg):
    msg = binascii.unhexlify(msg)
    enc_blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    ct = b''
    h = sha256(enc_blocks[0] + b'Command executed: cat secret.txt').digest()
    for i in range(1, len(enc_blocks)):
        ori_block = decrypt_block(enc_blocks[i], h)
        h = sha256(enc_blocks[i] + ori_block).digest()
        ct += ori_block
    return ct

r = remote('46.101.30.188',31123)
r.recvuntil('>')
r.sendline('cat secret.txt')
encrypted = r.recvline().strip().decode()
print(decrypt(encrypted))
