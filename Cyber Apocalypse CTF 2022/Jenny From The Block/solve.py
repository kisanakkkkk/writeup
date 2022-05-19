from pwn import *
from hashlib import sha256
from Crypto.Util.Padding import pad, unpad
import signal
import subprocess
import socketserver
import os

BLOCK_SIZE = 32

def decrypt_block(enc_block, secret):
    print('enc_bl', enc_block, secret)
    block = b''
    for i in range(BLOCK_SIZE):
        print(enc_block[i])
        val = enc_block[i]
        if val - secret[i] < 0:
            val+=256
        val = val - secret[i]
        block += bytes([val])
        print(bytes([enc_block[i]]), "=>", bytes([val]))
    return block

def decrypt(msg):
    msg = binascii.unhexlify(msg)
    print(msg)
    if len(msg) % BLOCK_SIZE != 0:
        msg = pad(msg, BLOCK_SIZE)
    enc_blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]#pemisahan per 32 byte
    print(enc_blocks)
    ct = b''
    h = sha256(enc_blocks[0] + b'Command executed: cat secret.txt').digest()
    for i in range(1, len(enc_blocks)):
        block = decrypt_block(enc_blocks[i], h)
        # print('lookatthis', block + enc_bloc)
        h = sha256(enc_blocks[i] + block).digest()
        ct += block

    return ct

r = remote('209.97.135.38', 30846)
r.recvuntil('>')
r.sendline('cat secret.txt')
encrypted = r.recvline().strip().decode()
print(decrypt(encrypted))

#b'\nIn case Jenny malfunctions say the following phrase: Melt My Eyez, See Your Future  \nThe AI system will shutdown and you will gain complete control of the spaceship.\n- Danbeer S.A.\nHTB{b451c_b10ck_c1ph3r_15_w34k!!!}\n\x07\x07\x07\x07\x07\x07\x07'