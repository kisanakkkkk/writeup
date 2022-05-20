<h1>Jenny From The Block</h1>
<!-- wp:heading -->
<h2><strong>Description</strong></h2>
<!-- /wp:heading -->

<!-- wp:preformatted -->
<pre class="wp-block-preformatted">Intrigued by the fact that you have found something your father made, and with much confidence that you can be useful to the team, you rush excitedly to integrate “Jenny” into the spaceship’s main operating system. For weeks, everything went smoothly, until you ran into a meteor storm. Having little to no data of training, the AI is now malfunctioning. Ulysses freaks out because he can no longer control the spaceship due to the AI overriding his manual commands. Big banging noises terrify your crew members. Everything is shaking. It’s time to act. Do you think you can temporarily shut down “Jenny” until she becomes more sophisticated?</pre>
<!-- /wp:preformatted -->
chall file: https://github.com/kisanakkkkk/writeup/blob/main/Cyber%20Apocalypse%20CTF%202022/Jenny%20From%20The%20Block/chall.py
<p><strong>TL;DR</strong>

- known plaintext based attack
- construct a decrypt function
- use sha256 hash of enc_blocks[0] + "Command executed: cat secret.txt" as initial key
- use sha256 hash of enc_blocks[i] + decrypted_block as continuous key
- loop from 1 until end of array enc_blocks
- store the plaintext
- ???
- profit
</p>

<!-- wp:heading -->
<h2><strong>Solution</strong></h2>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>Looking at given file chall.py we see:</p>
<!-- /wp:paragraph -->

<!-- wp:code -->
<pre class="wp-block-code"><code>
from hashlib import sha256
from Crypto.Util.Padding import pad, unpad
import signal
import subprocess
import socketserver
import os

allowed_commands = [b'whoami', b'ls', b'cat secret.txt', b'pwd']
BLOCK_SIZE = 32


def encrypt_block(block, secret):
    enc_block = b''
    for i in range(BLOCK_SIZE):
        val = (block[i]+secret[i]) % 256
        enc_block += bytes([val])
    return enc_block


def encrypt(msg, password):
    h = sha256(password).digest()
    if len(msg) % BLOCK_SIZE != 0:
        msg = pad(msg, BLOCK_SIZE)
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    ct = b''
    for block in blocks:
        enc_block = encrypt_block(block, h)
        h = sha256(enc_block + block).digest()
        ct += enc_block

    return ct.hex()


def run_command(cmd):
    if cmd in allowed_commands:
        try:
            resp = subprocess.run(
                cmd.decode().split(' '),  capture_output=True)
            output = resp.stdout
            return output
        except:
            return b'Something went wrong!\n'
    else:
        return b'Invalid command!\n'


def challenge(req):
    req.sendall(b'This is Jenny! I am the heart and soul of this spaceship.\n' +
                b'Welcome to the debug terminal. For security purposes I will encrypt any responses.')
    while True:
        req.sendall(b'\n> ')
        command = req.recv(4096).strip()
        output = run_command(command)
        response = b'Command executed: ' + command + b'\n' + output
        password = os.urandom(32)
        ct = encrypt(response, password)
        req.sendall(ct.encode())


class incoming(socketserver.BaseRequestHandler):
    def handle(self):
        signal.alarm(30)
        req = self.request
        challenge(req)


class ReusableTCPServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


def main():
    socketserver.TCPServer.allow_reuse_address = True
    server = ReusableTCPServer(("0.0.0.0", 1337), incoming)
    server.serve_forever()


if __name__ == "__main__":
    main()

</code></pre>
<!-- /wp:code -->

<!-- wp:paragraph -->
<p><strong>Code Analysis</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<ul>
  <li>there are several commands that can be accepted: b'whoami', b'ls', b'cat secret.txt', b'pwd'</li>
  <li>response are constructed from ('Command executed: ' + command + b'\n' + output)</li>
  <li>response will be divided into array of blocks with 32 bytes each, blocks with characters less than 32 will be padded</li>
  <li>initial key is sha256 of randomly generated 32 bytes</li>
  <li>each bytes from encrypted_block = each bytes from block + each bytes from key</li>
  <li>after first loop, key is changed to sha256 of the encrypted block plus the original block from that turn </li>
  <li>loop until all blocks are encrypted</li>
</ul>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><strong>Solving</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>We start by constructing encrypt_block to decrypt_block. As stated in the problem, each byte of encrypted_block is composed of the sum of each byte of the block with each byte of the key, then modulated by 256.</p>
 <code>Encrypted_block[i] = (ori_block[i] + key[i]) %256</code>
 <p>
To reverse it, we create a condition where when the encrypted_block bytes we have minus the bytes key is negative, then the encrypted_block must be plus by 256 then subtracted by the key bytes. Then we obtained bytes from the original block</p>
<pre><code>
if enc_block[i] - secret[i] < 0:
    enc_block[i] = enc_block[i] + 256
enc_block[i] = enc_block[i] - secret[i]
</code></pre>
<p>here's the full function</p>
<pre><code>
def decrypt_block(enc_block, secret):
    ori_block = b''
    for i in range(BLOCK_SIZE):
        if enc_block[i] - secret[i] < 0:
            enc_block[i] = enc_block[i] + 256
        enc_block[i] = enc_block[i] - secret[i]
        ori_block += bytes([enc_block[i]])
    return ori_block
</code></pre>


<p>To create a decrypt function, the incoming ciphertext must be converted into bytes first. Like encryption, the ciphertext bytes are also divided into 32-byte block arrays. Now it's just a matter of keys. The initial key used when encrypting is 32 bytes which is randomly generated, and we also can get the key by reversing the known ori_block with encrypted_block. But, <strong>do we really have to get that random key?</strong></p>

<p>The part we can exploit is the key after the first round of encryption, which consists of encrypted_block + ori_block of that round. The encrypted block are from the ciphertext that is given, while to get the ori_block we have to decrypt the encrypted block to construct the next key. apparently, we can find out the original block of the first round by using a command, that is <em>'Command executed: cat secret.txt'</em> which has a length of 32 bytes.
</p>

<p>That way, we set an initial key for decrypt which consists of sha256 of encrypted_block[0] plus 'Command executed: cat secret.txt' to get original_block[1]. Then encrypted_block[1] + ori_block[1] is used as the key to get original_block[2], and so on.</p>

<p>construct all the concept above, and here's the python script i made:</p>

<pre><code>
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
</code></pre>
<!-- /wp:code -->
solve file: https://github.com/kisanakkkkk/writeup/blob/main/Cyber%20Apocalypse%20CTF%202022/Jenny%20From%20The%20Block/solve.py

<!-- wp:paragraph -->
<p>output:</p>
<!-- /wp:paragraph -->
<img src=https://user-images.githubusercontent.com/70153248/169468340-bee39f64-b71d-4721-a597-15b599558e4d.png>

<p><strong>Flag: HTB{b451c_b10ck_c1ph3r_15_w34k!!!}</strong></p>
