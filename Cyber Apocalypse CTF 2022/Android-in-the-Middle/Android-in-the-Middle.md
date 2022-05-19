<h1>Android in the middle</h1>

<!-- wp:heading -->
<h2><strong>Description</strong></h2>
<!-- /wp:heading -->

<!-- wp:preformatted -->
<pre class="wp-block-preformatted">Years have passed since Miyuki rescued you from the graveyard. When Virgil tells you that he needs your help with something he found there, desperate thoughts about your father and the disabilities you developed due to the disposal process come to mind. The device looks like an advanced GPS with AI capabilities. Riddled with questions about the past, you are pessimistic that you could be of any value. After hours of fiddling and observing the power traces of this strange device, you and Virgil manage to connect to the debugging interface and write an interpreter to control the signals. The protocol looks familiar to you. Your father always talked about implementing this scheme in devices for security reasons. Could it have been him?</pre>
<!-- /wp:preformatted -->
chall file: https://github.com/kisanakkkkk/writeup/blob/main/Cyber%20Apocalypse%20CTF%202022/Android-in-the-Middle/source.py
<p><strong>TL;DR</strong>
    
Diffie Helman using 0 to create shared secret with value 1</p>


<!-- wp:heading -->
<h2><strong>Solution</strong></h2>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>Looking at given file source.py we see:</p>
<!-- /wp:paragraph -->

<!-- wp:code -->
<pre class="wp-block-code"><code>from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import hashlib
import random
import socketserver
import signal


FLAG = "HTB{--REDACTED--}"
DEBUG_MSG = "DEBUG MSG - "
p = 0x509efab16c5e2772fa00fc180766b6e62c09bdbd65637793c70b6094f6a7bb8189172685d2bddf87564fe2a6bc596ce28867fd7bbc300fd241b8e3348df6a0b076a0b438824517e0a87c38946fa69511f4201505fca11bc08f257e7a4bb009b4f16b34b3c15ec63c55a9dac306f4daa6f4e8b31ae700eba47766d0d907e2b9633a957f19398151111a879563cbe719ddb4a4078dd4ba42ebbf15203d75a4ed3dcd126cb86937222d2ee8bddc973df44435f3f9335f062b7b68c3da300e88bf1013847af1203402a3147b6f7ddab422d29d56fc7dcb8ad7297b04ccc52f7bc5fdd90bf9e36d01902e0e16aa4c387294c1605c6859b40dad12ae28fdfd3250a2e9
g = 2


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        signal.alarm(0)
        main(self.request)


class ReusableTCPServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


def sendMessage(s, msg):
    s.send(msg.encode())


def recieveMessage(s, msg):
    sendMessage(s, msg)
    return s.recv(4096).decode().strip()


def decrypt(encrypted, shared_secret):
    key = hashlib.md5(long_to_bytes(shared_secret)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    message = cipher.decrypt(encrypted)
    return message


def main(s):
    sendMessage(s, DEBUG_MSG + "Generating The Global DH Parameters\n")
    sendMessage(s, DEBUG_MSG + f"g = {g}, p = {p}\n")
    sendMessage(s, DEBUG_MSG + "Calculation Complete\n\n")

    sendMessage(s, DEBUG_MSG + "Generating The Public Key of CPU...\n")
    c = random.randrange(2, p - 1)
    C = pow(g, c, p)
    sendMessage(s, DEBUG_MSG + "Calculation Complete\n")
    sendMessage(s, DEBUG_MSG + "Public Key is: ???\n\n")

    M = recieveMessage(s, "Enter The Public Key of The Memory: ")

    try:
        M = int(M)
    except:
        sendMessage(s, DEBUG_MSG + "Unexpected Error Occured\n")
        exit()

    sendMessage(s, "\n" + DEBUG_MSG + "The CPU Calculates The Shared Secret\n")
    shared_secret = pow(M, c, p)
    sendMessage(s, DEBUG_MSG + "Calculation Complete\n\n")

    encrypted_sequence = recieveMessage(
        s, "Enter The Encrypted Initialization Sequence: ")

    try:
        encrypted_sequence = bytes.fromhex(encrypted_sequence)
        assert len(encrypted_sequence) % 16 == 0
    except:
        sendMessage(s, DEBUG_MSG + "Unexpected Error Occured\n")
        exit()

    sequence = decrypt(encrypted_sequence, shared_secret)

    if sequence == b"Initialization Sequence - Code 0":
        sendMessage(s, "\n" + DEBUG_MSG +
                    "Reseting The Protocol With The New Shared Key\n")
        sendMessage(s, DEBUG_MSG + f"{FLAG}")
    else:
        exit()


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    server = ReusableTCPServer(("0.0.0.0", 1337), Handler)
    server.serve_forever()

</code></pre>
<!-- /wp:code -->

<!-- wp:paragraph -->
<p><strong>Code Analysis</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<ul>
  <li>modulus p and base g are given</li>
  <li>opponent's public key C generated from g<sup>c</sup> mod p, while secret integer c is random</li>
  <li>we cannot see opponent's public key C</li>
  <li>we provide our public key M</li>
  <li>shared_secret are calculated from M<sup>c</sup> mod p</li>
  <li>we provide hex-based encrypted message, the system will decrypt the ciphertext with AES.ECB mode and MD5 of shared_secret as key</li>
  <li>if the decrypted message is b"Initialization Sequence - Code 0", we get the flag.</li>
</ul>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><strong>Solving</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Let's take a look at how Diffie-Hellman key exchange works</p>
<!-- /wp:paragraph -->
<img src =https://user-images.githubusercontent.com/70153248/169298086-e5726b05-f593-44ca-bd77-bab43fb0ba4f.png>

<!-- wp:paragraph -->
<p>knowing that we can send any number for public key M, we can just send 0 as M, so the calculation of shared_secret will be:</p>
<em>0<sup>c</sup> mod p</em> or <em>pow(0, c, p)</em>
<br>
and we know that zero to the power of any positive number will result in zero, then the value of the shared_secret will also be 0.
</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>"Initialization Sequence - Code 0" have to be our decrypted message, so what we have to do is make an AES.ECB encrypt function, pass that message and 0 as key into the function, and send the encrypted to server.</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Construct all the concepts above into a python script, and this is the result I make:</p>
<!-- /wp:paragraph -->

<!-- wp:code -->
<pre class="wp-block-code"><code>
from Crypto.Cipher import AES
from Crypto.Util.number import *
import hashlib
import random
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
</code></pre>
<!-- /wp:code -->
solve file: https://github.com/kisanakkkkk/writeup/blob/main/Cyber%20Apocalypse%20CTF%202022/Android-in-the-Middle/solve.py
<!-- wp:paragraph -->
<p>output:</p>
<!-- /wp:paragraph -->

<!-- wp:image {"align":"center","id":5929,"sizeSlug":"full","linkDestination":"none"} -->
<div class="wp-block-image"><figure class="aligncenter size-full"><img src=https://user-images.githubusercontent.com/70153248/169301633-5509a424-bd3a-4994-a696-5a54a389d81e.png></div>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p><strong>Flag: HTB{7h15_p2070c0l_15_pr0tec73d_8y_D@nb3er_c0pyr1gh7_1aws}</strong></p>
<!-- /wp:paragraph -->
