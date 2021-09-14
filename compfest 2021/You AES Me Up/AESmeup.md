
**[470 pts] You AES Me Up**

_Description_

_So I can stand on scoreboard~_

_nc 103.152.242.242 10016_

_Author: prajnapras19_

chall file: https://github.com/kisanakkkkk/writeup/blob/main/compfest%202021/You%20AES%20Me%20Up/chall.py

TL;DR

Solution:
1. get the default IV (details below)
2. get the CBC plaintext by: (use decryption feature to decrypt given ciphertext) ⊕ default IV ⊕ new IV (obtained from cipherblock ⊕ plainblock)
3. decrypt the plaintext ECB method with default IV as key
4. profit

**Summary**

<!-- wp:paragraph -->
<p>As we can see, this code provides 3 options that we can use. The first feature will print the result of the encrypted flag via a special function get_flag(). The second feature allows us to encrypt our own string with key &amp; IV (Initializaton Vector) that has been determined by the code. The third feature allows us to decrypt encrypted text with key &amp; IV which has also been determined by the code. Key &amp; IV comes from the results of os.random(16), so each session will be different.</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":5498,"sizeSlug":"large","linkDestination":"none"} -->
<figure class="wp-block-image size-large"><img src="https://petircysec.com/wp-content/uploads/2021/09/image-28.png" alt="" class="wp-image-5498"/></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p><strong>Analyzing get_flag()</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>First, the flag will be encrypted with AES_ECB method, using the value IV as the key. After that, the results of the encryption will be divided into several blocks containing 16 bytes each, then each block will be encrypted by the AES_CBC method with a different IV each encryption. This IV comes from the XOR results between the Plaintext block (flag) and the previous round Ciphertext block. So roughly it will be like this:</p>

<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Cipher1 = [encrypt(Plain1, key, IV) where IV = default IV</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Cipher2 = [encrypt(Plain2, key, IV1) where IV1 = Plain1 <strong>⊕</strong> Cipher1</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Cipher3 = [encrypt(Plain3, key, IV2) where IV2 = Plain2 <strong>⊕</strong> Cipher2</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>...</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Well, because the results of the encryption of these blocks are based on the results of the previous encryption block, then we have to crack it from the first encryption block, which still uses the default IV as the IV.</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><strong>Finding Default IV</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>I used this writeup as reference (https://github.com/joshuahaddad/CTF_WriteUps/blob/master/SwampCtf/swampThreeKeys.md) to find the IV, in which it is explained that we can find the IV value of the custom plaintext and the result of the decryption of the plaintext. the code is something like this:</p>
<!-- /wp:paragraph -->

<!-- wp:code -->
<pre class="wp-block-code"><code>import sys
import os
import random
import binascii
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from pwn import *

def getIV(r):
	r.sendline('2')
	r.sendline('616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161')
	r.recvuntil('enc (in hex) = ')
	decsample = r.recvline().strip()

	c0 = decsample&#91;0:32]
	c1 = decsample&#91;32:64]
	c2 = decsample&#91;64:96]
	c3 = decsample&#91;96:128]
	payload = c0+c1+c0+c3
	
	r.sendline('3')
	r.sendline(payload)
	r.recvuntil('msg (in hex) = ')
	plain = r.recvline().strip()
	
	p0 = plain&#91;0:32]
	p1 = plain&#91;32:64]
	p2 = plain&#91;64:96]
	p3 = plain&#91;96:128]
	
	dkco = int(p2, 16)^int(c1, 16)
	iv = bytes.fromhex(hex(dkco ^ int(p0, 16))&#91;2:])
	print('default iv = ', iv)

if __name__ == "__main__":
	r = remote('103.152.242.242', 10016)
	getIV(r)
</code></pre>
<!-- /wp:code -->

<!-- wp:paragraph -->
<p>Output:</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":5503,"sizeSlug":"large","linkDestination":"none"} -->
<figure class="wp-block-image size-large"><img src="https://petircysec.com/wp-content/uploads/2021/09/image-29.png" alt="" class="wp-image-5503"/></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Okay, the default IV has been obtained, we just need to find a way to decrypt each Cipher block. Here we will take advantage of the decrypt feature from the program. For the first block cipher, the decryption runs safely and we can also get the newIV of the next encryption.</p>
<!-- /wp:paragraph -->

<!-- wp:code -->
<pre class="wp-block-code"><code>import sys
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

	c0 = decsample&#91;0:32]
	c1 = decsample&#91;32:64]
	c2 = decsample&#91;64:96]
	c3 = decsample&#91;96:128]
	payload = c0+c1+c0+c3
	
	r.sendline('3')
	r.sendline(payload)
	r.recvuntil('msg (in hex) = ')
	plain = r.recvline().strip()
	
	p0 = plain&#91;0:32]
	p1 = plain&#91;32:64]
	p2 = plain&#91;64:96]
	p3 = plain&#91;96:128]
	
	dkco = int(p2, 16)^int(c1, 16)
	iv = bytes.fromhex(hex(dkco ^ int(p0, 16))&#91;2:])
	print('default iv = ', iv)
	return iv

def decrypting(r):
	r.sendline('1')
	r.recvuntil('flag (in hex) = ')
	flag = r.recvline().strip()
	r.sendline('3')
	r.sendline(flag&#91;0:32])
	r.recvuntil("msg (in hex) = ")
	firstPlainPart = r.recvline().strip()#flag didecrypt
	print(decryptECB(iv, binascii.unhexlify(firstPlainPart)))
	newivone = hex(int(firstPlainPart, 16)^int(flag&#91;0:32], 16))&#91;2:]
	print('newivone', newivone)

if __name__ == "__main__":
	r = remote('103.152.242.242', 10016)
	iv = getIV(r)
	decrypting(r)
</code></pre>
<!-- /wp:code -->

<!-- wp:image {"id":5505,"sizeSlug":"large","linkDestination":"none"} -->
<figure class="wp-block-image size-large"><img src="https://petircysec.com/wp-content/uploads/2021/09/image-31.png" alt="" class="wp-image-5505"/></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>But the problem is, how do we decrypt if the IV used in the encryption process is different from the IV used in the decryption process (which still uses the default IV)? To answer this, let's take another look at the <strong>AES_CBC decryption process:

</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Plaintext = decrypt(<em>message, KEY, IV)</em></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Plaintext = decrypt(<em>message, KEY) </em><strong>⊕</strong> <em>IV</em></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Our objective is to XOR the decryption result not with the default IV, but with the newIV obtained from the block cipher <strong>⊕</strong> of the plaintext blocks from the previous round. Therefore, we use the default IV that we got to "remove" the default XOR effect from the decrypt feature and we XOR again with the newIV we have.</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Plaintext = (decrypt(<em>message, KEY) </em><strong>⊕</strong> <em>IV)</em> <strong>⊕</strong> <em>IV <strong>⊕</strong></em> <em>newIV</em></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Plaintext = decrypt(<em>message, KEY) <strong>⊕</strong></em> <em>newIV</em></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Now, just add this operation to the code and do it all the way to the last cipher block. Got the flag</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><strong>Full code:</strong></p>
<!-- /wp:paragraph -->
https://github.com/kisanakkkkk/writeup/blob/main/compfest%202021/You%20AES%20Me%20Up/rapi.py

<p><strong>Output:</strong></p>

<!-- wp:image {"id":5507,"sizeSlug":"large","linkDestination":"none"} -->
<figure class="wp-block-image size-large"><img src="https://petircysec.com/wp-content/uploads/2021/09/image-33.png" alt="" class="wp-image-5507"/></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p><strong>Flag = </strong>COMPFEST13{y0u_aes_me_UpPpppPp_____t0_c0d3_on_st0rmy_Sea4aA5____e0212d1a34}</p>
<!-- /wp:paragraph -->
