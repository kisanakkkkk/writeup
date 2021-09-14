**[494 pts] Secure Channel**

_Description:_
<!-- wp:paragraph -->
<p><em>You are able to watch the encrypted chat of Alice and Bob. They are talking about the flag right now. Can you get the flag from them?</em></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><em>P.S.: Alice and Bob once have said that they will communicate with some trivial encoding, so people will not notice their message at first glance. Although, people will know it if they search it on the internet! Sure, all of it is printable characters.</em></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><em>Watch the conversation: <code>nc 103.152.242.56 8231</code></em></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><em>Talk with Alice: <code>nc 103.152.242.56 8230</code></em></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><em>Talk with Bob: <code>nc 103.152.242.56 8232</code></em></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><em><strong>Author:</strong> prajnapras19</em></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><strong>secrets.py: </strong>https://github.com/kisanakkkkk/writeup/blob/main/compfest%202021/Secure%20Channel/secrets.py</p>
<!-- /wp:paragraph -->


<!-- wp:paragraph -->
<p><strong>alice-bob.py: </strong>https://github.com/kisanakkkkk/writeup/blob/main/compfest%202021/Secure%20Channel/alice-bob.py</p>
<!-- /wp:paragraph -->


<!-- wp:paragraph -->
<p><strong>talk-with-alice.py: </strong>https://github.com/kisanakkkkk/writeup/blob/main/compfest%202021/Secure%20Channel/talk-with-alice.py</p>
<!-- /wp:paragraph -->


<!-- wp:paragraph -->
<p><strong>talk-with-bob.py: </strong>https://github.com/kisanakkkkk/writeup/blob/main/compfest%202021/Secure%20Channel/talk-with-bob.py</p>
<!-- /wp:paragraph -->

TL;DR
Solution:

1. find bob's secret by brute force & compare our custom secret
2. get bob's key from make_private_part(bobsecret, alicepub, p)
3. create unpad function which remove unprintable string
4. decrypt each messages from the convo, decode with ascii85
5. profit

<!-- wp:paragraph -->
<p><strong>Summary</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>We are given 4 files: </p>
<!-- /wp:paragraph -->

<!-- wp:list {"ordered":true} -->
<ol><li>Secrets.py which contains the public and private part generator and other function, also class descriptions of the person named bob &amp; alice, and ourselves. </li><li>Alice-bob.py which contains the code for the conversation between bob &amp; alice about the flag we are looking for.</li><li>Talk-with-alice.py which contains the code when we want to have a conversation with alice.</li><li>Talk-with-bob.py which is the same as Talk- with-Alice.py, but with person bob.</li></ol>
<!-- /wp:list -->

<!-- wp:paragraph -->
<p>Let's jump right into the interesting part, the secrets.py file shows that each person has a SECRET object whose value is static but hidden. It says that Bob's character SECRET value is in the range of 2 - 100, which means it's small enough to do bruteforce. Let's try to get Bob SECRET by digging deeper the file <strong>talk-with-bob.py</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><strong>Finding Bob's SECRET</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>In talk-with-bob.py, we will be asked to enter our SECRET (you can fill whatever you want, base64-encoded) and the value of <em>g</em> in base64-encoded form, with a note the value must be <em>g </em>&gt; 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF. This g value will be "calculated" with the respective SECRET and the <em>p </em> value (obtained from getPrime function) and will become the respective <strong>public part</strong> which will be printed later. So from here we can brute-force our SECRET from 2 - 100, then compare our public part and Bob's public part and if they are the same, that means we get Bob's secret value. Don't mind the <em>g</em> too much, as long as we follow the conditions where g value is greater than 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF (when doing bruteforce I use <em>g </em> value of 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF+1). With the following code:</p>
<!-- /wp:paragraph -->

<!-- wp:code -->
<pre class="wp-block-code"><code>import binascii
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

if __name__ == "__main__":
	bobSecret = getBobSecret()</code></pre>
<!-- /wp:code -->

<!-- wp:image {"id":5514,"sizeSlug":"large","linkDestination":"none"} -->
<figure class="wp-block-image size-large"><img src="https://petircysec.com/wp-content/uploads/2021/09/image-34.png" alt="" class="wp-image-5514"/></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Our public part and Bob's public part are the same, meaning that the SECRET we entered and Bob's SECRET are also the same, which is 73. With this information, we can "reveal" the contents of alice and bob's conversations that were initially encrypted.</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><strong>Finding Bob's KEY</strong> <strong>&amp; Decrypt the Messages</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>If we look at the Secrets.py file, every time a person wants to send a message, the message will be encrypted with AES_CBC in the <strong>send_message()</strong> function which requires a KEY from the sender. This KEY is generated by the <strong>make_private_part()</strong> function which requires the SECRET of the sender, the Public Part of the recipient, and the <em>p</em> value provided at the beginning (see the formula in the alice-bob.py file). We already have Bob's SECRET, Alice's PublicPart (printed in the program, just decode it and convert it to decimal), and the <em>p</em> value which has also been printed. Just generate the KEY based on the make_private_part() function, then decrypt the message based on the <strong>receive_message()</strong> function.

</p>
<!-- /wp:paragraph -->

<!-- wp:code -->
<pre class="wp-block-code"><code>import binascii
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

def receive_message(key, enc_message):
	iv = enc_message&#91;:16]
	enc = enc_message&#91;16:]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	msg = cipher.decrypt(enc)
	return msg

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
		AliceMessage = r.recvline().strip()
		decrypted = receive_message(key, base64.b64decode(AliceMessage))
		print('a:', decrypted)
		r.recvuntil("Messages from Bob:\n")
		bobMessage = r.recvline().strip()
		decrypted = receive_message(key, base64.b64decode(bobMessage))
		print('b:', decrypted)</code></pre>
<!-- /wp:code -->

<!-- wp:paragraph {"style":{"typography":{"fontSize":14}}} -->
<p style="font-size:14px">*Note: A key from one of the person can be used to decrypt other person messages, so we can also read Alice's message with Bob's Key</p>
<!-- /wp:paragraph -->

<!-- wp:image {"id":5518,"sizeSlug":"large","linkDestination":"none"} -->
<figure class="wp-block-image size-large"><img src="https://petircysec.com/wp-content/uploads/2021/09/image-36.png" alt="" class="wp-image-5518"/></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Why is the output seems ... weird? That's because the message is still padded (see the <strong>pad()</strong> function in the secrets.py file). Simply put, this pad function will add random unprintable string characters between the original message characters. How to delete it? just make an unpad() function which contains looping per character of the message and returns all the characters which is in <strong>string.printable</strong>.</p>
<!-- /wp:paragraph -->

<!-- wp:code -->
<pre class="wp-block-code"><code>import binascii
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
	iv = enc_message&#91;:16]
	enc = enc_message&#91;16:]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	msg = cipher.decrypt(enc)
	return unpad(msg)

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
		AliceMessage = r.recvline().strip()
		decrypted = receive_message(key, base64.b64decode(AliceMessage))
		print('a:', decrypted)
		r.recvuntil("Messages from Bob:\n")
		bobMessage = r.recvline().strip()
		decrypted = receive_message(key, base64.b64decode(bobMessage))
		print('b:', decrypted)</code></pre>
<!-- /wp:code -->

<!-- wp:image {"id":5519,"sizeSlug":"large","linkDestination":"none"} -->
<figure class="wp-block-image size-large"><img src="https://petircysec.com/wp-content/uploads/2021/09/image-37.png" alt="" class="wp-image-5519"/></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Why is it still weird -.-? The description said that the messages they exchange with each other are still encoded in a "specific" encoding. After searching for a while, it turns out that the message is encoded with ascii85, and we can decode it using <em>base64.a85decode(msg)</em> python function. We just need to refine our code, read the conversation, and get the flag.</p>
<!-- /wp:paragraph -->

**Full Code:**
https://github.com/kisanakkkkk/writeup/blob/main/compfest%202021/Secure%20Channel/solve.py

<!-- wp:image {"id":5522,"sizeSlug":"large","linkDestination":"none"} -->
<figure class="wp-block-image size-large"><img src="https://petircysec.com/wp-content/uploads/2021/09/image-40.png" alt="" class="wp-image-5522"/></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p><strong>Flag = COMPFEST13{4fd29464a28a1b39559f4fc500b41c4b17ec8ad74512394a830b51506AIUEOuh_f8facf99fe}</strong></p>
<!-- /wp:paragraph -->
