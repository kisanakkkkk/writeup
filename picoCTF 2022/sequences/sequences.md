<h1>[400 pts] Sequences</h1>

<!-- wp:heading -->
<h2><strong>Description</strong></h2>
<!-- /wp:heading -->

<!-- wp:preformatted -->
<pre class="wp-block-preformatted">I wrote this linear recurrence function, can you figure out how to make it run fast enough and get the flag? Download the code here sequences.py Note that even an efficient solution might take several seconds to run. If your solution is taking several minutes, then you may need to reconsider your approach.

Hint #1 : Google "matrix diagonalization". Can you figure out how to apply it to this function?</pre>
<!-- /wp:preformatted -->
chall file: https://github.com/kisanakkkkk/writeup/blob/main/picoCTF%202022/sequences/sequences.py
<p><strong>TL;DR</strong>
    
Optimize fibonacci-like code with matrix diagonalization method</p>


<!-- wp:heading -->
<h2><strong>Solution</strong></h2>
<!-- /wp:heading -->

<!-- wp:paragraph -->
<p>Looking at given file sequences.py we see:</p>
<!-- /wp:paragraph -->

<!-- wp:code -->
<pre class="wp-block-code"><code>import math
import hashlib
import sys
from tqdm import tqdm
import functools

ITERS = int(2e7)
VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"
ENCRYPTED_FLAG = bytes.fromhex("42cbbce1487b443de1acf4834baed794f4bbd0dfb78a053d258da7c42b")

# This will overflow the stack, it will need to be significantly optimized in order to get the answer :)
@functools.cache
def m_func(i):
    if i == 0: return 1
    if i == 1: return 2
    if i == 2: return 3
    if i == 3: return 4

    return 55692*m_func(i-4) - 9549*m_func(i-3) + 301*m_func(i-2) + 21*m_func(i-1)


# Decrypt the flag
def decrypt_flag(sol):
    sol = sol % (10**10000)
    sol = str(sol)
    sol_md5 = hashlib.md5(sol.encode()).hexdigest()

    if sol_md5 != VERIF_KEY:
        print("Incorrect solution")
        sys.exit(1)

    key = hashlib.sha256(sol.encode()).digest()
    flag = bytearray(&#91;char ^ key&#91;i] for i, char in enumerate(ENCRYPTED_FLAG)]).decode()

    print(flag)

if __name__ == "__main__":
    sol = m_func(ITERS)
    decrypt_flag(sol)
</code></pre>
<!-- /wp:code -->

<!-- wp:paragraph -->
<p><strong>Code Analysis</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Basically, the decrypt_flag function will accept the variable sol, which will later be tested whether the value of sol is true or not by comparing its hash with the precomputed hash value “VERIF_KEY”. If this returns true, that value will be used as the key to decrypt the ciphertext “ENCRYPTED_FLAG”.
The value of sol itself can actually be obtained automatically from the m_funct function. But the problem is to get this value, you have to do recursion repeatedly as much as 2e7 (or 20000000) times, so of course using this method plainly will takes too much time. <strong>We need to make more optimal code that will calculate faster and still gives us the correct value.</strong>
</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>The value of sol itself can actually be obtained automatically from the m_funct function. But the problem is to get this value, you have to do recursion repeatedly as much as 2e7 (or 20000000) times, so of course using this method plainly will takes too much time. We need to make more optimal code that will calculate faster and still gives us the correct value.</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><strong>Solving</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Let's take a look at the m_func function, it will return</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><em> 55692*m_func(i-4) - 9549*m_func(i-3) + 301*m_func(i-2) + 21*m_func(i-1)</em> </p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>every time it is called until the value of i reach 0, 1, 2, or 3. Looks familiar, doesn't it? Yes, this function is similar to the Fibonacci sequence recursive function, but with the addition of a few more constants and ranges.</p>
<!-- /wp:paragraph -->

<!-- wp:image {"align":"center","id":5907,"sizeSlug":"full","linkDestination":"none"} -->
<div class="wp-block-image"><figure class="aligncenter size-full"><img src="https://petircysec.com/wp-content/uploads/2022/03/image-1.png" alt="" class="wp-image-5907"/></figure></div>
<!-- /wp:image -->
<p>normal fibonacci code</p>

<!-- wp:paragraph -->
<p>Based on the hint given, I found out that Fibonacci can be optimized with the concept of matrix diagonalization. This problem is similar to Fibonacci, so maybe we can just take the Fibonacci matrix diagonalization formula and modify it by a little. I use <a href="https://medium.com/@andrew.chamberlain/the-linear-algebra-view-of-the-fibonacci-sequence-4e81f78935a3" data-type="URL" data-id="https://medium.com/@andrew.chamberlain/the-linear-algebra-view-of-the-fibonacci-sequence-4e81f78935a3">this</a> and <a href="http://www.math.hawaii.edu/~pavel/fibonacci.pdf" data-type="URL" data-id="http://www.math.hawaii.edu/~pavel/fibonacci.pdf">this</a> as a reference.</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><strong>Step 1: find A (core matrix)</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>First, we convert the recursive from “m_funct” to Fn notation where n is the number of iterations:</p>
<!-- /wp:paragraph -->

<!-- wp:verse {"textAlign":"center"} -->
<pre class="wp-block-verse has-text-align-center">F(n) =  21*F(n-1) + 301*F(n-2) - 9549*F(n-3) + 55692*F(n-4)</pre>
<!-- /wp:verse -->

<!-- wp:paragraph -->
<p>to create a linear equations, we need 3 more equations. We can obtain each of the equations by simply multiplying 0 in every n term other than the one we are looking for.</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph {"align":"center"} -->
<p class="has-text-align-center">F(n-1) =  F(n-1) +  (0)*F(n-2)  +  (0)*F(n-3)   +  (0)*F(n-4)<br>F(n-2) =  (0)*F(n-1) +  F(n-2)  +  (0)*F(n-3)   +  (0)*F(n-4)<br>F(n-3) =  (0)*F(n-1) +  (0)*F(n-2)  +  F(n-3)   +  (0)*F(n-4)<br></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>so that it can be formed in matrix notation as follows:</p>
<!-- /wp:paragraph -->

<!-- wp:image {"align":"center","id":5909,"sizeSlug":"full","linkDestination":"none"} -->
<div class="wp-block-image"><figure class="aligncenter size-full"><img src="https://petircysec.com/wp-content/uploads/2022/03/image-2.png" alt="" class="wp-image-5909"/></figure></div>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>We take this matrix model and name it as "A"</p>
<!-- /wp:paragraph -->

<!-- wp:image {"align":"center","id":5911,"sizeSlug":"full","linkDestination":"none"} -->
<div class="wp-block-image"><figure class="aligncenter size-full"><img src="https://petircysec.com/wp-content/uploads/2022/03/image-4.png" alt="" class="wp-image-5911"/></figure></div>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p><strong>Step 2: find eigenvectors of A, combine it.</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Next, what we need to look for are the eigenvectors of this matrix A. I used the online tools https://www.symbolab.com/solver/matrix-eigenvectors-calculator/ and the results are:</p>
<!-- /wp:paragraph -->

<!-- wp:image {"align":"center","id":5913,"sizeSlug":"full","linkDestination":"none"} -->
<div class="wp-block-image"><figure class="aligncenter size-full"><img src="https://petircysec.com/wp-content/uploads/2022/03/image-6.png" alt="" class="wp-image-5913"/></figure></div>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>we got four eigenvectors, we combine the four into new matrix and name it as "S"</p>
<!-- /wp:paragraph -->

<!-- wp:image {"align":"center","id":5914,"sizeSlug":"full","linkDestination":"none"} -->
<div class="wp-block-image"><figure class="aligncenter size-full"><img src="https://petircysec.com/wp-content/uploads/2022/03/image-7.png" alt="" class="wp-image-5914"/></figure></div>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p><strong>Step 3: find Λ, the diagonal matrix</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>and the last thing we need is to find the diagonal matrix (<strong>Λ</strong>), and we can get it by the formula:</p>
<!-- /wp:paragraph -->

<!-- wp:image {"align":"center","id":5915,"width":373,"height":98,"sizeSlug":"full","linkDestination":"none"} -->
<div class="wp-block-image"><figure class="aligncenter size-full is-resized"><img src="https://petircysec.com/wp-content/uploads/2022/03/image-8.png" alt="" class="wp-image-5915" width="373" height="98"/></figure></div>
<!-- /wp:image -->
<p>matrix diagonal = <em>(S inverse)*(matrix A)*(matrix S)</p>


<!-- wp:image {"align":"center","id":5916,"width":337,"height":147,"sizeSlug":"full","linkDestination":"none"} -->
<div class="wp-block-image"><figure class="aligncenter size-full is-resized"><img src="https://petircysec.com/wp-content/uploads/2022/03/image-9.png" alt="" class="wp-image-5916" width="337" height="147"/></figure></div>
<!-- /wp:image -->
<p>(result)</p>


<!-- wp:paragraph -->
<p><strong>Final step: Calculate F(n)</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>We already have the A as core matrix, the diagonal matrix Λ and the S matrix, so to find the nth m_funct number, we can use the following formula.</p>
<!-- /wp:paragraph -->

<!-- wp:image {"align":"center","id":5922,"width":285,"height":131,"sizeSlug":"full","linkDestination":"none"} -->
<div class="wp-block-image"><figure class="aligncenter size-full is-resized"><img src="https://petircysec.com/wp-content/uploads/2022/03/image-10.png" alt="" class="wp-image-5922" width="285" height="131"/></figure></div>
<!-- /wp:image -->
<p>(if we take n = 0, then:<br>F(0) = 1,<br>F(0+1) = 2,<br>F(0+2) = 3,<br>F(0+3) = 4<br>and also that’s why matrix [4, 3, 2, 1] exists in the formula)<br></p>

<!-- wp:image {"align":"center","id":5924,"sizeSlug":"full","linkDestination":"none"} -->
<div class="wp-block-image"><figure class="aligncenter size-full"><img src="https://petircysec.com/wp-content/uploads/2022/03/image-12.png" alt="" class="wp-image-5924"/></figure></div>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>from here, we just input ITERS as n in the diagonal matrix. Once the multiplication above is done by the computer (which should be much faster than the recursive method), you will get a 4x1 matrix as the result matrix. </p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>What we want to look for is F(n), so we only need to take value from the 4th row of the result, then just pass that value to the decrypt_flag() function, and the flag could be obtained. </p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Construct all the concepts above into a python script with sage module, and this is the result I make:</p>
<!-- /wp:paragraph -->

<!-- wp:code -->
<pre class="wp-block-code"><code>import hashlib
from sage.all import *

ITERS = int(2e7)
VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"
ENCRYPTED_FLAG = bytes.fromhex("42cbbce1487b443de1acf4834baed794f4bbd0dfb78a053d258da7c42b")
def decrypt_flag(sol):
    sol = sol % (10**10000)
    sol = str(sol)
    sol_md5 = hashlib.md5(sol.encode()).hexdigest()

    if sol_md5 != VERIF_KEY:
        print("Incorrect solution")
        sys.exit(1)

    key = hashlib.sha256(sol.encode()).digest()
    flag = bytearray(&#91;char ^ key&#91;i] for i, char in enumerate(ENCRYPTED_FLAG)]).decode()

    print(flag)


if __name__=="__main__":
    #step 1: find A
    A = matrix(QQ, &#91;&#91;21,301,-9549, 55692],&#91;1,0,0,0],&#91;0,1,0,0],&#91;0,0,1,0]])
    print('matrix A:\n', A)

    #step 2: find Eigenvector of A using https://www.symbolab.com/solver/matrix-eigenvectors-calculator, combine it as S.
    S = matrix(&#91;&#91;1728, 2197, 4913, -9261], &#91;144, 169, 289, 441], &#91;12, 13, 17, -21], &#91;1, 1, 1, 1]])
    print('matrix S:\n', S)

    #step 3: find diagonal matrix
    diagonal_matrix = S.inverse()*A*S
    print('diagonal matrix:\n', diagonal_matrix)
    
    #step 4: find fn
    res = S*(diagonal_matrix**ITERS)*S.inverse()*matrix(&#91;&#91;4], &#91;3], &#91;2], &#91;1]])
    sol = res.list()&#91;-1] #take bottom value from the matrix result

    #pass to function
    print('begin final calculation')
    decrypt_flag(sol)
</code></pre>
<!-- /wp:code -->
solve file: https://github.com/kisanakkkkk/writeup/blob/main/picoCTF%202022/sequences/solve.py
<!-- wp:paragraph -->
<p>output:</p>
<!-- /wp:paragraph -->

<!-- wp:image {"align":"center","id":5929,"sizeSlug":"full","linkDestination":"none"} -->
<div class="wp-block-image"><figure class="aligncenter size-full"><img src="https://petircysec.com/wp-content/uploads/2022/03/image-13.png" alt="" class="wp-image-5929"/></figure></div>
<!-- /wp:image -->
<p>calculation time: &lt;5s</p>

<!-- wp:paragraph -->
<p><strong>Flag: picoCTF{b1g_numb3rs_cd8e813d}</strong></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>reference:</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><a href="https://medium.com/@andrew.chamberlain/the-linear-algebra-view-of-the-fibonacci-sequence-4e81f78935a3">https://medium.com/@andrew.chamberlain/the-linear-algebra-view-of-the-fibonacci-sequence-4e81f78935a3</a></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><a href="http://www.math.hawaii.edu/~pavel/fibonacci.pdf">http://www.math.hawaii.edu/~pavel/fibonacci.pdf</a></p>
<!-- /wp:paragraph -->
