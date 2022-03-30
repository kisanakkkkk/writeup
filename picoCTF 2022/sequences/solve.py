import hashlib
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
    flag = bytearray([char ^ key[i] for i, char in enumerate(ENCRYPTED_FLAG)]).decode()

    print(flag)


if __name__=="__main__":
    #step 1: find A
    A = matrix(QQ, [[21,301,-9549, 55692],[1,0,0,0],[0,1,0,0],[0,0,1,0]])
    print('matrix A:\n', A)

    #step 2: find Eigenvector of A using https://www.symbolab.com/solver/matrix-eigenvectors-calculator, combine it as S.
    S = matrix([[1728, 2197, 4913, -9261], [144, 169, 289, 441], [12, 13, 17, -21], [1, 1, 1, 1]])
    print('matrix S:\n', S)

    #step 3: find diagonal matrix
    diagonal_matrix = S.inverse()*A*S
    print('diagonal matrix:\n', diagonal_matrix)
    
    #step 4: find fn
    res = S*(diagonal_matrix**ITERS)*S.inverse()*matrix([[4], [3], [2], [1]])
    sol = res.list()[-1] #take bottom value from the matrix result

    #pass to function
    print('begin final calculation')
    decrypt_flag(sol)