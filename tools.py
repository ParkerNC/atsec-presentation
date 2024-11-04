from random import randrange

def fastexp(b: int, e: int, n: int) -> int:
    #part 1 fast modular exponentiation
    prod = 1
    base = b
    exp = bin(e)[::-1]
    exp = exp[:-2]
    for bit in exp:
        if bit == "1":
            prod = (prod * base) %n
        
        base = (base * base ) %n

    return prod

def millerR(p: int, i: int) -> bool:
    #part 2 miller robin implementation
    s = 0
    n = p
    d = n-1
    while(d%2 == 0):
        s += 1
        d = d >> 1

    for r in range(i):
        prime = False
        a = randrange(2, n-2)
        x = fastexp(a, d, n)
        if x == 1 or x == (n-1):
            continue
        for step in range(s-1):
            x = fastexp(x, 2, n)
            if x == (n-1):
                prime = True
                break
        
        if prime:
            continue

        return False

    return True

def diffe_helman_pk(p: int, a: int, g: int) -> int:
    #generates a prvate key number for diffie helman

    pKey = fastexp(g, a, p)

    return pKey

def diffe_helman_decrypt(mykey: int, theykey: int, mod: int) -> int:
    shared = fastexp(theykey, mykey, mod)

    return shared

def safePrimeGen(bitlen: int) -> int:
    qlen = bitlen-1
    #safe prime gen for diffie helman with a few optimizations, ie checking ez primes and making sure even
    while(1):
        test = randrange(2**(qlen-1)+1, 2**qlen-1)
        #test = getrandbits(qlen)
        if not test & 1:
            continue


        if millerR(test, 10):
            test = (test << 1) + 1

            if millerR(test, 10):
                return test

    return test

if __name__ == "__main__":
    print(safePrimeGen(512))