# CryptoSystem — TryHackMe Writeup

**Room:** Cryptosystem  
**Category:** Crypto  
**Difficulty:** Medium

---

## The Challenge

We're given a Python script that encrypted a flag using RSA. The story is that we intercepted a message between "Cipher" and three associates named Rivest, Shamir, and Adleman (hint hint). The goal is to recover the secret key (the flag).

The file we recovered:

```python
from Crypto.Util.number import *
from flag import FLAG

def primo(n):
    n += 2 if n & 1 else 1
    while not isPrime(n):
        n += 2
    return n

p = getPrime(1024)
q = primo(p)
n = p * q
e = 0x10001
d = inverse(e, (p-1) * (q-1))
c = pow(bytes_to_long(FLAG.encode()), e, n)
#c = 3591116664...
#n = 15956250162...
```

The actual `c` and `n` values are commented out at the bottom.

---

## Figuring Out the Vulnerability

First thing I noticed was the `primo(p)` function. It just finds the next prime after `p`. So `q` isn't random at all — it's basically `p + a tiny bit`.

That's bad for RSA. The whole point is that `p` and `q` should be random and far apart. If they're close, there's a known attack called **Fermat's Factorization** that can factor `n` really quickly.

Normally factoring a 1024-bit RSA modulus would be impossible. But here because `p ≈ q`, `sqrt(n)` lands right between them. So you just start guessing from `sqrt(n)` and you find them almost immediately.

---

## The Solve

I wrote a quick script to do it:

```python
from math import isqrt, ceil

n = 15956250162063169819282947443743274370048643274416742655348817823973383829364700573954709256391245826513107784713930378963551647706777479778285473302665664446406061485616884195924631582130633137574953293367927991283669562895956699807156958071540818023122362163066253240925121801013767660074748021238790391454429710804497432783852601549399523002968004989537717283440868312648042676103745061431799927120153523260328285953425136675794192604406865878795209326998767174918642599709728617452705492122243853548109914399185369813289827342294084203933615645390728890698153490318636544474714700796569746488209438597446475170891

c = 3591116664311986976882299385598135447435246460706500887241769555088416359682787844532414943573794993699976035504884662834956846849863199643104254423886040489307177240200877443325036469020737734735252009890203860703565467027494906178455257487560902599823364571072627673274663460167258994444999732164163413069705603918912918029341906731249618390560631294516460072060282096338188363218018310558256333502075481132593474784272529318141983016684762611853350058135420177436511646593703541994904632405891675848987355444490338162636360806437862679321612136147437578799696630631933277767263530526354532898655937702383789647510

e = 0x10001

# fermat's factorization — find p and q
a = ceil(isqrt(n)) + 1
while True:
    b2 = a * a - n
    b = isqrt(b2)
    if b * b == b2:
        p = a - b
        q = a + b
        break
    a += 1

# standard rsa decryption from here
phi = (p - 1) * (q - 1)

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

def inverse(e, phi):
    _, x, _ = egcd(e, phi)
    return x % phi

d = inverse(e, phi)
m = pow(c, d, n)

flag = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
print(flag)
```

Ran it and got the flag immediately.

---

## Key Takeaway

The mistake was using `q = nextprime(p)`. That makes `p` and `q` nearly identical, which completely breaks RSA's security. Fermat's factorization exploits exactly this — when `p` and `q` are close, you can recover them from `n` in seconds instead of never.

Once you have `p` and `q`, the rest is just standard RSA math.

---

**Flag:** `THM{Just_s0m3_small_amount_of_RSA!}`****
