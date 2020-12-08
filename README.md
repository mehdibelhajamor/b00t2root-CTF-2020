# b00t2root 2020 CTF - Crypto Challenges

I represent to you my writeups for all Crypto challenges from b00t2root 2020 CTF.
![2020-12-07 00_50_28-boot2root](https://user-images.githubusercontent.com/62826765/101377456-215cdc00-38b2-11eb-9146-1ada39a974df.png)

![2020-12-08 18_37_24-b00t2root-2020-CTF-Crypto-Challenges_README md at main · MehdiBHA_b00t2root-2020](https://user-images.githubusercontent.com/62826765/101520233-79641300-3984-11eb-888f-1ad5c2c6d68c.png)

## Challenge 1 : _Try try but don't cry_
![2020-12-07 17_39_03-boot2root](https://user-images.githubusercontent.com/62826765/101378399-54ec3600-38b3-11eb-9461-bc4896baa4c4.png)

We were given a source code :
```python
import random
def xor(a,b):
	l=""
	for i in range(min(len(a), len(b))):
		l+=chr(ord(a[i]) ^ ord(b[i]))
	return l

def encrypt(flag):
	l=random.randrange(2)
	if(l==0):
		return flag.encode('base64')
	elif(l==1):
		return flag.encode('hex')
	

flag="################"
assert(len(flag)==22)
c=xor(flag[:11], flag[11:])
c=c.encode('hex')

n=random.randint(1,20)
#print(n)

for _ in range(n):
	c=encrypt(c)

f=open('chall.txt', 'w')
f.write(c)
f.close()
```
The main problem here is that we don't know when it's Base64 or Hex. So i just wrote a script to decode it manualy by entering H if it's Hex or B if it's Base64, then since i know a part of the flag which is "_b00t2root{}_" with length **11**, I can retrive the flag.

**Solver :**
```python
from pwn import xor
import base64

cipher = open("chall.txt").read().strip()

while len(cipher) != 22:
	print(cipher)
	ans = input('> ').strip()

	if ans == 'H':
		cipher = bytes.fromhex(cipher).decode()
	elif ans == 'B':
		cipher = base64.b64decode(cipher).decode()

cipher = bytes.fromhex(cipher).decode()
s = b"b00t2root{"
s += xor(cipher[-1], '}')
t = xor(s, cipher[:len(s)])
flag = s+t
print(flag)
```
![2020-12-07 18_05_58-Kali - VMware Workstation](https://user-images.githubusercontent.com/62826765/101381366-f3c66180-38b6-11eb-91fe-c6b60ddc5f62.png)

FLAG is **_b00t2root{fantasticcc}_**

![2020-12-08 18_37_24-b00t2root-2020-CTF-Crypto-Challenges_README md at main · MehdiBHA_b00t2root-2020](https://user-images.githubusercontent.com/62826765/101520233-79641300-3984-11eb-888f-1ad5c2c6d68c.png)

## Challenge 2 :  _Euler's Empire_
![2020-12-07 18_13_22-boot2root](https://user-images.githubusercontent.com/62826765/101382177-f07fa580-38b7-11eb-813d-b948caa5d38d.png)

I'll skip this cause it's almost the same challenge as [Time Capsule](https://github.com/pberba/ctf-solutions/blob/master/20190810-crytoctf/crypto-122-time-capsule/time-capsule-solution.ipynb) from Crypto CTF 2019.

FLAG is **_b00t2root{Eul3r_w4s_4_G3niu5}_**

![2020-12-08 18_37_24-b00t2root-2020-CTF-Crypto-Challenges_README md at main · MehdiBHA_b00t2root-2020](https://user-images.githubusercontent.com/62826765/101520233-79641300-3984-11eb-888f-1ad5c2c6d68c.png)

## Challenge 3 : _007_
![2020-12-07 18_29_27-boot2root](https://user-images.githubusercontent.com/62826765/101384040-33db1380-38ba-11eb-9b9c-45e1c41708f9.png)

We were given a source code :
```python
import random
def rot(s, num):
	l=""
	for i in s:
		if(ord(i) in range(97,97+26)):
			l+=chr((ord(i)-97+num)%26+97)
		else:
			l+=i
	return l

def xor(a, b):
	return chr(ord(a)^ord(b))

def encrypt(c):
	cipher = c
	x=random.randint(1,1000)
	for i in range(x):
		cipher = rot(cipher, random.randint(1,26))
	cipher = cipher.encode('base64')

	l = ""
	for i in range(len(cipher)):
		l += xor(cipher[i], cipher[(i+1)%len(cipher)])
	return l.encode('base64')

flag = "#################"
print "cipher =", encrypt(flag)

#OUTPUT: cipher = MRU2FDcePBQlPwAdVXo5ElN3MDwMNURVDCc9PgwPORJTdzATN2wAN28=
```
To reverse the xor loop, we have to know the first character of the _cipher_. It should be in [a-z], so with simple bruteforce we can retrieve the correct rotated string. Then we try all rotations from 1 to 26 and get the flag.

**Solver :**
```python
import random
import base64

def rot(s, num):
	l=""
	for i in s:
		if(ord(i) in range(97,97+26)):
			l+=chr((ord(i)-97+num)%26+97)
		else:
			l+=i
	return l

def xor(a, b):
	return chr(ord(a)^ord(b))

enc = base64.b64decode("MRU2FDcePBQlPwAdVXo5ElN3MDwMNURVDCc9PgwPORJTdzATN2wAN28=").decode('latin-1')

for i in range(97,123):
	xored = chr(i)
	j = -1
	while j != -len(enc):
		xored = xor(enc[j],xored[0]) + xored
		j -= 1
	xored = xored[-1] + xored[:-1]
	try:
		res = base64.b64decode(xored).decode()
		for i in range(1, 26):
			flag = rot(res, i)
			if "b00t2root{" in flag:
				print(flag)
	except:
		pass
```

FLAG is **_b00t2root{Bond. James Bond.}_**

![2020-12-08 18_37_24-b00t2root-2020-CTF-Crypto-Challenges_README md at main · MehdiBHA_b00t2root-2020](https://user-images.githubusercontent.com/62826765/101520233-79641300-3984-11eb-888f-1ad5c2c6d68c.png)

## Challenge 4 : _brokenRSA_
![2020-12-07 21_55_33-boot2root](https://user-images.githubusercontent.com/62826765/101519634-b7146c00-3983-11eb-9984-0167017a9899.png)

We were given a source code :
```python
from Crypto.Util.number import *
import random
e = 4
def func(m):
	while(True):
		n = getPrime(512)
		x = pow(m, e, n)
		if(pow(x, (n-1)//2, n) == 1):
			return n

flag = bytes_to_long(b"############################")
n = func(flag)
print("n =", n)
print("c =", pow(flag, e, n))

# OUTPUT
# n = 11183632493295722900188836927564142822637910363304123337597708503476804292242860556684644449701772313571249316546794463854991452685201761786385895405863639
# c = 8939043592146774508422725937231398285333145869395369605787177287036646137314173055510198460479672008589091362568215564488685390459997440273900039337645280
```
We can observe that the modulus ```n``` is a prime number. So since the exponent ```e``` is a power of 2, we can take consecutive square roots to find the eth root.
Therefore we will use [Tonelli Shanks Algorithm](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm) to compute module square roots and convert each one to get the correct flag.

**Solver :**
```python
from Crypto.Util.number import long_to_bytes

n = 11183632493295722900188836927564142822637910363304123337597708503476804292242860556684644449701772313571249316546794463854991452685201761786385895405863639
c = 8939043592146774508422725937231398285333145869395369605787177287036646137314173055510198460479672008589091362568215564488685390459997440273900039337645280
e = 4

def legendre(a, p):
    return pow(a, (p - 1) // 2, p)
 
def tonelli(n, p):
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r

def find_square_roots(c, e):
	if e == 1:
		flag = long_to_bytes(c)
		if b"b00t2root" in flag:
			print(flag)
		return

	elif pow(c,(n-1)//2,n) != 1:
		return

	else:
		rt1 = tonelli(c, n)
		find_square_roots(rt1, e//2)
		rt2 = n - rt1
		find_square_roots(rt2, e//2)
	return

find_square_roots(c, e)
```

FLAG is **_b00t2root{finally_legendre_symbol_came_in_handy}_**

![2020-12-08 18_37_24-b00t2root-2020-CTF-Crypto-Challenges_README md at main · MehdiBHA_b00t2root-2020](https://user-images.githubusercontent.com/62826765/101520233-79641300-3984-11eb-888f-1ad5c2c6d68c.png)

## Challenge 5 : _The Heist_
![2020-12-07 21_55_49-boot2root](https://user-images.githubusercontent.com/62826765/101521105-a36a0500-3985-11eb-9605-65011955feef.png)

We were given a netcat server and a source code of the program running on it :
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import binascii
import sys

key = b"****************"
iv = key
flag = "***********************"

def encrypt(str1):
    obj = AES.new(key, AES.MODE_CBC, iv)
    str1 = pad(str1,16)
    ciphertext = obj.encrypt(str1)
    return binascii.hexlify(ciphertext)

def decrypt(str2):
    obj=AES.new(key, AES.MODE_CBC, iv)
    plaintext=obj.decrypt(str2)
    return binascii.hexlify(plaintext)

s="""
1. Enter key and get flag
2. Encrypt plaintext
3. Decrypt ciphertext

Enter option: """

while(True):
    try:
        print(s, end='')
        opt=int(input())

        if(opt==1):
            KEY = input("Enter hex key: ")
            KEY = binascii.unhexlify(KEY)
            if(KEY==key):
                print(flag)
                break;

        elif(opt==2):
            pt = input("Enter hex plaintext: ")
            pt = pt.encode('utf-8')
            pt = binascii.unhexlify(pt)
            print("Ciphertext: ", encrypt(pt).decode('utf-8'))

        elif(opt==3):
            ct = input("Enter hex ciphertext: ")
            ct = ct.encode('utf-8')
            ct = binascii.unhexlify(ct)
            print("Plaintext: ", decrypt(ct).decode('utf-8'))

        else:
            print("The input should be in between 1 and 3")

    except:
        print("Error")
```
When we connect to the server, it gives us 3 choices :

![2020-12-08 19_18_03-Kali - VMware Workstation](https://user-images.githubusercontent.com/62826765/101524398-28efb400-398a-11eb-8318-1b204380042e.png)

The encryption/decryption is based on AES CBC mode. 

To get the flag we should retrieve the _key_. We can see that ```IV = KEY``` so we need to know the value of _IV_. Let's do some analysis :

Suppose we encrypt a plaintext with 3 blocks (48 bytes) and we get our ciphertext. Now we are going to decrypt it, so the equations for each plaintext block will be :
```
P1 = D(C1) xor IV
P2 = D(C2) xor C1
P3 = D(C3) xor C2
```
When C1 = C3 and C2 is an empty block (which means 16*"\x00"), then :
```
P1 = D(C3) xor IV
P3 = D(C3)
```
So by xoring P1 and P3 we get the _IV_.

**Solver :**
```python
from pwn import *

cipher = "414141414141414141414141414141410000000000000000000000000000000041414141414141414141414141414141"

conn = remote("157.230.237.229",2200)
conn.recvuntil("Enter option: ")
conn.sendline('3')
conn.recvuntil("Enter hex ciphertext: ")
conn.sendline(cipher)

plaintext = conn.recvline().decode().strip().split(' ')[2]
plaintext = bytes.fromhex(plaintext)
IV = xor(plaintext[0:16],plaintext[32:48]).hex()

conn.recvuntil("Enter option: ")
conn.sendline('1')
conn.recvuntil("Enter hex key: ")
conn.sendline(IV)

flag = conn.recv().strip().decode()
print(flag)
```
![2020-12-08 19_35_16-Kali - VMware Workstation](https://user-images.githubusercontent.com/62826765/101526169-98ff3980-398c-11eb-9018-cdb00b89c41d.png)

FLAG is **_b00t2root{th3y_4r3_g0ing_t0_k1ll_u5}_**
