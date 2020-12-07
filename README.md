# b00t2root 2020 CTF - Crypto Challenges

I represent to you my writeups for all Crypto challenges from b00t2root 2020 CTF.
![2020-12-07 00_50_28-boot2root](https://user-images.githubusercontent.com/62826765/101377456-215cdc00-38b2-11eb-9146-1ada39a974df.png)

## Try try but don't cry
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
The main problem here is that we don't know when it's Base64 or Hex. So i just wrote a script to decode it manualy by entering H if it's Hex or B if it's Base64, then since i know a part of the flag which is "_b00t2root{}_" with length **11**, so I can retrive the hole flag :
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


## Euler's Empire
![2020-12-07 18_13_22-boot2root](https://user-images.githubusercontent.com/62826765/101382177-f07fa580-38b7-11eb-813d-b948caa5d38d.png)

I'll skip this cause it's almost the same challenge as [Time Capsule](https://github.com/pberba/ctf-solutions/blob/master/20190810-crytoctf/crypto-122-time-capsule/time-capsule-solution.ipynb) from Crypto CTF 2019.


## 007

## brokenRSA

## The Heist

