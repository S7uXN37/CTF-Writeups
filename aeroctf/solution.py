from pwn import *
from binascii import *
from time import sleep
from z3 import *

ciphers = [
"7685737a9f7895737a9f84857b769f7a" + "657b769f78898378",
"717785747885858d6f7e917364686776",
"7393a992708d8fad708d83aa7273707d" + "6f3939856b7d398bb53b8b34b573b6c5618e7135"
]

plains = [
"test_test_test_t" + "est_test",
"qwertyuiopasdfgh",
"skIllaoInasJjklq" + "o19akq9k13k45k69alq1"
]

secret = "8185748f7b3b3a3565454584b8babbb8" + "b441323ebc8b3a86b5899283b9c2c56d64388889b781"

#for i in range(len(ciphers)):
#	ciphers[i] = unhexlify(ciphers[i])

keysize = 16
# allowed key chars:   0-9, a-h

solver = Solver()
key = [BitVec("key" + str(i), 8) for i in range(keysize)]

for (p,c) in zip(plains, ciphers[:3]):
	for pos in range(len(p)):
		solver.add(int(c[2*pos:2*pos+2], 16) == (key[pos % 16] + (key[pos % 16] ^ ord(p[pos]))) & 0xff)

# constrain to aero{...}
start = "Aero{"
for i in range(len(start)):
	v = int(secret[2*i:2*i+2], 16)
	dec = ((v - key[i]) & 0xff) ^ key[i]
	dec = dec & 0xff
	solver.add( dec == ord(start[i]))

print("Solving...")
# Solve the equations
while solver.check() == sat:
	modl = solver.model()

	keyVals = [modl[key[i]].as_long() for i in range(keysize)]
	#print("Found key: " + str(keyVals))

	flag = [int(secret[2*pos:2*pos+2], 16) for pos in range(len(secret) // 2)]
	flag = [((flag[i] - keyVals[i % 16]) & 0xff) ^ keyVals[i % 16] for i in range(len(flag))]

	f = ""
	for i in range(len(flag)):
		f += chr(flag[i])

	full_ascii = True
	for c in f:
		if ord(c) < 0x20 or ord(c) > 0x80:
			full_ascii = False

	if full_ascii:
		print(f)

# Encryption works like:
# output byte = key[mod 16] + key[mod 16] ^ plain byte