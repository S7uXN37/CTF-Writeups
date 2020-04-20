# Babycrypt
## Challenge
In this challenge, we're given a stripped ELF 64-bit executable 'bcry' (redistributed in this repo) and 'note.dat':
```
key: %key%
text: test_test_test_test_test
Encoded: 7685737a9f7895737a9f84857b769f7a657b769f78898378

key: %key%
text: qwertyuiopasdfgh
Encoded: 717785747885858d6f7e917364686776

key: %key%
text: skIllaoInasJjklqo19akq9k13k45k69alq1
Encoded: 7393a992708d8fad708d83aa7273707d6f3939856b7d398bb53b8b34b573b6c5618e7135

key: %key%
text: %flag%
Encoded: 8185748f7b3b3a3565454584b8babbb8b441323ebc8b3a86b5899283b9c2c56d64388889b781


*Note: in all three cases used one key*
```

It looks like the program they gave us was used to encode some text using the same key, including the flag.

Wouldn't it be nice if we could derive the key from the input/output pairs and decode the flag? ;)

## Reversing

If we take a look at the binary in our favorite disassembler and start reversing, we end up with the following main function:
```C
undefined8 main(void)

{
  MyStruct *buffer;
  
  readInputs(&buffer);   // asks for a key (re: [0-9a-h]{16}) and the text to encrypt
  shuffle(&buffer);  // shuffles(?) the key in some way
  FUN_00101ade(&buffer); // never figured out what this does
  xor(&buffer);  // encrypt the text
  output(&buffer);  // output the result
  FUN_001018ec(&buffer);
  return 0;
}
```

Since the key is the same for all input/output pairs, we really don't much care about the shuffle part or `FUN_00101ade` at all.

Let's take a look at `xor` instead:

```C
void xor(long buffer)
{
  char plainChar;
  uint key2;
  byte bVar1;
  ulong plainLen;
  char *pcVar2;
  uint *key1;
  int *key3;
  ulong i;
  int local_20;
  int index;
  
  index = 0;
  while( true ) {
    i = SEXT48(index);
    plainLen = FUN_00101f74(buffer + 0x58);
    if (plainLen <= i) break;
    pcVar2 = (char *)getChar(buffer + 0x58,(long)index,buffer + 0x58);
    plainChar = *pcVar2;
    bVar1 = (byte)(index >> 0x37);
    key1 = (uint *)getByteOff((char)buffer,((char)index + (bVar1 >> 4) & 0xf) - (bVar1 >> 4));
    key2 = *key1;
    bVar1 = (byte)(index >> 0x37);
    key3 = (int *)getByteOff((char)buffer,((char)index + (bVar1 >> 4) & 0xf) - (bVar1 >> 4));
    local_20 = *key3 + ((int)plainChar ^ key2);
    appendByte(buffer + 0x70,&local_20);
    index = index + 1;
  }
  return;
}
```
(key1, key2 and key3 all have the same value - not sure why this looks more complicated than it is)

We notice that a byte from the key is loaded (index mod 16), xor'ed with the plaintext byte, added to the result and that is then saved.
This gives us the following equation for each byte of the plaintext:
```python
out[i] = key[i % 16] + key[i % 16] ^ text[i]
```

## Z3
Because I didn't see any convenient way to solve this equation for the key byte directly,
I used z3 in python to solve all the equations at once.
There were many solutions but after constrainging the output to the flag format,
printable ASCII characters and accounting for overflow, we got the flag.

## Putting it all together
This is the script I used to solve the challenge (if my comments annoy you, the full file is available on the repo as well).

Some imports and variables:
```python
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

keysize = 16
# allowed key chars:   0-9, a-h

solver = Solver()
key = [BitVec("key" + str(i), 8) for i in range(keysize)]
```

Now we add the equations to our Solver. Because z3 does not deal with overflow on its own when doing BitVec addition,
I had to account for it by adding `& 0xff`.
```python
for (p,c) in zip(plains, ciphers[:3]):
	for pos in range(len(p)):
		solver.add(int(c[2*pos:2*pos+2], 16) == (key[pos % 16] + (key[pos % 16] ^ ord(p[pos]))) & 0xff)
```

Constraining the output to start with `Aero{`
```python
# constrain to aero{...}
start = "Aero{"
for i in range(len(start)):
	v = int(secret[2*i:2*i+2], 16)
	dec = ((v - key[i]) & 0xff) ^ key[i]
	dec = dec & 0xff
	solver.add( dec == ord(start[i]))
```

And finally, iterating over all solutions and outputting only those that are all in the printable ASCII range.
```python
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
```

And running this takes only a short time and gives us the flag:
`Aero{381a95d003629088c8f1ebc189ab6fe7}`
