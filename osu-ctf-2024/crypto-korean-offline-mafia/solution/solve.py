from pwn import *
from randcrack import RandCrack
from tqdm import tqdm
import json

rc = RandCrack()

# Solving their PoW 
p = remote('chal.osugaming.lol', 7275)
p.recvuntil(b'proof of work:\n')
proc = subprocess.Popen(p.recvline().decode(), shell=True, stdout=subprocess.PIPE)
stdout, _ = proc.communicate()
p.send(stdout)

p.recvuntil(b"n = ")
n = int(p.recvline().decode(), 10)

p.recvuntil(b'vs = ')
vs = json.loads(p.recvline().decode())


for i in tqdm(range(624), desc="RandCrack progress"):
    p.sendlineafter(b"Pick a random r, give me x = r^2 (mod n): ", b"1")
    p.recvuntil(b"Here's a random mask:  ")
    mask = int(p.recvline().decode(), 2)
    rc.submit(mask)
    p.sendlineafter(b"Now give me r*product of IDs with mask applied: ", b"1")

for i in range(10):
    mask = '{:032b}'.format(rc.predict_getrandbits(32))
    val = 1
    for i in range(32):
    	if mask[i] == '1':
            val = (val * vs[i]) % n
    # find modular inverse of value
    x = str(pow(val, -1, n)).encode()

    p.sendlineafter(b"Pick a random r, give me x = r^2 (mod n): ", x)
    p.sendlineafter(b"Now give me r*product of IDs with mask applied: ", b"1")

    info(p.recvline().decode())
info(p.clean().decode())


