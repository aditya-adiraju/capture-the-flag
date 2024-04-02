from pwn import *
import subprocess

p = process("./main.py")

character = 'a'

diffs = [0] * 5
for i in range(5):
    p.recvuntil(b"What's your guess?")
    p.sendline((character * 5).encode())
    p.recvline() # get rid of extra newline char 
    diffs[i] = int(p.recvline().decode()[:-1])
    character = chr(ord(character) + 1)

a, b, c, d, e = diffs
s = subprocess.run(["sage", "-python", "solver.sage", str(a), str(b), str(c), str(d), str(e)], capture_output=True)
word = s.stdout.decode()
print(word)
info(f"The word has these letters: {word}")

p.interactive()









