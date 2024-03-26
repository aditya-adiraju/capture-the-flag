
# HTB Cyber Apocalypse 2024: Hacker Royale

| Name   | Primary Knowledge |
| ---- | ---- | 
| Category | Crypto |
| Author | aris |
| Difficulty | insane |
| Attachments | [server.py](./rot128/server.py) |


## Overview

The challenges use a custom hashing algorithm in order to verify the user's identity. You are provided with a `(message, digest)` pair that the algorithm generated with a secret key. 

The goal is to find another key (referred to as a `state` by the algorithm) that would produce the same hash for the given message. The flag will be printed if you successfully do this three times in a row. 


## Taking a look at the source 

There's a lot of driver code in the source code and it's unlikely that there are any side-channel attacks. So, I will only include the relevant bits of the source here. Let's take a look at the hsshing algorithm used. 

```py
N = 128
# left rotates an N-bit word x by i bits
# ROtate Left (ROL)
_ROL_ = lambda x, i : ((x << i) | (x >> (N-i))) & (2**N - 1)

class HashRoll:
    def __init__(self):
        self.reset_state()

    def hash_step(self, i):
        r1, r2 = self.state[2*i], self.state[2*i+1]
        return _ROL_(self.state[-2], r1) ^ _ROL_(self.state[-1], r2)

    def update_state(self, state=None):
        if not state:
            self.state = [0] * 6
            self.state[:4] = [random.randint(0, N) for _ in range(4)]
            self.state[-2:] = [random.randint(0, 2**N) for _ in range(2)]
        else:
            self.state = state
    
    def reset_state(self):
        self.update_state()

    def digest(self, buffer):
        buffer = int.from_bytes(buffer, byteorder='big')
        m1 = buffer >> N
        m2 = buffer & (2**N - 1)
        self.h = b''
        for i in range(2):
            self.h += int.to_bytes(self.hash_step(i) ^ (m1 if not i else m2), length=N//8, byteorder='big')
        return self.h
```

Time to go through this step-by-step:

- `__init__()` is our constructor that doesn't accept any arguments and calls `reset_state()` on our object.
- `reset_state()` looks like a simple wrapper around a no argument call to `update_state()`
- `update_state()` takes in an optional argument for the `state` to set the `state` variable of our Hasher. If there is no `state` provided, it will generate a random staate with the `randome` module.

Before we move on, it's important to make a few observations about the structure of our `state` attribute. Based on the `update_state()` method, it looks like our state is 6 element array `[a, b, c, d, e, f]` where `a, b, c, d` are integers in the range between $0$ and $128$ and `e, f` are integers in the range between $0$ and $2^{128}$. Now back to our regularly scheduled programming...

- `hash_step()`: ignore the meaning of `r1` and `r2` for now. The method returns a bitwise XOR operation result of `RoL(e, r1)` and `RoL(f, r2)`. 
- `digest(buffer)`: hashes the given `buffer`.
-

## Digesting some ROLls

Alright, maybe the `digest()` method warrants a bit more exploration. So first things first, the method splits our buffer (32 bytes long as indicated by the usage of the method in other parts of the code) into two N-bit/128-bit words called `m1` and `m2`.

it builds the output as two blocks that are concatenated to create the final output. Let's call them `t1` and `t2` where `t_i = hash_step(i - 1) ^ m_i`

Expanding and evaluating expressions where necessary we have that:

$$t_1 = \text{RotateLeft}(e, a) \oplus \text{RotateLeft}(f, b) \oplus m_1$$
$$t_2 = \text{RotateLeft}(e, c) \oplus \text{RotateLeft}(f, d) \oplus m_2$$

Now we know what $t_1, t_2, m_1,$ and $m_2$ are. To simplify this system, let $c_i = t_i \oplus m_i$.

We have that, 

$$c_1 = \text{RotateLeft}(e, a) \oplus \text{RotateLeft}(f, b)$$
$$c_2 = \text{RotateLeft}(e, c) \oplus \text{RotateLeft}(f, d)$$

Now, I could find an actual solution this system using some fancy group theory. But I was too lazy to do so, and I instead I opted to `z3` this. 

NOTE: if you are interested in the intended solution. Check out [this post](https://crypto.stackexchange.com/questions/107005/a-problem-related-to-two-bitwise-sums-of-rotations-of-two-different-bitstrings)


## Z3 is a beautiful creation and solve script

The solve script didn't always work (due to the SIGALARM call) but it worked on my like 5th attempt so I never bothered changing it. 

```py
from pwn import *
import random, os, signal
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from z3 import *
N = 128
def xor_bytes(byte_string1, byte_string2):
    # Ensure both byte strings have the same length
    if len(byte_string1) != len(byte_string2):
        raise ValueError("Byte strings must be of equal length")

    # XOR each byte in the two byte strings
    result = bytearray()
    for b1, b2 in zip(byte_string1, byte_string2):
        result.append(b1 ^ b2)

    return bytes(result)

e = BitVec('e', N)
f = BitVec('f', N)
a, b, c, d = BitVecs('a b c d', N)
s = Solver()
def solve():
    # p = remote("94.237.51.203", 57730)
    p = process(["python3", "test.py"])
    for i in range(3):
        s.reset()
        s.add(a >= 0, a < N)
        s.add(b >= 0, b < N)
        s.add(c >= 0, c < N)
        s.add(d >= 0, d < N)
        s.add(a + b + c + d >= 2)
        p.recvuntil(b"You know H")
        m = bytes.fromhex(p.recvuntil(b")").decode()[1:-1])
        p.recvuntil(b' = ')
        t = bytes.fromhex(p.recvline().decode())
        info(f"{m.hex()}")
        info(f"{t.hex()}")
        
        
        m1, m2 = m[:16], m[16:] 
        t1, t2 = t[:16], t[16:] 
        comp1, comp2 = xor_bytes(m1, t1), xor_bytes(m2, t2)
        
        
        s.add(RotateLeft(e, a) ^ RotateLeft(f, b) == b2l(comp1))
        s.add(RotateLeft(e, c) ^ RotateLeft(f, d) == b2l(comp2))
        
        
        res = s.check()
        print(res)

        if res != sat:
            print("failed")
            p.clean()
            p.close()
            exit()
        else:
            m = s.model()

        payload = f"{m[a]}, {m[b]}, {m[c]}, {m[d]}, {m[e]}, {m[f]}"
        print("SENDLING payload")
        p.sendlineafter(b"::", payload.encode())

        
    while True:
        print(p.recvline())

solve()
```

## Thoughts

I liked this challenge. In particular, I enjoyed trying to cryptanalyze an algorithm myself and finding a vulnerability and exploiting it (albeit using a SAT solver). 
