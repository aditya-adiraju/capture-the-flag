# HTB Cyber Apocalypse 2024: Hacker Royale

| Name   | Primary Knowledge |
| ---- | ---- | 
| Category | Crypto |
| Author | aris |
| Difficulty | Easy |
| Attachments | [source.py](./primary-knowledge/source.py) [output.txt](./primary-knowledge/output.txt) |


## Overview

The challenge provides you with two files, `source.py` and the resulting `output.txt`. It's an offline challenge that essentially implements the `RSA` encryption algorithm. However, at first glance there's seems to be something wrong. 

## Inspecting the source


```py
import math
from Crypto.Util.number import getPrime, bytes_to_long
from secret import FLAG

m = bytes_to_long(FLAG)

# ADITYA: 2**0 == 1, so like the n is literally just a prime number since the list has one element 
n = math.prod([getPrime(1024) for _ in range(2**0)])
e = 0x10001

# ADITYA: fairly standard setup besides that. 
c = pow(m, e, n)

with open('output.txt', 'w') as f:
    f.write(f'{n = }\n')
    f.write(f'{e = }\n')
    f.write(f'{c = }\n')

```


As noted in the source code comments, we have that `n` is prime. AHA! we found our vulnerability. 

## But aren't prime numbers the coolest set of numbers ever?

Yes they are. However


