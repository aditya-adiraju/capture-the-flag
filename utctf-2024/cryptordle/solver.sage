import sys
from sage.all import *

n = len(sys.argv)
assert n == 6

diffs = [int(sys.argv[i]) for i in range(1, 6)]

# The really mathy part of the solve

R = PolynomialRing(GF(31), names=('a', 'b', 'c', 'd', 'e',)); (a, b, c, d, e,) = R._first_ngens(5)
Id = Ideal((0 -a)*(0 -b)*(0 -c)*(0 -d)*(0 -e) - diffs[0], 
           (1 -a)*(1 -b)*(1 -c)*(1 -d)*(1 -e) - diffs[1], 
           (2 -a)*(2 -b)*(2 -c)*(2 -d)*(2 -e) - diffs[2], 
           (3 -a)*(3 -b)*(3 -c)*(3 -d)*(3 -e) - diffs[3], 
           (4 -a)*(4 -b)*(4 -c)*(4 -d)*(4 -e) - diffs[4])

letters = Id.variety()[0]
word = chr(int(letters[a]) + ord('a')) + chr(int(letters[b]) + ord('a')) + chr(int(letters[c]) + ord('a')) + chr(int(letters[d]) + ord('a')) + chr(int(letters[e]) + ord('a'))
print(word)
