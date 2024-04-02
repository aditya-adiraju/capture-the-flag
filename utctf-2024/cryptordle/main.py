#!/usr/bin/env python3
import random

# wordlist = open('/src/wordlist.txt', 'r').read().split('\n')

# Patched for local testing
wordlist = open('./src/wordlist.txt', 'r').read().split('\n')[:-1]

for word in wordlist:
    assert len(word) == 5
    for letter in word:
        assert letter in 'abcdefghijklmnopqrstuvwxyz'

answer = random.choice(wordlist)

num_guesses = 0
while True:
    num_guesses += 1

    print("What's your guess?")
    guess = input().lower()

    assert len(guess) == 5
    for letter in guess:
        assert letter in 'abcdefghijklmnopqrstuvwxyz'

    if guess == answer:
        break

    response = 1
    for x in range(5):
        a = ord(guess[x]) - ord('a')
        b = ord(answer[x]) - ord('a')
        response = (response * (a-b)) % 31
    print(response)

if num_guesses <= 6:
    print('Nice! You got it :) Have a flag:')
    flag = open('/src/flag.txt', 'r').read();
    print(flag)
else:
    print(f"You took {num_guesses} tries. No flag for you :(")
