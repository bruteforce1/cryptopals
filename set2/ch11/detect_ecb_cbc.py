#!/usr/bin/python3

"""
Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random
 bytes.

Write a function that encrypts data under an unknown key --- that is,
 a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen
 randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and
 under CBC the other half (just use random IVs each time for CBC). Use
 rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You
 should end up with a piece of code that, pointed at a block box that
 might be encrypting ECB or CBC, tells you which one is happening.
"""

import argparse
import random
import string
import sys
sys.path.insert(0, '../../utils')
from cpset2 import aes_ecb, aes_cbc, test_aes_ecb

random.seed()

def gen_random_bytes(block=16):
    if not 1 <= block <= 32:
        return b''
    return bytes(random.randint(0,255) for _ in range(block))

def encryption_oracle(text):
    if type(text).__name__ == 'str':
        t = text.encode('utf-8')
    elif type(message).__name__ == 'bytes':
        t = text
    else:
        return b''

    key = gen_random_bytes()
    bef = gen_random_bytes(random.randint(5,10))
    af = gen_random_bytes(random.randint(5,10))
    pt = bef + t + af
    if random.randint(0,1):
        iv = gen_random_bytes()
        ret = aes_cbc(pt, key, iv)
        encmode = 0
    else:
        ret = aes_ecb(pt, key)
        encmode = 1
    guess = test_aes_ecb(ret)
    print('AES Mode: {0}; Guess: {1}'.format(['CBC','ECB'][encmode],
        ['CBC','ECB'][guess]))
    if encmode == guess:
        return 1
    return 0

def main():
    ans = encryption_oracle('a' * 1000)
    if ans:
        print('AES Mode Detected!')
        return 0
    print('Wrong Guess.')
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Uses an encryption oracle to encrypt data with AES in \
        either ECB or CBC mode.  Then we guess which method is used.'
        )
    args = parser.parse_args()

    sys.exit(main())
