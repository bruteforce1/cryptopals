#!/usr/bin/python3

"""
Copy your oracle function to a new function that encrypts buffers under
 ECB mode using a consistent but unknown key (for instance, assign a
 single random key, once, to a global variable).

Now take that same function and have it append to the plaintext,
 BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

|-------------------------------------------|
|Spoiler alert.                             |
|                                           |
|Do not decode this string now. Don't do it.|
|-------------------------------------------|

Base64 decode the string before appending it. Do not base64 decode the
 string by hand; make your code do it. The point is that you don't know
 its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to
 the oracle function!

Here's roughly how:

    Feed identical bytes of your-string to the function 1 at a time ---
 start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the
 block size of the cipher. You know it, but do this step anyway.

    Detect that the function is using ECB. You already know, but do
 this step anyways.

    Knowing the block size, craft an input block that is exactly 1 byte
 short (for instance, if the block size is 8 bytes, make "AAAAAAA").
 Think about what the oracle function is going to put in that last byte
 position.

    Make a dictionary of every possible last byte by feeding different
 strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
 "AAAAAAAC", remembering the first block of each invocation.

    Match the output of the one-byte-short input to one of the entries
 in your dictionary. You've now discovered the first byte of
 unknown-string.

    Repeat for the next byte.

"""

import argparse
import base64
import math
import os
import random
import string
import sys
sys.path.insert(0, '../../utils')
from cpset2 import aes_ecb, gen_random_bytes, test_aes_ecb

random.seed(1)
GLOBAL_KEY = gen_random_bytes(16)

def check_oracle_ecb(block):
    if test_aes_ecb('A' * block * 10) != 0:
        return True
    return False

def convert_to_bytes(text):
    if type(text).__name__ == 'str':
        t = text.encode('utf-8')
    elif type(text).__name__ == 'bytes':
        t = text
    else:
        raise TypeError('Bad type passed to encryption_oracle')
    return t

def get_oracle_block_size():
    l = 0
    resize = 0
    cnt = 0
    for i in range(1,100):
        test = b'A' * i
        tl = len(encryption_oracle(test))
        if l == 0:
            l = tl
        elif resize == 0:
            if tl != l:
                cnt = 1
                l = tl
                resize = 1
        elif l == tl:
            cnt += 1
        else:
            return cnt
    return -1

def encryption_oracle(text):
    crypt = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
    crypt += 'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
    crypt += 'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
    crypt += 'YnkK'
    return aes_ecb(convert_to_bytes(text) + base64.b64decode(crypt), 
                   convert_to_bytes(GLOBAL_KEY))

def main():
    #ans = encryption_oracle("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",crypt)
    bs = get_oracle_block_size()
    if bs:
        print(bs)
        ecb = check_oracle_ecb(bs)
        if ecb:
            print('ECB detected!')
            return 0
    print('Fail.')
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Uses an oracle to decrypt AES in ECB mode, one byte at \
        a time.  This is the simple approach.'
        )
    args = parser.parse_args()

    sys.exit(main())
