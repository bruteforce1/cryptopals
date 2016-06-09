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
import os
import random
import string
import sys
sys.path.insert(0, '../../utils')
from cpset2 import aes_ecb

random.seed(1)

def convert_to_bytes(text):
    if type(text).__name__ == 'str':
        t = text.encode('utf-8')
    elif type(text).__name__ == 'bytes':
        t = text
    else:
        raise TypeError('Bad type passed to encryption_oracle')
    return t

def gen_random_bytes(block=16):
    if not 1 <= block <= 32:
        return b''
    return bytes(random.randint(0,255) for _ in range(block))

def encryption_oracle(text, crypt, key):
    return aes_ecb(convert_to_bytes(text) + convert_to_bytes(crypt), 
                   convert_to_bytes(key))

def main(filename):
    print('Input File: ' + str(filename))
    key = gen_random_bytes(16)
    print('Key: ' + str(key))
    crypt = ''

    if not os.path.isfile(filename):
        print(filename + ' is not a valid file.')
        return -1

    with open(filename,'r') as infile:
        for line in infile:
            crypt += line

    ans = encryption_oracle("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",crypt,key)
    if ans:
        print(ans)
        return 0
    print('Fail.')
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Uses an oracle to decrypt AES in ECB mode, one byte at \
        a time.  This is the simple approach.'
        )
    parser.add_argument('-f', '--inputfile', help='opt. file encrypted \
        with AES in ECB mode',
        default='./12.txt')
    args = parser.parse_args()

    sys.exit(main(args.inputfile))
