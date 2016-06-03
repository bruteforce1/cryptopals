#!/usr/bin/python3

"""
In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and
 deterministic; the same 16 byte plaintext block will always produce
 the same 16 byte ciphertext. 
"""

import argparse
import binascii
import string
import sys

def detect_aes_ecb(filename):

    def test_aes_ecb(ct):
        blocks = []
        for x in range(32,len(ct),32):
            blocks.append(ct[x-32:x])
        blocks.sort()
        ret = 0
        for y in range(1,len(blocks)):
            if blocks[y-1] == blocks[y]:
                ret += 1
        return ret

    tests = []
    with open(filename,'r') as f:
        for line in f:
            test = line.rstrip()
            tests.append((test,test_aes_ecb(test)))
    tests.sort(key=lambda x: x[1], reverse=True)
    return tests[0][0]

def main(filename):
    ans = detect_aes_ecb(filename)
    if ans:
        print('AES in ECB Detected:')
        print(ans)
        return 0
    print('Unable to detect AES in ECB mode block.')
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Takes a file with a bunch of cipher texts, and finds \
        the line encrypted with AES in ECB mode.'
        )
    parser.add_argument('inputfile', help='file with contents that contain \
        one string encrypted by AES in ECB mode')
    args = parser.parse_args()

    sys.exit(main(args.inputfile))
