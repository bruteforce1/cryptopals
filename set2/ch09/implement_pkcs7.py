#!/usr/bin/python3

"""
 A block cipher transforms a fixed-sized block (usually 8 or 16 bytes)
 of plaintext into ciphertext. But we almost never want to transform a
 single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding,
 creating a plaintext that is an even multiple of the blocksize. The
 most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number
 of bytes of padding to the end of the block. For instance,

"YELLOW SUBMARINE"

... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"
"""

import argparse
import string
import sys
sys.path.insert(0, '../../utils')
from cpset2 import pkcs7_padding

def main(message, bl):
    print('Line: ' + str(message))
    print('blocklength: ' + str(bl))
    ret = pkcs7_padding(message,bl,1)
    if ret:
        print('PKCS#7 padded: ')
        print(ret)
        unret = pkcs7_padding(ret,bl,0)
        if unret:
            print('PKCS#7 unpadded: ')
            print(unret)
            return 0
    print('Error.')
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Implements PKCS#7 padding of a message to a block \
        length of 20.'
        )
    parser.add_argument('-m', '--message', help='opt. message to pad',
                    default='YELLOW SUBMARINE')
    parser.add_argument('-b', '--blocklength', help='opt. block length \
                    in bytes, between 1-32',
                    default='20')
    args = parser.parse_args()
    sys.exit(main(args.message, args.blocklength))
