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

def pad_pkcs7(message, block):
    pad = block - len(message) % block
    pc = '\\x' + '%02d' % (pad,)
    return message + (pc * pad)

def check_args(bl):
    try: 
        block = int(bl)
        if 0 < block and block < 100:
            return block
    except ValueError:
        print('Not an integer')
    return -1

def main(message, bl):
    print('Line: ' + message)
    print('blocklength: ' + bl)
    block = check_args(bl)
    if block is not -1:
        ret = pad_pkcs7(message,block)
        if ret:
            print('PKCS#7 padded: ' + ret)
            return 0
        else:
            print('Error.')
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Implements PKCS#7 padding of a message to a block \
        length of 20.'
        )
    parser.add_argument('-m', '--message', help='opt. message to pad',
                    default='YELLOW SUBMARINE')
    parser.add_argument('-b', '--blocklength', help='opt. block length',
                    default='20')
    args = parser.parse_args()
    sys.exit(main(args.message, args.blocklength))
