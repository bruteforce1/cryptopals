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

def check_block(bl):
    try: 
        b = int(bl)
        if 1 < b and b <= 32:
            return b
        print('PKCS7 block size must be between 1 and 32 bytes')
    except ValueError:
        print('Not a valid integer')
    return -1


def pad_pkcs7(message, block=16):
    bl = check_block(block)
    assert(bl != -1)
    pad = bl
    if len(message) % bl:
        pad = bl - len(message) % bl
    ret = message + chr(pad) * pad
    return ret.encode('utf-8')

def unpad_pkcs7(message, block=16):
    bl = check_block(block)
    assert(bl != -1)
    assert(len(message) % int(bl) == 0)
    pad = int(message[-1])
    assert(message[-pad:] == bytes((pad,))*pad)
    return message[:-pad]

def main(message, bl):
    print('Line: ' + message)
    print('blocklength: ' + bl)
    ret = pad_pkcs7(message,bl)
    if ret:
        print('PKCS#7 padded: ')
        print(ret)
    unret = unpad_pkcs7(ret,bl)
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
