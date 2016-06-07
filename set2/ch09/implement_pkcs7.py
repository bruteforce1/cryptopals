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

def pkcs7_padding(message, block=16, pad=1):

    def check_pad_input(message,bl,pad):
        if type(message).__name__ == 'str':
            m = message.encode('utf-8')
        elif type(message).__name__ == 'bytes':
            m = message
        else:
            print('message is unexpected type.')
            return ('',-1,-1)
    
        try: 
            b = int(bl)
            if not 1 < b and b <= 32:
                raise ValueError('PKCS7 block must be between 1 and 32 bytes')
        except ValueError:
            print('Not a valid integer')
            return ('',-1,-1)

        try:
            p = int(pad)
            if not 0 <= pad <= 1:
                raise ValueError('Bad Encrypt')
        except ValueError:
            print('Encrypt not a valid integer between 0 and 1')
            return ('',-1,-1)
        return (m,b,p)

    def pkcs7_pad(m, bl=16):
        pad = bl
        if len(m) % bl:
            pad = bl - len(m) % bl
        ret = m + bytes([pad]) * pad
        return ret

    def pkcs7_unpad(m, bl=16):
        assert(len(m) % int(bl) == 0), 'Message length not evenly divided.'
        pad = int(m[-1])
        assert(m[-pad:] == bytes((pad,))*pad), 'Incorrect padding.'
        return m[:-pad]

    m, bl, p = check_pad_input(message, block, pad)
    assert(bl != -1), 'Invalid input.'
    if p:
        return(pkcs7_pad(m,bl))
    return(pkcs7_unpad(m,bl))

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
