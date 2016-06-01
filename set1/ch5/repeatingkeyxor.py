#!/usr/bin/python3

"""
Here is the opening stanza of an important work of the English 
 language:

    Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal

Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; 
 the first byte of plaintext will be XOR'd against I, the next C, the 
 next E, then I again for the 4th byte, and so on.

It should come out to:

0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263242727\
65272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e272\
82f

Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt
 your mail. Encrypt your password file. Your .sig file. Get a feel for 
 it. I promise, we aren't wasting your time with this. 
"""

import argparse
import string
import sys
import math
import binascii

def encrypt(msg, key):
    msglen=len(msg)
    testmsg = ''.join(chr(ord(x) ^ ord(y)) 
        for x,y in zip(key*(math.ceil(msglen/len(key))+1),msg))
    return binascii.hexlify(testmsg.encode('utf-8')).decode('utf-8')

def main(message, key):
    print('Line: ' + message)
    print('Key: ' + key)
    ret = encrypt(message,key)
    if ret:
        print('Encrypt: ' + ret)
        return 0
    print('Error.')
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Encrypts a message with repeating key XOR')
    parser.add_argument('-m', '--message', help='opt. message to encrypt',
                    default='')
    parser.add_argument('-k', '--key', help='opt. key',
                    default='ICE')
    args = parser.parse_args()
    if not args.message:
        args.message = 'Burning \'em, if you ain\'t quick and nimble\nI go'
        args.message += ' crazy when I hear a cymbal'
    sys.exit(main(args.message, args.key))
