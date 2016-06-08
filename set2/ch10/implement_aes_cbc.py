#!/usr/bin/python3

"""
 CBC mode is a block cipher mode that allows us to encrypt irregularly-
 sized messages, despite the fact that a block cipher natively only
 transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block
 before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext
 block, is added to a "fake 0th ciphertext block" called the
 initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote
 earlier, making it encrypt instead of decrypt (verify this by
 decrypting whatever you encrypt to test), and using your XOR function
 from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against
 "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c) 
"""

import argparse
import os
import string
import sys
sys.path.insert(0, '../../utils')
from cpset2 import aes_cbc

def main(filename, key, iv):
    print('Input File: ' + str(filename))
    print('Key: ' + str(key))
    print('IV: ' + str(iv))
    crypt = ''

    if not os.path.isfile(filename):
        print(filename + ' is not a valid file.')
        return -1
    
    with open(filename,'r') as infile:
        for line in infile:
            crypt += line

    ret = aes_cbc(crypt, key, iv, 0)
    if ret:
        print('Decrypted Contents in: ' + filename + '.dec')
        with open(filename + '.dec', 'w') as tf:
            tf.write(ret.decode('utf-8'))
        unret = aes_cbc(ret, key, iv)
        if unret:
            print('Encrypted Contents in: ' + filename + '.enc')
            with open(filename + '.enc', 'w') as tf:
                tf.write(unret.decode('utf-8'))
            return 0
    print('Error.')
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Implements AES CBC encryption and decryption manually.')
    parser.add_argument('-f', '--inputfile', help='opt. file encrypted \
        with AES in CBC mode', 
        default='./10.txt')
    parser.add_argument('-i', '--iv', help='opt. 16 byte initializtion \
        vector',
        default=chr(0) * 16)
    parser.add_argument('-k', '--key', help='opt. 16 byte encryption or \
        decryption key',
        default='YELLOW SUBMARINE')
    args = parser.parse_args()
    sys.exit(main(args.inputfile, args.key, args.iv))
