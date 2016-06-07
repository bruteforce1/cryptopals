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
import base64
from Crypto.Cipher import AES
import os
import string
import sys
import textwrap
sys.path.insert(0, '../')
from set2_util import pad_pkcs7, unpad_pkcs7

def check_aes_input(filename, key, iv, encrypt):
    if not os.path.isfile(filename):
        print(filename + ' is not a valid file.')
        return ('', b'', b'', -1)

    if type(key).__name__ == 'str':
        k = key.encode('utf-8')
    elif type(key).__name__ == 'bytes':
        k = key
    else:
        print('key is unexpected type.')
        return ('', b'', b'', -1)
    assert(len(k) == 16), 'Invalid key length'

    if type(iv).__name__ == 'str':
        i = iv.encode('utf-8')
    elif type(iv).__name__ == 'bytes':
        i = iv
    else:
        print('IV is unexpected type.')
        return ('', b'', b'', -1)
    assert(len(i) == 16), 'Invalid IV length'

    try:
        e = int(encrypt)
        if not 0 <= encrypt <= 1:
            raise ValueError('Bad Encrypt')
    except ValueError:
        print('Encrypt not a valid integer between 0 and 1')
        return ('', b'', b'', -1)
    return (filename, k, i, e)

def aes_cbc(filename, key, iv, encrypt=1):

    def xor_bytes(b1, b2):
        return b''.join(bytes([a ^ b]) for a,b in zip(b1,b2[:len(b1)]))

    def get_blocks(byte, bs):
        return [byte[i:i+bs] for i in range(0, len(byte), bs)]

    def enc(text, key, iv):
        ret = b''
        pb = iv
        crypt = pad_pkcs7(text)
        cipher = AES.new(key, AES.MODE_ECB)
        for bl in get_blocks(crypt, 16):
            pb = cipher.encrypt(xor_bytes(bl, pb))
            ret += pb
        return base64.b64encode(ret)

    def dec(text, key, iv):
        ret = b''
        pb = iv
        crypt = base64.b64decode(text)
        cipher = AES.new(key, AES.MODE_ECB)
        for bl in get_blocks(crypt, 16):
            ret += xor_bytes(cipher.decrypt(bl), pb)
            pb = bl
        return unpad_pkcs7(ret)

    f, k, i, e = check_aes_input(filename, key, iv, encrypt)
    assert(e is not -1), 'Invalid input.'

    crypt = ''

    with open(f,'r') as infile:
        for line in infile:
            if not e:
                line = line.rstrip()
            crypt += line
    if e:
        return enc(crypt, k, i)
    return dec(crypt, k, i)

def main(filename, key, iv):
    print('Input File: ' + str(filename))
    print('Key: ' + str(key))
    print('IV: ' + str(iv))
    ret = aes_cbc(filename, key, iv, 0)
    if ret:
        print('Decrypted Contents in: ' + filename + '.dec')
        with open(filename + '.dec', 'w') as tf:
            tf.write(ret.decode('utf-8'))
        unret = aes_cbc(filename + '.dec', key, iv)
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
