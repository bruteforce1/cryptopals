#!/usr/bin/python3

"""
This module is used to define functions as they are worked through in 
 each of the challenges.  Functions will be added after the challenge
 is completed for use in future challenges.
"""

import base64
from Crypto.Cipher import AES
import os
import random
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

def aes_cbc(message, key, iv, encrypt=1):

    def check_aes_input(message, key, iv, encrypt):
        if type(message).__name__ == 'str':
            m = message.encode('utf-8')
        elif type(message).__name__ == 'bytes':
            m = message
        else:
            print('message is unexpected type.')
            return (b'',b'',-1,-1)

        if type(key).__name__ == 'str':
            k = key.encode('utf-8')
        elif type(key).__name__ == 'bytes':
            k = key
        else:
            print('key is unexpected type.')
            return (b'', b'', b'', -1)
        assert(len(k) == 16), 'Invalid key length'

        if type(iv).__name__ == 'str':
            i = iv.encode('utf-8')
        elif type(iv).__name__ == 'bytes':
            i = iv
        else:
            print('IV is unexpected type.')
            return (b'', b'', b'', -1)
        assert(len(i) == 16), 'Invalid IV length'

        try:
            e = int(encrypt)
            if not 0 <= encrypt <= 1:
                raise ValueError('Bad Encrypt')
        except ValueError:
            print('Encrypt not a valid integer between 0 and 1')
            return (b'', b'', b'', -1)
        return (m, k, i, e)

    def dec(text, key, iv):
        ret = b''
        pb = iv
        crypt = base64.b64decode(text)
        cipher = AES.new(key, AES.MODE_ECB)
        for bl in get_blocks(crypt, 16):
            ret += xor_bytes(cipher.decrypt(bl), pb)
            pb = bl
        return pkcs7_padding(ret,16,0)

    def enc(text, key, iv):
        ret = b''
        pb = iv
        crypt = pkcs7_padding(text,16,1)
        cipher = AES.new(key, AES.MODE_ECB)
        for bl in get_blocks(crypt, 16):
            pb = cipher.encrypt(xor_bytes(bl, pb))
            ret += pb
        return base64.b64encode(ret)

    def get_blocks(byte, bs):
        return [byte[i:i+bs] for i in range(0, len(byte), bs)]

    def xor_bytes(b1, b2):
        return b''.join(bytes([a ^ b]) for a,b in zip(b1,b2[:len(b1)]))
    
    crypt, k, i, e = check_aes_input(message, key, iv, encrypt)
    assert(e != -1), 'Invalid input.'

    if e:
        return enc(crypt, k, i)
    return dec(crypt, k, i)

def aes_ecb(message, key, encrypt=1):

    def check_aes_input(message, key, encrypt):
        if type(message).__name__ == 'str':
            m = message.encode('utf-8')
        elif type(message).__name__ == 'bytes':
            m = message
        else:
            print('message is unexpected type.')
            return (b'',b'',-1)

        if type(key).__name__ == 'str':
            k = key.encode('utf-8')
        elif type(key).__name__ == 'bytes':
            k = key
        else:
            print('key is unexpected type.')
            return (b'',b'',-1)
        assert(len(k) == 16), 'Invalid key length'

        try:
            e = int(encrypt)
            if not 0 <= encrypt <= 1:
                raise ValueError('Bad Encrypt')
        except ValueError:
            print('Encrypt not a valid integer between 0 and 1')
            return (b'',b'',-1)
        return (m, k, e)

    def dec(ct, key):
        cry = base64.b64decode(ct)
        cipher = AES.new(key, AES.MODE_ECB)
        c = cipher.decrypt(cry)
        return pkcs7_padding(c, 16, 0)
        
    def enc(ct, key):
        cry = pkcs7_padding(ct,16,1)
        cipher = AES.new(key, AES.MODE_ECB)
        c = cipher.encrypt(cry)
        return base64.b64encode(cry)

    crypt, k, e = check_aes_input(message, key, encrypt)
    assert(e != -1), 'Invalid input.'

    if e:
        return enc(crypt, k)
    return dec(crypt, k)

def make_b64_printable(enc):
    ret = b''
    blocks = [enc[i:i+60] for i in range(0, len(enc), 60)]
    for b in blocks:
        ret += b
        ret += b'\n'
    return ret

def test_aes_ecb(ct):
    blocks = []
    for x in range(32,len(ct),32):
        blocks.append(ct[x-32:x])
    blocks.sort()
    ret = 0
    for y in range(1,len(blocks)):
        if blocks[y-1] == blocks[y]:
            ret = 1
    return ret

def gen_random_bytes(block=16):
    if not 1 <= block <= 32:
        return b''
    return bytes(random.randint(0,255) for _ in range(block))

