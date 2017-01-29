#!/usr/bin/python3

"""
This module is used to define functions as they are worked through in 
 each of the challenges.  Functions will be added after the challenge
 is completed for use in future challenges.
"""

import base64
from Crypto.Cipher import AES
import random


class PaddingError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


def pkcs7_padding(message, block=16, pad=1):
    #    class PaddingError(Exception):
    #        def __init__(self, value):
    #            self.value = value
    #        def __str__(self):
    #            return repr(self.value)

    def check_pad_input(msg, blk, padding):
        if type(msg).__name__ == 'str':
            m = msg.encode('utf-8')
        elif type(msg).__name__ == 'bytes':
            m = msg
        else:
            print('message is unexpected type.')
            return '', -1, -1
    
        try: 
            b = int(blk)
            if not 1 < b and b <= 32:
                raise ValueError('PKCS7 block must be between 1 and 32 bytes')
        except ValueError:
            print('Not a valid integer')
            return '', -1, -1

        try:
            p = int(padding)
            if not 0 <= padding <= 1:
                raise ValueError('Bad Encrypt')
        except ValueError:
            print('Encrypt not a valid integer between 0 and 1')
            return '', -1, -1
        return m, b, p

    def pkcs7_pad(msg, blk=16):
        padding = blk
        if len(my_msg) % blk:
            padding = blk - len(msg) % blk
        ret = msg + bytes([padding]) * padding
        return ret

    def pkcs7_unpad(msg, blk=16):
        if len(msg) % int(blk) != 0:
            raise PaddingError('Message length not evenly divided.')
        padding = int(msg[-1])
        if msg[-padding:] != bytes((padding,))*padding:
            raise PaddingError('Incorrect padding.')
        return msg[:-padding]

    my_msg, my_bl, my_pad = check_pad_input(message, block, pad)
    assert(my_bl != -1), 'Invalid input.'
    if my_pad:
        return pkcs7_pad(my_msg, my_bl)
    return pkcs7_unpad(my_msg, my_bl)


def aes_cbc(message, key, iv, encrypt=1):

    def check_aes_input(msg, in_key, in_iv, is_enc):
        if type(msg).__name__ == 'str':
            m = msg.encode('utf-8')
        elif type(msg).__name__ == 'bytes':
            m = msg
        else:
            print('message is unexpected type.')
            return b'', b'', -1, -1

        if type(in_key).__name__ == 'str':
            k = in_key.encode('utf-8')
        elif type(in_key).__name__ == 'bytes':
            k = in_key
        else:
            print('key is unexpected type.')
            return b'', b'', b'', -1
        if len(k) != 16 and len(k) != 24 and len(k) != 32:
            print('Invalid key length')
            return b'', b'', b'', -1

        if type(in_iv).__name__ == 'str':
            i = in_iv.encode('utf-8')
        elif type(in_iv).__name__ == 'bytes':
            i = in_iv
        else:
            print('IV is unexpected type.')
            return b'', b'', b'', -1
        assert(len(i) == 16), 'Invalid IV length'

        try:
            e = int(is_enc)
            if not 0 <= is_enc <= 1:
                raise ValueError('Bad Encrypt')
        except ValueError:
            print('Encrypt not a valid integer between 0 and 1')
            return b'', b'', b'', -1
        return m, k, i, e

    def dec(ct, in_key, in_iv):
        ret = b''
        pb = in_iv
        cry = base64.b64decode(ct)
        cipher = AES.new(in_key, AES.MODE_ECB)
        for bl in get_blocks(cry, 16):
            ret += xor_bytes(cipher.decrypt(bl), pb)
            pb = bl
        return pkcs7_padding(ret,16,0)

    def enc(text, in_key, in_iv):
        ret = b''
        pb = in_iv
        to_crypt = pkcs7_padding(text,16,1)
        cipher = AES.new(in_key, AES.MODE_ECB)
        for bl in get_blocks(to_crypt, 16):
            pb = cipher.encrypt(xor_bytes(bl, pb))
            ret += pb
        return base64.b64encode(ret)

    def get_blocks(byte, bs):
        return [byte[i:i+bs] for i in range(0, len(byte), bs)]

    def xor_bytes(b1, b2):
        return b''.join(bytes([a ^ b]) for a,b in zip(b1,b2[:len(b1)]))
    
    my_crypt, my_key, my_iv, my_enc = check_aes_input(message, key, iv, encrypt)
    assert(my_enc != -1), 'Invalid input.'

    if my_enc:
        return enc(my_crypt, my_key, my_iv)
    return dec(my_crypt, my_key, my_iv)


def aes_ecb(message, key, encrypt=1):

    def check_aes_input(msg, in_key, is_enc):
        if type(msg).__name__ == 'str':
            m = msg.encode('utf-8')
        elif type(msg).__name__ == 'bytes':
            m = msg
        else:
            print('message is unexpected type.')
            return b'', b'', -1

        if type(in_key).__name__ == 'str':
            k = in_key.encode('utf-8')
        elif type(in_key).__name__ == 'bytes':
            k = in_key
        else:
            print('key is unexpected type.')
            return b'', b'', -1
        if len(k) != 16 and len(k) != 24 and len(k) != 32:
            print('Invalid key length')
            print(len(k))
            return b'', b'', -1

        try:
            e = int(is_enc)
            if not 0 <= is_enc <= 1:
                raise ValueError('Bad Encrypt')
        except ValueError:
            print('Encrypt not a valid integer between 0 and 1')
            return b'', b'', -1
        return m, k, e

    def dec(ct, in_key):
        cry = base64.b64decode(ct)
        cipher = AES.new(in_key, AES.MODE_ECB)
        c = cipher.decrypt(cry)
        return pkcs7_padding(c, 16, 0)
        
    def enc(text, in_key):
        cry = pkcs7_padding(text, 16, 1)
        cipher = AES.new(in_key, AES.MODE_ECB)
        c = cipher.encrypt(cry)
        return base64.b64encode(c)

    my_crypt, my_key, my_enc = check_aes_input(message, key, encrypt)
    assert(my_enc != -1), 'Invalid input.'

    if my_enc:
        return enc(my_crypt, my_key)
    return dec(my_crypt, my_key)


def make_b64_printable(enc):
    ret = b''
    blocks = [enc[i:i+60] for i in range(0, len(enc), 60)]
    for b in blocks:
        ret += b
        ret += b'\n'
    return ret


def test_aes_ecb(ct, bs=16):
    blocks = []
    crypt = base64.b64decode(ct)
    for x in range(bs, len(crypt), bs):
        blocks.append(crypt[x-bs:x])
    blocks.sort()
    for y in range(1, len(blocks)):
        if blocks[y-1] == blocks[y]:
            return True
    return False


def gen_random_bytes(block=16):
    if not 1 <= block <= 32:
        return b''
    return bytes(random.randint(0, 255) for _ in range(block))

