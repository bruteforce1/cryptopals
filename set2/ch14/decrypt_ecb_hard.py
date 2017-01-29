#!/usr/bin/python3

"""

Take your oracle function from #12. Now generate a random count of
 random bytes and prepend this string to every plaintext. You are now
 doing:

AES-128-ECB(random-prefix || attacker-controlled 
            || target-bytes, random-key)

Same goal: decrypt the target-bytes.

Stop and think for a second.

What's harder than challenge #12 about doing this? How would you
 overcome that obstacle? The hint is: you're using all the tools you
 already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".

"""

import argparse
import base64
import random
import sys
from utils.cpset2 import aes_ecb, gen_random_bytes, test_aes_ecb

random.seed(1)
GLOBAL_KEY = gen_random_bytes(16)


def convert_to_bytes(text):
    if type(text).__name__ == 'str':
        t = text.encode('utf-8')
    elif type(text).__name__ == 'bytes':
        t = text
    else:
        raise TypeError('Bad type passed to encryption_oracle')
    return t


def decrypt_ecb(block):
    ans = b''
    mult = 0
    ora, enc = find_first_oracle(block)
    ct_len = len(enc) + block

    while len(ans) < ct_len:
        if len(ans) % block == 0:
            mult += 1
        pad = b'B' * block + b'A' * (block - (len(ans)%block + 1))
        oracle = b''
        while ora not in oracle:
            oracle = base64.b64decode(encryption_oracle(pad))
        oracle = oracle.split(ora)[1]
        found = 0
        for test in range(0, 255):
            te = pad + ans + bytes([test])
            enc = b''
            while ora not in enc:
                enc = base64.b64decode(encryption_oracle(te))
            enc = enc.split(ora)[1]
            if enc[:block*mult] == oracle[:block*mult]:
                ans += bytes([test])
                found = 1
                break
        if not found:
            break
    pad = int(ans[-1])
    if ans[-pad:] != bytes((pad,))*pad:
        print('Issue removing final pad.')
        print('Decrypted text: ')
        print(ans)
        return ''
    return ans[:-pad].decode('utf-8')


def encryption_oracle(text):
    ora_prefix = gen_random_bytes(random.randrange(0, 64))
    crypt = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
    crypt += 'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
    crypt += 'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
    crypt += 'YnkK'
    return aes_ecb(convert_to_bytes(ora_prefix) + convert_to_bytes(text)
                   + base64.b64decode(crypt),
                   convert_to_bytes(GLOBAL_KEY), 1)


def find_first_oracle(block):
    count = 0
    while count < block:
        found = False
        while not found:
            enc = encryption_oracle(b'B' * (2*block))
            if test_aes_ecb(enc):
                found = True
        blocks = []
        crypt = base64.b64decode(enc)
        for x in range(block, len(crypt), block):
            blocks.append(crypt[x-block:x])
        # blocks.sort()
        for y in range(1, len(blocks)-1):
            if blocks[y-1] == blocks[y]:
                return blocks[y], b''.join(x for x in blocks[y+1:])
        count += 1
    return ''


def find_max_block_size(test):
    l = 0
    for i in range(1, 256):
        tl = len(encryption_oracle(test))
        if l < tl:
            l = tl
    return l


def get_oracle_block_size():
    l = 0
    resize = 0
    cnt = 0
    for i in range(1, 100):
        test = b'A' * i
        tl = find_max_block_size(test)
        if l == 0:
            l = tl
        elif resize == 0:
            if tl != l:
                cnt = 1
                l = tl
                resize = 1
        elif l == tl:
            cnt += 1
        else:
            return cnt
    return -1


def is_oracle_ecb(block):
    enc = encryption_oracle('B' * block * 10)
    if test_aes_ecb(enc, block):
        return True
    return False


def manage_decrypt_aes_ecb():
    bs = get_oracle_block_size()
    if bs:
        ecb = is_oracle_ecb(bs)
        if ecb:
            return decrypt_ecb(bs)
    return ''


def main():
    ans = manage_decrypt_aes_ecb()
    if ans:
        print(ans)
        return 0
    print('Fail.')
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Uses an oracle to decrypt AES in ECB mode, one byte at \
        a time.  This is the hard approach.'
        )
    args = parser.parse_args()

    sys.exit(main())