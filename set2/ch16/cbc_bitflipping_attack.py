#!/usr/bin/python3

"""

Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

 "comment1=cooking%20MCs;userdata="

.. and append the string:

 ";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and
 encrypt it under the random AES key.

The second function should decrypt the string and look for the characters
 ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert
  each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to
 provide user input to it that will generate the string the second function is
 looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish
 this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext
 block:

    Completely scrambles the block the error occurs in
    Produces the identical 1-bit error(/edit) in the next ciphertext block.

Stop and think for a second.

Before you implement this attack, answer this question: why does CBC mode have
 this property?

"""

import argparse
import base64
import random
import re
import sys
from utils.cpset2 import aes_cbc, gen_random_bytes

random.seed(1)
GLOBAL_KEY = gen_random_bytes(16)
GLOBAL_IV = gen_random_bytes(16)
GLOBAL_PREPEND = 'comment1=cooking%20MCs;userdata='
GLOBAL_APPEND = ';comment2=%20like%20a%20pound%20of%20bacon'
GLOBAL_ADMIN = ';admin=true;'
GLOBAL_BLOCK = 16


def attacker():
    prepend_size = GLOBAL_BLOCK - (len(GLOBAL_PREPEND) % GLOBAL_BLOCK) + GLOBAL_BLOCK
    admin_mod = GLOBAL_ADMIN
    if admin_mod[-1:] == ';':
        admin_mod = admin_mod[:-1]
    admin_mod, flips = flip_admin(admin_mod)
    admin_profile = 'A' * prepend_size + admin_mod
    admin_enc = encrypt_user_data(admin_profile)
    admin_enc = flip_enc(admin_enc, flips, prepend_size)
    if decrypt_profile(admin_enc):
        return admin_profile
    return ''


def decrypt_profile(profile):
    dec_profile = aes_cbc(profile, GLOBAL_KEY, GLOBAL_IV, 0)
    print(dec_profile)
    if GLOBAL_ADMIN in str(dec_profile):
        return True
    return False


def encrypt_user_data(input_data):
    mod_input = re.sub('[=;]', '', input_data)
    profile = GLOBAL_PREPEND + mod_input + GLOBAL_APPEND
    return aes_cbc(profile, GLOBAL_KEY, GLOBAL_IV, 1)


def flip_admin(admin_input):
    flips = []
    admin_mod = admin_input
    for y in range(0, len(admin_mod)-1):
        if admin_mod[y] == '=' or admin_mod[y] == ';':
            new_val = chr(ord(admin_mod[y]) ^ 1)
            admin_mod = admin_mod[:y] + new_val + admin_mod[y+1:]
            flips.append(y)
    return admin_mod, flips


def flip_enc(admin_enc, flips, prepend_size):
    offset = len(GLOBAL_PREPEND) + prepend_size - GLOBAL_BLOCK
    admin_bin = bytearray(base64.b64decode(admin_enc.decode('utf-8')))
    for x in flips:
        pos = offset + x
        admin_bin[pos] ^= 1
    return base64.b64encode(admin_bin)


def main():
    ans = attacker()
    if ans:
        print('We can use the following input and flip bits in the prepended buffer to generate admin access:')
        print(ans)
        return 0
    print('Fail.')
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Conducts bit-flipping against CBC to convert a user to an admin.'
        )
    args = parser.parse_args()

    sys.exit(main())