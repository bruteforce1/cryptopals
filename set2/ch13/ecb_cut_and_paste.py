#!/usr/bin/python3

"""
 Write a k=v parsing routine, as if for a structured cookie. The
 routine should take:

foo=bar&baz=qux&zap=zazzle

... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given
 an email address. You should have something like:

profile_for("foo@bar.com")

... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}

... encoded as:

email=foo@bar.com&uid=10&role=user

Your "profile_for" function should not allow encoding metacharacters
 (& and =). Eat them, quote them, whatever you want to do, but don't
 let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

  - Encrypt the encoded user profile under the key; "provide" that to
 the "attacker".
  - Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate
 "valid" ciphertexts) and the ciphertexts themselves, make a role=admin
 profile. 
"""

import argparse
import binascii
import math
import random
import re
import sys
from utils.cpset2 import aes_ecb, gen_random_bytes, test_aes_ecb, pkcs7_padding

UID = 10
random.seed(1)
GLOBAL_KEY = gen_random_bytes(16)


def decode_profile(cookie):
    profile = []
    items = cookie.split('&')
    for item in items:
        if '=' not in item:
            return ''
        tup = [item.split('=')[0], item.split('=')[1]]
        profile.append(tup)
    return profile


def encode_profile(profile):
    enc_profile = ''
    for item in profile:
        if enc_profile:
            enc_profile = enc_profile + '&' + str(item[0]) \
                       + '=' + str(item[1])
        else:
            enc_profile = str(item[0]) + '=' + str(item[1])
    return enc_profile


def profile_for(email):
    global UID
    profile = []
    new_email = re.sub('[=&]', '', email)

    profile.append(['email', new_email])
    profile.append(['uid', UID])
    profile.append(['role', 'user'])
    enc_profile = encode_profile(profile)
    UID += 1
    return enc_profile


def encrypt_profile(profile):
    return aes_ecb(profile, GLOBAL_KEY, 1)


def decrypt_profile(profile):
    return aes_ecb(profile, GLOBAL_KEY, 0)


def attacker(email):
    block_len = 16
    
    def find_offsets(in_email):
        prof = profile_for(in_email)
        to_find = 'role='
        def_start = len(prof.split(in_email)[0])
        role_start = len(prof.split(to_find)[0]) + len(to_find)
        start_offset = block_len - def_start % block_len
        role_offset = block_len - role_start % block_len
        return start_offset, role_offset

    def find_profile(in_email):
        if not in_email:
            return ''

        apos, rpos = find_offsets(in_email)
        pk7pad = pkcs7_padding('admin')

        admin_email = in_email[0:apos].encode('UTF-8') + pk7pad
        admin_prof = profile_for(admin_email.decode('utf-8'))
        admin_email = encrypt_profile(admin_prof)
        admin_block = math.floor(len(admin_prof.split('admin')[0])/block_len) + 1

        role_email = in_email + in_email[-1] * rpos
        role_prof = profile_for(role_email)
        role_enc = encrypt_profile(role_prof)
        role_block = math.ceil(len(role_prof)/block_len)

        ret_enc = binascii.b2a_base64(binascii.a2b_base64(role_enc)[0:block_len*(role_block-1)] +
                                      binascii.a2b_base64(admin_email)[(admin_block-1)*block_len:admin_block*block_len])
        return ret_enc

    enc = find_profile(email)
    if enc:
        return enc
    return b''


def main(email):
    #    prof = decode_profile('test2=test2&user=foo&name=blah')
    #    encode_profile(prof)
    #    enc = encrypt_profile(prof)
    #    dec = decrypt_profile(enc)
    print('Attempting for email: {0}'.format(email))
    ans = attacker(email)
    if ans:
        dec = decrypt_profile(ans)
        print('Encrypted Profile: {0}'.format(ans))
        print('Decrypted Profile: {0}'.format(dec))
        return 0
    print('Fail.')
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Demonstrates the capability of an attacker to overwrite \
        data encrypted with ECB block mode by switching out blocks.'
        )
    parser.add_argument('-e', '--email', help='opt. email',
                        default='foo@bar.com')
    args = parser.parse_args()

    sys.exit(main(args.email))
