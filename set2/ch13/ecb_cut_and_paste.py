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
import string
import sys
sys.path.insert(0, './utils')
from cpset2 import aes_ecb, gen_random_bytes, test_aes_ecb, pkcs7_padding

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
    encprofile = ''
    for item in profile:
        if encprofile:
            encprofile = encprofile + '&' + str(item[0]) \
                       + '=' + str(item[1])
        else:
            encprofile = str(item[0]) + '=' + str(item[1])
    return encprofile

def profile_for(email):
    global UID
    profile = []
    newemail = re.sub('[=&]', '', email)

    profile.append(['email', newemail])
    profile.append(['uid', UID])
    profile.append(['role', 'user'])
    encprofile = encode_profile(profile)

    UID = UID + 1

    return encprofile

def encrypt_profile(profile):
    return aes_ecb(profile,GLOBAL_KEY,1)

def decrypt_profile(profile):
    return aes_ecb(profile,GLOBAL_KEY,0)

def attacker(email):
    blocklen = 16
    
    def findoffsets(email):
        prof = profile_for(email)
        tofind = 'role='
        def_start = len(prof.split(email)[0])
        role_start = len(prof.split(tofind)[0]) + len(tofind)
        start_offset = blocklen - def_start%blocklen
        role_offset = blocklen - role_start%blocklen
        return start_offset, role_offset

    def findprof(email):
        if not email:
            return ''

        apos,rpos = findoffsets(email)
        pk7pad = pkcs7_padding('admin')

        adminemail = email[0:apos].encode('UTF-8') + pk7pad
        adminprof = profile_for(adminemail.decode('utf-8'))
        adminenc = encrypt_profile(adminprof)
        adminblock = math.floor(len(adminprof.split('admin')[0])/blocklen) + 1

        roleemail = email + email[-1]*rpos
        roleprof = profile_for(roleemail)
        roleenc = encrypt_profile(roleprof)
        roleblock = math.ceil(len(roleprof)/blocklen)

        retenc = binascii.b2a_base64(binascii.a2b_base64(roleenc)[0:blocklen*(roleblock-1)] + \
                 binascii.a2b_base64(adminenc)[(adminblock-1)*blocklen:(adminblock)*blocklen])

        return retenc

    enc = findprof(email)
    if enc:
        return enc
    return b''

def main(email):
    #prof = decode_profile('test2=test2&user=foo&name=blah')
    #encode_profile(prof)
    #enc = encrypt_profile(prof)
    #dec = decrypt_profile(enc)
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
