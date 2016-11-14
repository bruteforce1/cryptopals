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
import random
import re
import string
import sys
sys.path.insert(0, './utils')
from cpset2 import aes_ecb, gen_random_bytes, test_aes_ecb

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

def attacker():
    #make up email.
    #count 'email=' + email account, find pos of 16th char
    #replace 16th char to end of email with 'admin' and pkcs7 padding
    #encrypt modded email
    #count rest of profile string after email account '&' and after
    #set email name so that 'role=' is the end of the 2nd to last block
    #replace last block with 'admin' block from first attempt
    #test print encrypted profile and decrypted modded profile
    #return above if role=admin
    #return empty string otherwise
    return b''

def main():
    #prof = decode_profile('test2=test2&user=foo&name=blah')
    #encode_profile(prof)
    prof = profile_for('foo@bar.com')
    enc = encrypt_profile(prof)
    dec = decrypt_profile(enc)
    print(dec)
    ans = attacker()
    if ans:
        print(ans)
        return 0
    print('Fail.')
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Demonstrates the capability of an attacker to overwrite \
        data encrypted with ECB block mode by switching out blocks.'
        )
    args = parser.parse_args()

    sys.exit(main())
