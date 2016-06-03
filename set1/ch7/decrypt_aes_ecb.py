#!/usr/bin/python3

"""
The Base64-encoded content in this file has been encrypted via AES-128
 in ECB mode under the key

"YELLOW SUBMARINE".

(case-sensitive, without the quotes; exactly 16 characters; I like
 "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do
 too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
"""

import argparse
import binascii
from Crypto.Cipher import AES
import string
import sys

def decrypt_aes_ecb(filename, key):

    def decrypt_cipher_text(ct, key):
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(ct).decode('utf-8')

    crypt = ''
    with open(filename,'r') as f:
        for line in f:
            crypt += line.rstrip()
    cry = binascii.a2b_base64(crypt)
    return decrypt_cipher_text(cry, key)

def main(filename, key):
    ans = decrypt_aes_ecb(filename, key)
    if key:
        print('Key: ' + key)
        print('Decrypted:')
        print(ans)
        return 0
    print('Error.')
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Takes a message encrypted with repeating key XOR, and \
        finds the key and decrypts it.'
        )
    parser.add_argument('inputfile', help='file with contents encrypted by \
        AES ECB and base64 encoded')
    parser.add_argument('-k', '--key', help='opt. key',
                    default='YELLOW SUBMARINE')
    args = parser.parse_args()

    sys.exit(main(args.inputfile,args.key))
