#!/usr/bin/python3

"""
 The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

... has been XOR'd against a single character. Find the key, decrypt 
    the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. 
    Character frequency is a good metric. Evaluate each output and 
    choose the one with the best score. 
"""

import argparse
import string
import binascii
import sys


def find_key(hex_str):
    keys = ('', '', '')
    score = 0
    try:
        msg = binascii.unhexlify(hex_str.encode('utf-8'))
    except binascii.Error:
        print('Hexadecimal strings must be even length')
        return ''

    def get_score(s):
        s_score = 0
        for c in s:
            if c in string.ascii_letters or c == ' ' or c == '\n':
                s_score += 1
            elif c in string.punctuation or c in string.digits:
                s_score -= 5
            else:
                s_score -= 100
        return s_score

    def xor_key(msg, key):
        test_msg = ''.join(chr(y ^ key) for y in msg)
        s_score = get_score(test_msg)
        if s_score > 0:
            return test_msg, s_score
        return '', -1

    for x in range(1, 255):
        test, test_score = xor_key(msg, x, len(hex_str) / 2)
        if score < test_score:
            score = test_score
            keys = (chr(x), test, score)
    return keys


def main():
    ret = find_key(
        '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        )
    if ret:
        print(ret[0] + ": " + ret[1])
        return 0
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Tests finding a single char key by XOR\'ing a fixed hex \
        value representing encrypted data.')
    args = parser.parse_args()
    sys.exit(main())
