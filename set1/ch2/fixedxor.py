#!/usr/bin/python3

"""
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c

... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965

... should produce:

746865206b696420646f6e277420706c6179
"""

import argparse
import base64
import sys
import binascii

def xorbinarystrings(str1, str2):
    if len(str1) != len(str2):
        print('XOR strings must be same length')
        return ''
    #print(bytes("".join(chr(x ^ y) for x, y in zip(binascii.unhexlify(str1), binascii.unhexlify(str2))), 'utf-8'))
    return binascii.hexlify(bytes("".join(chr(x ^ y) for x, y in zip(binascii.unhexlify(str1), binascii.unhexlify(str2))), 'utf-8')).decode('utf-8')

def main():
    ret = xorbinarystrings('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')
    print(ret)
    if ret == '746865206b696420646f6e277420706c6179':
        print('It worked!')
        return 0
    return -1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Tests XOR\'ing a fixed hex value against another fixed string.')
    args = parser.parse_args()
    sys.exit(main())
