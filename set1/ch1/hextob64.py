#!/usr/bin/python3

"""
 The string:

'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f75\
73206d757368726f6f6d'

Should produce:

SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
"""

import argparse
import binascii
import sys


def hex_to_base64(hex_string):
    try:
        ret = binascii.b2a_base64(
            binascii.unhexlify(hex_string)).decode("utf-8").rstrip()
    except binascii.Error:
        print("Hex string must contain an even length of values.")
        ret = ''
    return ret


def main(hex_string):
    ret = hex_to_base64(hex_string)
    if ret:
        print(ret)
        return 0
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Convert a hex string to base64.')
    parser.add_argument(
        '-x', '--hex', help='opt. hex string',
        default='49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    args = parser.parse_args()
    sys.exit(main(args.hex))
