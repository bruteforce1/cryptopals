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
import string
import sys

def hex_to_base64(hexstr):
    try:
        ret = binascii.b2a_base64(binascii.unhexlify(hexstr)).decode("utf-8").rstrip()
    except binascii.Error:
        print("Hex string must contain an even length of values.")
        ret = ''
    return ret

def main(hexstring):
    ret = hex_to_base64(hexstring)
    if ret:
        print(ret)
        return 0
    return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Convert a hex string to base64.')
    parser.add_argument('hex', help='hex string')
    args = parser.parse_args()
    sys.exit(main(args.hex))
