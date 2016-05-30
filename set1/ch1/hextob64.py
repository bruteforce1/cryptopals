#!/usr/bin/python3

"""
 The string:

'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f75\
73206d757368726f6f6d'

Should produce:

SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
"""

import argparse
import base64
import binascii
import sys

def hex_to_base64(hexstr):
    return base64.b64encode(bytes.fromhex(hexstr)).decode('utf-8')

def main(hexstring):
    print(hex_to_base64(hexstring))
    return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Convert a hex string to base64.')
    parser.add_argument('hex', help='hex string')
    args = parser.parse_args()
    sys.exit(main(args.hex))
