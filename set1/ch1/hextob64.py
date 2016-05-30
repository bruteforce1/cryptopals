#!/usr/bin/python3

"""
 The string:

49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

Should produce:

SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
"""

import argparse
import base64
import sys

def hextobase64(hexstr):
    return base64.b64encode(
        bytes(bytes.fromhex(hexstr).decode('utf-8'),'utf-8')).decode('utf-8')

def main(hexstring):
    print(hextobase64(hexstring))
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Convert a hex string to base64.')
    parser.add_argument('hex', help='hex string')
    args = parser.parse_args()
    sys.exit(main(args.hex))
